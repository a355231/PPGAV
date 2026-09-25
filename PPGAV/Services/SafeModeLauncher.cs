using System.Diagnostics;
using System.Security.Cryptography;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class SafeModeLauncher
{
    private readonly IOutboundNetworkBlocker _firewall;
    private readonly EventLogService _events;
    private readonly string _manifestRoot;
    private readonly Action<string, string>? _beforeMove;
    private readonly Func<string, IEnumerable<string>> _workshopRootProvider;
    private string ManifestRoot => _manifestRoot;
    public bool RecoverySucceeded { get; private set; } = true;

    private sealed record DisabledEntry(string Original, string Disabled, string State);
    private sealed record SafeModeManifest(int FormatVersion, string Owner, string SessionId, string GameRoot, string Executable, string FirewallRule, List<DisabledEntry> Entries, string State);

    public SafeModeLauncher(IOutboundNetworkBlocker firewall, EventLogService events, string? manifestRoot = null,
        Action<string, string>? beforeMove = null, Func<string, IEnumerable<string>>? workshopRootProvider = null)
    {
        _firewall = firewall; _events = events; _beforeMove = beforeMove;
        _workshopRootProvider = workshopRootProvider ?? GamePathDiscovery.FindWorkshopDirectories;
        _manifestRoot = Path.GetFullPath(manifestRoot ?? Path.Combine(AppPaths.SandboxFolder, "SafeModeSessions"));
    }

    public void RecoverStaleDisabledMods(string gameRoot)
    {
        RecoverySucceeded = true;
        string? configuredRoot = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(gameRoot) && Directory.Exists(gameRoot)) configuredRoot = SecurePathService.RequireExistingDirectory(gameRoot, "game directory");
        }
        catch (Exception ex) { _events.Log("Configured game path rejected during recovery", ex.Message, ScanCategory.Suspicious); }
        EnsureManifestRoot();
        foreach (var manifestPath in Directory.EnumerateFiles(ManifestRoot, "*.json", SearchOption.TopDirectoryOnly))
        {
            try
            {
                SecurePathService.RequireContained(ManifestRoot, manifestPath, true, "Safe Mode manifest");
                var manifest = AuthenticatedStateStore.Read<SafeModeManifest>(manifestPath);
                var root = SecurePathService.RequireExistingDirectory(manifest.GameRoot, "authenticated Safe Mode game directory");
                if (configuredRoot is not null && !configuredRoot.Equals(root, StringComparison.OrdinalIgnoreCase))
                    _events.Log("Safe Mode recovery path differs from settings", $"Recovering the authenticated interrupted session in its original game directory: {root}", ScanCategory.Suspicious);
                var allowedRoots = AllowedModDirectories(root);
                ValidateManifest(manifestPath, manifest, root, allowedRoots);
                var recovered = RestoreEntries(manifest, allowedRoots, out var restoreErrors);
                var firewallRemoved = _firewall.TryRemoveRule(manifest.FirewallRule);
                if (!recovered || !firewallRemoved)
                {
                    WriteManifest(manifestPath, manifest with { State = "CleanupRequired" });
                    RecoverySucceeded = false;
                    _events.Log("Safe Mode recovery needed", string.Join(" ", restoreErrors.Append(firewallRemoved ? "" : "Could not remove the Safe Mode firewall rule.")), ScanCategory.Suspicious);
                    continue;
                }
                File.Delete(manifestPath);
                _events.Log("Safe Mode recovery", $"Recovered interrupted PPGAV session {manifest.SessionId}; mod/Workshop paths and owned firewall state were restored.");
            }
            catch (Exception ex) { RecoverySucceeded = false; _events.Log("Safe Mode recovery needed", $"Manifest {Path.GetFileName(manifestPath)} was not trusted or could not be recovered: {ex.Message}", ScanCategory.Suspicious); }
        }
    }

    public LaunchSession Launch(AppSettings settings, ScanReport report)
    {
        var executable = SecurePathService.RequireExistingFile(settings.PpgExecutablePath, "People Playground executable");
        var gameRoot = SecurePathService.RequireExistingDirectory(settings.GameDirectory, "People Playground directory");
        SecurePathService.RequireContained(gameRoot, executable, true, "People Playground executable");
        var workshopRoots = GamePathDiscovery.FindWorkshopDirectories(gameRoot);
        var rootsToDisable = AllowedModDirectories(gameRoot).Where(Directory.Exists).Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (!ScannerService.VerifySnapshotExcludingRoots(report, workshopRoots, rootsToDisable, out var snapshotError))
            throw new IOException($"Malware Safe Mode launch refused because inspected content changed: {snapshotError}");
        var executableHash = Hash(gameRoot, executable);
        if (!report.ScannedHashes.TryGetValue(executable, out var inspectedHash) || !executableHash.Equals(inspectedHash, StringComparison.OrdinalIgnoreCase))
            throw new IOException("People Playground executable changed after inspection; Malware Safe Mode launch was aborted.");

        EnsureManifestRoot();
        var sessionId = Guid.NewGuid().ToString("N");
        var manifestPath = Path.Combine(ManifestRoot, sessionId + ".json");
        var allowedRoots = AllowedModDirectories(gameRoot);
        var entries = allowedRoots.Where(Directory.Exists).Select(path =>
        {
            SecurePathService.RequireExistingDirectory(path, "mod or Workshop directory");
            ValidateTreeNoReparse(path);
            var disabled = path + ".ppgav-disabled-" + sessionId;
            if (Directory.Exists(disabled) || File.Exists(disabled)) throw new IOException($"Refusing to overwrite a pre-existing Safe Mode destination: {disabled}");
            return new DisabledEntry(path, disabled, "NotStarted");
        }).ToList();
        if (entries.Count == 0) _events.Log("Safe Mode content check", "No local or external Mods/Workshop directories were present.");

        if (!_firewall.TryBlockOutbound(executable, out var ruleName)) throw new InvalidOperationException("Malware Safe Mode refused to launch because outbound network blocking could not be enabled.");
        var manifest = new SafeModeManifest(1, "PPGAV", sessionId, gameRoot, executable, ruleName, entries, "Active");
        var manifestWritten = false;
        try
        {
            WriteManifest(manifestPath, manifest); manifestWritten = true;
            for (var index = 0; index < manifest.Entries.Count; index++)
            {
                var entry = manifest.Entries[index];
                manifest.Entries[index] = entry with { State = "Pending" };
                WriteManifest(manifestPath, manifest);
                ValidateMovePaths(manifest, entry, allowedRoots);
                _beforeMove?.Invoke(entry.Original, entry.Disabled);
                SecurePathService.MoveDirectoryContained(Path.GetDirectoryName(entry.Original)!, entry.Original, entry.Disabled);
                manifest.Entries[index] = entry with { State = "Moved" };
                WriteManifest(manifestPath, manifest);
            }

            foreach (var entry in manifest.Entries.Where(x => x.State == "Moved"))
            {
                SecurePathService.RequireExistingDirectory(entry.Disabled, "disabled Safe Mode content");
                ValidateTreeNoReparse(entry.Disabled);
            }
            var movedGameRoots = manifest.Entries.Where(x => x.State == "Moved" && IsWithinRoot(gameRoot, x.Disabled)).Select(x => x.Disabled);
            var inactiveRoots = rootsToDisable.Concat(movedGameRoots);
            if (!ScannerService.VerifySnapshotExcludingRoots(report, workshopRoots, inactiveRoots, out snapshotError, allowMissingExcludedRoots: true))
                throw new IOException($"People Playground core files changed during Safe Mode staging; launch aborted: {snapshotError}");
            SecurePathService.RequireExistingFile(executable, "People Playground executable before launch");
            if (!Hash(gameRoot, executable).Equals(executableHash, StringComparison.OrdinalIgnoreCase)) throw new IOException("People Playground executable changed during Safe Mode staging; launch aborted.");
            var startInfo = new ProcessStartInfo(executable) { WorkingDirectory = gameRoot, UseShellExecute = false, CreateNoWindow = true };
            startInfo.ArgumentList.Add("-noWorkshop"); startInfo.Environment.Remove("SteamAppId"); startInfo.Environment.Remove("SteamGameId");
            var process = Process.Start(startInfo) ?? throw new InvalidOperationException("People Playground could not be started.");
            _events.Log("Malware Safe Mode started", "Mods/Workshop were transactionally disabled and Steam launch IDs were removed. Windows Firewall applies to the main executable only; child-process network access is not isolated.", ScanCategory.Suspicious);
            return new LaunchSession(LaunchMode.MalwareSafe, process, () => CleanupAsync(manifestPath, manifest), null, SandboxProvider.None);
        }
        catch (Exception launchError)
        {
            var restored = RestoreEntries(manifest, allowedRoots, out var errors);
            var firewallRemoved = _firewall.TryRemoveRule(ruleName);
            if (!restored || !firewallRemoved)
            {
                manifest = manifest with { State = "CleanupRequired" };
                try { WriteManifest(manifestPath, manifest); manifestWritten = true; }
                catch (Exception manifestError) { _events.Log("Safe Mode recovery manifest failed", manifestError.Message, ScanCategory.Malware); }
                _events.Log("Safe Mode rollback incomplete", string.Join(" ", errors.Append(firewallRemoved ? "" : "Firewall rule removal failed.").Append(launchError.Message)), ScanCategory.Malware);
                throw new IOException("Safe Mode launch failed and rollback is incomplete; PPGAV retained its recovery state where possible. " + string.Join(" ", errors), launchError);
            }
            if (manifestWritten) TryDeleteManifest(manifestPath);
            throw;
        }
    }

    private async ValueTask CleanupAsync(string manifestPath, SafeModeManifest manifest)
    {
        var allowedRoots = AllowedModDirectories(manifest.GameRoot);
        ValidateManifest(manifestPath, manifest, manifest.GameRoot, allowedRoots);
        var restored = RestoreEntries(manifest, allowedRoots, out var errors);
        var firewallRemoved = _firewall.TryRemoveRule(manifest.FirewallRule);
        if (!restored || !firewallRemoved)
        {
            WriteManifest(manifestPath, manifest with { State = "CleanupRequired" });
            var detail = string.Join(" ", errors.Concat(firewallRemoved ? [] : ["Firewall rule cleanup failed."]));
            _events.Log("Safe Mode cleanup failed", detail, ScanCategory.Suspicious);
            throw new IOException($"Safe Mode cleanup is incomplete; the authenticated recovery manifest was retained. {detail}");
        }
        File.Delete(manifestPath);
        _events.Log("Safe Mode cleanup complete", "Mod/Workshop directories and the owned firewall rule were restored/removed.");
        await ValueTask.CompletedTask;
    }

    private static bool RestoreEntries(SafeModeManifest manifest, IReadOnlyCollection<string> allowedRoots, out List<string> errors)
    {
        errors = [];
        foreach (var entry in manifest.Entries.AsEnumerable().Reverse())
        {
            if (entry.State == "NotStarted") continue;
            try
            {
                ValidateMovePaths(manifest, entry, allowedRoots);
                var originalExists = Directory.Exists(entry.Original) || File.Exists(entry.Original);
                var disabledExists = Directory.Exists(entry.Disabled) || File.Exists(entry.Disabled);
                if (originalExists && !disabledExists) continue; // not moved, or a prior restore completed
                if (originalExists && disabledExists) throw new IOException($"Both original and disabled paths exist; refusing to overwrite either: {entry.Original}");
                if (!originalExists && !disabledExists) throw new IOException($"Both original and session-owned paths are missing: {entry.Original}");
                if (!Directory.Exists(entry.Disabled)) throw new IOException($"Disabled Safe Mode path is not a directory: {entry.Disabled}");
                ValidateTreeNoReparse(entry.Disabled);
                SecurePathService.MoveDirectoryContained(Path.GetDirectoryName(entry.Original)!, entry.Disabled, entry.Original);
            }
            catch (Exception ex) { errors.Add($"Could not safely restore {entry.Original}: {ex.Message}"); }
        }
        return errors.Count == 0;
    }

    private static void ValidateManifest(string manifestPath, SafeModeManifest manifest, string expectedGameRoot, IReadOnlyCollection<string> allowedRoots)
    {
        var fileName = Path.GetFileNameWithoutExtension(manifestPath);
        if (manifest.FormatVersion != 1 || manifest.Owner != "PPGAV" || !Guid.TryParseExact(manifest.SessionId, "N", out _) ||
            !fileName.Equals(manifest.SessionId, StringComparison.OrdinalIgnoreCase) || !Path.GetFullPath(manifest.GameRoot).Equals(Path.GetFullPath(expectedGameRoot), StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(manifest.FirewallRule) || !manifest.FirewallRule.StartsWith("PPGAV Safe Mode ", StringComparison.Ordinal) ||
            manifest.Entries is null || manifest.Entries.Select(x => x.Original).Distinct(StringComparer.OrdinalIgnoreCase).Count() != manifest.Entries.Count)
            throw new InvalidDataException("Authenticated Safe Mode manifest fields are invalid.");
        SecurePathService.RequireExistingDirectory(manifest.GameRoot, "Safe Mode game directory");
        SecurePathService.RequireContained(manifest.GameRoot, manifest.Executable, true, "Safe Mode executable");
        foreach (var entry in manifest.Entries)
        {
            if (entry.State is not ("NotStarted" or "Pending" or "Moved")) throw new InvalidDataException("Safe Mode manifest contains an invalid move state.");
            ValidateMovePaths(manifest, entry, allowedRoots);
        }
    }

    private static void ValidateMovePaths(SafeModeManifest manifest, DisabledEntry entry, IEnumerable<string> allowedRoots)
    {
        var original = Path.GetFullPath(entry.Original);
        if (!allowedRoots.Any(root => Path.GetFullPath(root).Equals(original, StringComparison.OrdinalIgnoreCase)))
            throw new UnauthorizedAccessException($"Safe Mode path is not one of the configured Mods/Workshop roots: {entry.Original}");
        var expectedDisabled = original + ".ppgav-disabled-" + manifest.SessionId;
        if (!Path.GetFullPath(entry.Disabled).Equals(expectedDisabled, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Safe Mode disabled path does not match its authenticated session ID.");
        var parent = Path.GetDirectoryName(original) ?? throw new InvalidDataException("Safe Mode path has no parent.");
        SecurePathService.RequireExistingDirectory(parent, "Safe Mode path parent");
        SecurePathService.RejectReparse(entry.Disabled, "disabled mod path");
    }

    private static void ValidateTreeNoReparse(string root)
    {
        var pending = new Stack<string>(); pending.Push(root);
        while (pending.Count > 0)
        {
            var path = pending.Pop(); SecurePathService.RejectReparse(path, "Safe Mode content");
            foreach (var child in Directory.EnumerateFileSystemEntries(path))
            {
                var attrs = File.GetAttributes(child);
                if (attrs.HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"Safe Mode refuses reparse-point content: {child}");
                if (attrs.HasFlag(FileAttributes.Directory)) pending.Push(child);
            }
        }
    }

    private void EnsureManifestRoot()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(ManifestRoot)!);
        SecurePathService.RejectReparse(Path.GetDirectoryName(ManifestRoot)!, "PPGAV Safe Mode storage");
        Directory.CreateDirectory(ManifestRoot);
        SecurePathService.RequireExistingDirectory(ManifestRoot, "PPGAV Safe Mode manifest storage");
    }

    private static void WriteManifest(string path, SafeModeManifest manifest) => AuthenticatedStateStore.Write(path, manifest);
    private void TryDeleteManifest(string path)
    {
        try { if (File.Exists(path)) { SecurePathService.RequireContained(ManifestRoot, path, true, "Safe Mode manifest"); File.Delete(path); } }
        catch (Exception ex) { _events.Log("Safe Mode manifest cleanup failed", ex.Message, ScanCategory.Suspicious); }
    }

    private static string Hash(string root, string path) { using var stream = SecurePathService.OpenContainedRead(root, path, "People Playground executable"); return Convert.ToHexString(SHA256.HashData(stream)); }

    private static bool IsWithinRoot(string root, string path)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
        return !Path.IsPathRooted(relative) && relative != "." &&
            !relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x == "..");
    }

    private string[] AllowedModDirectories(string gameRoot) =>
        GameLayout.ModDirectories(gameRoot)
            .Concat(_workshopRootProvider(gameRoot))
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}

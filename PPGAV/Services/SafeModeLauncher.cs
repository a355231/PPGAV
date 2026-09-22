using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class SafeModeLauncher
{
    private readonly IOutboundNetworkBlocker _firewall;
    private readonly EventLogService _events;
    private static string ManifestRoot => Path.Combine(AppPaths.SandboxFolder, "SafeModeSessions");

    private sealed record DisabledEntry(string Original, string Disabled, bool Moved);
    private sealed record SafeModeManifest(string Owner, string SessionId, string Executable, string FirewallRule, List<DisabledEntry> Entries, string State);

    public SafeModeLauncher(IOutboundNetworkBlocker firewall, EventLogService events) { _firewall = firewall; _events = events; }

    public void RecoverStaleDisabledMods(string gameRoot)
    {
        Directory.CreateDirectory(AppPaths.SandboxFolder); SecurePathService.RejectReparse(AppPaths.SandboxFolder, "PPGAV Safe Mode storage"); Directory.CreateDirectory(ManifestRoot); SecurePathService.RejectReparse(ManifestRoot, "PPGAV Safe Mode manifest storage");
        foreach (var manifestPath in Directory.EnumerateFiles(ManifestRoot, "*.json", SearchOption.TopDirectoryOnly))
        {
            try
            {
                SecurePathService.RequireContained(ManifestRoot, manifestPath, true, "Safe Mode manifest");
                var manifest = JsonSerializer.Deserialize<SafeModeManifest>(File.ReadAllText(manifestPath));
                if (manifest is null || manifest.Owner != "PPGAV" || !Guid.TryParse(manifest.SessionId, out _)) continue;
                var allowedRoots = new[] { gameRoot }.Concat(GamePathDiscovery.FindWorkshopDirectories(gameRoot)).ToArray();
                if (!RestoreEntries(manifest.Entries, manifest.SessionId, allowedRoots, out var errors))
                {
                    _events.Log("Safe Mode recovery needed", string.Join(" ", errors), ScanCategory.Suspicious);
                    continue;
                }
                if (!_firewall.TryRemoveRule(manifest.FirewallRule))
                {
                    _events.Log("Safe Mode firewall cleanup needed", $"Could not remove rule {manifest.FirewallRule}.", ScanCategory.Suspicious);
                    continue;
                }
                File.Delete(manifestPath);
                _events.Log("Safe Mode recovery", "Recovered a verified PPGAV Safe Mode manifest after an interrupted session.");
            }
            catch (Exception ex) { _events.Log("Safe Mode recovery needed", $"Manifest {Path.GetFileName(manifestPath)} was not trusted: {ex.Message}", ScanCategory.Suspicious); }
        }
    }

    public LaunchSession Launch(AppSettings settings)
    {
        var executable = SecurePathService.RequireExistingFile(settings.PpgExecutablePath, "People Playground executable");
        var gameRoot = SecurePathService.RequireExistingDirectory(settings.GameDirectory, "People Playground directory");
        SecurePathService.RequireContained(gameRoot, executable, true, "People Playground executable");
        var executableHash = Hash(executable);
        Directory.CreateDirectory(ManifestRoot);
        var sessionId = Guid.NewGuid().ToString("N");
        var manifestPath = Path.Combine(ManifestRoot, sessionId + ".json");
        var entries = ModDirectories(gameRoot).Where(Directory.Exists).Select(path =>
        {
            SecurePathService.RequireExistingDirectory(path, "mod directory");
            var disabled = path + ".ppgav-disabled-" + sessionId;
            if (Directory.Exists(disabled) || File.Exists(disabled)) throw new IOException($"Refusing to overwrite an existing PPGAV Safe Mode destination: {disabled}");
            return new DisabledEntry(path, disabled, false);
        }).ToList();
        if (!_firewall.TryBlockOutbound(executable, out var ruleName)) throw new InvalidOperationException("Malware Safe Mode refused to launch because outbound network blocking could not be enabled.");
        var manifest = new SafeModeManifest("PPGAV", sessionId, executable, ruleName, entries, "Active");
        var moved = new List<DisabledEntry>();
        try
        {
            WriteManifest(manifestPath, manifest);
            foreach (var entry in entries)
            {
                SecurePathService.RequireExistingDirectory(entry.Original, "mod directory before move");
                Directory.Move(entry.Original, entry.Disabled);
                moved.Add(entry with { Moved = true });
                manifest = manifest with { Entries = manifest.Entries.Select(x => x.Original == entry.Original ? x with { Moved = true } : x).ToList() };
                WriteManifest(manifestPath, manifest);
            }
            SecurePathService.RequireExistingFile(executable, "People Playground executable before launch");
            if (!Hash(executable).Equals(executableHash, StringComparison.OrdinalIgnoreCase)) throw new IOException("People Playground executable changed during Safe Mode staging; launch aborted.");
            var startInfo = new ProcessStartInfo(executable) { WorkingDirectory = gameRoot, UseShellExecute = false, CreateNoWindow = true };
            startInfo.ArgumentList.Add("-noWorkshop"); startInfo.Environment.Remove("SteamAppId"); startInfo.Environment.Remove("SteamGameId");
            var process = Process.Start(startInfo) ?? throw new InvalidOperationException("People Playground could not be started.");
            _events.Log("Malware Safe Mode started", "Local and external Workshop content were transactionally disabled and outbound traffic was blocked.");
            return new LaunchSession(LaunchMode.MalwareSafe, process, () => CleanupAsync(manifestPath, manifest), null, SandboxProvider.None);
        }
        catch
        {
            var cleanupErrors = RestoreEntries(moved, sessionId, [gameRoot, .. GamePathDiscovery.FindWorkshopDirectories(gameRoot)], out var errors) ? [] : errors;
            var removed = _firewall.TryRemoveRule(ruleName);
            if (cleanupErrors.Count > 0 || !removed) WriteManifest(manifestPath, manifest with { State = "CleanupRequired" }); else TryDeleteManifest(manifestPath);
            throw;
        }
    }

    private async ValueTask CleanupAsync(string manifestPath, SafeModeManifest manifest)
    {
        var ok = RestoreEntries(manifest.Entries, manifest.SessionId, [Path.GetDirectoryName(manifest.Executable) ?? string.Empty, .. GamePathDiscovery.FindWorkshopDirectories(Path.GetDirectoryName(manifest.Executable))], out var errors);
        var firewallOk = _firewall.TryRemoveRule(manifest.FirewallRule);
        if (!ok || !firewallOk)
        {
            WriteManifest(manifestPath, manifest with { State = "CleanupRequired" });
            _events.Log("Safe Mode cleanup failed", string.Join(" ", errors.Append("Firewall rule cleanup failed.")), ScanCategory.Suspicious);
            throw new IOException($"Safe Mode cleanup did not complete; the verified recovery manifest was retained. {string.Join(" ", errors)}");
        }
        TryDeleteManifest(manifestPath);
        await ValueTask.CompletedTask;
    }

    private static bool RestoreEntries(IEnumerable<DisabledEntry> entries, string sessionId, IEnumerable<string> allowedRoots, out List<string> errors)
    {
        errors = [];
        foreach (var entry in entries.Reverse())
        {
            if (!entry.Moved) continue;
            try
            {
                if (!Guid.TryParse(sessionId, out _) || !entry.Disabled.Equals(entry.Original + ".ppgav-disabled-" + sessionId, StringComparison.OrdinalIgnoreCase) || !allowedRoots.Any(root => !string.IsNullOrWhiteSpace(root) && IsWithin(root, entry.Original))) { errors.Add($"Refused an untrusted Safe Mode recovery path: {entry.Original}"); continue; }
                SecurePathService.RejectReparse(entry.Disabled, "disabled mod directory");
                if (Directory.Exists(entry.Original) || File.Exists(entry.Original)) { errors.Add($"Refused to overwrite an existing path: {entry.Original}"); continue; }
                if (!Directory.Exists(entry.Disabled)) { errors.Add($"Missing PPGAV-owned disabled directory: {entry.Disabled}"); continue; }
                Directory.Move(entry.Disabled, entry.Original);
            }
            catch (Exception ex) { errors.Add($"Could not restore {entry.Original}: {ex.Message}"); }
        }
        return errors.Count == 0;
    }

    private static void WriteManifest(string path, SafeModeManifest manifest)
    {
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(temp, JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, path, true);
    }

    private static void TryDeleteManifest(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
    private static bool IsWithin(string root, string candidate) { var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar; return Path.GetFullPath(candidate).StartsWith(prefix, StringComparison.OrdinalIgnoreCase); }
    private static string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
    private static IEnumerable<string> ModDirectories(string gameRoot)
    {
        yield return Path.Combine(gameRoot, "Mods"); yield return Path.Combine(gameRoot, "Workshop");
        foreach (var workshop in GamePathDiscovery.FindWorkshopDirectories(gameRoot)) yield return workshop;
    }
}

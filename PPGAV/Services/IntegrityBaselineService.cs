using System.Security.AccessControl;
using System.Security.Cryptography;
using System.ComponentModel;
using System.Text;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public enum IntegrityBaselineStatus { Missing, Valid, Corrupt, Tampered, InstallationChanged, ContentChanged, Incomplete }

public sealed class IntegrityBaselineService
{
    private const int FormatVersion = 2;
    private readonly string _baselinePath;
    public IntegrityBaselineStatus LastStatus { get; private set; } = IntegrityBaselineStatus.Missing;

    private sealed record BaselineFile(string Path, string Hash);
    private sealed record BaselineEnvelope(int FormatVersion, string Owner, string InstallationIdentity, string GameRoot, string Executable, List<BaselineFile> Files, string ProtectedPayload);
    private sealed record ProtectedBaseline(int FormatVersion, string Owner, string InstallationIdentity, string GameRoot, string Executable, List<BaselineFile> Files);
    private sealed class BaselineTamperedException(string message) : Exception(message);

    public IntegrityBaselineService(string? baselinePath = null) => _baselinePath = baselinePath ?? Path.Combine(AppPaths.Root, "core-integrity.json");

    public List<ScanFinding> Check(string gameRoot, string? executablePath = null)
    {
        var findings = new List<ScanFinding>();
        BaselineEnvelope baseline;
        try
        {
            baseline = ReadAndValidateEnvelope();
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            LastStatus = IntegrityBaselineStatus.Missing;
            return [Finding(gameRoot, "baseline-missing", "No readable approved core integrity baseline exists. Explicit review is required before trusting this installation.")];
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode is 2 or 3)
        {
            LastStatus = IntegrityBaselineStatus.Missing;
            return [Finding(gameRoot, "baseline-missing", "No approved core integrity baseline exists. Explicit review is required before trusting this installation.")];
        }
        catch (BaselineTamperedException ex) { LastStatus = IntegrityBaselineStatus.Tampered; return [Finding(gameRoot, "baseline-tampered", $"The approved core integrity baseline failed its authenticity check: {ex.Message}")]; }
        catch (Exception ex) { LastStatus = IntegrityBaselineStatus.Corrupt; return [Finding(gameRoot, "baseline-invalid", $"The approved core integrity baseline could not be validated: {ex.Message}")]; }

        var root = SecurePathService.RequireExistingDirectory(gameRoot, "game directory");
        var executable = executablePath is null ? baseline.Executable : Path.GetFullPath(executablePath);
        var identity = ComputeInstallationIdentity(root, executable);
        if (!string.Equals(identity, baseline.InstallationIdentity, StringComparison.OrdinalIgnoreCase) || !string.Equals(root, baseline.GameRoot, StringComparison.OrdinalIgnoreCase) || !string.Equals(executable, baseline.Executable, StringComparison.OrdinalIgnoreCase))
        {
            LastStatus = IntegrityBaselineStatus.InstallationChanged;
            return [Finding(root, "baseline-installation-changed", "The game installation identity or location differs from the approved baseline.")];
        }

        var current = EnumerateCore(root, findings).ToDictionary(x => x.Path, x => x.Hash, StringComparer.OrdinalIgnoreCase);
        if (findings.Count > 0) { LastStatus = IntegrityBaselineStatus.Incomplete; return findings; }
        // Baselines approved by older builds pinned runtime data; ignore those entries instead of reporting them missing.
        var previous = baseline.Files.Where(x => !IsExcluded(root, x.Path)).ToDictionary(x => x.Path, x => x.Hash, StringComparer.OrdinalIgnoreCase);
        foreach (var changed in current.Where(x => !previous.TryGetValue(x.Key, out var hash) || !string.Equals(hash, x.Value, StringComparison.OrdinalIgnoreCase))) findings.Add(new(ScanCategory.Suspicious, changed.Key, "trusted-file-changed", "A core game file differs from the approved baseline.", changed.Value, ScanScope.GameCore, 80, DetectionKind.Confirmed));
        foreach (var missing in previous.Keys.Except(current.Keys, StringComparer.OrdinalIgnoreCase)) findings.Add(new(ScanCategory.Suspicious, missing, "trusted-file-missing", "A core game file from the approved baseline is missing.", string.Empty, ScanScope.GameCore, 80, DetectionKind.Confirmed));
        LastStatus = findings.Count == 0 ? IntegrityBaselineStatus.Valid : IntegrityBaselineStatus.ContentChanged;
        return findings;
    }

    [Obsolete("Use Check followed by explicit user approval and TrustCurrent.")]
    public List<ScanFinding> CheckAndUpdate(string gameRoot) => Check(gameRoot);

    public void TrustCurrent(string gameRoot, string executablePath, string approvalReason, ScanReport approvedScan)
    {
        if (string.IsNullOrWhiteSpace(approvalReason)) throw new ArgumentException("An approval reason is required.", nameof(approvalReason));
        var root = SecurePathService.RequireExistingDirectory(gameRoot, "game directory");
        var executable = SecurePathService.RequireExistingFile(executablePath, "People Playground executable");
        SecurePathService.RequireContained(root, executable, true, "People Playground executable");
        ArgumentNullException.ThrowIfNull(approvedScan);
        if (!approvedScan.IsComplete || !Path.GetFullPath(approvedScan.RootPath).Equals(root, StringComparison.OrdinalIgnoreCase) ||
            approvedScan.Findings.Any(x => x.Scope is (ScanScope.GameCore or ScanScope.Unknown) && !IsIntegrityRule(x.Rule)))
            throw new InvalidOperationException("A new core baseline can only be approved from a complete scan with no non-baseline core findings.");
        if (!ScannerService.VerifySnapshot(approvedScan, GamePathDiscovery.FindWorkshopDirectories(root), out var snapshotError))
            throw new IOException($"The scan snapshot changed before baseline approval: {snapshotError}");

        var enumerationErrors = new List<ScanFinding>();
        var files = EnumerateCore(root, enumerationErrors).OrderBy(x => x.Path, StringComparer.OrdinalIgnoreCase).ToList();
        if (enumerationErrors.Count > 0)
            throw new IOException("The core installation could not be completely enumerated for a trusted baseline: " + string.Join(" ", enumerationErrors.Select(x => x.FilePath + ": " + x.Detail)));
        if (files.Count == 0) throw new InvalidDataException("Cannot approve an empty or unreadable core installation.");
        var expectedCore = approvedScan.ScannedHashes
            .Where(x => IsCorePath(root, x.Key))
            .ToDictionary(x => Path.GetFullPath(x.Key), x => x.Value, StringComparer.OrdinalIgnoreCase);
        var actualCore = files.ToDictionary(x => Path.GetFullPath(x.Path), x => x.Hash, StringComparer.OrdinalIgnoreCase);
        if (!expectedCore.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(actualCore.Keys) ||
            actualCore.Any(x => !expectedCore.TryGetValue(x.Key, out var expected) || !expected.Equals(x.Value, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("Core files no longer match the exact completed scan approved by the user; rescan and review before trusting a baseline.");

        var envelope = new BaselineEnvelope(FormatVersion, "PPGAV", ComputeInstallationIdentity(root, executable), root, executable, files.Select(x => new BaselineFile(x.Path, x.Hash)).ToList(), string.Empty);
        var payload = JsonSerializer.Serialize(new ProtectedBaseline(envelope.FormatVersion, envelope.Owner, envelope.InstallationIdentity, envelope.GameRoot, envelope.Executable, envelope.Files));
        envelope = envelope with { ProtectedPayload = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(payload), null, DataProtectionScope.CurrentUser)) };
        Directory.CreateDirectory(Path.GetDirectoryName(_baselinePath)!);
        var temp = _baselinePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            var approvalLog = _baselinePath + ".approvals.log";
            SecurePathService.RejectReparse(Path.GetDirectoryName(_baselinePath)!, "baseline storage");
            SecurePathService.RejectReparse(approvalLog, "baseline approval log");
            using (var log = new FileStream(approvalLog, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(log, new UTF8Encoding(false), leaveOpen: true))
            {
                writer.WriteLine($"{DateTimeOffset.UtcNow:O}\t{ComputeInstallationIdentity(root, executable)}\t{root}\t{approvalReason.Replace('\r', ' ').Replace('\n', ' ')}");
                writer.Flush(); log.Flush(true);
            }
            ProtectBaselineFile(approvalLog);
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough)) { JsonSerializer.Serialize(stream, envelope, new JsonSerializerOptions { WriteIndented = true }); stream.Flush(true); }
            ProtectBaselineFile(temp); SecurePathService.MoveFileContained(Path.GetDirectoryName(_baselinePath)!, temp, _baselinePath, true); LastStatus = IntegrityBaselineStatus.Valid;
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private BaselineEnvelope ReadAndValidateEnvelope()
    {
        SecurePathService.RequireExistingFile(_baselinePath, "integrity baseline");
        using var stream = SecurePathService.OpenContainedRead(Path.GetDirectoryName(_baselinePath)!, _baselinePath, "integrity baseline");
        var baseline = JsonSerializer.Deserialize<BaselineEnvelope>(stream) ?? throw new InvalidDataException("Baseline is empty.");
        if (baseline.FormatVersion != FormatVersion || baseline.Owner != "PPGAV" || string.IsNullOrWhiteSpace(baseline.ProtectedPayload)) throw new InvalidDataException("Baseline metadata is invalid.");
        ProtectedBaseline protectedBaseline;
        try
        {
            var payload = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(baseline.ProtectedPayload), null, DataProtectionScope.CurrentUser));
            protectedBaseline = JsonSerializer.Deserialize<ProtectedBaseline>(payload) ?? throw new InvalidDataException("Protected baseline payload is empty.");
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException or InvalidDataException)
        {
            throw new BaselineTamperedException("DPAPI payload could not be authenticated or decoded.");
        }
        if (protectedBaseline.FormatVersion != baseline.FormatVersion || protectedBaseline.Owner != baseline.Owner ||
            !string.Equals(protectedBaseline.InstallationIdentity, baseline.InstallationIdentity, StringComparison.Ordinal) ||
            !string.Equals(protectedBaseline.GameRoot, baseline.GameRoot, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(protectedBaseline.Executable, baseline.Executable, StringComparison.OrdinalIgnoreCase) ||
            protectedBaseline.Files is null || baseline.Files is null || !protectedBaseline.Files.SequenceEqual(baseline.Files))
            throw new BaselineTamperedException("Public metadata does not match the DPAPI-authenticated payload.");
        if (baseline.Files.Count == 0 || baseline.Files.Any(x => string.IsNullOrWhiteSpace(x.Path) || x.Hash.Length != 64 || !x.Hash.All(Uri.IsHexDigit))) throw new InvalidDataException("Baseline file records are invalid.");
        if (baseline.Files.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != baseline.Files.Count) throw new InvalidDataException("Baseline contains duplicate paths.");
        var root = Path.GetFullPath(baseline.GameRoot);
        foreach (var item in baseline.Files)
        {
            var normalized = Path.GetFullPath(item.Path);
            if (!normalized.Equals(item.Path, StringComparison.OrdinalIgnoreCase) || !normalized.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Baseline contains a path outside the approved installation.");
        }
        return baseline;
    }

    private static IEnumerable<(string Path, string Hash)> EnumerateCore(string root, List<ScanFinding> findings)
    {
        var pending = new Stack<string>([root]);
        while (pending.Count > 0)
        {
            var directory = pending.Pop(); string[] children;
            try { SecurePathService.RejectReparse(directory, "core directory"); children = Directory.GetDirectories(directory); } catch (Exception ex) { findings.Add(Finding(directory, "baseline-inaccessible", ex.Message)); continue; }
            foreach (var child in children) if (!IsExcluded(root, child)) pending.Push(child);
            string[] files;
            try { files = Directory.GetFiles(directory); } catch (Exception ex) { findings.Add(Finding(directory, "baseline-inaccessible", ex.Message)); continue; }
            foreach (var file in files)
            {
                if (IsExcluded(root, file)) continue;
                string? hash = null;
                try { using var stream = SecurePathService.OpenContainedRead(root, file, "core file"); hash = Convert.ToHexString(SHA256.HashData(stream)); }
                catch (Exception ex) { findings.Add(Finding(file, "baseline-hash-failed", ex.Message)); }
                if (hash is not null) yield return (Path.GetFullPath(file), hash);
            }
        }
    }

    /// <summary>True for findings produced by this service rather than by content inspection.</summary>
    public static bool IsIntegrityRule(string rule) =>
        rule.StartsWith("baseline-", StringComparison.OrdinalIgnoreCase) || rule.StartsWith("trusted-file-", StringComparison.OrdinalIgnoreCase);

    // Mod folders and game-written settings/saves/logs change during normal play; pinning them made
    // every launch after the first play session fail with "core game file differs".
    private static bool IsExcluded(string root, string path) => GameLayout.IsModContent(root, path) || GameLayout.IsRuntimeData(root, path);
    private static bool IsCorePath(string root, string path)
    {
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullPath = Path.GetFullPath(path);
        var prefix = fullRoot + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && !IsExcluded(fullRoot, fullPath);
    }
    private static string ComputeInstallationIdentity(string root, string executable) { using var hash = SHA256.Create(); return Convert.ToHexString(hash.ComputeHash(Encoding.UTF8.GetBytes(root.ToUpperInvariant() + "\n" + executable.ToUpperInvariant()))); }
    private static ScanFinding Finding(string path, string rule, string detail) => new(ScanCategory.Suspicious, path, rule, detail, string.Empty, ScanScope.GameCore, 90, DetectionKind.Confirmed);

    private static void ProtectBaselineFile(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        var security = new FileSecurity(); security.SetAccessRuleProtection(true, false); var identity = System.Security.Principal.WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Current Windows identity is unavailable."); security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete, AccessControlType.Allow)); new FileInfo(path).SetAccessControl(security);
    }
}

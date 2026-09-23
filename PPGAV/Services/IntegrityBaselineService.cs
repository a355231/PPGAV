using System.Security.AccessControl;
using System.Security.Cryptography;
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
    private sealed record ProtectedPayload(int FormatVersion, string Owner, string InstallationIdentity, string GameRoot, string Executable, List<BaselineFile> Files);

    public IntegrityBaselineService(string? baselinePath = null) => _baselinePath = baselinePath ?? Path.Combine(AppPaths.Root, "core-integrity.json");

    public List<ScanFinding> Check(string gameRoot, string? executablePath = null)
    {
        var findings = new List<ScanFinding>();
        BaselineEnvelope baseline;
        try
        {
            if (!File.Exists(_baselinePath)) { LastStatus = IntegrityBaselineStatus.Missing; return [Finding(gameRoot, "baseline-missing", "No approved core integrity baseline exists. Explicit review is required before trusting this installation.")]; }
            baseline = ReadAndValidateEnvelope();
        }
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
        var previous = baseline.Files.ToDictionary(x => x.Path, x => x.Hash, StringComparer.OrdinalIgnoreCase);
        foreach (var changed in current.Where(x => !previous.TryGetValue(x.Key, out var hash) || !string.Equals(hash, x.Value, StringComparison.OrdinalIgnoreCase))) findings.Add(new(ScanCategory.Suspicious, changed.Key, "trusted-file-changed", "A core game file differs from the approved baseline.", changed.Value, ScanScope.GameCore, 80, DetectionKind.Confirmed));
        foreach (var missing in previous.Keys.Except(current.Keys, StringComparer.OrdinalIgnoreCase)) findings.Add(new(ScanCategory.Suspicious, missing, "trusted-file-missing", "A core game file from the approved baseline is missing.", string.Empty, ScanScope.GameCore, 80, DetectionKind.Confirmed));
        LastStatus = findings.Count == 0 ? IntegrityBaselineStatus.Valid : IntegrityBaselineStatus.ContentChanged;
        return findings;
    }

    [Obsolete("Use Check followed by explicit user approval and TrustCurrent.")]
    public List<ScanFinding> CheckAndUpdate(string gameRoot) => Check(gameRoot);

    public void TrustCurrent(string gameRoot, string executablePath, string approvalReason)
    {
        if (string.IsNullOrWhiteSpace(approvalReason)) throw new ArgumentException("An approval reason is required.", nameof(approvalReason));
        var root = SecurePathService.RequireExistingDirectory(gameRoot, "game directory");
        var executable = SecurePathService.RequireExistingFile(executablePath, "People Playground executable");
        SecurePathService.RequireContained(root, executable, true, "People Playground executable");
        var files = EnumerateCore(root, []).ToList();
        if (files.Count == 0) throw new InvalidDataException("Cannot approve an empty or unreadable core installation.");
        var envelope = new BaselineEnvelope(FormatVersion, "PPGAV", ComputeInstallationIdentity(root, executable), root, executable, files.Select(x => new BaselineFile(x.Path, x.Hash)).ToList(), string.Empty);
        var payload = JsonSerializer.Serialize(new { envelope.FormatVersion, envelope.Owner, envelope.InstallationIdentity, envelope.GameRoot, envelope.Executable, envelope.Files });
        envelope = envelope with { ProtectedPayload = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(payload), null, DataProtectionScope.CurrentUser)) };
        Directory.CreateDirectory(Path.GetDirectoryName(_baselinePath)!);
        var temp = _baselinePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough)) { JsonSerializer.Serialize(stream, envelope, new JsonSerializerOptions { WriteIndented = true }); stream.Flush(true); }
            ProtectBaselineFile(temp); File.Move(temp, _baselinePath, true); LastStatus = IntegrityBaselineStatus.Valid;
            File.AppendAllText(_baselinePath + ".approvals.log", $"{DateTimeOffset.UtcNow:O}\t{root}\t{approvalReason}{Environment.NewLine}");
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private BaselineEnvelope ReadAndValidateEnvelope()
    {
        SecurePathService.RequireExistingFile(_baselinePath, "integrity baseline");
        var baseline = JsonSerializer.Deserialize<BaselineEnvelope>(File.ReadAllText(_baselinePath)) ?? throw new InvalidDataException("Baseline is empty.");
        if (baseline.FormatVersion != FormatVersion || baseline.Owner != "PPGAV" || string.IsNullOrWhiteSpace(baseline.ProtectedPayload)) throw new InvalidDataException("Baseline metadata is invalid.");
        var payload = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(baseline.ProtectedPayload), null, DataProtectionScope.CurrentUser));
        var protectedFields = JsonSerializer.Deserialize<ProtectedPayload>(payload) ?? throw new InvalidDataException("Baseline protection validation failed.");
        if (protectedFields.InstallationIdentity != baseline.InstallationIdentity
            || !string.Equals(protectedFields.GameRoot, baseline.GameRoot, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(protectedFields.Executable, baseline.Executable, StringComparison.OrdinalIgnoreCase)
            || !protectedFields.Files.OrderBy(x => x.Path, StringComparer.OrdinalIgnoreCase).SequenceEqual(baseline.Files.OrderBy(x => x.Path, StringComparer.OrdinalIgnoreCase)))
            throw new InvalidDataException("Baseline protection validation failed.");
        if (baseline.Files.Count == 0 || baseline.Files.Any(x => string.IsNullOrWhiteSpace(x.Path) || string.IsNullOrWhiteSpace(x.Hash))) throw new InvalidDataException("Baseline file records are invalid.");
        if (baseline.Files.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != baseline.Files.Count) throw new InvalidDataException("Baseline contains duplicate paths.");
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
                try { SecurePathService.RequireContained(root, file, true, "core file"); using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan); hash = Convert.ToHexString(SHA256.HashData(stream)); }
                catch (Exception ex) { findings.Add(Finding(file, "baseline-hash-failed", ex.Message)); }
                if (hash is not null) yield return (Path.GetFullPath(file), hash);
            }
        }
    }

    private static bool IsExcluded(string root, string path) => Path.GetRelativePath(root, path).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x.Equals("Mods", StringComparison.OrdinalIgnoreCase) || x.Equals("Workshop", StringComparison.OrdinalIgnoreCase));
    private static string ComputeInstallationIdentity(string root, string executable) { using var hash = SHA256.Create(); return Convert.ToHexString(hash.ComputeHash(Encoding.UTF8.GetBytes(root.ToUpperInvariant() + "\n" + executable.ToUpperInvariant()))); }
    private static ScanFinding Finding(string path, string rule, string detail) => new(ScanCategory.Suspicious, path, rule, detail, string.Empty, ScanScope.GameCore, 90, DetectionKind.Confirmed);

    private static void ProtectBaselineFile(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        var security = new FileSecurity(); security.SetAccessRuleProtection(true, false); var identity = System.Security.Principal.WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Current Windows identity is unavailable."); security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete, AccessControlType.Allow)); new FileInfo(path).SetAccessControl(security);
    }
}

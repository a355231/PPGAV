using System.Security.Cryptography;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed record QuarantineItem(string OriginalPath, string QuarantinedPath, string? ManifestPath = null);

public sealed class QuarantineService
{
    private const int FormatVersion = 2;
    private static readonly SemaphoreSlim TransactionLock = new(1, 1);
    private readonly string _root;
    private readonly EventLogService _events;
    private readonly Action<int, string>? _beforeMove;
    public bool RecoverySucceeded { get; private set; } = true;

    private sealed record QuarantineManifest(string Owner, int FormatVersion, string SessionId, DateTimeOffset CreatedAt, string State, List<QuarantineRecord> Items);
    private sealed record QuarantineRecord(ScanScope Scope, string OriginalRoot, string OriginalPath, string QuarantinedPath, string Sha256,
        long Length, DateTime LastWriteUtc, FileAttributes Attributes, string Rules, string State);

    public QuarantineService(string? root = null, EventLogService? events = null, Action<int, string>? beforeMove = null)
    {
        _root = Path.GetFullPath(root ?? Path.Combine(AppPaths.Root, "Quarantine"));
        _events = events ?? new EventLogService();
        _beforeMove = beforeMove;
    }

    public IReadOnlyList<QuarantineItem> Quarantine(ScanReport report, bool allowHeuristic = false)
    {
        TransactionLock.Wait();
        try
        {
            var candidates = report.Findings
                .Where(x => x.Category == ScanCategory.Malware && (x.Scope is ScanScope.LocalMods or ScanScope.SteamWorkshop) &&
                    (x.Detection == DetectionKind.Confirmed || allowHeuristic))
                .Select(x => x with { FilePath = ContainingFile(x.FilePath) })
                .GroupBy(x => x.FilePath, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).ToList();
            if (candidates.Count == 0) return [];
            if (!report.IsComplete) throw new InvalidOperationException("Quarantine is refused because the source scan was incomplete.");

            EnsureStorage();
            var sessionId = Guid.NewGuid().ToString("N");
            var manifestPath = Path.Combine(_root, "manifests", sessionId + ".json");
            var records = new List<QuarantineRecord>();
            foreach (var finding in candidates)
            {
                var (scanRoot, source) = ValidateFinding(report, finding);
                var hash = Hash(scanRoot, source);
                if (!report.ScannedHashes.TryGetValue(source, out var inspectedHash) || !hash.Equals(inspectedHash, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrWhiteSpace(finding.Sha256) && !hash.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase)))
                    throw new IOException($"Malware candidate changed after scanning; quarantine refused: {source}");
                var info = new FileInfo(source);
                var destination = Path.Combine(_root, "files", DateTime.UtcNow.ToString("yyyyMMdd"), sessionId + "-" + Guid.NewGuid().ToString("N") + "-" + Path.GetFileName(source));
                records.Add(new QuarantineRecord(finding.Scope, scanRoot, source, destination, hash, info.Length, info.LastWriteTimeUtc, info.Attributes,
                    string.Join(",", report.Findings.Where(x => string.Equals(ContainingFile(x.FilePath), source, StringComparison.OrdinalIgnoreCase)).Select(x => x.Rule).Distinct()), "Pending"));
            }

            foreach (var record in records) EnsureParentDirectory(record.QuarantinedPath, _root);
            var manifest = new QuarantineManifest("PPGAV", FormatVersion, sessionId, DateTimeOffset.UtcNow, "Quarantining", records);
            WriteManifest(manifestPath, manifest);
            try
            {
                for (var index = 0; index < manifest.Items.Count; index++)
                {
                    var item = manifest.Items[index];
                    _beforeMove?.Invoke(index, item.OriginalPath);
                    var source = SecurePathService.RequireContained(item.OriginalRoot, item.OriginalPath, true, "quarantine source");
                    if (!Hash(item.OriginalRoot, source).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new IOException($"Malware candidate changed immediately before quarantine: {source}");
                    EnsureParentDirectory(item.QuarantinedPath, _root);
                    SecurePathService.RequireContained(_root, item.QuarantinedPath, false, "quarantine destination");
                    if (File.Exists(item.QuarantinedPath) || Directory.Exists(item.QuarantinedPath)) throw new IOException("Quarantine destination unexpectedly exists.");
                    File.Move(source, item.QuarantinedPath);
                    if (!Hash(_root, item.QuarantinedPath).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new IOException($"Quarantined content failed post-move verification: {item.QuarantinedPath}");
                    manifest.Items[index] = item with { State = "Moved" };
                    WriteManifest(manifestPath, manifest);
                }
                manifest = manifest with { State = "Completed" };
                WriteManifest(manifestPath, manifest);
                _events.Log("Quarantine transaction complete", $"Moved {manifest.Items.Count} confirmed/approved malicious mod or Workshop file(s). Recovery manifest: {manifestPath}.", ScanCategory.Malware);
                return manifest.Items.Select(x => new QuarantineItem(x.OriginalPath, x.QuarantinedPath, manifestPath)).ToArray();
            }
            catch (Exception moveError)
            {
                var rollbackErrors = RollBackQuarantine(manifestPath, manifest);
                if (rollbackErrors.Count != 0)
                {
                    manifest = manifest with { State = "RecoveryRequired" };
                    try { WriteManifest(manifestPath, manifest); } catch (Exception ex) { rollbackErrors.Add("Could not persist recovery state: " + ex.Message); }
                    _events.Log("Quarantine rollback incomplete", string.Join(" ", rollbackErrors), ScanCategory.Malware);
                    throw new IOException("Quarantine failed and rollback is incomplete. Keep the authenticated recovery manifest at " + manifestPath, new AggregateException([moveError, .. rollbackErrors.Select(x => new IOException(x))]));
                }
                manifest = manifest with { State = "RolledBack" };
                WriteManifest(manifestPath, manifest);
                throw new IOException("Quarantine failed; every moved file was restored to its original location.", moveError);
            }
        }
        finally { TransactionLock.Release(); }
    }

    public void RecoverPendingTransactions()
    {
        TransactionLock.Wait();
        try
        {
            RecoverySucceeded = true;
            var manifestDirectory = Path.Combine(_root, "manifests");
            if (!Directory.Exists(manifestDirectory)) return;
            SecurePathService.RequireExistingDirectory(_root, "quarantine root");
            SecurePathService.RequireExistingDirectory(manifestDirectory, "quarantine manifest directory");
            foreach (var path in Directory.EnumerateFiles(manifestDirectory, "*.json", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    var manifest = ReadManifest(path);
                    if (manifest.State == "Quarantining" || manifest.State == "RecoveryRequired")
                    {
                        var errors = RollBackQuarantine(path, manifest);
                        if (errors.Count != 0) throw new IOException(string.Join(" ", errors));
                        WriteManifest(path, manifest with { State = "RolledBack" });
                        _events.Log("Interrupted quarantine recovered", $"Recovered transaction {manifest.SessionId}; moved files were restored.", ScanCategory.Suspicious);
                    }
                    else if (manifest.State == "Restoring")
                    {
                        manifest = CompleteRestore(path, manifest);
                        _events.Log("Interrupted quarantine restore completed", $"Completed previously approved restore {manifest.SessionId}.", ScanCategory.Suspicious);
                    }
                }
                catch (Exception ex) { RecoverySucceeded = false; _events.Log("Quarantine recovery required", $"Manifest {Path.GetFileName(path)} was preserved: {ex.Message}", ScanCategory.Malware); }
            }
        }
        finally { TransactionLock.Release(); }
    }

    public void Restore(string manifestPath)
    {
        TransactionLock.Wait();
        try
        {
            var manifest = ReadManifest(manifestPath);
            if (manifest.State != "Completed") throw new InvalidDataException("Only a completed PPGAV quarantine transaction can be restored.");
            ValidateManifest(manifest);
            foreach (var item in manifest.Items)
            {
                var source = SecurePathService.RequireContained(_root, item.QuarantinedPath, true, "quarantined file");
                if (!Hash(_root, source).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Quarantined file changed: {source}");
                SecurePathService.RequireExistingDirectory(item.OriginalRoot, "original mod or Workshop root");
                SecurePathService.RequireContained(item.OriginalRoot, item.OriginalPath, false, "restore destination");
                if (File.Exists(item.OriginalPath) || Directory.Exists(item.OriginalPath)) throw new IOException($"Refusing to overwrite existing restore target: {item.OriginalPath}");
            }

            manifest = manifest with { State = "Restoring" };
            WriteManifest(manifestPath, manifest);
            manifest = CompleteRestore(manifestPath, manifest);
            _events.Log("Quarantine restore complete", $"Restored {manifest.Items.Count} validated file(s) to their original mod/Workshop paths.");
        }
        finally { TransactionLock.Release(); }
    }

    private QuarantineManifest CompleteRestore(string manifestPath, QuarantineManifest manifest)
    {
        for (var index = 0; index < manifest.Items.Count; index++)
        {
            var item = manifest.Items[index];
            var destinationExists = File.Exists(item.OriginalPath);
            var sourceExists = File.Exists(item.QuarantinedPath);
            if (destinationExists)
            {
                if (!Hash(item.OriginalRoot, item.OriginalPath).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new IOException($"Restore target is occupied by different content: {item.OriginalPath}");
                if (sourceExists)
                {
                    if (!Hash(_root, item.QuarantinedPath).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("Quarantine source changed during restore recovery.");
                    if (!SecurePathService.DeleteContainedFileIfHash(_root, item.QuarantinedPath, item.Sha256)) throw new IOException("Could not remove the verified duplicate quarantine copy.");
                }
            }
            else
            {
                var source = SecurePathService.RequireContained(_root, item.QuarantinedPath, true, "quarantined file");
                if (!Hash(_root, source).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Quarantined file changed: {source}");
                EnsureParentDirectory(item.OriginalPath, item.OriginalRoot);
                SecurePathService.RequireContained(item.OriginalRoot, item.OriginalPath, false, "restore destination");
                File.Move(source, item.OriginalPath);
                if (!Hash(item.OriginalRoot, item.OriginalPath).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("Restored file failed hash verification.");
            }
            File.SetAttributes(item.OriginalPath, item.Attributes & ~FileAttributes.ReparsePoint);
            File.SetLastWriteTimeUtc(item.OriginalPath, item.LastWriteUtc);
            manifest.Items[index] = item with { State = "Restored" };
            WriteManifest(manifestPath, manifest);
        }
        manifest = manifest with { State = "Restored" };
        WriteManifest(manifestPath, manifest);
        return manifest;
    }

    private List<string> RollBackQuarantine(string manifestPath, QuarantineManifest manifest)
    {
        var errors = new List<string>();
        for (var index = manifest.Items.Count - 1; index >= 0; index--)
        {
            var item = manifest.Items[index];
            try
            {
                var originalExists = File.Exists(item.OriginalPath);
                var quarantinedExists = File.Exists(item.QuarantinedPath);
                if (originalExists && !quarantinedExists)
                {
                    if (!Hash(item.OriginalRoot, item.OriginalPath).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("Original path has unexpected content.");
                    continue;
                }
                if (originalExists && quarantinedExists)
                {
                    if (!Hash(item.OriginalRoot, item.OriginalPath).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase) ||
                        !Hash(_root, item.QuarantinedPath).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("Both paths exist with content that does not match the authenticated transaction.");
                    if (!SecurePathService.DeleteContainedFileIfHash(_root, item.QuarantinedPath, item.Sha256)) throw new IOException("Could not remove the duplicate quarantine copy.");
                    continue;
                }
                if (!quarantinedExists) throw new FileNotFoundException("Both original and quarantined copies are missing.", item.QuarantinedPath);
                if (!Hash(_root, item.QuarantinedPath).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("Quarantined file hash does not match its manifest.");
                EnsureParentDirectory(item.OriginalPath, item.OriginalRoot);
                SecurePathService.RequireContained(item.OriginalRoot, item.OriginalPath, false, "quarantine rollback destination");
                if (File.Exists(item.OriginalPath) || Directory.Exists(item.OriginalPath)) throw new IOException("Original rollback destination is occupied.");
                File.Move(item.QuarantinedPath, item.OriginalPath);
                manifest.Items[index] = item with { State = "RolledBack" };
                WriteManifest(manifestPath, manifest);
            }
            catch (Exception ex) { errors.Add($"{item.OriginalPath}: {ex.Message}"); }
        }
        return errors;
    }

    private static bool IsLocalModFolderName(string segment) =>
        segment.Equals("Mods", StringComparison.OrdinalIgnoreCase) || segment.Equals("CompiledMods", StringComparison.OrdinalIgnoreCase);

    private static string ContainingFile(string findingPath) => ScannerService.ContainingFile(findingPath);

    private (string Root, string File) ValidateFinding(ScanReport report, ScanFinding finding)
    {
        var file = SecurePathService.RequireAbsolute(finding.FilePath, "malware finding path");
        var candidates = report.ScannedRoots
            .Select(path => SecurePathService.RequireExistingDirectory(path, "scanned root"))
            .Where(root => IsWithin(root, file))
            .OrderByDescending(root => root.Length).ToArray();
        if (candidates.Length == 0) throw new UnauthorizedAccessException("Finding path is not under a root inspected by this scan.");
        var root = candidates[0];
        SecurePathService.RequireContained(root, file, true, "malware candidate");
        var relative = Path.GetRelativePath(root, file);
        if (finding.Scope == ScanScope.LocalMods && !relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(IsLocalModFolderName))
            throw new UnauthorizedAccessException("The finding is not inside a local Mods directory.");
        if (finding.Scope == ScanScope.SteamWorkshop && !file.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x.Equals("workshop", StringComparison.OrdinalIgnoreCase) || x.Equals("Workshop", StringComparison.OrdinalIgnoreCase)))
            throw new UnauthorizedAccessException("The finding is not inside a Workshop directory.");
        return (root, file);
    }

    private QuarantineManifest ReadManifest(string path)
    {
        var directory = Path.Combine(_root, "manifests");
        SecurePathService.RequireExistingDirectory(_root, "quarantine root");
        SecurePathService.RequireExistingDirectory(directory, "quarantine manifest directory");
        var safePath = SecurePathService.RequireContained(directory, path, true, "quarantine manifest");
        var manifest = AuthenticatedStateStore.Read<QuarantineManifest>(safePath);
        ValidateManifest(manifest);
        if (!Path.GetFileName(safePath).Equals(manifest.SessionId + ".json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Quarantine manifest filename does not match its authenticated session identity.");
        return manifest;
    }

    private void ValidateManifest(QuarantineManifest manifest)
    {
        if (manifest.Owner != "PPGAV" || manifest.FormatVersion != FormatVersion || !Guid.TryParseExact(manifest.SessionId, "N", out _) ||
            manifest.State is not ("Quarantining" or "RecoveryRequired" or "Completed" or "Restoring" or "RolledBack" or "Restored") ||
            manifest.Items is null || manifest.Items.Count == 0 || manifest.Items.Count > 100_000)
            throw new InvalidDataException("Quarantine manifest ownership or format validation failed.");
        var seenSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenDestinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in manifest.Items)
        {
            if (item is null || item.Scope is not (ScanScope.LocalMods or ScanScope.SteamWorkshop) || item.State is not ("Pending" or "Moved" or "RolledBack" or "Restored") || item.Length < 0 ||
                string.IsNullOrWhiteSpace(item.OriginalRoot) || string.IsNullOrWhiteSpace(item.OriginalPath) || string.IsNullOrWhiteSpace(item.QuarantinedPath) ||
                item.Sha256 is not { Length: 64 } || !item.Sha256.All(Uri.IsHexDigit) || !seenSources.Add(Path.GetFullPath(item.OriginalPath)) ||
                !seenDestinations.Add(Path.GetFullPath(item.QuarantinedPath))) throw new InvalidDataException("Quarantine manifest contains invalid or duplicate records.");
            var root = SecurePathService.RequireAbsolute(item.OriginalRoot, "quarantine original root");
            _ = SecurePathService.RequireContained(root, item.OriginalPath, false, "quarantine original path");
            _ = SecurePathService.RequireContained(Path.Combine(_root, "files"), item.QuarantinedPath, false, "quarantine destination path");
            var relative = Path.GetRelativePath(root, item.OriginalPath);
            var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (item.Scope == ScanScope.LocalMods && !parts.Any(IsLocalModFolderName) ||
                item.Scope == ScanScope.SteamWorkshop && !item.OriginalPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x.Equals("workshop", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Quarantine manifest path is outside a supported Mods/Workshop location.");
            if (item.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException("Quarantine manifest requests restoring a reparse point.");
        }
    }

    private void EnsureStorage()
    {
        if (!Directory.Exists(_root)) Directory.CreateDirectory(_root);
        SecurePathService.RequireExistingDirectory(_root, "quarantine root");
        foreach (var path in new[] { Path.Combine(_root, "files"), Path.Combine(_root, "manifests") })
        {
            if (!Directory.Exists(path)) Directory.CreateDirectory(path);
            SecurePathService.RequireContained(_root, path, true, "quarantine storage directory");
        }
    }

    private void WriteManifest(string path, QuarantineManifest manifest)
    {
        ValidateManifest(manifest);
        var directory = Path.Combine(_root, "manifests");
        if (!Directory.Exists(directory)) Directory.CreateDirectory(directory);
        SecurePathService.RequireExistingDirectory(directory, "quarantine manifest directory");
        if (!IsWithin(directory, path)) throw new UnauthorizedAccessException("Quarantine manifest path escaped its owned directory.");
        AuthenticatedStateStore.Write(path, manifest);
    }

    private static void EnsureParentDirectory(string file, string root)
    {
        var safeRoot = SecurePathService.RequireExistingDirectory(root, "validated file root");
        var destination = SecurePathService.RequireAbsolute(file, "validated file destination");
        if (!IsWithin(safeRoot, destination)) throw new UnauthorizedAccessException("File destination escapes its validated root.");
        var parent = Path.GetDirectoryName(destination)!;
        var relative = Path.GetRelativePath(safeRoot, parent);
        var current = safeRoot;
        if (relative == ".") return;
        foreach (var part in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            current = Path.Combine(current, part);
            if (File.Exists(current)) throw new IOException($"A file blocks the validated destination directory: {current}");
            if (!Directory.Exists(current)) Directory.CreateDirectory(current);
            SecurePathService.RequireContained(safeRoot, current, true, "validated destination directory");
        }
    }

    private static string Hash(string root, string file)
    {
        using var stream = SecurePathService.OpenContainedRead(root, file, "quarantine file");
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static bool IsWithin(string root, string candidate)
    {
        var safeRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(candidate).StartsWith(safeRoot, StringComparison.OrdinalIgnoreCase);
    }
}

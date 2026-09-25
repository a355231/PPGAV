using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class BackupService
{
    private const int ManifestFormat = 3;
    private const long MaxArchiveBytes = 32L * 1024 * 1024 * 1024;
    private const int MaxFiles = 250_000;
    private const long MaxManifestBytes = 16L * 1024 * 1024;
    private static readonly SemaphoreSlim BackupLock = new(1, 1);
    private readonly EventLogService _events;
    private readonly string _restoreSafetyRoot;
    private sealed record Manifest(int FormatVersion, string Owner, string ArchiveId, DateTimeOffset CreatedAt, string GameDirectory, long TotalBytes, List<ManifestEntry> Files);
    private sealed record ManifestEntry(string Path, long Length, string Sha256);
    private sealed record ManifestEnvelope(int FormatVersion, string ProtectedPayload);
    private sealed record RestoreStageManifest(string Owner, string SessionId, string Purpose);

    public BackupService(EventLogService events, string? restoreSafetyRoot = null)
    {
        _events = events;
        _restoreSafetyRoot = Path.GetFullPath(restoreSafetyRoot ?? AppPaths.RestoreSafetyFolder);
    }

    public async Task<BackupInfo> CreateBackupAsync(string gameDirectory, string backupDirectory, int retentionCount, CancellationToken cancellationToken = default)
    {
        if (IsPeoplePlaygroundRunning(gameDirectory)) throw new InvalidOperationException("Close People Playground before creating a consistent full-game backup.");
        await BackupLock.WaitAsync(cancellationToken);
        try { return await CreateBackupCoreAsync(gameDirectory, backupDirectory, retentionCount, cancellationToken); }
        finally { BackupLock.Release(); }
    }

    private async Task<BackupInfo> CreateBackupCoreAsync(string gameDirectory, string backupDirectory, int retentionCount, CancellationToken cancellationToken)
    {
        var root = SecurePathService.RequireExistingDirectory(gameDirectory, "game directory");
        var backupRoot = Path.GetFullPath(backupDirectory);
        if (IsEqualOrWithin(root, backupRoot) || IsEqualOrWithin(backupRoot, root)) throw new InvalidOperationException("Backup directory must be completely separate from the game directory.");
        if (!Directory.Exists(backupRoot)) Directory.CreateDirectory(backupRoot);
        backupRoot = SecurePathService.RequireExistingDirectory(backupRoot, "backup directory");
        var finalPath = Path.Combine(backupRoot, $"PPG-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.ppgbackup.zip");
        var temporaryPath = finalPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            var entries = new List<ManifestEntry>(); long totalBytes = 0;
            using (var archive = ZipFile.Open(temporaryPath, ZipArchiveMode.Create))
            {
                foreach (var file in EnumerateFiles(root))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (entries.Count >= MaxFiles) throw new IOException("Backup file-count limit exceeded.");
                    var relative = Path.GetRelativePath(root, file).Replace(Path.DirectorySeparatorChar, '/');
                    ValidateRelativeArchivePath(relative);
                    var entry = archive.CreateEntry(relative, CompressionLevel.Fastest);
                    using var source = SecurePathService.OpenContainedRead(root, file, "backup source file");
                    using var destination = entry.Open();
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var buffer = new byte[128 * 1024]; int read; long fileBytes = 0;
                    while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        fileBytes = checked(fileBytes + read); totalBytes = checked(totalBytes + read);
                        if (totalBytes > MaxArchiveBytes) throw new IOException("Backup exceeds the configured expanded-size limit.");
                        destination.Write(buffer, 0, read); hash.AppendData(buffer, 0, read);
                    }
                    entries.Add(new ManifestEntry(relative, fileBytes, Convert.ToHexString(hash.GetHashAndReset())));
                }
                if (entries.Count == 0) throw new InvalidDataException("Refusing to create an empty game backup.");
                var manifest = new Manifest(ManifestFormat, "PPGAV", Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, root, totalBytes, entries);
                var envelope = new ManifestEnvelope(ManifestFormat, AuthenticatedStateStore.ProtectJson(manifest));
                var manifestEntry = archive.CreateEntry(".ppgav-manifest.json", CompressionLevel.NoCompression);
                using var writer = new StreamWriter(manifestEntry.Open(), new UTF8Encoding(false));
                writer.Write(JsonSerializer.Serialize(envelope));
            }
            SecurePathService.RequireExistingDirectory(backupRoot, "backup directory before publish");
            File.Move(temporaryPath, finalPath);
            Prune(backupRoot, retentionCount);
            var result = new FileInfo(finalPath);
            _events.Log("Backup created", $"Created authenticated full backup {result.Name} ({FormatSize(result.Length)}).", ScanCategory.Safe);
            return new BackupInfo(finalPath, result.CreationTimeUtc, result.Length);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }

    /// <summary>
    /// True when the game directory is byte-identical to the newest authenticated backup, so a
    /// scheduled run can skip writing another identical multi-hundred-megabyte archive (which also
    /// pushed older, distinct backups out of the retention window).
    /// </summary>
    public async Task<bool> MatchesLatestBackupAsync(string gameDirectory, string backupDirectory, CancellationToken cancellationToken = default)
    {
        await BackupLock.WaitAsync(cancellationToken);
        try
        {
            var latest = ListBackups(backupDirectory).FirstOrDefault();
            if (latest is null) return false;
            var root = SecurePathService.RequireExistingDirectory(gameDirectory, "game directory");
            var manifest = ReadAndValidateManifest(latest.Path);
            if (!Path.GetFullPath(manifest.GameDirectory).Equals(root, StringComparison.OrdinalIgnoreCase)) return false;
            var expected = manifest.Files.ToDictionary(x => x.Path, StringComparer.OrdinalIgnoreCase);
            var seen = 0;
            foreach (var file in EnumerateFiles(root))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relative = Path.GetRelativePath(root, file).Replace(Path.DirectorySeparatorChar, '/');
                if (!expected.TryGetValue(relative, out var entry) || new FileInfo(file).Length != entry.Length) return false;
                using (var source = SecurePathService.OpenContainedRead(root, file, "backup comparison file"))
                {
                    var hash = Convert.ToHexString(await SHA256.HashDataAsync(source, cancellationToken));
                    if (!hash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase)) return false;
                }
                seen++;
            }
            return seen == expected.Count;
        }
        finally { BackupLock.Release(); }
    }

    public IReadOnlyList<BackupInfo> ListBackups(string backupDirectory)
    {
        if (string.IsNullOrWhiteSpace(backupDirectory) || !Directory.Exists(backupDirectory)) return [];
        SecurePathService.RequireExistingDirectory(backupDirectory, "backup directory");
        var result = new List<BackupInfo>();
        foreach (var path in Directory.EnumerateFiles(backupDirectory, "*.ppgbackup.zip", SearchOption.TopDirectoryOnly))
        {
            try
            {
                var manifest = ReadAndValidateManifest(path);
                var info = new FileInfo(path);
                if (manifest.TotalBytes > MaxArchiveBytes || info.Length <= 0 || info.Length > MaxArchiveBytes) continue;
                result.Add(new BackupInfo(info.FullName, info.CreationTimeUtc, info.Length));
            }
            catch (Exception ex) { _events.Log("Untrusted backup ignored", $"Backup {Path.GetFileName(path)} failed authentication/validation: {ex.Message}", ScanCategory.Suspicious); }
        }
        return result.OrderByDescending(x => x.CreatedAt).ToArray();
    }

    public async Task RestoreAsync(string backupFile, string gameDirectory, string backupDirectory, CancellationToken cancellationToken = default)
    {
        if (IsPeoplePlaygroundRunning(gameDirectory)) throw new InvalidOperationException("Close People Playground before restoring a backup.");
        await BackupLock.WaitAsync(cancellationToken);
        try
        {
            var root = SecurePathService.RequireExistingDirectory(gameDirectory, "game directory");
            var archivePath = SecurePathService.RequireExistingFile(backupFile, "backup archive");
            var manifest = ReadAndValidateManifest(archivePath);
            if (!Path.GetFullPath(manifest.GameDirectory).Equals(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Backup belongs to a different game installation path; automatic restore is refused.");

            var configuredBackupRoot = SecurePathService.RequireExistingDirectory(backupDirectory, "configured backup directory");
            if (!IsEqualOrWithin(configuredBackupRoot, archivePath)) throw new UnauthorizedAccessException("The selected backup is outside the configured backup directory.");
            var rollbackDirectory = Path.Combine(_restoreSafetyRoot, "RestoreRollbacks");
            Directory.CreateDirectory(rollbackDirectory);
            rollbackDirectory = SecurePathService.RequireExistingDirectory(rollbackDirectory, "rollback backup storage");
            if (IsEqualOrWithin(root, rollbackDirectory) || IsEqualOrWithin(rollbackDirectory, root)) throw new InvalidOperationException("Rollback storage overlaps the game installation.");
            var rollback = await CreateBackupCoreAsync(root, rollbackDirectory, 100, cancellationToken);
            var rollbackManifest = ReadAndValidateManifest(rollback.Path);
            var rollbackFiles = rollbackManifest.Files.ToDictionary(x => x.Path, x => x.Sha256, StringComparer.OrdinalIgnoreCase);

            try { await RestoreArchiveContentsAsync(archivePath, root, cancellationToken); }
            catch (Exception restoreError)
            {
                try
                {
                    var targetOnlyFiles = manifest.Files
                        .Where(x => !rollbackFiles.ContainsKey(x.Path))
                        .ToDictionary(x => x.Path, x => x.Sha256, StringComparer.OrdinalIgnoreCase);
                    await RestoreArchiveContentsAsync(rollback.Path, root, CancellationToken.None, targetOnlyFiles);
                    _events.Log("Restore rolled back", $"Restore failed and the pre-restore backup was reapplied successfully from {rollback.Path}.", ScanCategory.Suspicious);
                }
                catch (Exception rollbackError)
                {
                    _events.Log("Restore rollback incomplete", $"Original restore failure: {restoreError.Message}; rollback failure: {rollbackError.Message}. Pre-restore backup retained at {rollback.Path}.", ScanCategory.Malware);
                    throw new IOException($"Restore failed and automatic rollback was incomplete. Preserve the rollback archive at {rollback.Path}.", new AggregateException(restoreError, rollbackError));
                }
                if (restoreError is OperationCanceledException) throw;
                throw new IOException($"Restore failed; the prior game contents were restored from the rollback archive. {restoreError.Message}", restoreError);
            }
            _events.Log("Backup restored", $"Restored {Path.GetFileName(archivePath)} into {root}; pre-restore rollback is retained at {rollback.Path}.");
        }
        finally { BackupLock.Release(); }
    }

    private async Task RestoreArchiveContentsAsync(string archivePath, string root, CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? removeAfterRestore = null)
    {
        var stageId = Guid.NewGuid().ToString("N");
        var stageRoot = Path.Combine(Path.GetTempPath(), "PPGAV-restore-" + stageId);
        if (Directory.Exists(stageRoot) || File.Exists(stageRoot)) throw new IOException("Refusing to reuse a restore staging directory.");
        Directory.CreateDirectory(stageRoot);
        var marker = Path.Combine(stageRoot, ".ppgav-restore-stage.json");
        var markerWritten = false;
        try
        {
            AuthenticatedStateStore.Write(marker, new RestoreStageManifest("PPGAV", stageId, "BackupRestore")); markerWritten = true;
            var manifest = await StageAndValidateBackupAsync(archivePath, stageRoot, cancellationToken);
            foreach (var item in manifest.Files)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var staged = SafeArchivePath(stageRoot, item.Path);
                    var destination = SafeArchivePath(root, item.Path);
                    EnsureSafeParents(root, destination);
                    var existed = File.Exists(destination) || Directory.Exists(destination);
                    if (Directory.Exists(destination)) throw new IOException($"Restore target is a directory: {destination}");
                    if (existed) SecurePathService.RequireContained(root, destination, true, "restore destination");
                    else SecurePathService.RequireContained(root, destination, false, "restore destination");
                    var temporary = Path.Combine(Path.GetDirectoryName(destination)!, ".ppgav-restore-" + Guid.NewGuid().ToString("N") + Path.GetExtension(destination));
                    try
                    {
                        using (var input = SecurePathService.OpenContainedRead(stageRoot, staged, "staged restore file"))
                        using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
                        {
                            await CopyAndHashAsync(input, output, cancellationToken, MaxArchiveBytes);
                            output.Flush(true);
                        }
                        if (!Hash(temporary).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Restore staging hash changed: {item.Path}");
                        SecurePathService.RequireExistingDirectory(Path.GetDirectoryName(destination)!, "restore destination parent before commit");
                        SecurePathService.RejectReparse(temporary, "restore temporary file");
                        SecurePathService.MoveFileContained(root, temporary, destination, true);
                    }
                    finally { if (File.Exists(temporary)) File.Delete(temporary); }
                }
                if (removeAfterRestore is not null)
                {
                    foreach (var (relativePath, expectedHash) in removeAfterRestore)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var extra = SafeArchivePath(root, relativePath);
                        if (!File.Exists(extra)) continue;
                        SecurePathService.RequireContained(root, extra, true, "transaction-created restore file");
                        if (!SecurePathService.DeleteContainedFileIfHash(root, extra, expectedHash))
                            throw new IOException($"Could not safely remove restore-created file: {relativePath}");
                    }
                }
        }
        finally
        {
            if (markerWritten)
            {
                try { DeleteVerifiedStage(stageRoot, marker, stageId); }
                catch (Exception ex) { _events.Log("Restore staging cleanup failed", $"Verified stage was retained at {stageRoot}: {ex.Message}", ScanCategory.Suspicious); }
            }
            else
            {
                try { if (Directory.Exists(stageRoot) && !Directory.EnumerateFileSystemEntries(stageRoot).Any()) Directory.Delete(stageRoot, false); }
                catch (Exception ex) { _events.Log("Restore staging cleanup failed", ex.Message, ScanCategory.Suspicious); }
            }
        }
    }

    private async Task<Manifest> StageAndValidateBackupAsync(string archivePath, string stageRoot, CancellationToken cancellationToken)
    {
        var manifest = ReadAndValidateManifest(archivePath);
        var parent = Path.GetDirectoryName(archivePath)!;
        using var archiveStream = SecurePathService.OpenContainedRead(parent, archivePath, "backup archive");
        using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read);
        var payloadEntries = archive.Entries.Where(x => !x.FullName.Equals(".ppgav-manifest.json", StringComparison.Ordinal)).ToArray();
        if (payloadEntries.Length != manifest.Files.Count || payloadEntries.Select(x => x.FullName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != payloadEntries.Length)
            throw new InvalidDataException("Backup archive has missing, duplicate, or unmanifested entries.");
        var expectedNames = manifest.Files.Select(x => x.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!payloadEntries.Select(x => x.FullName).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(expectedNames)) throw new InvalidDataException("Backup archive entries do not match the authenticated manifest.");
        long total = 0;
        foreach (var item in manifest.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateRelativeArchivePath(item.Path);
            var entry = archive.GetEntry(item.Path) ?? throw new InvalidDataException($"Missing backup entry: {item.Path}");
            if (entry.Length != item.Length) throw new InvalidDataException($"Backup entry length does not match its manifest: {item.Path}");
            total = checked(total + item.Length);
            if (total > MaxArchiveBytes) throw new InvalidDataException("Backup expanded size exceeds the restore limit.");
            var destination = SafeArchivePath(stageRoot, item.Path);
            EnsureSafeParents(stageRoot, destination);
            string hash;
            using (var input = entry.Open())
            using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
            {
                hash = await CopyAndHashAsync(input, output, cancellationToken, item.Length);
                output.Flush(true);
            }
            if (!hash.Equals(item.Sha256, StringComparison.OrdinalIgnoreCase) || !Hash(destination).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Backup hash validation failed: {item.Path}");
        }
        if (total != manifest.TotalBytes) throw new InvalidDataException("Backup total length does not match the authenticated manifest.");
        return manifest;
    }

    private Manifest ReadAndValidateManifest(string archivePath)
    {
        var safeArchive = SecurePathService.RequireExistingFile(archivePath, "backup archive");
        var info = new FileInfo(safeArchive);
        if (info.Length <= 0 || info.Length > MaxArchiveBytes) throw new InvalidDataException("Backup archive is empty or exceeds the archive limit.");
        using var input = SecurePathService.OpenContainedRead(Path.GetDirectoryName(safeArchive)!, safeArchive, "backup archive");
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: true);
        var manifests = archive.Entries.Where(x => x.FullName.Equals(".ppgav-manifest.json", StringComparison.Ordinal)).ToArray();
        if (manifests.Length != 1 || manifests[0].Length > MaxManifestBytes) throw new InvalidDataException("Backup manifest is missing, duplicated, or oversized.");
        using var entryStream = manifests[0].Open();
        var envelope = JsonSerializer.Deserialize<ManifestEnvelope>(ReadBounded(entryStream, MaxManifestBytes)) ?? throw new InvalidDataException("Backup manifest envelope is invalid.");
        if (envelope.FormatVersion != ManifestFormat) throw new InvalidDataException("Backup manifest version is unsupported or unauthenticated.");
        var manifest = AuthenticatedStateStore.UnprotectJson<Manifest>(envelope.ProtectedPayload);
        if (manifest.FormatVersion != ManifestFormat || manifest.Owner != "PPGAV" || !Guid.TryParseExact(manifest.ArchiveId, "N", out _) ||
            string.IsNullOrWhiteSpace(manifest.GameDirectory) || manifest.Files is null || manifest.Files.Count == 0 || manifest.Files.Count > MaxFiles ||
            manifest.TotalBytes < 0 || manifest.TotalBytes > MaxArchiveBytes ||
            manifest.Files.Any(x => x is null || string.IsNullOrWhiteSpace(x.Path) || string.IsNullOrWhiteSpace(x.Sha256)) ||
            manifest.Files.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != manifest.Files.Count)
            throw new InvalidDataException("Authenticated backup manifest failed validation.");
        long sum = 0;
        foreach (var item in manifest.Files)
        {
            ValidateRelativeArchivePath(item.Path);
            if (item.Length < 0 || item.Sha256.Length != 64 || !item.Sha256.All(Uri.IsHexDigit)) throw new InvalidDataException("Backup manifest contains an invalid size or hash.");
            sum = checked(sum + item.Length);
            if (sum > MaxArchiveBytes) throw new InvalidDataException("Backup manifest exceeds the expanded-size limit.");
        }
        if (sum != manifest.TotalBytes) throw new InvalidDataException("Backup manifest total size is inconsistent.");
        _ = SecurePathService.RequireAbsolute(manifest.GameDirectory, "backup game directory");
        return manifest;
    }

    private static IEnumerable<string> EnumerateFiles(string root)
    {
        var pending = new Stack<string>([root]);
        var count = 0;
        while (pending.Count > 0)
        {
            var directory = pending.Pop(); SecurePathService.RejectReparse(directory, "backup directory");
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"Backup refuses reparse-point content: {entry}");
                if (attributes.HasFlag(FileAttributes.Directory)) pending.Push(entry);
                else
                {
                    if (++count > MaxFiles) throw new IOException("Backup file-count limit exceeded.");
                    yield return entry;
                }
            }
        }
    }

    private static string SafeArchivePath(string root, string entryName)
    {
        ValidateRelativeArchivePath(entryName);
        var normalized = entryName.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
        var safeRoot = Path.GetFullPath(root);
        var destination = Path.GetFullPath(Path.Combine(safeRoot, normalized));
        if (!IsWithin(safeRoot, destination)) throw new InvalidDataException("Backup contains a path traversal entry.");
        return destination;
    }

    private static void ValidateRelativeArchivePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || Path.IsPathRooted(path) || path.Contains(':') || path.StartsWith('/') || path.StartsWith('\\'))
            throw new InvalidDataException("Backup contains an absolute or device path.");
        var segments = path.Replace('\\', '/').Split('/');
        if (segments.Any(x => string.IsNullOrWhiteSpace(x) || x is "." or "..")) throw new InvalidDataException("Backup contains an unsafe path component.");
    }

    private static void EnsureSafeParents(string root, string destination)
    {
        var safeRoot = SecurePathService.RequireExistingDirectory(root, "restore root");
        var relative = Path.GetRelativePath(safeRoot, destination);
        if (Path.IsPathRooted(relative) || relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x is ".." or ".")) throw new UnauthorizedAccessException("Restore path escapes its root.");
        var current = safeRoot;
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        foreach (var part in parts.Take(parts.Length - 1))
        {
            current = Path.Combine(current, part);
            if (File.Exists(current)) throw new IOException($"Restore parent path is a file: {current}");
            if (!Directory.Exists(current)) Directory.CreateDirectory(current);
            SecurePathService.RequireContained(safeRoot, current, true, "restore directory");
        }
    }

    private static async Task<string> CopyAndHashAsync(Stream input, Stream output, CancellationToken cancellationToken, long maximumBytes)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024]; int read; long total = 0;
        while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested(); total = checked(total + read);
            if (total > maximumBytes) throw new InvalidDataException("Archive entry expanded beyond its authenticated size limit.");
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken); hash.AppendData(buffer, 0, read);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static byte[] ReadBounded(Stream input, long maximumBytes)
    {
        using var result = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (result.Length + read > maximumBytes) throw new InvalidDataException("Backup manifest expanded beyond its configured size limit.");
            result.Write(buffer, 0, read);
        }
        return result.ToArray();
    }

    private void Prune(string directory, int retentionCount)
    {
        var valid = new List<FileInfo>();
        foreach (var path in Directory.EnumerateFiles(directory, "*.ppgbackup.zip", SearchOption.TopDirectoryOnly))
        {
            try { _ = ReadAndValidateManifest(path); valid.Add(new FileInfo(path)); }
            catch { /* Never delete an archive whose authenticated ownership cannot be established. */ }
        }
        foreach (var file in valid.OrderByDescending(x => x.CreationTimeUtc).Skip(Math.Max(1, retentionCount)))
        {
            _ = ReadAndValidateManifest(file.FullName);
            File.Delete(file.FullName);
            _events.Log("Old PPGAV backup pruned", $"Removed authenticated PPGAV-owned backup {file.Name} according to the configured retention limit.");
        }
    }

    private static void DeleteVerifiedStage(string root, string marker, string expectedSessionId)
    {
        SecurePathService.RequireExistingDirectory(root, "restore stage");
        SecurePathService.RequireContained(root, marker, true, "restore stage manifest");
        var record = AuthenticatedStateStore.Read<RestoreStageManifest>(marker);
        if (record.Owner != "PPGAV" || record.Purpose != "BackupRestore" || !record.SessionId.Equals(expectedSessionId, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(root).Equals("PPGAV-restore-" + expectedSessionId, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Restore stage ownership manifest is invalid.");
        ValidateTreeNoReparse(root);
        Directory.Delete(root, true);
    }

    private static void ValidateTreeNoReparse(string root)
    {
        var pending = new Stack<string>([root]);
        while (pending.TryPop(out var current))
        {
            SecurePathService.RejectReparse(current, "owned restore stage");
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attrs = File.GetAttributes(entry);
                if (attrs.HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"Restore stage contains a reparse point: {entry}");
                if (attrs.HasFlag(FileAttributes.Directory)) pending.Push(entry);
            }
        }
    }

    private static string Hash(string path)
    {
        using var stream = SecurePathService.OpenContainedRead(Path.GetDirectoryName(path)!, path, "restore verification file");
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static bool IsWithin(string root, string candidate)
    {
        var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(candidate).StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsEqualOrWithin(string root, string candidate) =>
        Path.GetFullPath(root).Equals(Path.GetFullPath(candidate), StringComparison.OrdinalIgnoreCase) || IsWithin(root, candidate);

    private static bool IsPeoplePlaygroundRunning(string gameDirectory)
    {
        if (string.IsNullOrWhiteSpace(gameDirectory)) return false;
        var executable = Path.GetFullPath(Path.Combine(gameDirectory, "People Playground.exe"));
        foreach (var process in Process.GetProcessesByName("People Playground"))
        {
            try { if (string.Equals(Path.GetFullPath(process.MainModule?.FileName ?? ""), executable, StringComparison.OrdinalIgnoreCase)) return true; }
            catch { return true; }
            finally { process.Dispose(); }
        }
        return false;
    }

    private static string FormatSize(long bytes)
    {
        var units = new[] { "B", "KB", "MB", "GB" }; var size = (double)bytes; var unit = 0;
        while (size >= 1024 && unit < units.Length - 1) { size /= 1024; unit++; }
        return $"{size:0.0} {units[unit]}";
    }
}

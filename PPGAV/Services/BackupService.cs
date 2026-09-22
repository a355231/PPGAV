using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class BackupService
{
    private const long MaxArchiveBytes = 32L * 1024 * 1024 * 1024;
    private static readonly SemaphoreSlim BackupLock = new(1, 1);
    private readonly EventLogService _events;
    private sealed record Manifest(string Owner, int FormatVersion, DateTimeOffset CreatedAt, string GameDirectory, long TotalBytes, List<ManifestEntry> Files);
    private sealed record ManifestEntry(string Path, long Length, string Sha256);

    public BackupService(EventLogService events) => _events = events;

    public async Task<BackupInfo> CreateBackupAsync(string gameDirectory, string backupDirectory, int retentionCount, CancellationToken cancellationToken = default)
    {
        await BackupLock.WaitAsync(cancellationToken);
        try { return await CreateBackupCoreAsync(gameDirectory, backupDirectory, retentionCount, cancellationToken); }
        finally { BackupLock.Release(); }
    }

    private async Task<BackupInfo> CreateBackupCoreAsync(string gameDirectory, string backupDirectory, int retentionCount, CancellationToken cancellationToken)
    {
        var root = SecurePathService.RequireExistingDirectory(gameDirectory, "game directory");
            var backupRoot = Path.GetFullPath(backupDirectory);
            if (IsWithin(root, backupRoot) || IsWithin(backupRoot, root)) throw new InvalidOperationException("Backup directory must not contain or be contained by the game directory.");
            Directory.CreateDirectory(backupRoot);
            SecurePathService.RejectReparse(backupRoot, "backup directory");
            var finalPath = Path.Combine(backupRoot, $"PPG-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.ppgbackup.zip");
            var temporaryPath = finalPath + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                var entries = new List<ManifestEntry>(); long totalBytes = 0;
                using (var archive = ZipFile.Open(temporaryPath, ZipArchiveMode.Create))
                {
                    foreach (var file in EnumerateFiles(root))
                    {
                        cancellationToken.ThrowIfCancellationRequested(); SecurePathService.RequireContained(root, file, true, "backup file");
                        var info = new FileInfo(file); totalBytes = checked(totalBytes + info.Length); if (totalBytes > MaxArchiveBytes) throw new IOException("Backup exceeds the configured archive size limit.");
                        var relative = Path.GetRelativePath(root, file).Replace(Path.DirectorySeparatorChar, '/');
                        if (relative.StartsWith("../", StringComparison.Ordinal) || relative.Contains("/../", StringComparison.Ordinal)) throw new InvalidDataException("Unsafe backup path.");
                        var entry = archive.CreateEntry(relative, CompressionLevel.Fastest);
                        using var source = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
                        using var destination = entry.Open();
                        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                        var buffer = new byte[1024 * 128]; int read;
                        while ((read = source.Read(buffer, 0, buffer.Length)) > 0) { cancellationToken.ThrowIfCancellationRequested(); destination.Write(buffer, 0, read); hash.AppendData(buffer, 0, read); }
                        entries.Add(new ManifestEntry(relative, info.Length, Convert.ToHexString(hash.GetHashAndReset())));
                    }
                    var manifest = new Manifest("PPGAV", 2, DateTimeOffset.UtcNow, root, totalBytes, entries);
                    var manifestEntry = archive.CreateEntry(".ppgav-manifest.json", CompressionLevel.NoCompression);
                    using var writer = new StreamWriter(manifestEntry.Open(), Encoding.UTF8); writer.Write(JsonSerializer.Serialize(manifest));
                }
                File.Move(temporaryPath, finalPath);
            }
            finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
            Prune(backupRoot, retentionCount);
            var result = new FileInfo(finalPath); _events.Log("Backup created", $"Created full backup {result.Name} ({FormatSize(result.Length)}).", ScanCategory.Safe); return new BackupInfo(finalPath, result.CreationTimeUtc, result.Length);
    }

    public IReadOnlyList<BackupInfo> ListBackups(string backupDirectory)
    {
        if (string.IsNullOrWhiteSpace(backupDirectory) || !Directory.Exists(backupDirectory)) return [];
        SecurePathService.RejectReparse(backupDirectory, "backup directory");
        return Directory.GetFiles(backupDirectory, "*.ppgbackup.zip", SearchOption.TopDirectoryOnly).Select(path => new FileInfo(path)).OrderByDescending(x => x.CreationTimeUtc).Select(x => new BackupInfo(x.FullName, x.CreationTimeUtc, x.Length)).ToArray();
    }

    public async Task RestoreAsync(string backupFile, string gameDirectory, string backupDirectory, CancellationToken cancellationToken = default)
    {
        if (IsPeoplePlaygroundRunning(gameDirectory)) throw new InvalidOperationException("Close People Playground before restoring a backup.");
        await BackupLock.WaitAsync(cancellationToken);
        var tempRoot = Path.Combine(Path.GetTempPath(), "PPGAV-restore-" + Guid.NewGuid().ToString("N"));
        try
        {
            var root = SecurePathService.RequireExistingDirectory(gameDirectory, "game directory");
            var archivePath = SecurePathService.RequireExistingFile(backupFile, "backup archive");
            Directory.CreateDirectory(tempRoot); SecurePathService.RejectReparse(tempRoot, "restore staging");
            using var archive = ZipFile.OpenRead(archivePath);
            var manifestEntry = archive.GetEntry(".ppgav-manifest.json") ?? throw new InvalidDataException("Backup manifest is missing.");
            var manifest = JsonSerializer.Deserialize<Manifest>(ReadEntry(manifestEntry)) ?? throw new InvalidDataException("Backup manifest is invalid.");
            if (manifest.Owner != "PPGAV" || manifest.FormatVersion != 2 || manifest.Files.Count == 0 || manifest.Files.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != manifest.Files.Count) throw new InvalidDataException("Backup manifest failed validation.");
            var archiveFiles = archive.Entries.Where(x => !x.FullName.Equals(".ppgav-manifest.json", StringComparison.OrdinalIgnoreCase)).ToList();
            if (archiveFiles.Count != manifest.Files.Count || archiveFiles.Any(x => string.IsNullOrEmpty(x.Name))) throw new InvalidDataException("Backup archive does not match its manifest.");
            foreach (var item in manifest.Files)
            {
                cancellationToken.ThrowIfCancellationRequested(); var entry = archive.GetEntry(item.Path) ?? throw new InvalidDataException($"Missing backup entry: {item.Path}");
                var destination = SafeArchivePath(tempRoot, item.Path); Directory.CreateDirectory(Path.GetDirectoryName(destination)!); SecurePathService.RejectReparse(Path.GetDirectoryName(destination)!, "restore directory");
                using var input = entry.Open(); using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, useAsync: true); await input.CopyToAsync(output, cancellationToken); await output.FlushAsync(cancellationToken); output.Close();
                if (new FileInfo(destination).Length != item.Length || !Hash(destination).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Backup hash validation failed: {item.Path}");
            }
            var rollback = await CreateBackupCoreAsync(root, backupDirectory, 1, cancellationToken);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var item in manifest.Files) { var source = SafeArchivePath(tempRoot, item.Path); var destination = SafeArchivePath(root, item.Path); SecurePathService.RequireContained(root, destination, false, "restore destination"); Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(source, destination, true); }
            }
            catch { _events.Log("Restore rollback available", $"Restore failed; rollback backup remains at {rollback.Path}.", ScanCategory.Suspicious); throw; }
            _events.Log("Backup restored", $"Restored {Path.GetFileName(archivePath)} into {root}.");
        }
        finally { try { if (Directory.Exists(tempRoot)) Directory.Delete(tempRoot, true); } catch (Exception ex) { _events.Log("Restore cleanup failed", ex.Message, ScanCategory.Suspicious); } BackupLock.Release(); }
    }

    private static IEnumerable<string> EnumerateFiles(string root)
    {
        var pending = new Stack<string>([root]);
        while (pending.Count > 0)
        {
            var directory = pending.Pop(); SecurePathService.RejectReparse(directory, "backup directory");
            foreach (var file in Directory.GetFiles(directory)) { SecurePathService.RejectReparse(file, "backup file"); yield return file; }
            foreach (var child in Directory.GetDirectories(directory)) { SecurePathService.RejectReparse(child, "backup directory"); pending.Push(child); }
        }
    }

    private static string SafeArchivePath(string root, string entryName)
    {
        var normalized = entryName.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar); if (Path.IsPathRooted(normalized)) throw new InvalidDataException("Backup contains an absolute path."); var destination = Path.GetFullPath(Path.Combine(root, normalized)); if (!IsWithin(root, destination)) throw new InvalidDataException("Backup contains a path traversal entry."); return destination;
    }
    private static string ReadEntry(ZipArchiveEntry entry) { using var reader = new StreamReader(entry.Open(), Encoding.UTF8); return reader.ReadToEnd(); }
    private static string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
    private static bool IsWithin(string root, string candidate) { var r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar; var c = Path.GetFullPath(candidate); return c.StartsWith(r, StringComparison.OrdinalIgnoreCase); }
    private static bool IsPeoplePlaygroundRunning(string gameDirectory) { var executable = Path.GetFullPath(Path.Combine(gameDirectory, "People Playground.exe")); foreach (var process in Process.GetProcessesByName("People Playground")) { try { if (string.Equals(process.MainModule?.FileName, executable, StringComparison.OrdinalIgnoreCase)) return true; } catch { } finally { process.Dispose(); } } return false; }
    private static void Prune(string directory, int retentionCount) { foreach (var file in Directory.GetFiles(directory, "*.ppgbackup.zip").OrderByDescending(File.GetCreationTimeUtc).Skip(Math.Max(1, retentionCount))) { try { File.Delete(file); } catch { } } }
    private static string FormatSize(long bytes) { var units = new[] { "B", "KB", "MB", "GB" }; var size = (double)bytes; var unit = 0; while (size >= 1024 && unit < units.Length - 1) { size /= 1024; unit++; } return $"{size:0.0} {units[unit]}"; }
}

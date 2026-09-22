using System.IO.Compression;
using System.Text;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class BackupService
{
    private readonly EventLogService _events;

    public BackupService(EventLogService events)
    {
        _events = events;
    }

    public async Task<BackupInfo> CreateBackupAsync(string gameDirectory, string backupDirectory, int retentionCount, CancellationToken cancellationToken = default)
    {
        var root = RequireDirectory(gameDirectory);
        Directory.CreateDirectory(backupDirectory);
        var backupRoot = Path.GetFullPath(backupDirectory);
        var fileName = $"PPG-{DateTime.Now:yyyyMMdd-HHmmss}.ppgbackup.zip";
        var finalPath = Path.Combine(backupRoot, fileName);
        var temporaryPath = finalPath + ".tmp";

        await Task.Run(() =>
        {
            using (var archive = ZipFile.Open(temporaryPath, ZipArchiveMode.Create))
            {
                foreach (var file in EnumerateFiles(root))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var relative = Path.GetRelativePath(root, file);
                    var entry = archive.CreateEntry(relative.Replace(Path.DirectorySeparatorChar, '/'), CompressionLevel.Fastest);
                    using var source = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var destination = entry.Open();
                    source.CopyTo(destination);
                }

                var manifest = JsonSerializer.Serialize(new { CreatedAt = DateTimeOffset.Now, GameDirectory = root, Format = "PPGAV-1" });
                var manifestEntry = archive.CreateEntry(".ppgav-manifest.json", CompressionLevel.Fastest);
                using var manifestWriter = new StreamWriter(manifestEntry.Open(), Encoding.UTF8);
                manifestWriter.Write(manifest);
            }

            File.Move(temporaryPath, finalPath, true);
        }, cancellationToken);

        Prune(backupRoot, retentionCount);
        var info = new FileInfo(finalPath);
        _events.Log("Backup created", $"Created full backup {info.Name} ({FormatSize(info.Length)}).");
        return new BackupInfo(finalPath, info.CreationTimeUtc, info.Length);

        IEnumerable<string> EnumerateFiles(string baseDirectory)
        {
            var normalizedBackup = Path.GetFullPath(backupRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var pending = new Stack<string>();
            pending.Push(baseDirectory);
            while (pending.Count > 0)
            {
                var directory = pending.Pop();
                string[] files;
                try { files = Directory.GetFiles(directory); } catch { continue; }
                foreach (var file in files)
                {
                    if (Path.GetFullPath(file).StartsWith(normalizedBackup, StringComparison.OrdinalIgnoreCase)) continue;
                    yield return file;
                }

                string[] children;
                try { children = Directory.GetDirectories(directory); } catch { continue; }
                foreach (var child in children)
                {
                    if (Path.GetFullPath(child).StartsWith(normalizedBackup, StringComparison.OrdinalIgnoreCase)) continue;
                    pending.Push(child);
                }
            }
        }
    }

    public IReadOnlyList<BackupInfo> ListBackups(string backupDirectory)
    {
        if (!Directory.Exists(backupDirectory)) return [];
        return Directory.GetFiles(backupDirectory, "*.ppgbackup.zip")
            .Select(path => new FileInfo(path))
            .OrderByDescending(info => info.CreationTimeUtc)
            .Select(info => new BackupInfo(info.FullName, info.CreationTimeUtc, info.Length))
            .ToArray();
    }

    public async Task RestoreAsync(string backupFile, string gameDirectory, string backupDirectory, CancellationToken cancellationToken = default)
    {
        if (IsPeoplePlaygroundRunning(gameDirectory))
        {
            throw new InvalidOperationException("Close People Playground before restoring a backup.");
        }

        var root = RequireDirectory(gameDirectory);
        var archivePath = Path.GetFullPath(backupFile);
        if (!File.Exists(archivePath)) throw new FileNotFoundException("Backup file not found.", archivePath);

        await Task.Run(() =>
        {
            using var archive = ZipFile.OpenRead(archivePath);
            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (entry.FullName.Equals(".ppgav-manifest.json", StringComparison.OrdinalIgnoreCase)) continue;
                var destination = SafeArchivePath(root, entry.FullName);
                if (string.IsNullOrEmpty(entry.Name))
                {
                    Directory.CreateDirectory(destination);
                    continue;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                entry.ExtractToFile(destination, true);
            }
        }, cancellationToken);

        _events.Log("Backup restored", $"Restored {Path.GetFileName(archivePath)} into {root}.");
    }

    private static string RequireDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A directory is required.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException(full);
        return full;
    }

    private static string SafeArchivePath(string root, string entryName)
    {
        var normalized = entryName.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
        if (Path.IsPathRooted(normalized)) throw new InvalidDataException("Backup contains an absolute path.");
        var destination = Path.GetFullPath(Path.Combine(root, normalized));
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!destination.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && !destination.Equals(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Backup contains a path traversal entry.");
        }

        return destination;
    }

    private static bool IsPeoplePlaygroundRunning(string gameDirectory)
    {
        var executable = Path.Combine(gameDirectory, "People Playground.exe");
        foreach (var process in Process.GetProcessesByName("People Playground"))
        {
            try
            {
                if (string.Equals(process.MainModule?.FileName, executable, StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch { }
            finally { process.Dispose(); }
        }

        return false;
    }

    private static void Prune(string directory, int retentionCount)
    {
        var files = Directory.GetFiles(directory, "*.ppgbackup.zip")
            .OrderByDescending(path => File.GetCreationTimeUtc(path))
            .Skip(Math.Max(1, retentionCount));
        foreach (var file in files)
        {
            try { File.Delete(file); } catch { }
        }
    }

    private static string FormatSize(long bytes)
    {
        var units = new[] { "B", "KB", "MB", "GB" };
        var size = (double)bytes;
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1) { size /= 1024; unit++; }
        return $"{size:0.0} {units[unit]}";
    }
}

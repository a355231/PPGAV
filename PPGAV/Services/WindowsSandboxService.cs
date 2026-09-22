using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class WindowsSandboxService
{
    private readonly EventLogService _events;
    private sealed record StageManifest(string Owner, string SessionId, Dictionary<string, string> Files);
    public WindowsSandboxService(EventLogService events) => _events = events;
    public bool IsAvailable => File.Exists(Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe"));

    public void CleanupAbandonedSessions()
    {
        var sessions = Path.Combine(AppPaths.SandboxFolder, "Sessions");
        if (!Directory.Exists(sessions)) return;
        foreach (var directory in Directory.EnumerateDirectories(sessions))
        {
            var marker = Path.Combine(directory, ".ppgav-staging.json");
            try
            {
                SecurePathService.RequireContained(sessions, directory, true, "sandbox session");
                var manifest = File.Exists(marker) ? JsonSerializer.Deserialize<StageManifest>(File.ReadAllText(marker)) : null;
                if (manifest?.Owner != "PPGAV" || !Guid.TryParse(manifest.SessionId, out _)) continue;
                Directory.Delete(directory, true);
                _events.Log("Abandoned sandbox staging removed", $"Removed verified PPGAV session {manifest.SessionId}.");
            }
            catch (Exception ex) { _events.Log("Sandbox cleanup needed", $"Could not remove abandoned session {directory}: {ex.Message}", ScanCategory.Suspicious); }
        }
    }

    public async Task<LaunchSession> LaunchAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) throw new InvalidOperationException("Windows Sandbox is not available.");
        var executable = SecurePathService.RequireExistingFile(settings.PpgExecutablePath, "People Playground executable");
        var gameRoot = SecurePathService.RequireExistingDirectory(settings.GameDirectory, "People Playground directory");
        SecurePathService.RequireContained(gameRoot, executable, true, "People Playground executable");
        var sessionId = Guid.NewGuid().ToString("N");
        var sessions = Path.Combine(AppPaths.SandboxFolder, "Sessions"); Directory.CreateDirectory(sessions);
        var sessionRoot = Path.Combine(sessions, sessionId); Directory.CreateDirectory(sessionRoot);
        var markerPath = Path.Combine(sessionRoot, ".ppgav-staging.json");
        var stagedGameRoot = Path.Combine(sessionRoot, "Game");
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var totalBytes = EnumerateSafeFiles(gameRoot).Sum(x => new FileInfo(x).Length);
            var drive = new DriveInfo(Path.GetPathRoot(sessionRoot)!);
            if (drive.AvailableFreeSpace < totalBytes * 2 + 256L * 1024 * 1024) throw new IOException("Insufficient free space for a disposable Windows Sandbox staging copy.");
            var manifest = new StageManifest("PPGAV", sessionId, new()); WriteMarker(markerPath, manifest);
            await CopyDirectoryAsync(gameRoot, stagedGameRoot, gameRoot, manifest, markerPath, cancellationToken);
            VerifyStagedHashes(stagedGameRoot, manifest.Files);
            var stagedExecutable = Path.Combine(stagedGameRoot, Path.GetRelativePath(gameRoot, executable));
            SecurePathService.RequireExistingFile(stagedExecutable, "staged executable");
            var configPath = Path.Combine(sessionRoot, "PPGAV.wsb");
            BuildConfiguration(stagedGameRoot, stagedExecutable).Save(configPath);
            var process = Process.Start(new ProcessStartInfo { FileName = Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe"), UseShellExecute = true, WorkingDirectory = sessionRoot, ArgumentList = { configPath } }) ?? throw new InvalidOperationException("Windows Sandbox could not be started.");
            _events.Log("Secure sandbox started", "Windows Sandbox is running from a verified disposable writable copy; the real game directory is not mapped.");
            return new LaunchSession(LaunchMode.SecureSandbox, process, async () =>
            {
                PersistApprovedSaveFiles(settings, stagedGameRoot, gameRoot);
                DeleteOwnedSession(sessionRoot, markerPath);
                await ValueTask.CompletedTask;
            }, configPath, SandboxProvider.WindowsSandbox);
        }
        catch { TryDeleteOwnedSession(sessionRoot, markerPath); throw; }
    }

    public XDocument BuildConfiguration(string gameRoot, string executable)
    {
        var mappedExecutable = "C:\\PPGAVGame\\" + Path.GetRelativePath(gameRoot, executable).Replace('/', '\\');
        return new XDocument(new XElement("Configuration", new XElement("MappedFolders", new XElement("MappedFolder", new XElement("HostFolder", gameRoot), new XElement("SandboxFolder", "C:\\PPGAVGame"), new XElement("ReadOnly", "false"))), new XElement("Networking", "Disable"), new XElement("ClipboardRedirection", "Disable"), new XElement("vGPU", "Disable"), new XElement("MemoryInMB", "4096"), new XElement("LogonCommand", new XElement("Command", mappedExecutable))));
    }

    public static void Stop(LaunchSession session) { try { if (!session.Process.HasExited) session.Process.Kill(true); } catch { } }

    private static async Task CopyDirectoryAsync(string source, string destination, string sourceRoot, StageManifest manifest, string markerPath, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
        {
            cancellationToken.ThrowIfCancellationRequested();
            SecurePathService.RejectReparse(file, "source file");
            var target = Path.Combine(destination, Path.GetFileName(file));
            await using (var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 64, useAsync: true))
            await using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 64, useAsync: true)) await input.CopyToAsync(output, cancellationToken);
            await using var stagedInput = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, useAsync: true);
            manifest.Files[Path.GetRelativePath(sourceRoot, file)] = Convert.ToHexString(await SHA256.HashDataAsync(stagedInput, cancellationToken));
            WriteMarker(markerPath, manifest);
        }
        foreach (var directory in Directory.EnumerateDirectories(source))
        {
            cancellationToken.ThrowIfCancellationRequested(); SecurePathService.RejectReparse(directory, "source directory");
            await CopyDirectoryAsync(directory, Path.Combine(destination, Path.GetFileName(directory)), sourceRoot, manifest, markerPath, cancellationToken);
        }
    }

    private static void VerifyStagedHashes(string root, IReadOnlyDictionary<string, string> hashes)
    {
        foreach (var item in hashes)
        {
            var path = SecurePathService.RequireContained(root, Path.Combine(root, item.Key), true, "staged file");
            using var stream = File.OpenRead(path); var actual = Convert.ToHexString(SHA256.HashData(stream));
            if (!actual.Equals(item.Value, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Staged hash changed before launch: {item.Key}");
        }
    }

    private void PersistApprovedSaveFiles(AppSettings settings, string stagedRoot, string realRoot)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".json", ".sav", ".dat", ".cfg", ".ini" };
        foreach (var configured in settings.SandboxSavePaths ?? [])
        {
            var staged = SecurePathService.RequireContained(stagedRoot, Path.Combine(stagedRoot, configured), true, "approved sandbox save");
            if (!allowed.Contains(Path.GetExtension(staged))) throw new InvalidOperationException($"Configured sandbox save is not an approved save extension: {configured}");
            var destination = SecurePathService.RequireContained(realRoot, Path.Combine(realRoot, configured), false, "sandbox save destination");
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!); SecurePathService.RejectReparse(Path.GetDirectoryName(destination)!, "sandbox save destination"); File.Copy(staged, destination, true);
            _events.Log("Sandbox save persisted", $"Persisted explicitly approved save file {configured}.");
        }
    }

    private static void WriteMarker(string path, StageManifest manifest)
    {
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try { File.WriteAllText(temporary, JsonSerializer.Serialize(manifest)); File.Move(temporary, path, true); } finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    private static bool IsReparse(string path) { try { return File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint); } catch { return true; } }
    private static IEnumerable<string> EnumerateSafeFiles(string root)
    {
        var pending = new Stack<string>([root]);
        while (pending.Count > 0)
        {
            var directory = pending.Pop(); SecurePathService.RejectReparse(directory, "sandbox source directory");
            foreach (var file in Directory.GetFiles(directory)) { SecurePathService.RejectReparse(file, "sandbox source file"); yield return file; }
            foreach (var child in Directory.GetDirectories(directory)) { SecurePathService.RejectReparse(child, "sandbox source directory"); pending.Push(child); }
        }
    }
    private static void DeleteOwnedSession(string sessionRoot, string marker) { SecurePathService.RequireExistingFile(marker, "sandbox ownership marker"); Directory.Delete(sessionRoot, true); }
    private static void TryDeleteOwnedSession(string sessionRoot, string marker) { try { if (File.Exists(marker)) DeleteOwnedSession(sessionRoot, marker); } catch { } }
}

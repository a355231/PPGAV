using System.IO.Compression;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class WindowsSandboxUnavailableException(string message, Exception? innerException = null) : IOException(message, innerException);

public sealed class WindowsSandboxService
{
    private const long MaximumStagingBytes = 16L * 1024 * 1024 * 1024;
    private const long MaximumPersistedSaveBytes = 512L * 1024 * 1024;
    private readonly EventLogService _events;
    private readonly Task<(bool Available, string Reason)> _availability;
    public bool RecoverySucceeded { get; private set; } = true;
    private sealed record StageManifest(int FormatVersion, string Owner, string SessionId, Dictionary<string, string> Files,
        int ProviderProcessId = 0, long ProviderStartTimeUtcTicks = 0);
    private sealed record PreviousSaveManifest(string Owner, string SessionId, string OriginalPath, string BackupPath, string Sha256,
        long Length, DateTime LastWriteUtc, FileAttributes Attributes, string State);
    private sealed class ProgressTracker(long total, IProgress<(long Copied, long Total)>? reporter)
    {
        private long _copied;
        public void Add(int count) => reporter?.Report((Interlocked.Add(ref _copied, count), total));
    }
    public WindowsSandboxService(EventLogService events)
    {
        _events = events;
        _availability = Task.Run(ProbeAvailability);
    }

    public bool IsAvailable => _availability.IsCompletedSuccessfully && _availability.Result.Available;
    public string AvailabilityReason => _availability.IsCompletedSuccessfully ? _availability.Result.Reason : "Windows Sandbox eligibility is still being checked.";
    public async Task<bool> CheckAvailabilityAsync() => (await _availability).Available;

    public void CleanupAbandonedSessions()
    {
        RecoverySucceeded = true;
        var sessions = Path.Combine(AppPaths.SandboxFolder, "Sessions");
        if (!Directory.Exists(sessions)) return;
        try { SecurePathService.RequireExistingDirectory(sessions, "sandbox session store"); }
        catch (Exception ex) { RecoverySucceeded = false; _events.Log("Sandbox cleanup blocked", ex.Message, ScanCategory.Suspicious); return; }
        foreach (var directory in Directory.EnumerateDirectories(sessions))
        {
            try
            {
                SecurePathService.RequireContained(sessions, directory, true, "sandbox session");
                var sessionId = Path.GetFileName(directory);
                var marker = Path.Combine(directory, ".ppgav-staging.json");
                var manifest = ReadAndValidateManifest(directory, marker, sessionId);
                if (HasAnyWindowsSandboxProcess() || IsRecordedProviderProcessActive(manifest))
                    throw new IOException("A Windows Sandbox provider process may still be using this staging tree. Close all Windows Sandbox sessions and retry recovery.");
                DeleteVerifiedSession(directory, marker, manifest);
                _events.Log("Abandoned sandbox staging removed", $"Removed verified PPGAV session {manifest.SessionId}.");
            }
            catch (Exception ex) { RecoverySucceeded = false; _events.Log("Sandbox cleanup needed", $"Could not remove abandoned session {directory}: {ex.Message}", ScanCategory.Suspicious); }
        }
    }

    public async Task<LaunchSession> LaunchAsync(AppSettings settings, ScanReport report,
        CancellationToken cancellationToken = default, IProgress<(long Copied, long Total)>? progress = null)
    {
        if (!await CheckAvailabilityAsync()) throw new WindowsSandboxUnavailableException(AvailabilityReason);
        if (!ScannerService.VerifySnapshot(report, GamePathDiscovery.FindWorkshopDirectories(settings.GameDirectory), out var snapshotError))
            throw new IOException($"Windows Sandbox launch refused because inspected content changed: {snapshotError}");
        if (report.ScannedHashes.Count == 0) throw new InvalidOperationException("Windows Sandbox launch requires the preflight hash snapshot.");
        var executable = SecurePathService.RequireExistingFile(settings.PpgExecutablePath, "People Playground executable");
        var gameRoot = SecurePathService.RequireExistingDirectory(settings.GameDirectory, "People Playground directory");
        SecurePathService.RequireContained(gameRoot, executable, true, "People Playground executable");
        var expected = report.ScannedHashes.ToDictionary(x => Path.GetFullPath(x.Key), x => x.Value, StringComparer.OrdinalIgnoreCase);
        var expectedGameFiles = expected.Where(x => IsWithin(gameRoot, x.Key)).ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
        if (!expectedGameFiles.ContainsKey(executable)) throw new InvalidDataException("The inspected hash snapshot does not include the game executable.");

        var sessionId = Guid.NewGuid().ToString("N");
        var sessions = Path.Combine(AppPaths.SandboxFolder, "Sessions");
        Directory.CreateDirectory(AppPaths.SandboxFolder); SecurePathService.RequireExistingDirectory(AppPaths.SandboxFolder, "sandbox storage");
        Directory.CreateDirectory(sessions); SecurePathService.RequireExistingDirectory(sessions, "sandbox session store");
        var sessionRoot = Path.Combine(sessions, sessionId);
        if (Directory.Exists(sessionRoot) || File.Exists(sessionRoot)) throw new IOException("Refusing to reuse an existing Windows Sandbox session directory.");
        Directory.CreateDirectory(sessionRoot); SecurePathService.RequireContained(sessions, sessionRoot, true, "new sandbox session");
        var markerPath = Path.Combine(sessionRoot, ".ppgav-staging.json");
        var stagedGameRoot = Path.Combine(sessionRoot, "Game");
        var manifest = new StageManifest(1, "PPGAV", sessionId, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
        var markerCreated = false;
        Process? launchedProcess = null;
        try
        {
            AuthenticatedStateStore.Write(markerPath, manifest); markerCreated = true;
            cancellationToken.ThrowIfCancellationRequested();
            var sourceFiles = EnumerateSafeFiles(gameRoot).ToArray();
            var sourceSet = sourceFiles.Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (!sourceSet.SetEquals(expectedGameFiles.Keys)) throw new IOException("The game directory file set changed since the preflight scan.");
            long totalBytes = 0;
            foreach (var file in sourceFiles) totalBytes = checked(totalBytes + new FileInfo(file).Length);
            if (totalBytes > MaximumStagingBytes) throw new IOException("Game staging exceeds the configured size limit.");
            var drive = new DriveInfo(Path.GetPathRoot(sessionRoot)!);
            if (drive.AvailableFreeSpace < checked(totalBytes * 2 + 256L * 1024 * 1024)) throw new IOException("Insufficient free space for a disposable Windows Sandbox staging copy.");

            var progressTracker = new ProgressTracker(totalBytes, progress);
            // The ownership marker was written before copying; rewriting the growing DPAPI manifest with
            // write-through after every file made staging quadratic in the number of game files.
            await CopyDirectoryAsync(gameRoot, stagedGameRoot, gameRoot, manifest, markerPath, expectedGameFiles, progressTracker, cancellationToken);
            AuthenticatedStateStore.Write(markerPath, manifest);
            var postCopyFiles = EnumerateSafeFiles(gameRoot).Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (!postCopyFiles.SetEquals(expectedGameFiles.Keys)) throw new IOException("The game directory changed while it was being staged.");
            VerifyStagedHashes(stagedGameRoot, manifest.Files);
            var stagedExecutable = Path.Combine(stagedGameRoot, Path.GetRelativePath(gameRoot, executable));
            SecurePathService.RequireContained(stagedGameRoot, stagedExecutable, true, "staged executable");
            if (!Hash(stagedGameRoot, stagedExecutable).Equals(expectedGameFiles[executable], StringComparison.OrdinalIgnoreCase)) throw new IOException("Staged executable did not match the scanned executable hash.");

            var configPath = Path.Combine(sessionRoot, "PPGAV.wsb");
            BuildConfiguration(stagedGameRoot, stagedExecutable).Save(configPath);
            SecurePathService.RequireContained(sessionRoot, configPath, true, "Windows Sandbox configuration");
            VerifyStagedHashes(stagedGameRoot, manifest.Files);
            if (!Hash(stagedGameRoot, stagedExecutable).Equals(expectedGameFiles[executable], StringComparison.OrdinalIgnoreCase))
                throw new IOException("The staged executable changed immediately before Windows Sandbox launch.");
            var sandboxExecutable = SecurePathService.RequireExistingFile(Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe"), "Windows Sandbox executable");
            var processInfo = new ProcessStartInfo(sandboxExecutable) { UseShellExecute = false, WorkingDirectory = sessionRoot, CreateNoWindow = true };
            processInfo.ArgumentList.Add(configPath);
            try { launchedProcess = Process.Start(processInfo) ?? throw new WindowsSandboxUnavailableException("Windows Sandbox did not start a provider process."); }
            catch (Win32Exception ex) { throw new WindowsSandboxUnavailableException($"Windows Sandbox could not start; PPGAV may use its installed Sandboxie fallback. {ex.Message}", ex); }
            manifest = manifest with { ProviderProcessId = launchedProcess.Id, ProviderStartTimeUtcTicks = launchedProcess.StartTime.ToUniversalTime().Ticks };
            AuthenticatedStateStore.Write(markerPath, manifest);
            _events.Log("Secure sandbox started", "Windows Sandbox is running from a verified disposable writable copy; the real game directory is not mapped. Host monitoring does not see guest processes.");
            return new LaunchSession(LaunchMode.SecureSandbox, launchedProcess, () => CleanupSessionAsync(settings, stagedGameRoot, sessionRoot, markerPath, sessionId), configPath, SandboxProvider.WindowsSandbox, sessionId);
        }
        catch (Exception launchError)
        {
            Exception? cleanupError = null;
            if (launchedProcess is not null)
            {
                try { StopProviderProcess(launchedProcess, manifest); }
                catch (Exception ex) { cleanupError = ex; _events.Log("Sandbox provider stop failed", $"Staging was retained because the Windows Sandbox process could not be stopped safely: {ex.Message}", ScanCategory.Suspicious); }
            }
            if (cleanupError is null && markerCreated)
            {
                try { DeleteVerifiedSession(sessionRoot, markerPath, ReadAndValidateManifest(sessionRoot, markerPath, sessionId)); }
                catch (Exception ex) { cleanupError = ex; _events.Log("Sandbox staging cleanup needed", $"Partial staging was retained for safe review: {ex.Message}", ScanCategory.Suspicious); }
            }
            else if (cleanupError is null)
            {
                try
                {
                    if (Directory.Exists(sessionRoot))
                    {
                        if (Directory.EnumerateFileSystemEntries(sessionRoot).Any()) throw new IOException("Unowned staging directory is not empty; it was preserved.");
                        Directory.Delete(sessionRoot, false);
                    }
                }
                catch (Exception ex) { cleanupError = ex; _events.Log("Sandbox staging cleanup needed", ex.Message, ScanCategory.Suspicious); }
            }
            if (launchError is WindowsSandboxUnavailableException && cleanupError is not null)
                throw new IOException("Windows Sandbox failed to start and its staging cleanup did not complete; provider fallback was blocked. " + cleanupError.Message, new AggregateException(launchError, cleanupError));
            throw;
        }
    }

    public XDocument BuildConfiguration(string gameRoot, string executable)
    {
        var relative = Path.GetRelativePath(gameRoot, executable);
        if (Path.IsPathRooted(relative) || relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x is ".." or "."))
            throw new UnauthorizedAccessException("The staged executable is outside the mapped game directory.");
        var mappedExecutable = "C:\\PPGAVGame\\" + relative.Replace('/', '\\');
        return new XDocument(new XElement("Configuration",
            new XElement("MappedFolders", new XElement("MappedFolder", new XElement("HostFolder", gameRoot), new XElement("SandboxFolder", "C:\\PPGAVGame"), new XElement("ReadOnly", "false"))),
            new XElement("Networking", "Disable"), new XElement("ClipboardRedirection", "Disable"), new XElement("vGPU", "Disable"),
            new XElement("MemoryInMB", GetSandboxMemoryLimit()), new XElement("LogonCommand", new XElement("Command", mappedExecutable))));
    }

    public static void Stop(LaunchSession session)
    {
        try
        {
            if (session.Process.HasExited) return;
            session.Process.Kill(true);
            if (!session.Process.WaitForExit(15000) && !session.Process.HasExited)
                throw new TimeoutException("Windows Sandbox did not stop within 15 seconds.");
        }
        catch (InvalidOperationException) when (session.Process.HasExited) { }
        catch (Exception ex) when (ex is not TimeoutException)
        {
            throw new IOException("Windows Sandbox session stop could not be verified.", ex);
        }
    }

    private async ValueTask CleanupSessionAsync(AppSettings settings, string stagedRoot, string sessionRoot, string marker, string sessionId)
    {
        Exception? saveError = null;
        try
        {
            var sessionManifest = ReadAndValidateManifest(sessionRoot, marker, sessionId);
            if (IsRecordedProviderProcessActive(sessionManifest)) throw new IOException("Windows Sandbox is still using the staging tree; save persistence and cleanup are deferred.");
            PersistApprovedSaveFiles(settings, stagedRoot, settings.GameDirectory, sessionId);
        }
        catch (Exception ex) { saveError = ex; }
        Exception? cleanupError = null;
        try
        {
            var manifest = ReadAndValidateManifest(sessionRoot, marker, Path.GetFileName(sessionRoot));
            DeleteVerifiedSession(sessionRoot, marker, manifest);
        }
        catch (Exception ex) { cleanupError = ex; }
        if (saveError is not null || cleanupError is not null)
        {
            var failures = new[] { saveError, cleanupError }.Where(x => x is not null).Select(x => x!.Message);
            throw new IOException("Windows Sandbox session cleanup was incomplete: " + string.Join(" | ", failures), saveError ?? cleanupError!);
        }
        await ValueTask.CompletedTask;
    }

    private static async Task CopyDirectoryAsync(string source, string destination, string sourceRoot, StageManifest manifest,
        string markerPath, IReadOnlyDictionary<string, string> expectedHashes, ProgressTracker progress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Directory.CreateDirectory(destination); SecurePathService.RejectReparse(destination, "staging destination");
        foreach (var file in Directory.EnumerateFiles(source))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var fullSource = Path.GetFullPath(file);
            var relative = Path.GetRelativePath(sourceRoot, fullSource);
            if (Path.IsPathRooted(relative) || relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x is ".." or ".")) throw new IOException("Unsafe source relative path during staging.");
            if (!expectedHashes.TryGetValue(fullSource, out var expected)) throw new IOException($"A file appeared after inspection and cannot be staged: {fullSource}");
            var target = Path.Combine(destination, Path.GetFileName(file));
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var input = SecurePathService.OpenContainedRead(sourceRoot, fullSource, "sandbox source file"))
            await using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 128, useAsync: true))
            {
                var buffer = new byte[128 * 1024]; int read;
                while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    hash.AppendData(buffer, 0, read); progress.Add(read);
                }
                await output.FlushAsync(cancellationToken); output.Flush(true);
            }
            var actual = Convert.ToHexString(hash.GetHashAndReset());
            if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase)) throw new IOException($"Source changed after inspection; staging was aborted: {fullSource}");
            manifest.Files[relative] = actual;
        }
        foreach (var directory in Directory.EnumerateDirectories(source))
        {
            cancellationToken.ThrowIfCancellationRequested();
            SecurePathService.RejectReparse(directory, "sandbox source directory");
            await CopyDirectoryAsync(directory, Path.Combine(destination, Path.GetFileName(directory)), sourceRoot, manifest, markerPath, expectedHashes, progress, cancellationToken);
        }
    }

    private static void VerifyStagedHashes(string root, IReadOnlyDictionary<string, string> hashes)
    {
        var files = EnumerateSafeFiles(root).Select(path => Path.GetRelativePath(root, path)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!files.SetEquals(hashes.Keys)) throw new InvalidDataException("Staged directory has missing or unexpected files.");
        foreach (var item in hashes)
        {
            var path = SecurePathService.RequireContained(root, Path.Combine(root, item.Key), true, "staged file");
            if (!Hash(root, path).Equals(item.Value, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Staged hash changed before launch: {item.Key}");
        }
    }

    private void PersistApprovedSaveFiles(AppSettings settings, string stagedRoot, string realRoot, string sessionId)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".json", ".sav", ".dat", ".cfg", ".ini" };
        var configuredPaths = settings.SandboxSavePaths ?? [];
        if (configuredPaths.Count > 64) throw new InvalidOperationException("At most 64 explicit sandbox save paths may be configured.");
        long totalPersisted = 0;
        foreach (var configured in configuredPaths)
        {
            var relative = ValidateRelativePath(configured);
            if (!allowed.Contains(Path.GetExtension(relative))) throw new InvalidOperationException($"Configured sandbox save is not an approved save extension: {configured}");
            var staged = SecurePathService.RequireContained(stagedRoot, Path.Combine(stagedRoot, relative), true, "approved sandbox save");
            using var input = SecurePathService.OpenContainedRead(stagedRoot, staged, "approved sandbox save");
            if (input.Length > MaximumPersistedSaveBytes) throw new InvalidDataException($"Approved sandbox save exceeds the size limit: {configured}");
            totalPersisted = checked(totalPersisted + input.Length);
            if (totalPersisted > 1024L * 1024 * 1024) throw new InvalidDataException("Explicit sandbox saves exceed the 1 GiB per-session persistence limit.");
            var destination = EnsureDestinationPath(realRoot, relative);
            var destinationExists = File.Exists(destination);
            if (Directory.Exists(destination)) throw new IOException($"Approved save destination is a directory: {destination}");
            var originalHash = destinationExists ? Hash(realRoot, destination) : null;
            if (destinationExists) PreservePreviousSave(sessionId, realRoot, destination, originalHash!);
            var temporary = Path.Combine(Path.GetDirectoryName(destination)!, ".ppgav-save-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
                { input.CopyTo(output); output.Flush(true); }
                SecurePathService.RejectReparse(temporary, "sandbox save temporary file");
                if (destinationExists && !Hash(realRoot, destination).Equals(originalHash, StringComparison.OrdinalIgnoreCase))
                    throw new IOException($"Host save changed during the sandbox session; it was not overwritten: {destination}");
                if (!destinationExists && (File.Exists(destination) || Directory.Exists(destination)))
                    throw new IOException($"A new host save appeared during the sandbox session; it was not overwritten: {destination}");
                SecurePathService.MoveFileContained(realRoot, temporary, destination, destinationExists);
                _events.Log("Sandbox save persisted", $"Persisted explicitly approved save file {configured}.");
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }

    private void PreservePreviousSave(string sessionId, string gameRoot, string source, string expectedHash)
    {
        var backupRoot = Path.Combine(AppPaths.RestoreSafetyFolder, "SandboxSaves", sessionId);
        var files = Path.Combine(backupRoot, "files");
        var manifests = Path.Combine(backupRoot, "manifests");
        foreach (var directory in new[] { backupRoot, files, manifests })
        {
            if (!Directory.Exists(directory)) Directory.CreateDirectory(directory);
            if (directory.Equals(AppPaths.RestoreSafetyFolder, StringComparison.OrdinalIgnoreCase))
                SecurePathService.RequireExistingDirectory(directory, "save recovery root");
            else SecurePathService.RequireContained(AppPaths.RestoreSafetyFolder, directory, true, "save recovery directory");
        }
        var id = Guid.NewGuid().ToString("N");
        var backupPath = Path.Combine(files, id + ".bak");
        var manifestPath = Path.Combine(manifests, id + ".json");
        var info = new FileInfo(source);
        var record = new PreviousSaveManifest("PPGAV", sessionId, source, backupPath, expectedHash, info.Length,
            info.LastWriteTimeUtc, info.Attributes, "Pending");
        AuthenticatedStateStore.Write(manifestPath, record);
        var temporary = backupPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            string copiedHash;
            using (var input = SecurePathService.OpenContainedRead(gameRoot, source, "previous host save"))
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
            {
                copiedHash = CopyAndHash(input, output, MaximumPersistedSaveBytes);
                output.Flush(true);
            }
            if (!copiedHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) throw new IOException("Previous host save changed while its recovery copy was being made.");
            SecurePathService.MoveFileContained(files, temporary, backupPath);
            AuthenticatedStateStore.Write(manifestPath, record with { State = "Complete" });
            _events.Log("Previous sandbox save preserved", $"A pre-overwrite copy of {source} was saved at {backupPath}; its authenticated manifest is {manifestPath}.");
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static string CopyAndHash(Stream input, Stream output, long maximumBytes)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        long total = 0;
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            total = checked(total + read);
            if (total > maximumBytes) throw new InvalidDataException("Previous save exceeds its recovery-copy size limit.");
            output.Write(buffer, 0, read);
            hash.AppendData(buffer, 0, read);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string EnsureDestinationPath(string root, string relative)
    {
        var safeRoot = SecurePathService.RequireExistingDirectory(root, "game save root");
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = safeRoot;
        foreach (var part in parts.Take(parts.Length - 1))
        {
            current = Path.Combine(current, part);
            if (File.Exists(current)) throw new IOException($"Save destination parent is a file: {current}");
            if (!Directory.Exists(current)) Directory.CreateDirectory(current);
            SecurePathService.RequireContained(safeRoot, current, true, "save destination directory");
        }
        var target = Path.Combine(current, parts[^1]);
        if (File.Exists(target) || Directory.Exists(target)) SecurePathService.RequireContained(safeRoot, target, true, "save destination");
        else SecurePathService.RequireContained(safeRoot, target, false, "save destination");
        return target;
    }

    private static string ValidateRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || Path.IsPathRooted(path)) throw new InvalidDataException("Save paths must be non-empty relative paths.");
        var normalized = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        var parts = normalized.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(p => p is "." or ".." || p.Contains(':') || p.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)) throw new InvalidDataException("Save path contains an unsafe component.");
        return Path.Combine(parts);
    }

    private static StageManifest ReadAndValidateManifest(string sessionRoot, string marker, string expectedSessionId)
    {
        SecurePathService.RequireExistingDirectory(sessionRoot, "sandbox session directory");
        SecurePathService.RequireContained(sessionRoot, marker, true, "sandbox ownership marker");
        var manifest = AuthenticatedStateStore.Read<StageManifest>(marker);
        if (manifest.FormatVersion != 1 || manifest.Owner != "PPGAV" || !Guid.TryParseExact(manifest.SessionId, "N", out _) ||
            !manifest.SessionId.Equals(expectedSessionId, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(sessionRoot).Equals(manifest.SessionId, StringComparison.OrdinalIgnoreCase) ||
            manifest.ProviderProcessId < 0 || manifest.ProviderStartTimeUtcTicks < 0 ||
            (manifest.ProviderProcessId == 0) != (manifest.ProviderStartTimeUtcTicks == 0) ||
            manifest.Files is null || manifest.Files.Any(x => string.IsNullOrWhiteSpace(x.Key) || string.IsNullOrWhiteSpace(x.Value) || x.Value.Length != 64 || !x.Value.All(Uri.IsHexDigit)))
            throw new InvalidDataException("Sandbox ownership manifest failed validation.");
        foreach (var item in manifest.Files.Keys) _ = ValidateRelativePath(item);
        return manifest;
    }

    private static void DeleteVerifiedSession(string sessionRoot, string marker, StageManifest manifest)
    {
        var authenticated = ReadAndValidateManifest(sessionRoot, marker, manifest.SessionId);
        if (!manifest.SessionId.Equals(authenticated.SessionId, StringComparison.OrdinalIgnoreCase) || manifest.Owner != authenticated.Owner)
            throw new InvalidDataException("Sandbox session ownership changed during cleanup.");
        if (IsRecordedProviderProcessActive(authenticated)) throw new IOException("A verified Windows Sandbox process is still using this session tree.");
        ValidateTreeNoReparse(sessionRoot);
        SecurePathService.RequireExistingDirectory(Path.GetDirectoryName(sessionRoot)!, "sandbox session parent");
        Directory.Delete(sessionRoot, true);
        if (Directory.Exists(sessionRoot)) throw new IOException("Sandbox session directory remained after cleanup.");
    }

    private static void ValidateTreeNoReparse(string root)
    {
        var pending = new Stack<string>([root]);
        while (pending.TryPop(out var current))
        {
            SecurePathService.RejectReparse(current, "sandbox owned session tree");
            foreach (var child in Directory.EnumerateFileSystemEntries(current))
            {
                if (File.GetAttributes(child).HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"Refusing recursive cleanup of a session containing a reparse point: {child}");
                if (Directory.Exists(child)) pending.Push(child);
            }
        }
    }

    private static bool HasAnyWindowsSandboxProcess()
    {
        try
        {
            foreach (var process in Process.GetProcessesByName("WindowsSandbox"))
            {
                using (process)
                    if (!process.HasExited) return true;
            }
            return false;
        }
        catch { return true; }
    }

    private static bool IsRecordedProviderProcessActive(StageManifest manifest)
    {
        if (manifest.ProviderProcessId <= 0 || manifest.ProviderStartTimeUtcTicks <= 0) return false;
        try
        {
            using var process = Process.GetProcessById(manifest.ProviderProcessId);
            if (process.HasExited || process.StartTime.ToUniversalTime().Ticks != manifest.ProviderStartTimeUtcTicks) return false;
            var expectedPath = Path.GetFullPath(Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe"));
            return string.Equals(Path.GetFullPath(process.MainModule?.FileName ?? string.Empty), expectedPath, StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException) { return false; }
        catch { return true; }
    }

    private static void StopProviderProcess(Process process, StageManifest manifest)
    {
        if (process.HasExited) return;
        var startTimeTicks = process.StartTime.ToUniversalTime().Ticks;
        if (!string.Equals(Path.GetFullPath(process.MainModule?.FileName ?? string.Empty),
                Path.GetFullPath(Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe")), StringComparison.OrdinalIgnoreCase) ||
            manifest.ProviderProcessId > 0 && (process.Id != manifest.ProviderProcessId || startTimeTicks != manifest.ProviderStartTimeUtcTicks))
            throw new InvalidOperationException("The Windows Sandbox process identity changed; refusing to terminate it.");
        process.Kill(true);
        if (!process.WaitForExit(10000) && !process.HasExited) throw new TimeoutException("Windows Sandbox did not stop before staging cleanup.");
    }

    private static IEnumerable<string> EnumerateSafeFiles(string root)
    {
        var safeRoot = SecurePathService.RequireExistingDirectory(root, "sandbox source root");
        var pending = new Stack<string>([safeRoot]);
        while (pending.TryPop(out var directory))
        {
            SecurePathService.RejectReparse(directory, "sandbox source directory");
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"Sandbox source contains a reparse point: {entry}");
                if (attributes.HasFlag(FileAttributes.Directory)) pending.Push(entry);
                else yield return entry;
            }
        }
    }

    private static (bool Available, string Reason) ProbeAvailability()
    {
        if (!OperatingSystem.IsWindows()) return (false, "Windows Sandbox is supported only on Windows.");
        if (Environment.OSVersion.Version.Build < 18305) return (false, "This Windows build is below the Windows Sandbox minimum build.");
        var executable = Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe");
        if (!File.Exists(executable)) return (false, "WindowsSandbox.exe is not installed.");
        if (Environment.ProcessorCount < 2 || !IsProcessorFeaturePresent(21)) return (false, "Windows Sandbox CPU virtualization prerequisites are unavailable or disabled in firmware.");
        if (!GetPhysicallyInstalledSystemMemory(out var memoryKb) || memoryKb < 4UL * 1024 * 1024)
            return (false, "Windows Sandbox requires at least 4 GiB of installed physical memory.");
        return (true, "Windows Sandbox executable is installed and the available hardware prerequisites are present.");
    }

    private static int GetSandboxMemoryLimit()
    {
        if (!OperatingSystem.IsWindows() || !GetPhysicallyInstalledSystemMemory(out var memoryKb)) return 2048;
        return (int)Math.Clamp((memoryKb / 1024) / 2, 2048UL, 4096UL);
    }

    private static string Hash(string root, string path) { using var stream = SecurePathService.OpenContainedRead(root, path, "sandbox file"); return Convert.ToHexString(SHA256.HashData(stream)); }
    private static bool IsWithin(string root, string candidate) => Path.GetFullPath(candidate).StartsWith(Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    [DllImport("kernel32.dll", SetLastError = false)] private static extern bool IsProcessorFeaturePresent(uint processorFeature);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetPhysicallyInstalledSystemMemory(out ulong totalMemoryInKilobytes);
}

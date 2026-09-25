using System.Diagnostics;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class SandboxieService
{
    private static readonly Version MinimumSupportedClassicVersion = new(5, 73, 4);
    private const string ExpectedCompany = "Sandboxie-Plus.com";
    private readonly EventLogService _events;
    public bool RecoverySucceeded { get; private set; } = true;
    private static string SessionRoot => Path.Combine(AppPaths.SandboxFolder, "SandboxieSessions");
    private sealed record Installation(string Start, string Ini, Version Version);
    private sealed record SessionManifest(int FormatVersion, string Owner, string SessionId, string BoxName, string Executable, string State);

    public SandboxieService(EventLogService events) => _events = events;
    public string? StartExecutable => FindSupportedInstallation(out _)?.Start;
    public string? IniExecutable => FindSupportedInstallation(out _)?.Ini;
    public bool IsAvailable => FindSupportedInstallation(out _) is not null;
    public string AvailabilityReason => FindSupportedInstallation(out var reason) is not null ? "Sandboxie is signed and meets the minimum supported version." : reason;

    public void CleanupAbandonedSessions()
    {
        RecoverySucceeded = true;
        if (!Directory.Exists(SessionRoot)) return;
        try { SecurePathService.RequireExistingDirectory(SessionRoot, "Sandboxie session store"); }
        catch (Exception ex) { RecoverySucceeded = false; _events.Log("Sandboxie recovery blocked", ex.Message, ScanCategory.Suspicious); return; }
        foreach (var path in Directory.EnumerateFiles(SessionRoot, "*.json", SearchOption.TopDirectoryOnly))
        {
            try
            {
                SecurePathService.RequireContained(SessionRoot, path, true, "Sandboxie recovery record");
                var manifest = AuthenticatedStateStore.Read<SessionManifest>(path);
                ValidateManifest(path, manifest);
                CleanupOwnedSession(path, manifest);
                _events.Log("Sandboxie recovery", $"Stopped and cleaned PPGAV-owned box {manifest.BoxName} after an interrupted session.");
            }
            catch (Exception ex) { RecoverySucceeded = false; _events.Log("Sandboxie recovery needed", $"Could not safely recover {Path.GetFileName(path)}: {ex.Message}", ScanCategory.Suspicious); }
        }
    }

    public LaunchSession Launch(AppSettings settings, ScanReport report)
    {
        var install = FindSupportedInstallation(out var reason) ?? throw new InvalidOperationException(reason);
        var executable = SecurePathService.RequireExistingFile(settings.PpgExecutablePath, "People Playground executable");
        var gameRoot = SecurePathService.RequireExistingDirectory(settings.GameDirectory, "People Playground directory");
        SecurePathService.RequireContained(gameRoot, executable, true, "People Playground executable");
        if (!ScannerService.VerifySnapshot(report, GamePathDiscovery.FindWorkshopDirectories(gameRoot), out var snapshotError))
            throw new IOException($"Sandboxie launch refused because inspected content changed: {snapshotError}");

        Directory.CreateDirectory(AppPaths.SandboxFolder); SecurePathService.RequireExistingDirectory(AppPaths.SandboxFolder, "PPGAV application storage");
        Directory.CreateDirectory(SessionRoot); SecurePathService.RequireExistingDirectory(SessionRoot, "Sandboxie session store");
        var sessionId = Guid.NewGuid().ToString("N");
        var box = "PPGAV-" + sessionId;
        var manifestPath = Path.Combine(SessionRoot, sessionId + ".json");
        if (IsBoxConfigured(install, box)) throw new InvalidOperationException($"Refusing to modify the pre-existing Sandboxie box {box}.");
        var manifest = new SessionManifest(1, "PPGAV", sessionId, box, executable, "Preparing");
        AuthenticatedStateStore.Write(manifestPath, manifest);
        Process? startProcess = null;
        try
        {
            ConfigureBox(install, box);
            VerifyOwnedBox(install, box);
            manifest = manifest with { State = "Ready" };
            AuthenticatedStateStore.Write(manifestPath, manifest);

            if (!ScannerService.VerifySnapshot(report, GamePathDiscovery.FindWorkshopDirectories(gameRoot), out snapshotError))
                throw new IOException($"Sandboxie launch refused because inspected content changed during box preparation: {snapshotError}");

            var info = new ProcessStartInfo(install.Start) { UseShellExecute = false, WorkingDirectory = gameRoot, CreateNoWindow = true };
            foreach (var arg in new[] { $"/box:{box}", "/silent", "/wait", executable, "-noWorkshop" }) info.ArgumentList.Add(arg);
            info.Environment.Remove("SteamAppId"); info.Environment.Remove("SteamGameId");
            startProcess = Process.Start(info) ?? throw new InvalidOperationException("Sandboxie could not start People Playground.");
            WaitForGameInOwnedBox(install, box, executable, startProcess);
            _events.Log("Sandboxie containment started", $"People Playground is running in verified unique PPGAV-owned box {box}; only supported, signed Sandboxie builds are accepted.");
            return new LaunchSession(LaunchMode.SecureSandbox, startProcess, () => CleanupAsync(manifestPath, manifest), null, SandboxProvider.SandboxieClassic, box);
        }
        catch (Exception launchError)
        {
            Exception? cleanupError = null;
            try
            {
                if (IsOwnedBox(install, box)) CleanupOwnedSession(manifestPath, manifest);
                else
                {
                    cleanupError = new UnauthorizedAccessException($"Box {box} ownership could not be verified; it was not modified or deleted.");
                    _events.Log("Sandboxie cleanup deferred", $"{cleanupError.Message} {launchError.Message}", ScanCategory.Suspicious);
                }
            }
            catch (Exception ex) { cleanupError = ex; _events.Log("Sandboxie cleanup failed", $"Owned box {box} requires recovery: {ex.Message}", ScanCategory.Suspicious); }
            startProcess?.Dispose();
            if (cleanupError is not null)
                throw new IOException($"Sandboxie launch failed and owned-session cleanup was incomplete. Recovery record retained at {manifestPath}.", new AggregateException(launchError, cleanupError));
            throw;
        }
    }

    public void Stop(LaunchSession session)
    {
        var box = session.ProviderResourceName;
        if (string.IsNullOrWhiteSpace(box) || !box.StartsWith("PPGAV-", StringComparison.Ordinal)) return;
        var install = FindSupportedInstallation(out var reason);
        if (install is null || !IsOwnedBox(install, box))
        {
            _events.Log("Sandboxie stop refused", $"Could not verify the active PPGAV box: {reason}", ScanCategory.Suspicious);
            return;
        }
        if (!StopBox(install, box)) throw new IOException($"Could not verify termination of PPGAV-owned box {box}.");
    }

    private async ValueTask CleanupAsync(string manifestPath, SessionManifest manifest)
    {
        ValidateManifest(manifestPath, manifest);
        manifest = manifest with { State = "CleanupPending" };
        AuthenticatedStateStore.Write(manifestPath, manifest);
        var install = FindSupportedInstallation(out var reason) ?? throw new InvalidOperationException(reason);
        VerifyOwnedBox(install, manifest.BoxName);
        if (!StopBox(install, manifest.BoxName)) throw new IOException($"Sandboxie still reports processes in {manifest.BoxName}; cleanup was not attempted.");
        DeleteOwnedBox(install, manifest.BoxName);
        File.Delete(manifestPath);
        _events.Log("Sandboxie cleanup complete", $"Stopped PPGAV-owned box {manifest.BoxName}, verified it empty, deleted its contents/configuration, and removed its session record.");
        await ValueTask.CompletedTask;
    }

    private void CleanupOwnedSession(string manifestPath, SessionManifest manifest)
    {
        ValidateManifest(manifestPath, manifest);
        var install = FindSupportedInstallation(out var reason) ?? throw new InvalidOperationException(reason);
        RequireOwnership(install, manifest.BoxName);
        if (!StopBox(install, manifest.BoxName)) throw new IOException($"Sandboxie did not verify that {manifest.BoxName} is stopped.");
        DeleteOwnedBox(install, manifest.BoxName);
        SecurePathService.RequireContained(SessionRoot, manifestPath, true, "Sandboxie recovery record");
        File.Delete(manifestPath);
    }

    private void DeleteOwnedBox(Installation install, string box)
    {
        RequireOwnership(install, box);
        if (!RunStart(install, [ $"/box:{box}", "delete_sandbox" ], TimeSpan.FromSeconds(60))) throw new IOException($"Sandboxie did not confirm deletion of the owned box contents: {box}");
        if (!TryListPids(install, box, out var pids, out var error) || pids.Count != 0) throw new IOException($"Sandboxie box did not verify empty after content deletion: {error}");
        VerifyOwnedBox(install, box);
        RequireIni(install, "set", box, "*", string.Empty);
        if (IsBoxConfigured(install, box)) throw new IOException($"Sandboxie box configuration remained after deletion: {box}");
    }

    private bool StopBox(Installation install, string box)
    {
        if (!IsOwnedBox(install, box)) return false;
        if (!RunStart(install, [ $"/box:{box}", "/terminate" ], TimeSpan.FromSeconds(15))) return false;
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
        do
        {
            if (TryListPids(install, box, out var pids, out _) && pids.Count == 0) return true;
            Thread.Sleep(250);
        } while (DateTimeOffset.UtcNow < deadline);
        return false;
    }

    private static void WaitForGameInOwnedBox(Installation install, string box, string executable, Process startProcess)
    {
        var expectedPath = Path.GetFullPath(executable);
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(15);
        string lastError = string.Empty;
        do
        {
            if (startProcess.HasExited)
                throw new InvalidOperationException($"Sandboxie Start.exe exited with code {startProcess.ExitCode} before People Playground containment could be confirmed.");
            if (TryListPids(install, box, out var pids, out lastError))
            {
                foreach (var pid in pids)
                {
                    try
                    {
                        using var game = Process.GetProcessById(pid);
                        if (game.HasExited) continue;
                        var actualPath = game.MainModule?.FileName;
                        if (actualPath is not null && Path.GetFullPath(actualPath).Equals(expectedPath, StringComparison.OrdinalIgnoreCase))
                        {
                            if (startProcess.HasExited)
                                throw new InvalidOperationException("Sandboxie supervision exited while the game was starting; refusing an unmonitored session.");
                            return;
                        }
                    }
                    catch (ArgumentException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                }
            }
            Thread.Sleep(250);
        } while (DateTimeOffset.UtcNow < deadline);

        throw new TimeoutException($"People Playground did not appear in the verified Sandboxie box within 15 seconds. {lastError}");
    }

    private static bool TryListPids(Installation install, string box, out IReadOnlyList<int> pids, out string error)
    {
        pids = []; error = string.Empty;
        try
        {
            using var process = Process.Start(new ProcessStartInfo(install.Start)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
                ArgumentList = { $"/box:{box}", "/listpids" }
            });
            if (process is null) throw new IOException("Sandboxie Start.exe could not list box processes.");
            var output = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(5000)) { try { process.Kill(true); process.WaitForExit(1000); } catch { } throw new TimeoutException("Sandboxie process listing timed out."); }
            if (process.ExitCode != 0) throw new IOException($"Sandboxie process listing exited with {process.ExitCode}: {stderr.GetAwaiter().GetResult()}");
            var lines = output.GetAwaiter().GetResult().SplitLines().Select(x => x.Trim()).Where(x => x.Length > 0).ToArray();
            if (lines.Length == 0 || !int.TryParse(lines[0], out var count) || count < 0 || lines.Length - 1 < count) throw new InvalidDataException("Sandboxie returned an invalid process list.");
            pids = lines.Skip(1).Take(count).Select(x => int.TryParse(x, out var pid) ? pid : throw new InvalidDataException("Sandboxie returned a malformed process ID.")).ToArray();
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    private void ConfigureBox(Installation install, string box)
    {
        Set(install, box, "Enabled", "y"); Set(install, box, "ConfigLevel", "10"); Set(install, box, "AutoRecover", "n");
        Set(install, box, "DropAdminRights", "y"); Set(install, box, "NetworkAccess", "n"); Set(install, box, "PPGAVOwner", box);
        var paths = new[] { @"\Device\RawIp", @"\Device\Ip*", @"\Device\Tcp*", @"\Device\Afd*" };
        Set(install, box, "ClosedFilePath", paths[0]); foreach (var path in paths.Skip(1)) Append(install, box, "ClosedFilePath", path);
        VerifyOwnedBox(install, box);
        foreach (var path in paths)
            if (!GetValues(install, box, "ClosedFilePath").Contains(path, StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException($"Sandboxie network endpoint restriction was not persisted: {path}");
    }

    private void VerifyOwnedBox(Installation install, string box)
    {
        if (!GetValues(install, box, "PPGAVOwner").Contains(box, StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException($"Sandboxie ownership marker did not match {box}.");
        RequireValue(install, box, "Enabled", "y"); RequireValue(install, box, "ConfigLevel", "10"); RequireValue(install, box, "AutoRecover", "n");
        RequireValue(install, box, "DropAdminRights", "y"); RequireValue(install, box, "NetworkAccess", "n");
        var network = GetValues(install, box, "ClosedFilePath");
        foreach (var path in new[] { @"\Device\RawIp", @"\Device\Ip*", @"\Device\Tcp*", @"\Device\Afd*" })
            if (!network.Contains(path, StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException($"Sandboxie network restriction is missing: {path}");
    }

    private bool IsOwnedBox(Installation install, string box)
    {
        try { return GetValues(install, box, "PPGAVOwner").Contains(box, StringComparer.OrdinalIgnoreCase); }
        catch { return false; }
    }

    private void RequireOwnership(Installation install, string box)
    {
        if (!IsOwnedBox(install, box)) throw new UnauthorizedAccessException($"Sandboxie box ownership could not be verified; refusing to modify or delete {box}.");
    }

    private bool IsBoxConfigured(Installation install, string box)
    {
        var sections = RunIni(install, "query", "*", null, null);
        if (sections.ExitCode != 0) throw new IOException($"Sandboxie configuration could not be queried (exit code {sections.ExitCode}); box creation is refused.");
        return sections.Output.SplitLines().Select(x => x.Trim().Trim('[', ']')).Any(x => x.Equals(box, StringComparison.OrdinalIgnoreCase));
    }

    private void RequireValue(Installation install, string box, string setting, string expected)
    {
        if (!GetValues(install, box, setting).Contains(expected, StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException($"Sandboxie setting {setting} did not match required value {expected}.");
    }

    private string[] GetValues(Installation install, string box, string setting)
    {
        var result = RunIni(install, "query", box, setting, null);
        if (result.ExitCode != 0) throw new IOException($"Sandboxie could not query {setting} for {box} (exit code {result.ExitCode}).");
        return result.Output.SplitLines().Select(line =>
        {
            var separator = line.IndexOf('=');
            return separator >= 0 ? line[(separator + 1)..].Trim() : line.Trim();
        }).Where(x => x.Length > 0).ToArray();
    }

    private void Set(Installation install, string box, string setting, string value) => RequireIni(install, "set", box, setting, value);
    private void Append(Installation install, string box, string setting, string value) => RequireIni(install, "append", box, setting, value);
    private void RequireIni(Installation install, string verb, string box, string setting, string? value)
    {
        var result = RunIni(install, verb, box, setting, value);
        if (result.ExitCode != 0) throw new InvalidOperationException($"Sandboxie configuration operation {verb} {setting} failed (exit code {result.ExitCode}).");
    }

    private static (int ExitCode, string Output) RunIni(Installation install, string verb, string section, string? setting, string? value)
    {
        var info = new ProcessStartInfo(install.Ini) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(install.Ini)! };
        foreach (var arg in new[] { verb, section }.Concat(setting is null ? [] : new[] { setting }).Concat(value is null ? [] : new[] { value })) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("SbieIni could not start.");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(10000)) { try { process.Kill(true); process.WaitForExit(1000); } catch { } throw new TimeoutException("SbieIni timed out."); }
        Task.WaitAll(output, error);
        return (process.ExitCode, output.Result + error.Result);
    }

    private static bool RunStart(Installation install, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        try
        {
            var info = new ProcessStartInfo(install.Start) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(install.Start)! };
            foreach (var argument in arguments) info.ArgumentList.Add(argument);
            using var process = Process.Start(info);
            if (process is null || !process.WaitForExit((int)timeout.TotalMilliseconds)) { try { process?.Kill(true); process?.WaitForExit(1000); } catch { } return false; }
            return process.ExitCode == 0;
        }
        catch { return false; }
    }

    private static void ValidateManifest(string path, SessionManifest manifest)
    {
        if (manifest.FormatVersion != 1 || manifest.Owner != "PPGAV" || !Guid.TryParseExact(manifest.SessionId, "N", out _) ||
            !Path.GetFileNameWithoutExtension(path).Equals(manifest.SessionId, StringComparison.OrdinalIgnoreCase) ||
            !manifest.BoxName.Equals("PPGAV-" + manifest.SessionId, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(manifest.Executable) || manifest.State is not ("Preparing" or "Ready" or "CleanupPending"))
            throw new InvalidDataException("Sandboxie session manifest is invalid.");
        SecurePathService.RequireAbsolute(manifest.Executable, "Sandboxie game executable");
    }

    private static Installation? FindSupportedInstallation(out string reason)
    {
        reason = "Sandboxie Classic 5.73.4 or newer with trusted Authenticode signatures is required.";
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sandboxie", "Start.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sandboxie-Plus", "Start.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Sandboxie", "Start.exe")
        };
        foreach (var start in candidates)
        {
            try
            {
                if (!File.Exists(start)) continue;
                var ini = Path.Combine(Path.GetDirectoryName(start)!, "SbieIni.exe");
                if (!File.Exists(ini)) continue;
                var versionText = FileVersionInfo.GetVersionInfo(start).FileVersion;
                if (!Version.TryParse(versionText, out var version) || !IsVersionSupported(version)) { reason = $"Sandboxie {versionText} is below the minimum security release 1.18.4 / 5.73.4."; continue; }
                var iniVersion = FileVersionInfo.GetVersionInfo(ini).FileVersion;
                if (!Version.TryParse(iniVersion, out var parsedIniVersion) || parsedIniVersion != version) { reason = "Sandboxie Start.exe and SbieIni.exe versions do not match."; continue; }
                var startSignature = AuthenticodeService.Inspect(start);
                var iniSignature = AuthenticodeService.Inspect(ini);
                if (!startSignature.Signed || !startSignature.Trusted || !iniSignature.Signed || !iniSignature.Trusted) { reason = "Sandboxie binaries do not have valid trusted Authenticode signatures."; continue; }
                var startCompany = FileVersionInfo.GetVersionInfo(start).CompanyName;
                var iniCompany = FileVersionInfo.GetVersionInfo(ini).CompanyName;
                if (!string.Equals(startCompany, ExpectedCompany, StringComparison.OrdinalIgnoreCase) || !string.Equals(iniCompany, ExpectedCompany, StringComparison.OrdinalIgnoreCase))
                { reason = "Sandboxie binary publisher metadata does not match the expected signed publisher."; continue; }
                return new Installation(SecurePathService.RequireExistingFile(start, "Sandboxie Start.exe"), SecurePathService.RequireExistingFile(ini, "Sandboxie SbieIni.exe"), version);
            }
            catch (Exception ex) { reason = $"Sandboxie installation could not be verified: {ex.Message}"; }
        }
        return null;
    }

    private static bool IsVersionSupported(Version version) => version.Major == 1 ? version >= new Version(1, 18, 4) : version.Major == 5 && version >= MinimumSupportedClassicVersion;
}

using PPGAV.Models;

namespace PPGAV.Services;

public sealed class SandboxieService
{
    private readonly EventLogService _events;
    public SandboxieService(EventLogService events) => _events = events;
    public string? StartExecutable => new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sandboxie", "Start.exe"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sandboxie-Plus", "Start.exe"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Sandboxie", "Start.exe") }.FirstOrDefault(File.Exists);
    public string? IniExecutable => StartExecutable is { } start ? Path.Combine(Path.GetDirectoryName(start)!, "SbieIni.exe") : null;
    public bool IsAvailable => StartExecutable is not null && File.Exists(IniExecutable);

    public LaunchSession Launch(AppSettings settings)
    {
        if (!IsAvailable) throw new InvalidOperationException("No supported sandbox is installed.");
        var executable = SecurePathService.RequireExistingFile(settings.PpgExecutablePath, "People Playground executable");
        var box = "PPGAV-" + Guid.NewGuid().ToString("N");
        RefuseExistingBox(box);
        ConfigureBox(box);
        var info = new ProcessStartInfo(StartExecutable!) { UseShellExecute = false, WorkingDirectory = settings.GameDirectory, CreateNoWindow = true };
        foreach (var arg in new[] { $"/box:{box}", "/silent", "/wait", executable, "-noWorkshop" }) info.ArgumentList.Add(arg);
        var process = Process.Start(info) ?? throw new InvalidOperationException("Sandboxie could not start People Playground.");
        _events.Log("Sandboxie containment started", $"People Playground is running in verified PPGAV-owned box {box}.");
        return new LaunchSession(LaunchMode.SecureSandbox, process, async () =>
        {
            if (!StopBox(box)) throw new IOException($"Sandboxie did not confirm termination of {box}.");
            if (!DeleteBox(box)) throw new IOException($"Sandboxie did not confirm cleanup of {box}.");
            await ValueTask.CompletedTask;
        }, null, SandboxProvider.SandboxieClassic, box);
    }

    public void Stop(LaunchSession session)
    {
        var box = session.ProviderResourceName;
        if (string.IsNullOrWhiteSpace(box) || !box.StartsWith("PPGAV-", StringComparison.Ordinal)) return;
        if (!StopBox(box)) _events.Log("Sandboxie stop failed", $"Could not confirm termination of owned box {box}.", ScanCategory.Suspicious);
    }

    private void RefuseExistingBox(string box)
    {
        var result = RunIni("get", box, "Enabled", null);
        if (result.ExitCode == 0 && !string.IsNullOrWhiteSpace(result.Output)) throw new InvalidOperationException($"Refusing to modify an existing Sandboxie box: {box}.");
    }

    private void ConfigureBox(string box)
    {
        Set(box, "Enabled", "y"); Set(box, "ConfigLevel", "10"); Set(box, "AutoRecover", "n"); Set(box, "DropAdminRights", "y"); Set(box, "NetworkAccess", "n"); Set(box, "PPGAVOwner", box);
        var endpoints = new[] { @"\Device\RawIp", @"\Device\Ip*", @"\Device\Tcp*", @"\Device\Afd*" };
        Set(box, "ClosedFilePath", endpoints[0]); foreach (var endpoint in endpoints.Skip(1)) Append(box, "ClosedFilePath", endpoint);
        var verify = string.Join("\n", new[] { "PPGAVOwner", "Enabled", "ConfigLevel", "DropAdminRights", "NetworkAccess" }.Select(setting => RunIni("get", box, setting, null)));
        if (!verify.Contains(box, StringComparison.Ordinal) || !verify.Contains("Enabled", StringComparison.OrdinalIgnoreCase) || !verify.Contains("NetworkAccess", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException($"Sandboxie ownership/settings verification failed for {box}.");
    }

    private bool StopBox(string box) => RunStart(box, "/terminate");
    private bool DeleteBox(string box) => RunStart(box, "delete_sandbox_silent");
    private void Set(string box, string setting, string value) => RequireIni("set", box, setting, value);
    private void Append(string box, string setting, string value) => RequireIni("append", box, setting, value);
    private void RequireIni(string verb, string box, string setting, string value) { var result = RunIni(verb, box, setting, value); if (result.ExitCode != 0) throw new InvalidOperationException($"Sandboxie configuration failed for {setting}."); }
    private (int ExitCode, string Output) RunIni(string verb, string box, string setting, string? value)
    {
        var info = new ProcessStartInfo(IniExecutable!) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var arg in new[] { verb, box, setting }.Concat(value is null ? [] : new[] { value })) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("SbieIni could not start.");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(5000)) { try { process.Kill(true); } catch { } throw new TimeoutException("SbieIni timed out."); }
        Task.WaitAll(output, error); return (process.ExitCode, output.Result + error.Result);
    }
    private bool RunStart(string box, string command)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(StartExecutable!) { UseShellExecute = false, CreateNoWindow = true, ArgumentList = { $"/box:{box}", command } });
            if (process is null || !process.WaitForExit(10000)) { try { process?.Kill(true); } catch { } return false; }
            return process.ExitCode == 0;
        }
        catch { return false; }
    }
}

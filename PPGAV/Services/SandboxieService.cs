using PPGAV.Models;

namespace PPGAV.Services;

public sealed class SandboxieService
{
    private const string Box = "PPGAV";
    private readonly EventLogService _events;
    public SandboxieService(EventLogService events) => _events = events;

    public string? StartExecutable => new[]
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sandboxie", "Start.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sandboxie-Plus", "Start.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Sandboxie", "Start.exe")
    }.FirstOrDefault(File.Exists);
    public string? IniExecutable => StartExecutable is { } start ? Path.Combine(Path.GetDirectoryName(start)!, "SbieIni.exe") : null;
    public bool IsAvailable => StartExecutable is not null && File.Exists(IniExecutable);

    public LaunchSession Launch(AppSettings settings)
    {
        if (!IsAvailable) throw new InvalidOperationException("No supported sandbox is installed. Install the free open-source Sandboxie Classic package.");
        if (!File.Exists(settings.PpgExecutablePath)) throw new FileNotFoundException("People Playground.exe was not found.", settings.PpgExecutablePath);
        ConfigureBox();
        var info = new ProcessStartInfo(StartExecutable!) { UseShellExecute = false, WorkingDirectory = settings.GameDirectory, CreateNoWindow = true };
        foreach (var arg in new[] { $"/box:{Box}", "/silent", "/wait", settings.PpgExecutablePath, "-noWorkshop" }) info.ArgumentList.Add(arg);
        var process = Process.Start(info) ?? throw new InvalidOperationException("Sandboxie could not start People Playground.");
        _events.Log("Sandboxie containment started", "People Playground is running in the dedicated PPGAV box with recovery, administrator rights, and network access disabled.");
        return new LaunchSession(LaunchMode.SecureSandbox, process, async () =>
        {
            RunStart("/terminate");
            RunStart("delete_sandbox_silent");
            await ValueTask.CompletedTask;
        });
    }

    private void ConfigureBox()
    {
        Set("Enabled", "y"); Set("ConfigLevel", "10"); Set("AutoRecover", "n"); Set("DropAdminRights", "y");
        var endpoints = new[] { @"\Device\RawIp", @"\Device\Ip*", @"\Device\Tcp*", @"\Device\Afd*" };
        Set("ClosedFilePath", endpoints[0]);
        foreach (var endpoint in endpoints.Skip(1)) Append("ClosedFilePath", endpoint);
    }
    private void Set(string setting, string value) => RunIni("set", setting, value);
    private void Append(string setting, string value) => RunIni("append", setting, value);
    private void RunIni(string verb, string setting, string value)
    {
        var p = Process.Start(new ProcessStartInfo(IniExecutable!) { UseShellExecute = false, CreateNoWindow = true, ArgumentList = { verb, Box, setting, value } });
        p?.WaitForExit(5000);
        if (p is null || p.ExitCode != 0) throw new InvalidOperationException($"Sandboxie configuration failed for {setting}.");
    }
    private void RunStart(string command)
    {
        try { Process.Start(new ProcessStartInfo(StartExecutable!) { UseShellExecute = false, CreateNoWindow = true, ArgumentList = { $"/box:{Box}", command } })?.WaitForExit(5000); } catch { }
    }
}

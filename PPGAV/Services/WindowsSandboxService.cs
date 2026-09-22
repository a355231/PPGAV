using System.Security;
using System.Security.Principal;
using System.Xml.Linq;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class WindowsSandboxService
{
    private readonly EventLogService _events;

    public WindowsSandboxService(EventLogService events)
    {
        _events = events;
    }

    public bool IsAvailable => File.Exists(Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe"));

    public async Task<LaunchSession> LaunchAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
        {
            throw new InvalidOperationException("Windows Sandbox is not available. Enable the Windows Sandbox optional feature or use Malware Safe Mode.");
        }

        var executable = RequireExecutable(settings);
        var gameRoot = Path.GetFullPath(settings.GameDirectory);
        if (!IsWithin(gameRoot, executable))
        {
            throw new InvalidOperationException("The game executable must be inside the configured game directory for read-only sandbox mapping.");
        }

        Directory.CreateDirectory(AppPaths.SandboxFolder);
        var configPath = Path.Combine(AppPaths.SandboxFolder, $"ppgav-{Guid.NewGuid():N}.wsb");
        var config = BuildConfiguration(gameRoot, executable);
        config.Save(configPath);
        
        /*
         * The sandbox profile deliberately maps the host game directory read-only.
         * PPGAV data and backups remain outside that mapping.
         */
        
        /*
         * Keep the generated profile on disk only for the lifetime of the session.
         */

        var process = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsSandbox.exe"),
            Arguments = $"\"{configPath}\"",
            UseShellExecute = true,
            WorkingDirectory = AppPaths.SandboxFolder
        });
        if (process is null)
        {
            TryDelete(configPath);
            throw new InvalidOperationException("Windows Sandbox could not be started.");
        }

        _events.Log("Secure sandbox started", "People Playground is running with a read-only game mapping and disabled networking.");
        await Task.CompletedTask;
        return new LaunchSession(LaunchMode.SecureSandbox, process, async () =>
        {
            TryDelete(configPath);
            await Task.CompletedTask;
        }, configPath);
    }

    public XDocument BuildConfiguration(string gameRoot, string executable)
    {
        var mappedExecutable = "C:\\PPGAVGame\\" + Path.GetRelativePath(gameRoot, executable).Replace('/', '\\');
        return new XDocument(
            new XElement("Configuration",
                new XElement("MappedFolders",
                    new XElement("MappedFolder",
                        new XElement("HostFolder", gameRoot),
                        new XElement("SandboxFolder", "C:\\PPGAVGame"),
                        new XElement("ReadOnly", "true"))),
                new XElement("Networking", "Disable"),
                new XElement("ClipboardRedirection", "Disable"),
                new XElement("vGPU", "Disable"),
                new XElement("MemoryInMB", "4096"),
                new XElement("LogonCommand",
                    new XElement("Command", $"cmd.exe /c \"\"{mappedExecutable}\"\""))));
    }

    public static void Stop(LaunchSession session)
    {
        try
        {
            if (!session.Process.HasExited) session.Process.Kill(true);
        }
        catch { }
    }

    private static string RequireExecutable(AppSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.PpgExecutablePath) || !File.Exists(settings.PpgExecutablePath))
        {
            throw new FileNotFoundException("People Playground.exe was not found.", settings.PpgExecutablePath);
        }

        return Path.GetFullPath(settings.PpgExecutablePath);
    }

    private static bool IsWithin(string root, string candidate)
    {
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

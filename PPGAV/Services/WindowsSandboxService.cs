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
            throw new InvalidOperationException("The game executable must be inside the configured game directory for disposable sandbox staging.");
        }

        Directory.CreateDirectory(AppPaths.SandboxFolder);
        var sessionRoot = Path.Combine(AppPaths.SandboxFolder, "Sessions", Guid.NewGuid().ToString("N"));
        var stagedGameRoot = Path.Combine(sessionRoot, "Game");
        CopyDirectory(gameRoot, stagedGameRoot);
        var stagedExecutable = Path.Combine(stagedGameRoot, Path.GetRelativePath(gameRoot, executable));
        if (!File.Exists(stagedExecutable))
        {
            TryDeleteDirectory(sessionRoot);
            throw new InvalidOperationException("The game could not be copied into the disposable Windows Sandbox staging area.");
        }
        var configPath = Path.Combine(sessionRoot, "PPGAV.wsb");
        var config = BuildConfiguration(stagedGameRoot, stagedExecutable);
        config.Save(configPath);
        
        /*
         * The real game directory is never mapped into the sandbox. A disposable
         * writable copy provides normal in-session saves/configuration while keeping
         * malware writes away from the real installation.
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
            TryDeleteDirectory(sessionRoot);
            throw new InvalidOperationException("Windows Sandbox could not be started.");
        }

        _events.Log("Secure sandbox started", "People Playground is running from a disposable writable game copy; networking, clipboard, and vGPU are disabled.");
        await Task.CompletedTask;
        return new LaunchSession(LaunchMode.SecureSandbox, process, async () =>
        {
            PersistSafeData(stagedGameRoot, gameRoot);
            TryDelete(configPath);
            TryDeleteDirectory(sessionRoot);
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
                        new XElement("ReadOnly", "false"))),
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

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, true); } catch { }
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
        {
            try { File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), true); } catch { }
        }
        foreach (var directory in Directory.EnumerateDirectories(source))
        {
            if (File.GetAttributes(directory).HasFlag(FileAttributes.ReparsePoint)) continue;
            CopyDirectory(directory, Path.Combine(destination, Path.GetFileName(directory)));
        }
    }

    private static void PersistSafeData(string stagedRoot, string realRoot)
    {
        var safeExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".json", ".sav", ".dat", ".cfg", ".ini" };
        try
        {
            foreach (var file in Directory.EnumerateFiles(stagedRoot, "*", SearchOption.AllDirectories))
            {
                if (new FileInfo(file).Length > 16 * 1024 * 1024 || !safeExtensions.Contains(Path.GetExtension(file))) continue;
                var relative = Path.GetRelativePath(stagedRoot, file);
                if (relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x.Equals("Mods", StringComparison.OrdinalIgnoreCase) || x.Equals("Workshop", StringComparison.OrdinalIgnoreCase))) continue;
                var destination = Path.Combine(realRoot, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(file, destination, true);
            }
        }
        catch { }
    }
}

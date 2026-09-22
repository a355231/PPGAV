using PPGAV.Models;

namespace PPGAV.Services;

public sealed class SafeModeLauncher
{
    private readonly IOutboundNetworkBlocker _firewall;
    private readonly EventLogService _events;

    public SafeModeLauncher(IOutboundNetworkBlocker firewall, EventLogService events)
    {
        _firewall = firewall;
        _events = events;
    }

    public void RecoverStaleDisabledMods(string gameRoot)
    {
        if (string.IsNullOrWhiteSpace(gameRoot)) return;
        var root = Path.Combine(AppPaths.SandboxFolder, "DisabledMods");
        Directory.CreateDirectory(root);
        foreach (var batch in Directory.GetDirectories(root))
        {
            foreach (var disabled in Directory.GetDirectories(batch))
            {
                var name = Path.GetFileName(disabled);
                if (name is not ("Mods" or "Workshop")) continue;
                var original = Path.Combine(gameRoot, name);
                try
                {
                    if (Directory.Exists(original)) continue;
                    Directory.CreateDirectory(Path.GetDirectoryName(original)!);
                    Directory.Move(disabled, original);
                    _events.Log("Safe Mode recovery", $"Restored a temporarily disabled {name} directory after an interrupted session.");
                }
                catch (Exception ex)
                {
                    _events.Log("Safe Mode recovery needed", $"Could not restore {name}: {ex.Message}", ScanCategory.Suspicious);
                }
            }

            try
            {
                if (!Directory.EnumerateFileSystemEntries(batch).Any()) Directory.Delete(batch);
            }
            catch { }
        }
        foreach (var original in ModDirectories(gameRoot))
        {
            var parent = Path.GetDirectoryName(original);
            if (parent is null || !Directory.Exists(parent) || Directory.Exists(original)) continue;
            foreach (var disabled in Directory.GetDirectories(parent, Path.GetFileName(original) + ".ppgav-disabled-*"))
            {
                try { Directory.Move(disabled, original); _events.Log("Safe Mode recovery", $"Restored {original} after an interrupted session."); break; }
                catch (Exception ex) { _events.Log("Safe Mode recovery needed", ex.Message, ScanCategory.Suspicious); }
            }
        }
    }

    public LaunchSession Launch(AppSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.PpgExecutablePath) || !File.Exists(settings.PpgExecutablePath))
        {
            throw new FileNotFoundException("People Playground.exe was not found.", settings.PpgExecutablePath);
        }

        var executable = Path.GetFullPath(settings.PpgExecutablePath);
        var gameRoot = Path.GetFullPath(settings.GameDirectory);
        if (!IsWithin(gameRoot, executable)) throw new InvalidOperationException("The game executable must be inside the configured game directory.");

        if (!_firewall.TryBlockOutbound(executable, out _))
        {
            if (settings.RequireNetworkBlockInSafeMode)
            {
                throw new InvalidOperationException("Malware Safe Mode refused to launch because outbound network blocking could not be enabled.");
            }
        }

        var disabled = DisableModDirectories(gameRoot);
        try
        {
            var startInfo = new ProcessStartInfo(executable)
            {
                WorkingDirectory = gameRoot,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add("-noWorkshop");
            startInfo.Environment.Remove("SteamAppId");
            startInfo.Environment.Remove("SteamGameId");
            var process = Process.Start(startInfo) ?? throw new InvalidOperationException("People Playground could not be started.");
            _events.Log("Malware Safe Mode started", "People Playground launched without local or Steam Workshop content and with outbound network blocking requested.");
            return new LaunchSession(LaunchMode.MalwareSafe, process, async () =>
            {
                RestoreModDirectories(disabled);
                _firewall.TryRemove(executable);
                await Task.CompletedTask;
            });
        }
        catch
        {
            RestoreModDirectories(disabled);
            _firewall.TryRemove(executable);
            throw;
        }
    }

    private static List<(string Original, string Disabled)> DisableModDirectories(string gameRoot)
    {
        var moved = new List<(string Original, string Disabled)>();
        foreach (var original in ModDirectories(gameRoot))
        {
            if (!Directory.Exists(original)) continue;
            var disabled = original + $".ppgav-disabled-{Guid.NewGuid():N}";
            Directory.Move(original, disabled);
            moved.Add((original, disabled));
        }

        return moved;
    }

    private static IEnumerable<string> ModDirectories(string gameRoot)
    {
        yield return Path.Combine(gameRoot, "Mods");
        yield return Path.Combine(gameRoot, "Workshop");
        foreach (var workshop in GamePathDiscovery.FindWorkshopDirectories(gameRoot)) yield return workshop;
    }

    private static void RestoreModDirectories(IEnumerable<(string Original, string Disabled)> moved)
    {
        foreach (var (original, disabled) in moved.Reverse())
        {
            try
            {
                if (Directory.Exists(original)) Directory.Delete(original, true);
                if (Directory.Exists(disabled))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(original)!);
                    Directory.Move(disabled, original);
                }
            }
            catch { }
        }
    }

    private static bool IsWithin(string root, string candidate)
    {
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }
}

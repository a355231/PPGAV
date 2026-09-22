using System.Diagnostics;
using System.IO;
using PPGAV.Interop;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class BehaviorMonitor
{
    private static readonly HashSet<string> ClearlyDangerousChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe"
    };

    private readonly EventLogService _events;

    public BehaviorMonitor(EventLogService events)
    {
        _events = events;
    }

    public async Task MonitorAsync(LaunchSession session, string gameDirectory, Action<BehaviorAlert> onAlert, CancellationToken cancellationToken)
    {
        using var watcher = session.Mode == LaunchMode.MalwareSafe ? CreateWatcher(gameDirectory, onAlert) : null;
        var reportedProcessIds = new HashSet<int>();
        while (!cancellationToken.IsCancellationRequested)
        {
            if (session.Process.HasExited) return;

            if (session.Mode == LaunchMode.MalwareSafe)
            {
                foreach (var child in ProcessTree.Descendants(session.Process.Id))
                {
                    if (!reportedProcessIds.Add(child.ProcessId)) continue;
                    if (ClearlyDangerousChildren.Contains(child.Name))
                    {
                        var alert = new BehaviorAlert(ScanCategory.Malware, "Blocked child process", $"People Playground spawned {child.Name}, which is not allowed in Malware Safe Mode.", true);
                        _events.Log(alert.Title, alert.Detail, alert.Category);
                        onAlert(alert);
                        ProcessTree.KillTree(session.Process);
                        return;
                    }

                    if (!string.Equals(child.Name, "UnityCrashHandler64.exe", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(child.Name, "conhost.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        var alert = new BehaviorAlert(ScanCategory.Suspicious, "Unexpected child process", $"People Playground spawned {child.Name}. Review the event log.", false);
                        _events.Log(alert.Title, alert.Detail, alert.Category);
                        onAlert(alert);
                    }
                }
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
        }
    }

    private static FileSystemWatcher CreateWatcher(string gameDirectory, Action<BehaviorAlert> onAlert)
    {
        var watcher = new FileSystemWatcher(gameDirectory)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
            EnableRaisingEvents = true,
            Filter = "*.*"
        };
        FileSystemEventHandler handler = (_, args) =>
        {
            var extension = Path.GetExtension(args.FullPath);
            if (!new[] { ".dll", ".exe", ".ps1", ".bat", ".cmd" }.Contains(extension, StringComparer.OrdinalIgnoreCase)) return;
            var known = Path.GetFileName(args.FullPath).Contains("FPSPlusPlus", StringComparison.OrdinalIgnoreCase);
            onAlert(new BehaviorAlert(known ? ScanCategory.Malware : ScanCategory.Suspicious, "Game files changed during safe launch", args.FullPath, known));
        };
        watcher.Created += handler;
        watcher.Changed += handler;
        watcher.Renamed += (_, args) => handler(watcher, new FileSystemEventArgs(WatcherChangeTypes.Renamed, Path.GetDirectoryName(args.FullPath) ?? gameDirectory, Path.GetFileName(args.FullPath)));
        return watcher;
    }
}

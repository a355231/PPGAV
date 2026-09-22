using System.Diagnostics;
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
    private readonly ScannerService _scanner;

    public BehaviorMonitor(EventLogService events, ScannerService scanner)
    {
        _events = events;
        _scanner = scanner;
    }

    public async Task MonitorAsync(LaunchSession session, string gameDirectory, Action<BehaviorAlert> onAlert, CancellationToken cancellationToken, IEnumerable<string>? additionalRoots = null)
    {
        var watchers = new List<FileSystemWatcher> { CreateWatcher(gameDirectory, ScanScope.GameCore, onAlert) };
        foreach (var root in additionalRoots ?? []) if (Directory.Exists(root)) watchers.Add(CreateWatcher(root, ScanScope.SteamWorkshop, onAlert));
        var reportedProcessIds = new HashSet<int>();
        var knownEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (session.Process.HasExited) return;
                foreach (var child in ProcessTree.Descendants(session.Process.Id))
                {
                    if (!reportedProcessIds.Add(child.ProcessId)) continue;
                    if (ClearlyDangerousChildren.Contains(child.Name))
                    {
                        Alert(onAlert, new BehaviorAlert(ScanCategory.Malware, "Blocked child process", $"People Playground spawned {child.Name}, which is not allowed.", true));
                        ProcessTree.KillTree(session.Process); return;
                    }
                    if (!string.Equals(child.Name, "UnityCrashHandler64.exe", StringComparison.OrdinalIgnoreCase) && !string.Equals(child.Name, "conhost.exe", StringComparison.OrdinalIgnoreCase))
                        Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Unexpected child process", $"People Playground spawned {child.Name}.", false));
                }
                foreach (var endpoint in NetworkActivityMonitor.Snapshot().Where(x => x.ProcessId == session.Process.Id || reportedProcessIds.Contains(x.ProcessId)))
                {
                    var key = $"{endpoint.Protocol}|{endpoint.Local}|{endpoint.Remote}|{endpoint.ProcessId}";
                    if (knownEndpoints.Add(key))
                    {
                        var external = IsExternalEndpoint(endpoint.Remote);
                        Alert(onAlert, new BehaviorAlert(external ? ScanCategory.Malware : ScanCategory.Suspicious, external ? "External network activity blocked" : "Local network activity", $"PPG process opened {endpoint.Protocol} {endpoint.Remote}.", external));
                        if (external) { ProcessTree.KillTree(session.Process); return; }
                    }
                }
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            }
        }
        finally { foreach (var watcher in watchers) watcher.Dispose(); }
    }

    private FileSystemWatcher CreateWatcher(string root, ScanScope scope, Action<BehaviorAlert> onAlert)
    {
        var watcher = new FileSystemWatcher(root) { IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size, Filter = "*.*", EnableRaisingEvents = true };
        FileSystemEventHandler handler = (_, args) =>
        {
            var effectiveScope = scope == ScanScope.GameCore ? ScopeFor(root, args.FullPath) : scope;
            var report = _scanner.ScanFile(args.FullPath, effectiveScope);
            foreach (var finding in report.Findings)
                Alert(onAlert, new BehaviorAlert(finding.Category, "Changed content detected", $"{finding.FilePath}: {finding.Rule}", finding.Category == ScanCategory.Malware));
        };
        watcher.Created += handler; watcher.Changed += handler;
        watcher.Renamed += (_, args) => handler(watcher, new FileSystemEventArgs(WatcherChangeTypes.Renamed, Path.GetDirectoryName(args.FullPath) ?? root, Path.GetFileName(args.FullPath)));
        return watcher;
    }

    private void Alert(Action<BehaviorAlert> callback, BehaviorAlert alert)
    {
        _events.Log(alert.Title, alert.Detail, alert.Category);
        callback(alert);
    }

    private static ScanScope ScopeFor(string root, string path)
    {
        var parts = Path.GetRelativePath(root, path).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Any(x => x.Equals("Mods", StringComparison.OrdinalIgnoreCase))) return ScanScope.LocalMods;
        if (parts.Any(x => x.Equals("Workshop", StringComparison.OrdinalIgnoreCase))) return ScanScope.SteamWorkshop;
        return ScanScope.GameCore;
    }

    private static bool IsExternalEndpoint(string remote)
    {
        var value = remote.Split(':')[0];
        return value is not ("*" or "0.0.0.0" or "127.0.0.1" or "::1" or "[::1]") && !value.StartsWith("127.", StringComparison.OrdinalIgnoreCase);
    }
}

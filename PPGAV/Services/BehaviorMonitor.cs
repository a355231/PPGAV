using System.Diagnostics;
using System.Collections.Concurrent;
using System.Net;
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
        var watchRoot = session.Provider == SandboxProvider.WindowsSandbox && session.SandboxConfigPath is not null
            ? Path.Combine(Path.GetDirectoryName(session.SandboxConfigPath)!, "Game")
            : gameDirectory;
        var watchers = new List<FileSystemWatcher>();
        var reportedProcessIdentities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var reportedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var knownEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var lastObservedChildren = new Dictionary<int, ProcessSnapshot>();
        var rootStartTimeUtc = session.Process.StartTime.ToUniversalTime();
        var rootPath = session.Process.MainModule?.FileName;
        if (session.Provider == SandboxProvider.WindowsSandbox)
            Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Guest process monitoring limitation", "Windows Sandbox guest processes are not visible to this host-side monitor; network denial and disposable staging are enforced by the sandbox provider.", false));
        try
        {
            watchers.Add(CreateWatcher(watchRoot, ScanScope.GameCore, onAlert));
            if (session.Provider != SandboxProvider.WindowsSandbox)
                foreach (var root in additionalRoots ?? []) if (Directory.Exists(root)) watchers.Add(CreateWatcher(root, ScanScope.SteamWorkshop, onAlert));
            bool InspectModules(Process inspected)
            {
                try
                {
                    foreach (ProcessModule module in inspected.Modules)
                    {
                        var path = module.FileName;
                        if (!reportedModules.Add(path)) continue;
                        var underMods = path.StartsWith(Path.Combine(gameDirectory, "Mods") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || path.StartsWith(Path.Combine(gameDirectory, "Workshop") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
                        if (underMods || IsSuspiciousModulePath(path))
                        {
                            Alert(onAlert, new BehaviorAlert(ScanCategory.Malware, "Suspicious module load", $"PPG loaded an untrusted module: {path}", true));
                            ProcessTree.KillTree(session.Process);
                            return false;
                        }
                    }
                    return true;
                }
                catch (Exception ex)
                {
                    if (session.Provider == SandboxProvider.WindowsSandbox)
                    {
                        Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Host process inspection unavailable", $"The Windows Sandbox guest is not visible to this host-side check: {ex.Message}", false));
                        return true;
                    }
                    Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Process module inspection failed", $"Could not inspect modules for process {inspected.Id}: {ex.Message}", true));
                    ProcessTree.KillTree(session.Process);
                    return false;
                }
            }
            while (!cancellationToken.IsCancellationRequested)
            {
                if (session.Process.HasExited)
                {
                    ProcessTree.KillObservedChildren(session.Process.Id, rootStartTimeUtc, rootPath, lastObservedChildren.Values);
                    return;
                }
                var descendants = session.Provider == SandboxProvider.WindowsSandbox ? [] : ProcessTree.Descendants(session.Process);
                foreach (var child in descendants)
                {
                    if (child.StartTimeUtc is null)
                    {
                        Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Process identity unavailable", $"Could not establish the identity of child process {child.ProcessId}; session monitoring is incomplete.", true));
                        ProcessTree.KillTree(session.Process); return;
                    }
                    if (!ProcessTree.IsCurrentDescendant(session.Process, child)) continue;
                    lastObservedChildren[child.ProcessId] = child;
                    if (lastObservedChildren.Count > 8192) lastObservedChildren.Remove(lastObservedChildren.Keys.First());
                    var identity = $"{child.ProcessId}|{child.StartTimeUtc.Value:O}|{child.Path}";
                    if (!reportedProcessIdentities.Add(identity)) continue;
                    if (ClearlyDangerousChildren.Contains(child.Name))
                    {
                        Alert(onAlert, new BehaviorAlert(ScanCategory.Malware, "Blocked child process", $"People Playground spawned {child.Name}, which is not allowed.", true));
                        ProcessTree.KillTree(session.Process); return;
                    }
                    if (!string.Equals(child.Name, "UnityCrashHandler64.exe", StringComparison.OrdinalIgnoreCase) && !string.Equals(child.Name, "conhost.exe", StringComparison.OrdinalIgnoreCase))
                        Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Unexpected child process", $"People Playground spawned {child.Name}.", false));
                }
                if (!InspectModules(session.Process)) return;
                foreach (var child in descendants)
                {
                    if (!ProcessTree.IsCurrentDescendant(session.Process, child)) continue;
                    try
                    {
                        using var inspected = Process.GetProcessById(child.ProcessId);
                        if (child.StartTimeUtc is null || inspected.StartTime.ToUniversalTime() != child.StartTimeUtc.Value ||
                            child.Path is not null && !string.Equals(inspected.MainModule?.FileName, child.Path, StringComparison.OrdinalIgnoreCase) ||
                            !ProcessTree.IsCurrentDescendant(session.Process, child)) continue;
                        if (!InspectModules(inspected)) return;
                    }
                    catch (Exception ex)
                    {
                        if (session.Provider != SandboxProvider.WindowsSandbox)
                        {
                            Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Process module inspection failed", $"Could not inspect modules for process {child.ProcessId}: {ex.Message}", true));
                            ProcessTree.KillTree(session.Process); return;
                        }
                    }
                }
                IReadOnlyList<NetworkEndpoint> endpoints = [];
                if (session.Provider != SandboxProvider.WindowsSandbox)
                {
                    if (!NetworkActivityMonitor.TrySnapshot(out endpoints, out var networkError))
                    {
                        Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Network monitor failed", $"Network activity could not be observed: {networkError}", true));
                        ProcessTree.KillTree(session.Process); return;
                    }
                }
                foreach (var endpoint in endpoints)
                {
                    if (endpoint.ProcessId == session.Process.Id)
                    {
                        if (!ProcessTree.IsCurrentRoot(session.Process)) continue;
                    }
                    else
                    {
                        var identity = descendants.FirstOrDefault(x => x.ProcessId == endpoint.ProcessId);
                        if (identity is null || !ProcessTree.IsCurrentDescendant(session.Process, identity)) continue;
                    }
                    var key = $"{endpoint.Protocol}|{endpoint.Local}|{endpoint.Remote}|{endpoint.ProcessId}";
                    if (knownEndpoints.Add(key))
                    {
                        var external = IsExternalEndpoint(endpoint.Remote);
                        Alert(onAlert, new BehaviorAlert(external ? ScanCategory.Malware : ScanCategory.Suspicious, external ? "External network activity observed" : "Local network activity", external ? $"PPG process opened {endpoint.Protocol} {endpoint.Remote}; the connection may already have occurred, so PPGAV is stopping the session." : $"PPG process opened {endpoint.Protocol} {endpoint.Remote}.", external));
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
        SecurePathService.RequireExistingDirectory(root, "behavior monitor root");
        var watcher = new FileSystemWatcher(root) { IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size, Filter = "*.*", EnableRaisingEvents = true, InternalBufferSize = 64 * 1024 };
        var recent = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        FileSystemEventHandler handler = (_, args) =>
        {
            try
            {
                if (recent.TryGetValue(args.FullPath, out var last) && DateTimeOffset.UtcNow - last < TimeSpan.FromMilliseconds(300)) return;
                if (recent.Count > 10000) recent.Clear();
                recent[args.FullPath] = DateTimeOffset.UtcNow;
                if (Directory.Exists(args.FullPath)) return;
                var effectiveScope = scope == ScanScope.GameCore ? GameLayout.ScopeFor(root, args.FullPath) : scope;
                var report = _scanner.ScanFile(args.FullPath, effectiveScope, scope == ScanScope.GameCore && GameLayout.IsCompiledModCache(root, args.FullPath));
                if (!report.IsComplete) { Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Watcher inspection incomplete", $"Changed content could not be completely inspected: {args.FullPath}", true)); return; }
                foreach (var finding in report.Findings.Where(x => x.Category != ScanCategory.Safe)) Alert(onAlert, new BehaviorAlert(finding.Category, "Changed content detected", $"{finding.FilePath}: {finding.Rule}", finding.Category == ScanCategory.Malware));
            }
            catch (Exception ex) { Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Watcher failure", ex.Message, true)); }
        };
        watcher.Error += (_, args) => Alert(onAlert, new BehaviorAlert(ScanCategory.Suspicious, "Watcher overflow", args.GetException().Message, true));
        watcher.Created += handler; watcher.Changed += handler;
        watcher.Renamed += (_, args) => handler(watcher, new FileSystemEventArgs(WatcherChangeTypes.Renamed, Path.GetDirectoryName(args.FullPath) ?? root, Path.GetFileName(args.FullPath)));
        return watcher;
    }

    private void Alert(Action<BehaviorAlert> callback, BehaviorAlert alert)
    {
        try { _events.Log(alert.Title, alert.Detail, alert.Category); callback(alert); }
        catch (Exception ex) { _events.Log("Behavior monitor callback failed", ex.Message, ScanCategory.Suspicious); }
    }

    private static bool IsExternalEndpoint(string remote)
    {
        var value = remote.Trim();
        if (value is "*:*" or "0.0.0.0:0" or "[::]:0") return false;
        if (value.StartsWith("[", StringComparison.Ordinal) && value.IndexOf(']') is var close && close > 0) value = value[1..close];
        else if (value.Count(c => c == ':') == 1) value = value[..value.IndexOf(':')];
        if (IPAddress.TryParse(value, out var address)) return !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any);
        return value is not ("*" or "0.0.0.0" or "::" or "127.0.0.1" or "::1") && !value.StartsWith("127.", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsSuspiciousModulePath(string path)
    {
        var full = Path.GetFullPath(path);
        var temp = Path.GetFullPath(Path.GetTempPath());
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        return IsBelow(full, temp) || IsBelow(full, appData) || IsBelow(full, downloads);
    }

    private static bool IsBelow(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(path).StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }
}

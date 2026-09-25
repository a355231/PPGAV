using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace PPGAV.Interop;

public sealed record ProcessSnapshot(int ProcessId, int ParentProcessId, string Name, string? Path, DateTime? StartTimeUtc);

public static class ProcessTree
{
    private const uint SnapshotProcess = 0x00000002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int Priority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static IReadOnlyList<ProcessSnapshot> Snapshot()
    {
        var result = new List<ProcessSnapshot>();
        var handle = CreateToolhelp32Snapshot(SnapshotProcess, 0);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not take a process snapshot.");

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(handle, ref entry))
            {
                var error = Marshal.GetLastWin32Error();
                if (error == 18) return result;
                throw new Win32Exception(error, "Could not enumerate the process snapshot.");
            }
            do
            {
                string? path = null; DateTime? start = null;
                try { using var inspected = Process.GetProcessById((int)entry.ProcessId); path = inspected.MainModule?.FileName; start = inspected.StartTime.ToUniversalTime(); } catch { }
                result.Add(new ProcessSnapshot((int)entry.ProcessId, (int)entry.ParentProcessId, entry.ExeFile, path, start));
            }
            while (Process32Next(handle, ref entry));
        }
        finally
        {
            CloseHandle(handle);
        }

        return result;
    }

    public static IReadOnlyList<ProcessSnapshot> Descendants(int rootProcessId)
    {
        var all = Snapshot();
        var ids = new HashSet<int> { rootProcessId };
        var result = new List<ProcessSnapshot>();
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var process in all)
            {
                if (ids.Contains(process.ParentProcessId) && ids.Add(process.ProcessId))
                {
                    result.Add(process);
                    changed = true;
                }
            }
        }

        return result;
    }

    public static IReadOnlyList<ProcessSnapshot> Descendants(Process root)
    {
        if (!IsCurrentIdentity(root)) throw new InvalidOperationException("The monitored root process identity changed.");
        var all = Snapshot();
        var rootSnapshot = all.FirstOrDefault(x => x.ProcessId == root.Id);
        if (rootSnapshot is null || rootSnapshot.StartTimeUtc is null || rootSnapshot.StartTimeUtc.Value != root.StartTime.ToUniversalTime() ||
            rootSnapshot.Path is null || !string.Equals(rootSnapshot.Path, root.MainModule?.FileName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The process snapshot no longer matches the monitored root identity.");
        var ids = new HashSet<int> { root.Id };
        var descendants = new List<ProcessSnapshot>();
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var process in all)
            {
                if (ids.Contains(process.ParentProcessId) && ids.Add(process.ProcessId)) { descendants.Add(process); changed = true; }
            }
        }
        return descendants;
    }

    public static bool IsCurrentRoot(Process process) => IsCurrentIdentity(process);

    public static bool IsCurrentDescendant(Process root, ProcessSnapshot expected)
    {
        if (!IsCurrentIdentity(root)) return false;
        var all = Snapshot();
        var byId = all.ToDictionary(x => x.ProcessId);
        if (!byId.TryGetValue(root.Id, out var rootSnapshot) || !Matches(rootSnapshot, root.StartTime.ToUniversalTime(), root.MainModule?.FileName)) return false;
        if (!byId.TryGetValue(expected.ProcessId, out var current) || current.ParentProcessId != expected.ParentProcessId ||
            current.StartTimeUtc != expected.StartTimeUtc || !string.Equals(current.Path, expected.Path, StringComparison.OrdinalIgnoreCase)) return false;

        var seen = new HashSet<int>();
        while (current.ParentProcessId != 0 && seen.Add(current.ProcessId))
        {
            if (current.ParentProcessId == root.Id) return true;
            if (!byId.TryGetValue(current.ParentProcessId, out current!)) return false;
        }
        return false;
    }

    public static void KillTree(Process root)
    {
        if (!IsCurrentIdentity(root)) return;
        for (var pass = 0; pass < 3; pass++)
        {
            var snapshots = Descendants(root);
            if (snapshots.Count == 0) break;
            var byId = snapshots.ToDictionary(x => x.ProcessId);
            foreach (var child in snapshots.OrderByDescending(x => Depth(root.Id, x, byId)))
            {
                try
                {
                    if (child.StartTimeUtc is null || !IsCurrentDescendant(root, child)) continue;
                    using var process = Process.GetProcessById(child.ProcessId);
                    if (process.StartTime.ToUniversalTime() != child.StartTimeUtc.Value ||
                        child.Path is not null && !string.Equals(process.MainModule?.FileName, child.Path, StringComparison.OrdinalIgnoreCase) ||
                        !IsCurrentDescendant(root, child)) continue;
                    process.Kill();
                }
                catch { }
            }
            if (Descendants(root).Count == 0) break;
        }

        try { if (IsCurrentIdentity(root) && !root.HasExited) root.Kill(); } catch { }
    }

    public static void KillObservedChildren(int rootProcessId, DateTime rootStartTimeUtc, string? rootPath, IEnumerable<ProcessSnapshot> observedChildren)
    {
        if (rootProcessId <= 0) return;
        var observed = observedChildren.GroupBy(x => x.ProcessId).Select(x => x.Last()).ToDictionary(x => x.ProcessId);
        Dictionary<int, ProcessSnapshot> current;
        try { current = Snapshot().ToDictionary(x => x.ProcessId); }
        catch { return; }
        if (current.TryGetValue(rootProcessId, out var currentRoot) &&
            (currentRoot.StartTimeUtc != rootStartTimeUtc || !string.Equals(currentRoot.Path, rootPath, StringComparison.OrdinalIgnoreCase))) return;

        foreach (var child in observed.Values)
        {
            if (child.StartTimeUtc is null || !current.TryGetValue(child.ProcessId, out var snapshot) ||
                snapshot.ParentProcessId != child.ParentProcessId || snapshot.StartTimeUtc != child.StartTimeUtc ||
                !string.Equals(snapshot.Path, child.Path, StringComparison.OrdinalIgnoreCase)) continue;

            // A still-running intermediary must retain the same observed identity and parent edge.
            // Direct children are allowed to retain the now-exited root PID as their recorded parent.
            if (child.ParentProcessId != rootProcessId &&
                (!observed.TryGetValue(child.ParentProcessId, out var expectedParent) ||
                 !current.TryGetValue(child.ParentProcessId, out var currentParent) ||
                 currentParent.StartTimeUtc != expectedParent.StartTimeUtc || currentParent.ParentProcessId != expectedParent.ParentProcessId ||
                 !string.Equals(currentParent.Path, expectedParent.Path, StringComparison.OrdinalIgnoreCase))) continue;

            try
            {
                using var process = Process.GetProcessById(child.ProcessId);
                if (process.HasExited || process.StartTime.ToUniversalTime() != child.StartTimeUtc.Value ||
                    child.Path is not null && !string.Equals(process.MainModule?.FileName, child.Path, StringComparison.OrdinalIgnoreCase)) continue;
                var immediatelyBeforeKill = Snapshot().FirstOrDefault(x => x.ProcessId == child.ProcessId);
                if (immediatelyBeforeKill is null || immediatelyBeforeKill.ParentProcessId != child.ParentProcessId ||
                    immediatelyBeforeKill.StartTimeUtc != child.StartTimeUtc || !string.Equals(immediatelyBeforeKill.Path, child.Path, StringComparison.OrdinalIgnoreCase)) continue;
                process.Kill();
            }
            catch { }
        }
    }

    private static bool Matches(ProcessSnapshot snapshot, DateTime expectedStart, string? expectedPath) =>
        snapshot.StartTimeUtc == expectedStart && (expectedPath is null || string.Equals(snapshot.Path, expectedPath, StringComparison.OrdinalIgnoreCase));

    private static int Depth(int rootId, ProcessSnapshot child, IReadOnlyDictionary<int, ProcessSnapshot> snapshots)
    {
        var depth = 1;
        var current = child;
        var seen = new HashSet<int> { child.ProcessId };
        while (current.ParentProcessId != rootId)
        {
            if (!snapshots.TryGetValue(current.ParentProcessId, out var parent) || !seen.Add(parent.ProcessId)) break;
            current = parent;
            depth++;
        }
        return depth;
    }

    private static bool IsCurrentIdentity(Process expected)
    {
        try
        {
            using var current = Process.GetProcessById(expected.Id);
            return current.StartTime.ToUniversalTime() == expected.StartTime.ToUniversalTime() && string.Equals(current.MainModule?.FileName, expected.MainModule?.FileName, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}

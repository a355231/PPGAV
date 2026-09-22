using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PPGAV.Interop;

public sealed record ProcessSnapshot(int ProcessId, int ParentProcessId, string Name, string? Path);

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
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return result;

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(handle, ref entry)) return result;
            do
            {
                string? path = null;
                try { path = Process.GetProcessById((int)entry.ProcessId).MainModule?.FileName; } catch { }
                result.Add(new ProcessSnapshot((int)entry.ProcessId, (int)entry.ParentProcessId, entry.ExeFile, path));
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

    public static void KillTree(Process root)
    {
        foreach (var child in Descendants(root.Id).OrderByDescending(p => p.ParentProcessId))
        {
            try { Process.GetProcessById(child.ProcessId).Kill(true); } catch { }
        }

        try { if (!root.HasExited) root.Kill(true); } catch { }
    }
}

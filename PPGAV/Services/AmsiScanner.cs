using System.Runtime.InteropServices;

namespace PPGAV.Services;

internal static class AmsiScanner
{
    public static bool TryScan(byte[] content, string contentName, out bool malware, out string? error)
    {
        malware = false; error = null;
        if (!OperatingSystem.IsWindows()) return true;
        var task = Task.Run(() => ScanCore(content, contentName));
        if (!task.Wait(TimeSpan.FromSeconds(2))) { error = "AMSI did not return within the scan deadline."; return false; }
        try { malware = task.Result; return true; }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    public static bool IsMalware(byte[] content, string contentName) => TryScan(content, contentName, out var malware, out _) && malware;

    private static bool ScanCore(byte[] content, string contentName)
    {
        IntPtr context = IntPtr.Zero;
        try
        {
            if (AmsiInitialize("PPGAV", out context) != 0 || context == IntPtr.Zero) throw new InvalidOperationException("AMSI initialization failed.");
            var hr = AmsiScanBuffer(context, content, (uint)content.Length, contentName, IntPtr.Zero, out var result);
            if (hr != 0) throw new InvalidOperationException($"AMSI scan failed with HRESULT 0x{hr:X8}.");
            return result >= 32768;
        }
        finally { if (context != IntPtr.Zero) AmsiUninitialize(context); }
    }

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)] private static extern int AmsiInitialize(string appName, out IntPtr context);
    [DllImport("amsi.dll")] private static extern void AmsiUninitialize(IntPtr context);
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)] private static extern int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out uint result);
}

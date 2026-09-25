using System.Runtime.InteropServices;

namespace PPGAV.Services;

internal static class AmsiScanner
{
    private static int _scanInProgress;
    private static int _timedOut;

    public static bool TryScan(byte[] content, string contentName, out bool malware, out string? error)
    {
        malware = false; error = null;
        if (!OperatingSystem.IsWindows()) return true;
        // AmsiScanBuffer rejects zero-length buffers with E_INVALIDARG; there is nothing to classify.
        if (content.Length == 0) return true;
        if (Volatile.Read(ref _timedOut) != 0) { error = "AMSI previously exceeded its deadline; this process cannot safely continue AMSI scans."; return false; }
        if (Interlocked.CompareExchange(ref _scanInProgress, 1, 0) != 0) { error = "Another AMSI request is still running; concurrent scanning is refused."; return false; }
        var releaseGate = true;
        try
        {
            var task = Task.Run(() => ScanCore(content, contentName));
            bool completed;
            try { completed = task.Wait(TimeSpan.FromSeconds(10)); }
            catch (AggregateException ex) { error = ex.GetBaseException().Message; return false; }
            if (!completed)
            {
                // The native call is still running; keep the gate closed so it is never re-entered.
                releaseGate = false;
                Interlocked.Exchange(ref _timedOut, 1);
                error = "AMSI did not return within the scan deadline. Further AMSI scans are disabled for this process.";
                return false;
            }
            malware = task.Result;
            return true;
        }
        finally { if (releaseGate) Interlocked.Exchange(ref _scanInProgress, 0); }
    }

    public static bool IsMalware(byte[] content, string contentName) => TryScan(content, contentName, out var malware, out _) && malware;

    // AMSI is designed to be initialized once per application; re-initializing the provider for every
    // buffer dominated preflight time on real installs and pushed scans past their deadline.
    private static IntPtr _context;

    private static bool ScanCore(byte[] content, string contentName)
    {
        if (_context == IntPtr.Zero)
        {
            if (AmsiInitialize("PPGAV", out var context) != 0 || context == IntPtr.Zero) throw new InvalidOperationException("AMSI initialization failed.");
            _context = context;
        }
        var hr = AmsiScanBuffer(_context, content, (uint)content.Length, contentName, IntPtr.Zero, out var result);
        if (hr != 0) throw new InvalidOperationException($"AMSI scan failed with HRESULT 0x{hr:X8}.");
        return result >= 32768;
    }

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)] private static extern int AmsiInitialize(string appName, out IntPtr context);
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)] private static extern int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out uint result);
}

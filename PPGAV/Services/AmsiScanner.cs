using System.Runtime.InteropServices;

namespace PPGAV.Services;

internal static class AmsiScanner
{
    public static bool IsMalware(byte[] content, string contentName)
    {
        if (!OperatingSystem.IsWindows()) return false;
        IntPtr context = IntPtr.Zero;
        try
        {
            if (AmsiInitialize("PPGAV", out context) != 0 || context == IntPtr.Zero) return false;
            var hr = AmsiScanBuffer(context, content, (uint)content.Length, contentName, IntPtr.Zero, out var result);
            return hr == 0 && result >= 32768;
        }
        catch (DllNotFoundException) { return false; }
        catch (EntryPointNotFoundException) { return false; }
        finally { if (context != IntPtr.Zero) AmsiUninitialize(context); }
    }

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)] private static extern int AmsiInitialize(string appName, out IntPtr context);
    [DllImport("amsi.dll")] private static extern void AmsiUninitialize(IntPtr context);
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)] private static extern int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out uint result);
}

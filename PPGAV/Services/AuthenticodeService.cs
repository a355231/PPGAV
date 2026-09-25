using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace PPGAV.Services;

public sealed record SignatureInspection(bool Signed, bool Trusted, string Subject);

public static class AuthenticodeService
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    private const uint WtdUiNone = 2;
    private const uint WtdChoiceFile = 1;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00000010;

    public static SignatureInspection Inspect(string path)
    {
        if (!OperatingSystem.IsWindows()) return new SignatureInspection(false, false, string.Empty);
        IntPtr fileInfoPointer = IntPtr.Zero;
        IntPtr dataPointer = IntPtr.Zero;
        try
        {
            var full = SecurePathService.RequireExistingFile(path, "signed binary");
#pragma warning disable SYSLIB0057
            using var embeddedCertificate = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(full);
#pragma warning restore SYSLIB0057
            using var certificate = X509CertificateLoader.LoadCertificate(embeddedCertificate.GetRawCertData());
            var subject = certificate.Subject;
            var fileInfo = new WinTrustFileInfo { StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(), FilePath = full, FileHandle = IntPtr.Zero, KnownSubject = IntPtr.Zero };
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            var trustData = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(), UiChoice = WtdUiNone, RevocationChecks = 0,
                UnionChoice = WtdChoiceFile, FileInfo = fileInfoPointer, StateAction = 0,
                ProviderFlags = WtdCacheOnlyUrlRetrieval, UiContext = 0
            };
            dataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(trustData, dataPointer, false);
            var status = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, dataPointer);
            return new SignatureInspection(true, status == 0, subject);
        }
        catch { return new SignatureInspection(false, false, string.Empty); }
        finally
        {
            if (dataPointer != IntPtr.Zero) Marshal.FreeHGlobal(dataPointer);
            if (fileInfoPointer != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPointer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid actionId, IntPtr trustData);
}

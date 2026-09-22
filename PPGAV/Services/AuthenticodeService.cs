using System.Security.Cryptography.X509Certificates;

namespace PPGAV.Services;

public sealed record SignatureInspection(bool Signed, bool Trusted, string Subject);

public static class AuthenticodeService
{
    public static SignatureInspection Inspect(string path)
    {
        try
        {
            using var certificate2 = X509CertificateLoader.LoadCertificateFromFile(path);
            using var chain = new X509Chain();
            var trusted = chain.Build(certificate2);
            return new SignatureInspection(true, trusted, certificate2.Subject);
        }
        catch { return new SignatureInspection(false, false, string.Empty); }
    }
}

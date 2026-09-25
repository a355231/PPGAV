using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PPGAV.Services;

/// <summary>DPAPI-authenticated, atomically replaced state for recovery manifests.</summary>
internal static class AuthenticatedStateStore
{
    private sealed record Envelope(int FormatVersion, string ProtectedPayload);
    private const int Version = 1;

    public static void Write<T>(string path, T value)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Authenticated PPGAV state requires Windows DPAPI.");
        var parent = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new InvalidOperationException("State path has no parent directory.");
        SecurePathService.RequireExistingDirectory(parent, "state directory");
        var envelope = new Envelope(Version, ProtectJson(value));
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, envelope);
                stream.Flush(true);
            }
            SecurePathService.RejectReparse(temporary, "state temporary file");
            SecurePathService.MoveFileContained(parent, temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static T Read<T>(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Authenticated PPGAV state requires Windows DPAPI.");
        var parent = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new InvalidOperationException("State path has no parent directory.");
        using var input = SecurePathService.OpenContainedRead(parent, path, "authenticated state file");
        var envelope = JsonSerializer.Deserialize<Envelope>(input) ?? throw new InvalidDataException("Authenticated state envelope is invalid.");
        if (envelope.FormatVersion != Version || string.IsNullOrWhiteSpace(envelope.ProtectedPayload)) throw new InvalidDataException("Authenticated state format is invalid.");
        return UnprotectJson<T>(envelope.ProtectedPayload);
    }

    public static string ProtectJson<T>(T value)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Authenticated PPGAV state requires Windows DPAPI.");
        return Convert.ToBase64String(ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(value), null, DataProtectionScope.CurrentUser));
    }

    public static T UnprotectJson<T>(string protectedPayload)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Authenticated PPGAV state requires Windows DPAPI.");
        try
        {
            var cleartext = ProtectedData.Unprotect(Convert.FromBase64String(protectedPayload), null, DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<T>(Encoding.UTF8.GetString(cleartext)) ?? throw new InvalidDataException("Authenticated state payload is empty.");
        }
        catch (CryptographicException) { throw; }
        catch (Exception ex) when (ex is FormatException or JsonException) { throw new InvalidDataException("Authenticated state payload could not be decoded.", ex); }
    }
}

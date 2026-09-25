using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace PPGAV.Services;

public sealed record UpdateInfo(Version Version, string Tag, Uri MsiUri, string Sha256);

public sealed class UpdateService
{
    private const string LatestReleaseApi = "https://api.github.com/repos/a355231/PPGAV/releases/latest";
    private const int MaximumReleaseMetadataBytes = 8 * 1024 * 1024;
    private const long MaximumUpdateBytes = 512L * 1024 * 1024;
    private readonly HttpClient _http;
    public UpdateService(HttpClient? http = null) { _http = http ?? new HttpClient(); _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("PPGAV", "1.0")); }

    public async Task<UpdateInfo?> CheckLatestAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _http.GetAsync(LatestReleaseApi, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode || response.RequestMessage?.RequestUri is not { Scheme: "https", Host: "api.github.com" } ||
            response.Content.Headers.ContentLength is > MaximumReleaseMetadataBytes) return null;
        await using var metadataStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = JsonDocument.Parse(await ReadBoundedAsync(metadataStream, MaximumReleaseMetadataBytes, cancellationToken));
        var root = document.RootElement;
        var tag = root.GetProperty("tag_name").GetString() ?? string.Empty;
        if (!TryParseVersion(tag, out var version)) return null;
        foreach (var asset in root.GetProperty("assets").EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString() ?? string.Empty;
            var digest = asset.TryGetProperty("digest", out var digestElement) ? digestElement.GetString() : null;
            var url = asset.GetProperty("browser_download_url").GetString();
            if (name.Equals($"PPGAV-{version}.msi", StringComparison.OrdinalIgnoreCase) &&
                Uri.TryCreate(url, UriKind.Absolute, out var uri) && IsPinnedReleaseUri(uri, tag) &&
                digest?.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) == true && digest.Length == 71 && digest[7..].All(Uri.IsHexDigit))
                return new UpdateInfo(version, tag, uri, digest[7..]);
        }
        return null;
    }

    public async Task<string> DownloadAndVerifyAsync(UpdateInfo update, CancellationToken cancellationToken = default)
    {
        var updateDirectory = Path.Combine(AppPaths.Root, "Updates");
        Directory.CreateDirectory(updateDirectory);
        SecurePathService.RequireExistingDirectory(updateDirectory, "update download directory");
        if (!IsPinnedReleaseUri(update.MsiUri, update.Tag) || !update.MsiUri.AbsolutePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Update download URI is not an MSI asset from the pinned GitHub repository release.");
        var path = Path.Combine(updateDirectory, $"PPGAV-{update.Version}.msi");
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using var response = await _http.GetAsync(update.MsiUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();
            if (response.RequestMessage?.RequestUri is not { } finalUri || !IsAllowedReleaseHost(finalUri))
                throw new InvalidDataException("Update asset redirected outside the allowed GitHub release-content hosts.");
            if (response.Content.Headers.ContentLength is > MaximumUpdateBytes) throw new InvalidDataException("Update MSI exceeds the download size limit.");
            await using (var source = await response.Content.ReadAsStreamAsync(cancellationToken))
            await using (var destination = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, useAsync: true))
            {
                var buffer = new byte[65536];
                long total = 0;
                int read;
                while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
                {
                    total = checked(total + read);
                    if (total > MaximumUpdateBytes) throw new InvalidDataException("Update MSI exceeded the download size limit.");
                    await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
                await destination.FlushAsync(cancellationToken);
                destination.Flush(true);
            }
            if (!VerifySha256(temporary, update.Sha256)) throw new InvalidDataException("The downloaded update failed its GitHub release digest verification.");
            SecurePathService.MoveFileContained(updateDirectory, temporary, path, true); return path;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static bool IsNewerVersion(Version candidate, Version current) => candidate > current;
    public static bool VerifySha256(string path, string expectedHex)
    {
        try { using var stream = File.OpenRead(path); return CryptographicOperations.FixedTimeEquals(SHA256.HashData(stream), Convert.FromHexString(expectedHex)); }
        catch { return false; }
    }
    public static bool TryParseVersion(string tag, out Version version)
    {
        var value = tag.Trim().TrimStart('v', 'V');
        return Version.TryParse(value, out version!);
    }

    private static bool IsPinnedReleaseUri(Uri uri, string tag) =>
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) &&
        uri.AbsolutePath.StartsWith($"/a355231/PPGAV/releases/download/{Uri.EscapeDataString(tag)}/", StringComparison.OrdinalIgnoreCase);

    private static bool IsAllowedReleaseHost(Uri uri) => uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host is "github.com" or "objects.githubusercontent.com" or "release-assets.githubusercontent.com";

    private static async Task<byte[]> ReadBoundedAsync(Stream input, int maximumBytes, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
        {
            if (output.Length + read > maximumBytes) throw new InvalidDataException("GitHub release metadata exceeded the response limit.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }
}

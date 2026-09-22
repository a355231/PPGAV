using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace PPGAV.Services;

public sealed record UpdateInfo(Version Version, string Tag, Uri MsiUri, string Sha256);

public sealed class UpdateService
{
    private const string LatestReleaseApi = "https://api.github.com/repos/a355231/PPGAV/releases/latest";
    private readonly HttpClient _http;
    public UpdateService(HttpClient? http = null) { _http = http ?? new HttpClient(); _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("PPGAV", "1.0")); }

    public async Task<UpdateInfo?> CheckLatestAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _http.GetAsync(LatestReleaseApi, cancellationToken);
        if (!response.IsSuccessStatusCode) return null;
        using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));
        var root = document.RootElement;
        var tag = root.GetProperty("tag_name").GetString() ?? string.Empty;
        if (!TryParseVersion(tag, out var version)) return null;
        foreach (var asset in root.GetProperty("assets").EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString() ?? string.Empty;
            var digest = asset.TryGetProperty("digest", out var digestElement) ? digestElement.GetString() : null;
            var url = asset.GetProperty("browser_download_url").GetString();
            if (name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps && digest?.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) == true)
                return new UpdateInfo(version, tag, uri, digest[7..]);
        }
        return null;
    }

    public async Task<string> DownloadAndVerifyAsync(UpdateInfo update, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.Combine(AppPaths.Root, "Updates"));
        var path = Path.Combine(AppPaths.Root, "Updates", $"PPGAV-{update.Version}.msi");
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var source = await _http.GetStreamAsync(update.MsiUri, cancellationToken))
            await using (var destination = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, useAsync: true)) await source.CopyToAsync(destination, cancellationToken);
            if (!VerifySha256(temporary, update.Sha256)) throw new InvalidDataException("The downloaded update failed its GitHub release digest verification.");
            File.Move(temporary, path, true); return path;
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
}

using System.Security.Cryptography;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class IntegrityBaselineService
{
    private readonly string _baselinePath;
    public IntegrityBaselineService(string? baselinePath = null) => _baselinePath = baselinePath ?? Path.Combine(AppPaths.Root, "core-integrity.json");

    public List<ScanFinding> Check(string gameRoot)
    {
        var current = EnumerateCore(gameRoot).ToDictionary(x => x.Path, x => x.Hash, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string>? previous = null;
        try { if (File.Exists(_baselinePath)) previous = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_baselinePath)); } catch { }
        var findings = new List<ScanFinding>();
        if (previous is not null)
        {
            foreach (var changed in current.Where(x => !previous.TryGetValue(x.Key, out var hash) || !string.Equals(hash, x.Value, StringComparison.OrdinalIgnoreCase)))
                findings.Add(new(ScanCategory.Suspicious, changed.Key, "trusted-file-changed", "A core game file differs from the last trusted baseline.", changed.Value, ScanScope.GameCore, 60));
            foreach (var missing in previous.Keys.Except(current.Keys, StringComparer.OrdinalIgnoreCase))
                findings.Add(new(ScanCategory.Suspicious, missing, "trusted-file-missing", "A core game file from the trusted baseline is missing.", string.Empty, ScanScope.GameCore, 60));
        }
        return findings;
    }

    public List<ScanFinding> CheckAndUpdate(string gameRoot)
    {
        var findings = Check(gameRoot);
        if (findings.Count == 0) TrustCurrent(gameRoot);
        return findings;
    }

    public void TrustCurrent(string gameRoot)
    {
        var current = EnumerateCore(gameRoot).ToDictionary(x => x.Path, x => x.Hash, StringComparer.OrdinalIgnoreCase);
        Directory.CreateDirectory(Path.GetDirectoryName(_baselinePath)!);
        File.WriteAllText(_baselinePath, JsonSerializer.Serialize(current, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static IEnumerable<(string Path, string Hash)> EnumerateCore(string root)
    {
        if (!Directory.Exists(root)) yield break;
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(root, file);
            if (relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(x => x.Equals("Mods", StringComparison.OrdinalIgnoreCase) || x.Equals("Workshop", StringComparison.OrdinalIgnoreCase))) continue;
            string hash; try { using var stream = File.OpenRead(file); hash = Convert.ToHexString(SHA256.HashData(stream)); } catch { continue; }
            yield return (Path.GetFullPath(file), hash);
        }
    }
}

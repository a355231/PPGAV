using System.Security.Cryptography;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed record QuarantineItem(string OriginalPath, string QuarantinedPath);

public sealed class QuarantineService
{
    private readonly string _root;
    private sealed record QuarantineManifest(string Owner, int FormatVersion, DateTimeOffset CreatedAt, List<QuarantineRecord> Items);
    private sealed record QuarantineRecord(string OriginalPath, string QuarantinedPath, string Sha256, long Length, DateTime LastWriteUtc, FileAttributes Attributes, string Rules);

    public QuarantineService(string? root = null) => _root = root ?? Path.Combine(AppPaths.Root, "Quarantine");

    public IReadOnlyList<QuarantineItem> Quarantine(ScanReport report, bool allowHeuristic = false)
    {
        var candidates = report.Findings.Where(x => x.Category == ScanCategory.Malware && (allowHeuristic || x.Detection == DetectionKind.Confirmed) && x.Scope is ScanScope.LocalMods or ScanScope.SteamWorkshop or ScanScope.Archive).GroupBy(x => x.FilePath, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).ToList();
        var moved = new List<(QuarantineItem Item, QuarantineRecord Record)>();
        try
        {
            foreach (var finding in candidates)
            {
                var source = SecurePathService.RequireExistingFile(finding.FilePath, "malware candidate");
                if (finding.Scope is ScanScope.GameCore or ScanScope.Unknown) throw new UnauthorizedAccessException("Core or unscoped files are never quarantined.");
                var hash = Hash(source); if (!string.IsNullOrWhiteSpace(finding.Sha256) && !hash.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase)) throw new IOException($"Malware candidate changed before quarantine: {source}");
                var root = Path.GetFullPath(_root); if (SecurePathService.IsWithin(Path.GetDirectoryName(source)!, root)) throw new UnauthorizedAccessException("Quarantine storage must not be inside the scanned content tree.");
                var destination = Path.Combine(root, DateTime.UtcNow.ToString("yyyyMMdd"), Guid.NewGuid().ToString("N") + "-" + Path.GetFileName(source));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!); SecurePathService.RejectReparse(Path.GetDirectoryName(destination)!, "quarantine directory");
                var info = new FileInfo(source); var record = new QuarantineRecord(source, destination, hash, info.Length, info.LastWriteTimeUtc, info.Attributes, string.Join(",", report.Findings.Where(x => string.Equals(x.FilePath, source, StringComparison.OrdinalIgnoreCase)).Select(x => x.Rule).Distinct()));
                File.Move(source, destination); moved.Add((new QuarantineItem(source, destination), record));
            }
            if (moved.Count == 0) return [];
            WriteManifest(moved.Select(x => x.Record).ToList()); return moved.Select(x => x.Item).ToArray();
        }
        catch
        {
            foreach (var item in moved.AsEnumerable().Reverse()) { try { if (!File.Exists(item.Item.OriginalPath) && File.Exists(item.Item.QuarantinedPath)) File.Move(item.Item.QuarantinedPath, item.Item.OriginalPath); } catch { } }
            throw;
        }
    }

    public void Restore(string manifestPath)
    {
        var fullManifest = SecurePathService.RequireExistingFile(manifestPath, "quarantine manifest");
        var manifest = JsonSerializer.Deserialize<QuarantineManifest>(File.ReadAllText(fullManifest)) ?? throw new InvalidDataException("Quarantine manifest is invalid.");
        if (manifest.Owner != "PPGAV" || manifest.FormatVersion != 1 || manifest.Items.Count == 0) throw new InvalidDataException("Quarantine manifest ownership validation failed.");
        foreach (var item in manifest.Items)
        {
            var source = SecurePathService.RequireExistingFile(item.QuarantinedPath, "quarantined file");
            if (!Hash(source).Equals(item.Sha256, StringComparison.OrdinalIgnoreCase) || new FileInfo(source).Length != item.Length) throw new InvalidDataException($"Quarantined file changed: {source}");
            if (File.Exists(item.OriginalPath) || Directory.Exists(item.OriginalPath)) throw new IOException($"Refusing to overwrite existing restore target: {item.OriginalPath}");
            SecurePathService.RejectReparse(Path.GetDirectoryName(item.OriginalPath)!, "restore directory"); Directory.CreateDirectory(Path.GetDirectoryName(item.OriginalPath)!); File.Move(source, item.OriginalPath); File.SetAttributes(item.OriginalPath, item.Attributes); File.SetLastWriteTimeUtc(item.OriginalPath, item.LastWriteUtc);
        }
    }

    private void WriteManifest(List<QuarantineRecord> records)
    {
        var manifestDirectory = Path.Combine(_root, "manifests"); Directory.CreateDirectory(manifestDirectory); var path = Path.Combine(manifestDirectory, DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N") + ".json"); var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try { File.WriteAllText(temp, JsonSerializer.Serialize(new QuarantineManifest("PPGAV", 1, DateTimeOffset.UtcNow, records), new JsonSerializerOptions { WriteIndented = true })); File.Move(temp, path); } finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    private static string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
}

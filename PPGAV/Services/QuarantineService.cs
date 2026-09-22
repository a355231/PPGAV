using PPGAV.Models;

namespace PPGAV.Services;

public sealed record QuarantineItem(string OriginalPath, string QuarantinedPath);

public sealed class QuarantineService
{
    private readonly string _root;
    public QuarantineService(string? root = null) => _root = root ?? Path.Combine(AppPaths.Root, "Quarantine");

    public IReadOnlyList<QuarantineItem> Quarantine(ScanReport report)
    {
        var moved = new List<QuarantineItem>();
        foreach (var file in report.Findings.Where(x => x.Category == ScanCategory.Malware && (x.Scope is ScanScope.LocalMods or ScanScope.SteamWorkshop or ScanScope.Archive)).Select(x => x.FilePath).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!File.Exists(file)) continue;
            var destination = Path.Combine(_root, DateTime.UtcNow.ToString("yyyyMMdd"), Guid.NewGuid().ToString("N") + "-" + Path.GetFileName(file));
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Move(file, destination);
                File.WriteAllText(destination + ".origin", file);
                moved.Add(new(file, destination));
            }
            catch { }
        }
        return moved;
    }
}

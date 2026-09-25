using PPGAV.Models;

namespace PPGAV.Services;

/// <summary>
/// Single source of truth for how paths inside a People Playground installation are classified.
/// Only the first path segment below the game root is considered, so a nested folder that happens
/// to be named "Mods" inside core game data cannot downgrade a core finding to a mod finding.
/// </summary>
public static class GameLayout
{
    /// <summary>Top-level folders that hold untrusted mod code; Malware Safe Mode disables all of them.</summary>
    public static IReadOnlyList<string> ModDirectoryNames { get; } = ["Mods", "Workshop", "CompiledMods"];

    /// <summary>Top-level entries People Playground rewrites during normal play (settings, saves, logs).</summary>
    private static readonly HashSet<string> RuntimeDataNames = new(StringComparer.OrdinalIgnoreCase)
        { "Contraptions", "Logs", "tmp", "config.json", "externalactives" };

    public static ScanScope ScopeFor(string gameRoot, string path)
    {
        var first = FirstSegment(gameRoot, path);
        if (first is null) return ScanScope.GameCore;
        if (first.Equals("Workshop", StringComparison.OrdinalIgnoreCase)) return ScanScope.SteamWorkshop;
        if (first.Equals("Mods", StringComparison.OrdinalIgnoreCase) || first.Equals("CompiledMods", StringComparison.OrdinalIgnoreCase)) return ScanScope.LocalMods;
        return ScanScope.GameCore;
    }

    public static bool IsModContent(string gameRoot, string path) => ScopeFor(gameRoot, path) is ScanScope.LocalMods or ScanScope.SteamWorkshop;

    /// <summary>
    /// CompiledMods holds assemblies the game's own mod compiler generated from scanned mod source, so
    /// DLLs there are expected; they are still inspected (AMSI, markers, capability strings) as mod code.
    /// </summary>
    public static bool IsCompiledModCache(string gameRoot, string path) =>
        string.Equals(FirstSegment(gameRoot, path), "CompiledMods", StringComparison.OrdinalIgnoreCase);

    /// <summary>True for game-written settings/saves/logs that legitimately change between sessions.</summary>
    public static bool IsRuntimeData(string gameRoot, string path) => FirstSegment(gameRoot, path) is { } first && RuntimeDataNames.Contains(first);

    public static IEnumerable<string> ModDirectories(string gameRoot) => ModDirectoryNames.Select(name => Path.Combine(gameRoot, name));

    private static string? FirstSegment(string root, string path)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
        if (relative == "." || Path.IsPathRooted(relative)) return null;
        var first = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)[0];
        return first == ".." ? null : first;
    }
}

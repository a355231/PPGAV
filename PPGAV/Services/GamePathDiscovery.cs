using Microsoft.Win32;

namespace PPGAV.Services;

public static class GamePathDiscovery
{
    private const string GameFolderName = "People Playground";
    private const string ExecutableName = "People Playground.exe";

    public static string? FindGameDirectory()
    {
        foreach (var root in EnumerateSteamRoots())
        {
            var candidate = Path.Combine(root, "steamapps", "common", GameFolderName);
            if (File.Exists(Path.Combine(candidate, ExecutableName)))
            {
                return candidate;
            }
        }

        return null;
    }

    public static string? FindExecutable(string? gameDirectory)
    {
        if (string.IsNullOrWhiteSpace(gameDirectory))
        {
            return null;
        }

        var path = Path.Combine(gameDirectory, ExecutableName);
        return File.Exists(path) ? path : null;
    }

    public static IReadOnlyList<string> FindWorkshopDirectories(string? gameDirectory = null)
    {
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(gameDirectory))
        {
            var full = Path.GetFullPath(gameDirectory);
            var marker = $"{Path.DirectorySeparatorChar}steamapps{Path.DirectorySeparatorChar}common{Path.DirectorySeparatorChar}";
            var index = full.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index >= 0) results.Add(Path.Combine(full[..(index + "\\steamapps".Length)], "workshop", "content", "1118200"));
        }
        foreach (var root in EnumerateSteamRoots()) results.Add(Path.Combine(root, "steamapps", "workshop", "content", "1118200"));
        return results.Where(Directory.Exists).ToArray();
    }

    private static IEnumerable<string> EnumerateSteamRoots()
    {
        var pending = new Queue<string>();
        var queued = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddRoot(string? root)
        {
            if (string.IsNullOrWhiteSpace(root)) return;
            try
            {
                var full = Path.GetFullPath(root.Trim().Trim('"'));
                if (Path.IsPathRooted(full) && queued.Add(full)) pending.Enqueue(full);
            }
            catch { }
        }

        foreach (var root in new[]
        {
            @"C:\Program Files (x86)\Steam",
            @"C:\Program Files\Steam",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Steam")
        }) AddRoot(root);

        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(@"SOFTWARE\Valve\Steam");
                    var installPath = key?.GetValue("InstallPath") as string;
                    AddRoot(installPath);
                }
                catch
                {
                    // Registry access is optional; common paths are still checked.
                }
            }
        }

        var discovered = 0;
        while (pending.Count > 0 && discovered < 32)
        {
            var root = pending.Dequeue();
            if (!Directory.Exists(root)) continue;
            discovered++;
            yield return root;

            var libraryFile = Path.Combine(root, "steamapps", "libraryfolders.vdf");
            try
            {
                var info = new FileInfo(libraryFile);
                if (!info.Exists || info.Length <= 0 || info.Length > 2 * 1024 * 1024) continue;
                var text = File.ReadAllText(libraryFile);
                foreach (System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(
                             text,
                             @"""path""\s+""(?<path>[^""]+)""",
                             System.Text.RegularExpressions.RegexOptions.IgnoreCase,
                             TimeSpan.FromMilliseconds(250)))
                {
                    AddRoot(match.Groups["path"].Value.Replace("\\\\", "\\"));
                    if (queued.Count >= 32) break;
                }
            }
            catch { /* Steam discovery is optional; one malformed/inaccessible library must not abort startup. */ }
        }
    }
}

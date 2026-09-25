namespace PPGAV.Services;

public static class AppPaths
{
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PPGAV");
    public static string SettingsFile => Path.Combine(Root, "settings.json");
    public static string EventLogFile => Path.Combine(Root, "events.jsonl");
    public static string StartupShortcut => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "PPGAV.lnk");
    public static string SandboxFolder => Path.Combine(Root, "Sandbox");
    public static string RestoreSafetyFolder => Path.Combine(Root, "RestoreSafety");

    public static void EnsureDirectories()
    {
        EnsureOwnedDirectory(Root, null);
        EnsureOwnedDirectory(SandboxFolder, Root);
        EnsureOwnedDirectory(RestoreSafetyFolder, Root);
    }

    private static void EnsureOwnedDirectory(string path, string? parent)
    {
        if (!Directory.Exists(path)) Directory.CreateDirectory(path);
        if (parent is null) SecurePathService.RequireExistingDirectory(path, "PPGAV application data directory");
        else SecurePathService.RequireContained(parent, path, true, "PPGAV application data subdirectory");
    }
}

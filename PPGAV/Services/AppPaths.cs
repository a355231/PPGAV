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
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(SandboxFolder);
        Directory.CreateDirectory(RestoreSafetyFolder);
    }
}

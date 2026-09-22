using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class SettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public SettingsService()
    {
        AppPaths.EnsureDirectories();
    }

    public AppSettings Load()
    {
        try
        {
            if (File.Exists(AppPaths.SettingsFile))
            {
                var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(AppPaths.SettingsFile), JsonOptions) ?? CreateDefaults();
                settings.Normalize();
                return settings;
            }
        }
        catch
        {
            // A corrupt settings file should never prevent the protective UI from starting.
        }

        return CreateDefaults();
    }

    public void Save(AppSettings settings)
    {
        settings.Normalize();
        AppPaths.EnsureDirectories();
        var temporary = AppPaths.SettingsFile + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(settings, JsonOptions));
        File.Move(temporary, AppPaths.SettingsFile, true);
    }

    private static AppSettings CreateDefaults()
    {
        var gameDirectory = GamePathDiscovery.FindGameDirectory() ?? string.Empty;
        var executable = GamePathDiscovery.FindExecutable(gameDirectory) ?? string.Empty;
        return new AppSettings
        {
            GameDirectory = gameDirectory,
            PpgExecutablePath = executable,
            BackupDirectory = Path.Combine(AppPaths.Root, "Backups")
        };
    }
}

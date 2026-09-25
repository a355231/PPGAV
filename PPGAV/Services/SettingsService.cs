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
                using var input = SecurePathService.OpenContainedRead(AppPaths.Root, AppPaths.SettingsFile, "PPGAV settings file");
                if (input.Length > 1024 * 1024) throw new InvalidDataException("Settings exceed the configured size limit.");
                using var reader = new StreamReader(input);
                var settings = JsonSerializer.Deserialize<AppSettings>(reader.ReadToEnd(), JsonOptions) ?? CreateDefaults();
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
        var temporary = AppPaths.SettingsFile + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 16384, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(output)) { writer.Write(JsonSerializer.Serialize(settings, JsonOptions)); writer.Flush(); output.Flush(true); }
            SecurePathService.MoveFileContained(AppPaths.Root, temporary, AppPaths.SettingsFile, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
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

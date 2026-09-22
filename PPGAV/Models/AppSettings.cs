namespace PPGAV.Models;

public sealed class AppSettings
{
    public string GameDirectory { get; set; } = string.Empty;
    public string PpgExecutablePath { get; set; } = string.Empty;
    public string BackupDirectory { get; set; } = string.Empty;
    public int BackupIntervalHours { get; set; } = 2;
    public int BackupRetentionCount { get; set; } = 8;
    public bool StartWithWindows { get; set; } = true;
    public bool StartMinimized { get; set; } = false;
    public bool ScanBeforeLaunch { get; set; } = true;
    public bool WatchProcess { get; set; } = true;
    public bool UseWindowsSandbox { get; set; } = true;
    public bool RequireNetworkBlockInSafeMode { get; set; } = true;

    public void Normalize()
    {
        BackupIntervalHours = Math.Clamp(BackupIntervalHours, 1, 24);
        BackupRetentionCount = Math.Clamp(BackupRetentionCount, 1, 100);
        GameDirectory = NormalizePath(GameDirectory);
        PpgExecutablePath = NormalizePath(PpgExecutablePath);
        BackupDirectory = NormalizePath(BackupDirectory);
    }

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        try
        {
            return Path.GetFullPath(Environment.ExpandEnvironmentVariables(value.Trim().Trim('"')));
        }
        catch
        {
            return value.Trim().Trim('"');
        }
    }
}

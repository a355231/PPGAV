namespace PPGAV.Models;

public enum ScanCategory
{
    Safe,
    Suspicious,
    Malware
}

public enum ScanScope { Unknown, GameCore, LocalMods, SteamWorkshop, Archive }
public enum PreflightAction { AllowSecure, LaunchSafeMode, BlockAll }
public enum SandboxProvider { None, WindowsSandbox, SandboxieClassic }

public sealed record ScanFinding(
    ScanCategory Category,
    string FilePath,
    string Rule,
    string Detail,
    string Sha256,
    ScanScope Scope = ScanScope.Unknown,
    int RiskScore = 0);

public sealed class ScanReport
{
    public string RootPath { get; init; } = string.Empty;
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset CompletedAt { get; set; }
    public int FilesInspected { get; set; }
    public List<ScanFinding> Findings { get; } = [];
    public List<string> Errors { get; } = [];

    public ScanCategory Category => Findings.Any(f => f.Category == ScanCategory.Malware)
        ? ScanCategory.Malware
        : Findings.Any(f => f.Category == ScanCategory.Suspicious)
            ? ScanCategory.Suspicious
            : ScanCategory.Safe;

    public int Count(ScanCategory category) => Findings.Count(f => f.Category == category);
    public bool HasMalware => Category == ScanCategory.Malware;
    public bool HasCoreFinding => Findings.Any(f => f.Scope is ScanScope.GameCore or ScanScope.Unknown);
}

public sealed record BehaviorAlert(
    ScanCategory Category,
    string Title,
    string Detail,
    bool StopRequired);

public sealed record BackupInfo(string Path, DateTimeOffset CreatedAt, long SizeBytes);

public sealed record DefenderScanResult(bool Started, int ExitCode, string ExecutablePath, string Output);

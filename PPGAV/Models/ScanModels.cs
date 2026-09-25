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
    int RiskScore = 0,
    DetectionKind Detection = DetectionKind.Heuristic);

public enum DetectionKind { Heuristic, Confirmed }

public sealed class ScanReport
{
    public string RootPath { get; init; } = string.Empty;
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset CompletedAt { get; set; }
    public int FilesInspected { get; set; }
    public List<ScanFinding> Findings { get; } = [];
    public List<string> Errors { get; } = [];
    public List<string> SkippedPaths { get; } = [];
    public Dictionary<string, string> ScannedHashes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> ScannedRoots { get; } = [];
    public long BytesInspected { get; set; }
    public bool IsComplete { get; set; }
    public bool Cancelled { get; set; }

    public ScanCategory Category => !IsComplete || SkippedPaths.Count > 0 || Errors.Count > 0
        ? Findings.Any(f => f.Category == ScanCategory.Malware) ? ScanCategory.Malware : ScanCategory.Suspicious
        : Findings.Any(f => f.Category == ScanCategory.Malware)
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

public sealed record DefenderScanResult(bool Started, int ExitCode, string ExecutablePath, string Output,
    bool StatusVerified = false, bool ThreatsDetected = true, bool ProtectionEnabled = false, bool SignaturesCurrent = false)
{
    public bool IsClean => Started && ExitCode == 0 && StatusVerified && !ThreatsDetected && ProtectionEnabled && SignaturesCurrent;

    /// <summary>
    /// True only when Defender positively reported a threat (MpCmdRun exit code 2, or a verified
    /// active-threat record). <see cref="ThreatsDetected"/> defaults to true for fail-closed
    /// <see cref="IsClean"/> checks and must not be reported to the user as a detection.
    /// </summary>
    public bool ThreatConfirmed => Started && (ExitCode == 2 || StatusVerified && ThreatsDetected);
}

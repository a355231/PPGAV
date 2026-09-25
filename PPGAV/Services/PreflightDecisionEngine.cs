using PPGAV.Models;

namespace PPGAV.Services;

public static class PreflightDecisionEngine
{
    public static PreflightAction Decide(ScanReport report, bool defenderClean = false)
    {
        if (!defenderClean || !report.IsComplete || report.Errors.Count > 0 || report.SkippedPaths.Count > 0 ||
            report.Findings.Any(f => f.Scope is ScanScope.GameCore or ScanScope.Unknown))
            return PreflightAction.BlockAll;
        return report.Findings.Any(f => f.Category != ScanCategory.Safe) ? PreflightAction.LaunchSafeMode : PreflightAction.AllowSecure;
    }
}

public static class SandboxProviderSelector
{
    public static SandboxProvider Choose(bool windowsSandboxAvailable, bool sandboxieAvailable) =>
        windowsSandboxAvailable ? SandboxProvider.WindowsSandbox : sandboxieAvailable ? SandboxProvider.SandboxieClassic : SandboxProvider.None;
}

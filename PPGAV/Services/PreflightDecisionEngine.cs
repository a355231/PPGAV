using PPGAV.Models;

namespace PPGAV.Services;

public static class PreflightDecisionEngine
{
    public static PreflightAction Decide(ScanReport report, bool defenderClean = true)
    {
        if (!defenderClean || report.Errors.Count > 0 || report.HasCoreFinding && report.Findings.Count > 0)
            return PreflightAction.BlockAll;
        return report.Findings.Count > 0 ? PreflightAction.LaunchSafeMode : PreflightAction.AllowSecure;
    }
}

public static class SandboxProviderSelector
{
    public static SandboxProvider Choose(bool windowsSandboxAvailable, bool sandboxieAvailable) =>
        windowsSandboxAvailable ? SandboxProvider.WindowsSandbox : sandboxieAvailable ? SandboxProvider.SandboxieClassic : SandboxProvider.None;
}

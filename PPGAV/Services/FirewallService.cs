using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace PPGAV.Services;

public sealed class FirewallService : IOutboundNetworkBlocker
{
    private readonly EventLogService _events;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _rules = new(StringComparer.OrdinalIgnoreCase);

    public FirewallService(EventLogService events)
    {
        _events = events;
    }

    public string RuleNameFor(string executablePath) => $"PPGAV Safe Mode {Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(executablePath))))[..12]}-{Guid.NewGuid():N}";

    public bool TryBlockOutbound(string executablePath, out string ruleName)
    {
        ruleName = RuleNameFor(executablePath);
        var arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block program=\"{Path.GetFullPath(executablePath)}\" enable=yes profile=any protocol=any";
        var success = RunElevated(arguments);
        if (success) _rules[Path.GetFullPath(executablePath)] = ruleName;
        if (success) _events.Log("Network isolation enabled", "Outbound connections for People Playground are blocked for Malware Safe Mode.");
        else _events.Log("Network isolation unavailable", "Windows Firewall could not create the Malware Safe Mode rule. Safe launch was refused.", Models.ScanCategory.Suspicious);
        return success;
    }

    public bool TryRemove(string executablePath)
    {
        return _rules.TryGetValue(Path.GetFullPath(executablePath), out var ruleName) && TryRemoveRule(ruleName);
    }

    public bool TryRemoveRule(string ruleName) => RunElevated($"advfirewall firewall delete rule name=\"{ruleName}\"") && VerifyAbsent(ruleName);

    private static bool RunElevated(string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"),
                Arguments = arguments,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true
            });
            if (process is null) return false;
            if (!process.WaitForExit(15000)) { try { process.Kill(true); } catch { } return false; }
            return process.HasExited && process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyAbsent(string ruleName)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo { FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"), Arguments = $"advfirewall firewall show rule name=\"{ruleName}\"", UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true });
            if (process is null || !process.WaitForExit(10000)) { try { process?.Kill(true); } catch { } return false; }
            return process.ExitCode != 0 || !process.StandardOutput.ReadToEnd().Contains(ruleName, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}

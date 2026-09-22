using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace PPGAV.Services;

public sealed class FirewallService : IOutboundNetworkBlocker
{
    private readonly EventLogService _events;

    public FirewallService(EventLogService events)
    {
        _events = events;
    }

    public string RuleNameFor(string executablePath)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(executablePath))))[..12];
        return $"PPGAV Safe Mode {hash}";
    }

    public bool TryBlockOutbound(string executablePath, out string ruleName)
    {
        ruleName = RuleNameFor(executablePath);
        var arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block program=\"{Path.GetFullPath(executablePath)}\" enable=yes profile=any";
        var success = RunElevated(arguments);
        if (success) _events.Log("Network isolation enabled", "Outbound connections for People Playground are blocked for Malware Safe Mode.");
        else _events.Log("Network isolation unavailable", "Windows Firewall could not create the Malware Safe Mode rule. Safe launch was refused.", Models.ScanCategory.Suspicious);
        return success;
    }

    public bool TryRemove(string executablePath)
    {
        var ruleName = RuleNameFor(executablePath);
        return RunElevated($"advfirewall firewall delete rule name=\"{ruleName}\"");
    }

    private static bool RunElevated(string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true
            });
            if (process is null) return false;
            process.WaitForExit(15000);
            return process.HasExited && process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}

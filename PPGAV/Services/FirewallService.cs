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
        var executable = SecurePathService.RequireExistingFile(executablePath, "firewall target executable");
        ruleName = RuleNameFor(executablePath);
        var arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block program=\"{executable}\" enable=yes profile=any protocol=any localip=any remoteip=any localport=any remoteport=any";
        var success = RunElevated(arguments);
        if (success) success = VerifyPresent(ruleName, executable);
        if (success) _rules[Path.GetFullPath(executablePath)] = ruleName;
        if (success) _events.Log("Main-executable firewall rule verified", "Windows Firewall reports an outbound block rule for the People Playground executable. Child-process traffic is not covered by this rule.", Models.ScanCategory.Suspicious);
        else _events.Log("Network isolation unavailable", "Windows Firewall could not create the Malware Safe Mode rule. Safe launch was refused.", Models.ScanCategory.Suspicious);
        if (!success && ruleName.StartsWith("PPGAV Safe Mode ", StringComparison.Ordinal)) _ = TryRemoveRule(ruleName);
        return success;
    }

    public bool TryRemove(string executablePath)
    {
        return _rules.TryGetValue(Path.GetFullPath(executablePath), out var ruleName) && TryRemoveRule(ruleName);
    }

    public bool TryRemoveRule(string ruleName)
    {
        if (!IsOwnedRuleName(ruleName)) return false;
        _ = RunElevated($"advfirewall firewall delete rule name=\"{ruleName}\"");
        var absent = VerifyAbsent(ruleName);
        if (absent)
        {
            foreach (var item in _rules.Where(x => x.Value.Equals(ruleName, StringComparison.OrdinalIgnoreCase)).ToArray()) _rules.TryRemove(item.Key, out _);
            _events.Log("Firewall cleanup verified", $"Owned rule {ruleName} is absent.");
        }
        else _events.Log("Firewall cleanup failed", $"Could not verify removal of owned rule {ruleName}; cleanup remains required.", Models.ScanCategory.Suspicious);
        return absent;
    }

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
            if (!TryQuery(ruleName, out var output, out var exitCode)) return false;
            if (output.Contains(ruleName, StringComparison.OrdinalIgnoreCase)) return false;
            return exitCode == 0 || output.Contains("No rules match the specified criteria", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool VerifyPresent(string ruleName, string executable)
    {
        try
        {
            if (!TryQuery(ruleName, out var output, out var exitCode) || exitCode != 0) return false;
            return output.Contains(ruleName, StringComparison.OrdinalIgnoreCase) && output.Contains(executable, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool TryQuery(string ruleName, out string output, out int exitCode)
    {
        output = string.Empty; exitCode = -1;
        if (!IsOwnedRuleName(ruleName)) return false;
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"),
            Arguments = $"advfirewall firewall show rule name=\"{ruleName}\" verbose",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        });
        if (process is null) return false;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(10000))
        {
            try { process.Kill(true); } catch { }
            try { process.WaitForExit(5000); } catch { }
            return false;
        }
        Task.WaitAll(stdout, stderr);
        output = stdout.Result + Environment.NewLine + stderr.Result;
        exitCode = process.ExitCode;
        return true;
    }

    private static bool IsOwnedRuleName(string ruleName) =>
        !string.IsNullOrWhiteSpace(ruleName) && ruleName.StartsWith("PPGAV Safe Mode ", StringComparison.Ordinal) &&
        ruleName.Length <= 96 && ruleName.All(c => char.IsAsciiLetterOrDigit(c) || c is ' ' or '-');
}

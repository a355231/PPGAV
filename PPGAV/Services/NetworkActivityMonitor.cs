using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

namespace PPGAV.Services;

public sealed record NetworkEndpoint(string Protocol, string Local, string Remote, int ProcessId);

public static class NetworkActivityMonitor
{
    private static readonly Regex Line = new(@"^(?<protocol>TCP|UDP)\s+(?<local>\S+)\s+(?<remote>\S+)(?:\s+\S+)?\s+(?<pid>\d+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    public static IReadOnlyList<NetworkEndpoint> ParseNetstat(IEnumerable<string> lines) => lines.Select(x => Line.Match(x.Trim())).Where(x => x.Success).Select(x => new NetworkEndpoint(x.Groups["protocol"].Value.ToUpperInvariant(), x.Groups["local"].Value, x.Groups["remote"].Value, int.Parse(x.Groups["pid"].Value))).ToArray();

    public static IReadOnlyList<NetworkEndpoint> Snapshot()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netstat.exe"), "-ano") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true });
            if (process is null) return [];
            var output = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(3000)) { try { process.Kill(true); } catch { } return []; }
            var lines = output.GetAwaiter().GetResult().SplitLines();
            return ParseNetstat(lines);
        }
        catch { return []; }
    }
}

internal static class StringLineExtensions
{
    public static string[] SplitLines(this string value) => value.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);
}

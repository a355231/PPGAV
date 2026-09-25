using System.Diagnostics;
using System.Text.RegularExpressions;

namespace PPGAV.Services;

public sealed record NetworkEndpoint(string Protocol, string Local, string Remote, int ProcessId);

public static class NetworkActivityMonitor
{
    private static readonly Regex Line = new(@"^(?<protocol>TCP|UDP)\s+(?<local>\S+)\s+(?<remote>\S+)(?:\s+\S+)?\s+(?<pid>\d+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));

    public static IReadOnlyList<NetworkEndpoint> ParseNetstat(IEnumerable<string> lines)
    {
        var result = new List<NetworkEndpoint>();
        foreach (var line in lines)
        {
            var match = Line.Match(line.Trim());
            if (match.Success && int.TryParse(match.Groups["pid"].Value, out var pid))
                result.Add(new NetworkEndpoint(match.Groups["protocol"].Value.ToUpperInvariant(), match.Groups["local"].Value, match.Groups["remote"].Value, pid));
        }
        return result;
    }

    public static IReadOnlyList<NetworkEndpoint> Snapshot()
    {
        if (!TrySnapshot(out var endpoints, out var error)) throw new IOException(error);
        return endpoints;
    }

    public static bool TrySnapshot(out IReadOnlyList<NetworkEndpoint> endpoints, out string error)
    {
        endpoints = [];
        error = string.Empty;
        var netstat = Path.Combine(Environment.SystemDirectory, "netstat.exe");
        try
        {
            if (!File.Exists(netstat)) throw new FileNotFoundException("System netstat.exe was not found.", netstat);
            using var process = Process.Start(new ProcessStartInfo(SecurePathService.RequireExistingFile(netstat, "Windows netstat utility"), "-ano")
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = Environment.SystemDirectory
            });
            if (process is null) throw new IOException("Could not start system netstat.exe.");
            var output = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(3000))
            {
                try { process.Kill(true); process.WaitForExit(1000); } catch { }
                throw new TimeoutException("netstat.exe exceeded its 3-second deadline.");
            }
            var errorText = stderr.GetAwaiter().GetResult();
            if (process.ExitCode != 0) throw new IOException($"netstat.exe exited with code {process.ExitCode}: {errorText}");
            endpoints = ParseNetstat(output.GetAwaiter().GetResult().SplitLines());
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }
}

internal static class StringLineExtensions
{
    public static string[] SplitLines(this string value) => value.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);
}

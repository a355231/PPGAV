using System.Diagnostics;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class DefenderService
{
    private readonly EventLogService _events;

    public DefenderService(EventLogService events)
    {
        _events = events;
    }

    public string? FindMpCmdRun()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var root = Path.Combine(programData, "Microsoft", "Windows Defender", "Platform");
        try
        {
            var latest = Directory.Exists(root)
                ? Directory.GetDirectories(root).OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase)
                    .Select(path => Path.Combine(path, "MpCmdRun.exe")).FirstOrDefault(File.Exists)
                : null;
            if (latest is not null) return latest;
        }
        catch { }

        var fallback = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32", "MpCmdRun.exe");
        return File.Exists(fallback) ? fallback : null;
    }

    public async Task<DefenderScanResult> RunFullScanAsync(string? customPath = null, CancellationToken cancellationToken = default)
    {
        var executable = FindMpCmdRun();
        if (executable is null)
        {
            _events.Log("Defender unavailable", "Windows Defender command-line scanner was not found.", ScanCategory.Suspicious);
            return new DefenderScanResult(false, -1, string.Empty, "MpCmdRun.exe was not found.");
        }

        var psi = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(executable) ?? Environment.SystemDirectory
        };
        if (!string.IsNullOrWhiteSpace(customPath) && (File.Exists(customPath) || Directory.Exists(customPath)))
        {
            psi.ArgumentList.Add("-Scan");
            psi.ArgumentList.Add("-ScanType");
            psi.ArgumentList.Add("3");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(Path.GetFullPath(customPath));
        }
        else
        {
            psi.ArgumentList.Add("-Scan");
            psi.ArgumentList.Add("-ScanType");
            psi.ArgumentList.Add("2");
        }

        try
        {
            using var process = Process.Start(psi);
            if (process is null) return new DefenderScanResult(false, -1, executable, "Could not start MpCmdRun.exe.");
            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            var output = (await outputTask) + Environment.NewLine + (await errorTask);
            _events.Log("Defender scan finished", $"Windows Defender returned exit code {process.ExitCode}.", process.ExitCode == 0 ? ScanCategory.Safe : ScanCategory.Suspicious);
            return new DefenderScanResult(true, process.ExitCode, executable, output.Trim());
        }
        catch (Exception ex)
        {
            _events.Log("Defender scan failed", ex.Message, ScanCategory.Suspicious);
            return new DefenderScanResult(false, -1, executable, ex.Message);
        }
    }
}

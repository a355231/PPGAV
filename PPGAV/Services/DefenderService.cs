using System.Diagnostics;
using System.Text.Json;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class DefenderService
{
    private readonly EventLogService _events;
    private const string StatusScript = "$ErrorActionPreference='Stop'; Import-Module Defender -ErrorAction Stop; $s=Get-MpComputerStatus -ErrorAction Stop; $t=@(Get-MpThreat -ErrorAction Stop); $a=@($t | Where-Object { $_.IsActive -eq $true }).Count; $age=[math]::Floor(((Get-Date)-$s.AntivirusSignatureLastUpdated).TotalHours); [pscustomobject]@{AntivirusEnabled=[bool]$s.AntivirusEnabled;RealTimeProtectionEnabled=[bool]$s.RealTimeProtectionEnabled;ActiveThreatCount=[int]$a;SignatureAgeHours=[int]$age}|ConvertTo-Json -Compress";

    public DefenderService(EventLogService events) => _events = events;

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
            if (latest is not null) return SecurePathService.RequireExistingFile(latest, "Microsoft Defender scanner");
        }
        catch { }
        var fallback = Path.Combine(Environment.SystemDirectory, "MpCmdRun.exe");
        try { return File.Exists(fallback) ? SecurePathService.RequireExistingFile(fallback, "Microsoft Defender scanner") : null; }
        catch { return null; }
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
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(executable) ?? Environment.SystemDirectory
        };
        if (!string.IsNullOrWhiteSpace(customPath))
        {
            var full = Path.GetFullPath(customPath);
            if (!File.Exists(full) && !Directory.Exists(full)) return new DefenderScanResult(false, -1, executable, "Requested Defender scan path does not exist.");
            psi.ArgumentList.Add("-Scan"); psi.ArgumentList.Add("-ScanType"); psi.ArgumentList.Add("3"); psi.ArgumentList.Add("-File"); psi.ArgumentList.Add(full);
        }
        else { psi.ArgumentList.Add("-Scan"); psi.ArgumentList.Add("-ScanType"); psi.ArgumentList.Add("2"); }

        Process? running = null;
        try
        {
            running = Process.Start(psi);
            if (running is null) return new DefenderScanResult(false, -1, executable, "Could not start MpCmdRun.exe.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromMinutes(15));
            var outputTask = running.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = running.StandardError.ReadToEndAsync(timeout.Token);
            await running.WaitForExitAsync(timeout.Token);
            var output = (await outputTask) + Environment.NewLine + (await errorTask);
            if (running.ExitCode != 0)
            {
                _events.Log("Defender scan failed", $"Microsoft Defender returned exit code {running.ExitCode}.", ScanCategory.Suspicious);
                return new DefenderScanResult(true, running.ExitCode, executable, output.Trim());
            }

            var status = await QueryDefenderStatusAsync(cancellationToken);
            var result = new DefenderScanResult(true, running.ExitCode, executable,
                string.Join(Environment.NewLine, new[] { output.Trim(), status.Output }.Where(x => !string.IsNullOrWhiteSpace(x))),
                status.Verified, status.ThreatsDetected, status.ProtectionEnabled, status.SignaturesCurrent);
            var category = result.IsClean ? ScanCategory.Safe : ScanCategory.Suspicious;
            _events.Log("Defender scan finished", result.IsClean
                ? "Microsoft Defender scan completed, active-threat state is empty, real-time protection is enabled, and signatures are current."
                : $"Microsoft Defender could not establish a clean state (status verified={status.Verified}, active threat={status.ThreatsDetected}, protection={status.ProtectionEnabled}, signatures current={status.SignaturesCurrent}).", category);
            return result;
        }
        catch (Exception ex)
        {
            try { if (running is not null && !running.HasExited) running.Kill(true); } catch { }
            _events.Log("Defender scan failed", ex.Message, ScanCategory.Suspicious);
            return new DefenderScanResult(false, -1, executable, ex.Message);
        }
        finally { running?.Dispose(); }
    }

    private static async Task<(bool Verified, bool ThreatsDetected, bool ProtectionEnabled, bool SignaturesCurrent, string Output)> QueryDefenderStatusAsync(CancellationToken cancellationToken)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell)) return (false, true, false, false, "Windows PowerShell status query is unavailable.");
        var psi = new ProcessStartInfo(SecurePathService.RequireExistingFile(powershell, "Windows PowerShell"))
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory
        };
        foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", StatusScript }) psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi);
        if (process is null) return (false, true, false, false, "Windows PowerShell status query could not start.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token); var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
        try { await process.WaitForExitAsync(timeout.Token); }
        catch { try { if (!process.HasExited) process.Kill(true); } catch { } throw; }
        var output = await stdout; var error = await stderr;
        if (process.ExitCode != 0) return (false, true, false, false, $"Defender status query failed: {error.Trim()}");
        try
        {
            using var json = JsonDocument.Parse(output);
            var root = json.RootElement;
            var enabled = root.GetProperty("AntivirusEnabled").GetBoolean() && root.GetProperty("RealTimeProtectionEnabled").GetBoolean();
            var count = root.GetProperty("ActiveThreatCount").GetInt32();
            var signatureAge = root.GetProperty("SignatureAgeHours").GetInt32();
            return (true, count > 0, enabled, signatureAge is >= 0 and <= 168,
                $"Defender status: active threats={count}; real-time protection={enabled}; signature age={signatureAge}h.");
        }
        catch (Exception ex) { return (false, true, false, false, $"Defender returned an unreadable status record: {ex.Message}"); }
    }
}

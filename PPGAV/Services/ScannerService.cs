using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class ScannerService
{
    private sealed record Rule(string Name, string Pattern, int Score, string Detail);
    private static readonly Regex KnownMalware = Rx(@"FPS\s*\+{2,5}|FPSPlusPlus|jJ9aatj9|RejectShadyCode\s*=\s*false|FPSPlusPlusPlusPlusPlus");
    private static readonly Rule[] Rules =
    [
        new("credential-theft", @"Login Data|Local State|Cookies|Web Data|passwords?|tokens?|discord|wallet|Steam\\config|ssfn\d+", 55, "References credentials, browser, Discord, wallet, or Steam secrets."),
        new("network-access/data-exfiltration", @"webhook|HttpClient|WebClient|HttpWebRequest|TcpClient|UdpClient|Socket|Upload(String|Data|File)|PostAsync", 25, "Can communicate with or upload data to the network."),
        new("persistence", @"CurrentVersion\\Run|Startup|schtasks|TaskScheduler|CreateService|ServiceController|Winlogon|Registry.*(SetValue|CreateSubKey)", 55, "Can establish Windows persistence."),
        new("process-injection", @"OpenProcess|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|SetThreadContext|NtMapViewOfSection", 80, "Contains process-injection primitives."),
        new("security-tampering", @"Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|WinDefend|SecurityHealth|firewall.*(disable|off)|bcdedit|NtRaiseHardError", 80, "Attempts to weaken Windows security or system stability."),
        new("destructive-io", @"(File|Directory)\s*\.\s*(Delete|Move)\b|DeleteFile|SHFileOperation|Format-Volume|Remove-Item\s+-Recurse", 35, "Can delete or destructively move files."),
        new("dynamic-code", @"Assembly\s*\.\s*(Load|LoadFrom)|AppDomain\s*\.\s*Load|Reflection\.Emit|CSharpCodeProvider|DynamicMethod", 30, "Dynamically loads or generates code."),
        new("encoded-payload", @"FromBase64String|DeflateStream|GZipStream|BinaryFormatter|Invoke-Expression|powershell(.exe)?\s+.*-(enc|encodedcommand)", 30, "Contains an encoded, compressed, or interpreted payload chain."),
        new("process-launch", @"Process\s*\.\s*Start|ProcessStartInfo|CreateProcess|ShellExecute|cmd\.exe|powershell\.exe|rundll32|regsvr32|mshta", 25, "Can launch external programs or living-off-the-land tools."),
        new("workshop-modification", @"CreateCommunityFile|SubmitItemUpdate|SteamUGC|workshop\\content|ResetAll|WithContent", 30, "Can modify Steam Workshop content or data."),
        new("user-data-discovery", @"SpecialFolder\s*\.\s*(UserProfile|ApplicationData|LocalApplicationData|MyDocuments)|GetFolderPath|EnvironmentVariable", 20, "Discovers personal data outside the game."),
        new("native-code", @"DllImport|LoadLibrary|GetProcAddress|Marshal\s*\.\s*GetDelegateForFunctionPointer", 25, "Loads or invokes native code."),
        new("anti-analysis", @"IsDebuggerPresent|CheckRemoteDebuggerPresent|VirtualMachine|sandboxie|SbieDll", 20, "Contains anti-analysis or sandbox-awareness logic.")
    ];
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase) { ".cs", ".json", ".xml", ".txt", ".config", ".ini", ".md", ".yaml", ".yml", ".shader", ".bytes", ".ps1", ".bat", ".cmd", ".js", ".vbs" };
    private static readonly HashSet<string> PayloadExtensions = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".com", ".scr", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk" };

    public ScanReport Scan(string rootPath, CancellationToken token = default) => ScanInstallation(rootPath, [], token);
    public ScanReport ScanInstallation(string gameRoot, IEnumerable<string> workshopRoots, CancellationToken token = default)
    {
        var report = new ScanReport { RootPath = gameRoot, StartedAt = DateTimeOffset.Now };
        var roots = new List<(string Path, ScanScope Scope)> { (gameRoot, ScanScope.GameCore) };
        roots.AddRange(workshopRoots.Where(Directory.Exists).Select(x => (x, ScanScope.SteamWorkshop)));
        foreach (var (path, forcedScope) in roots.DistinctBy(x => Path.GetFullPath(x.Path), StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(path)) { report.Errors.Add($"Scan root is unavailable: {path}"); continue; }
            foreach (var file in EnumerateFiles(path))
            {
                token.ThrowIfCancellationRequested(); report.FilesInspected++;
                InspectFile(file, forcedScope == ScanScope.SteamWorkshop ? forcedScope : ScopeFor(path, file), report);
            }
        }
        report.CompletedAt = DateTimeOffset.Now; return report;
    }

    private static IEnumerable<string> EnumerateFiles(string root)
    {
        var pending = new Stack<string>(); pending.Push(Path.GetFullPath(root));
        while (pending.TryPop(out var dir))
        {
            try { if (File.GetAttributes(dir).HasFlag(FileAttributes.ReparsePoint)) continue; } catch { continue; }
            string[] files; try { files = Directory.GetFiles(dir); } catch { continue; }
            foreach (var file in files) yield return file;
            string[] dirs; try { dirs = Directory.GetDirectories(dir); } catch { continue; }
            foreach (var child in dirs) if (!Path.GetFileName(child).Equals("Backups", StringComparison.OrdinalIgnoreCase)) pending.Push(child);
        }
    }

    private static void InspectFile(string file, ScanScope scope, ScanReport report)
    {
        var hash = Hash(file); var name = Path.GetFileName(file); var ext = Path.GetExtension(file);
        if (KnownMalware.IsMatch(name)) { Add(report, ScanCategory.Malware, file, "known-ppg-malware-name", "Matches a known PPG malware family.", hash, scope, 100); return; }
        if (ext.Equals(".zip", StringComparison.OrdinalIgnoreCase)) { InspectArchive(file, scope, hash, report); return; }
        if (scope is ScanScope.LocalMods or ScanScope.SteamWorkshop && PayloadExtensions.Contains(ext))
            Add(report, ScanCategory.Malware, file, "untrusted-executable-payload", "Executable or script payload exists in mod content.", hash, scope, 85);
        string? content = null;
        try
        {
            var length = new FileInfo(file).Length;
            if (TextExtensions.Contains(ext) && length <= 8 * 1024 * 1024) content = File.ReadAllText(file, Encoding.UTF8);
            else if (scope is ScanScope.LocalMods or ScanScope.SteamWorkshop && (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) || ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)) && length <= 32 * 1024 * 1024) content = ExtractStrings(File.ReadAllBytes(file));
        }
        catch { report.Errors.Add($"Could not inspect {file}."); }
        if (string.IsNullOrEmpty(content)) return;
        var amsiBytes = Encoding.UTF8.GetBytes(content);
        if (AmsiScanner.IsMalware(amsiBytes, file)) { Add(report, ScanCategory.Malware, file, "windows-amsi", "Windows Antimalware Scan Interface classified the content as malware.", hash, scope, 100); return; }
        if (KnownMalware.IsMatch(content)) { Add(report, ScanCategory.Malware, file, "known-ppg-malware-signature", "Contains a known PPG malware marker.", hash, scope, 100); return; }
        var matched = Rules.Where(r => Rx(r.Pattern).IsMatch(content)).ToArray();
        if (matched.Length == 0) return;
        var score = Math.Min(100, matched.Sum(x => x.Score));
        if (matched.Any(x => x.Score >= 80)) score = Math.Max(score, 90);
        Add(report, score >= 70 ? ScanCategory.Malware : ScanCategory.Suspicious, file, string.Join(", ", matched.Select(x => x.Name)), string.Join(" ", matched.Select(x => x.Detail).Distinct()), hash, scope, score);
    }

    private static void InspectArchive(string file, ScanScope scope, string hash, ScanReport report)
    {
        try
        {
            using var zip = ZipFile.OpenRead(file);
            foreach (var entry in zip.Entries.Take(4096))
            {
                var normalized = entry.FullName.Replace('\\', '/');
                if (normalized.StartsWith('/') || normalized.Split('/').Contains("..") || Path.IsPathRooted(entry.FullName))
                    Add(report, ScanCategory.Malware, file, "archive-path-traversal", $"Archive entry escapes its destination: {entry.FullName}", hash, scope, 100);
                if (PayloadExtensions.Contains(Path.GetExtension(entry.Name)))
                    Add(report, ScanCategory.Malware, file, "archive-executable-payload", $"Archive contains executable/script entry: {entry.FullName}", hash, scope, 90);
                if (entry.Length > 256L * 1024 * 1024 || entry.CompressedLength > 0 && entry.Length / Math.Max(1, entry.CompressedLength) > 200)
                    Add(report, ScanCategory.Suspicious, file, "archive-bomb", $"Archive entry has dangerous expansion characteristics: {entry.FullName}", hash, scope, 60);
            }
        }
        catch (InvalidDataException) { Add(report, ScanCategory.Suspicious, file, "invalid-archive", "Archive is malformed or unreadable.", hash, scope, 50); }
    }

    private static ScanScope ScopeFor(string root, string path)
    {
        var parts = Path.GetRelativePath(root, path).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Any(p => p.Equals("Mods", StringComparison.OrdinalIgnoreCase))) return ScanScope.LocalMods;
        if (parts.Any(p => p.Equals("Workshop", StringComparison.OrdinalIgnoreCase))) return ScanScope.SteamWorkshop;
        return ScanScope.GameCore;
    }
    private static string ExtractStrings(byte[] bytes) => Encoding.UTF8.GetString(bytes.Select(b => b is >= 32 and <= 126 ? b : (byte)' ').ToArray());
    private static Regex Rx(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static void Add(ScanReport r, ScanCategory c, string f, string rule, string d, string h, ScanScope s, int score) => r.Findings.Add(new(c, f, rule, d, h, s, score));
    private static string Hash(string file) { try { using var stream = File.OpenRead(file); return Convert.ToHexString(SHA256.HashData(stream)); } catch { return string.Empty; } }
}

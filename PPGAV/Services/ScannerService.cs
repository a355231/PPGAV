using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using PPGAV.Models;

namespace PPGAV.Services;

public sealed class ScannerService
{
    private const long MaxTotalBytes = 8L * 1024 * 1024 * 1024;
    private static readonly TimeSpan MaxScanDuration = TimeSpan.FromMinutes(2);
    private sealed record Rule(string Name, string Pattern, int Score, string Detail);
    private static readonly Regex KnownMalware = Rx(@"FPS\s*\+{2,5}|FPSPlusPlus|jJ9aatj9|RejectShadyCode\s*=\s*false|FPSPlusPlusPlusPlusPlus");
    private static readonly Rule[] Rules =
    [
        new("credential-theft", @"Login Data|Local State|Cookies|Web Data|passwords?|tokens?|discord|wallet|Steam\\config|ssfn\d+", 55, "References credentials, browser, Discord, wallet, or Steam secrets."),
        new("network-access/data-exfiltration", @"webhook|HttpClient|WebClient|HttpWebRequest|TcpClient|UdpClient|Socket|Upload(String|Data|File)|PostAsync", 25, "Can communicate with or upload data to the network."),
        new("persistence", @"CurrentVersion\\Run|Startup|schtasks|TaskScheduler|CreateService|ServiceController|Winlogon|Registry.*(SetValue|CreateSubKey)", 55, "Can establish Windows persistence."),
        new("delayed-execution", @"Timer|Task\.Delay|Thread\.Sleep|DateTime\.(Now|UtcNow)|Environment\.TickCount|Mutex|NamedPipe", 20, "Contains delayed-trigger, mutex, or synchronization behavior."),
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
    public ScanReport ScanFile(string filePath, ScanScope scope = ScanScope.Unknown)
    {
        var report = new ScanReport { RootPath = filePath, StartedAt = DateTimeOffset.Now };
        if (File.Exists(filePath)) InspectFile(filePath, scope, report); else { report.Errors.Add($"The watched file disappeared before inspection: {filePath}"); report.SkippedPaths.Add(filePath); }
        report.IsComplete = report.Errors.Count == 0 && report.SkippedPaths.Count == 0;
        report.CompletedAt = DateTimeOffset.Now;
        return report;
    }
    public ScanReport ScanInstallation(string gameRoot, IEnumerable<string> workshopRoots, CancellationToken token = default)
    {
        var report = new ScanReport { RootPath = gameRoot, StartedAt = DateTimeOffset.Now };
        var deadline = DateTimeOffset.UtcNow + MaxScanDuration;
        var roots = new List<(string Path, ScanScope Scope)> { (gameRoot, ScanScope.GameCore) };
        roots.AddRange(workshopRoots.Where(Directory.Exists).Select(x => (x, ScanScope.SteamWorkshop)));
        try
        {
            foreach (var (path, forcedScope) in roots.DistinctBy(x => Path.GetFullPath(x.Path), StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(path)) { report.Errors.Add($"Scan root is unavailable: {path}"); report.SkippedPaths.Add(path); continue; }
                SecurePathService.RequireExistingDirectory(path, "scan root");
                foreach (var file in EnumerateFiles(path, report))
                {
                    token.ThrowIfCancellationRequested();
                    if (DateTimeOffset.UtcNow >= deadline || report.BytesInspected >= MaxTotalBytes)
                    {
                        report.Errors.Add("The scan resource limit was reached before inspection completed."); report.SkippedPaths.Add(file); break;
                    }
                    report.FilesInspected++;
                    try { report.BytesInspected += new FileInfo(file).Length; } catch { report.Errors.Add($"Could not read file metadata: {file}"); report.SkippedPaths.Add(file); continue; }
                    InspectFile(file, forcedScope == ScanScope.SteamWorkshop ? forcedScope : ScopeFor(path, file), report);
                }
            }
        }
        catch (OperationCanceledException) { report.Cancelled = true; report.Errors.Add("The scan was cancelled before inspection completed."); }
        catch (Exception ex) { report.Errors.Add($"The scan failed closed: {ex.Message}"); }
        report.IsComplete = !report.Cancelled && report.Errors.Count == 0 && report.SkippedPaths.Count == 0;
        report.CompletedAt = DateTimeOffset.Now; return report;
    }

    private static IEnumerable<string> EnumerateFiles(string root, ScanReport report)
    {
        var pending = new Stack<string>(); pending.Push(Path.GetFullPath(root));
        while (pending.TryPop(out var dir))
        {
            try { if (File.GetAttributes(dir).HasFlag(FileAttributes.ReparsePoint)) { report.SkippedPaths.Add(dir); continue; } } catch (Exception ex) { report.Errors.Add($"Could not inspect directory {dir}: {ex.Message}"); continue; }
            string[] files; try { files = Directory.GetFiles(dir); } catch (Exception ex) { report.Errors.Add($"Could not enumerate directory {dir}: {ex.Message}"); continue; }
            foreach (var file in files)
            {
                try { if (File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint)) { report.SkippedPaths.Add(file); continue; } } catch (Exception ex) { report.Errors.Add($"Could not inspect file {file}: {ex.Message}"); continue; }
                yield return file;
            }
            string[] dirs; try { dirs = Directory.GetDirectories(dir); } catch (Exception ex) { report.Errors.Add($"Could not enumerate directory {dir}: {ex.Message}"); continue; }
            foreach (var child in dirs) if (!Path.GetFileName(child).Equals("Backups", StringComparison.OrdinalIgnoreCase)) pending.Push(child);
        }
    }

    private static void InspectFile(string file, ScanScope scope, ScanReport report)
    {
        var hash = Hash(file); var name = Path.GetFileName(file); var ext = Path.GetExtension(file);
        if (string.IsNullOrEmpty(hash)) { report.Errors.Add($"Could not hash {file}; scan is incomplete."); report.SkippedPaths.Add(file); return; }
        if (KnownMalware.IsMatch(name)) { Add(report, ScanCategory.Malware, file, "known-ppg-malware-name", "Matches a known PPG malware family.", hash, scope, 100, DetectionKind.Confirmed); return; }
        if (ext.Equals(".zip", StringComparison.OrdinalIgnoreCase)) { InspectArchive(file, scope, hash, report); return; }
        if (scope is ScanScope.LocalMods or ScanScope.SteamWorkshop && PayloadExtensions.Contains(ext))
            Add(report, ScanCategory.Malware, file, "untrusted-executable-payload", "Executable or script payload exists in mod content.", hash, scope, 85, DetectionKind.Confirmed);
        string? content = null;
        try
        {
            var length = new FileInfo(file).Length;
            if (TextExtensions.Contains(ext) && length <= 8 * 1024 * 1024) content = File.ReadAllText(file, Encoding.UTF8);
            else if (scope is ScanScope.LocalMods or ScanScope.SteamWorkshop && (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) || ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)) && length <= 32 * 1024 * 1024)
            {
                var bytes = File.ReadAllBytes(file);
                if (!AmsiScanner.TryScan(bytes, file, out var binaryMalware, out var amsiError)) report.Errors.Add($"AMSI inspection failed for {file}: {amsiError}");
                else if (binaryMalware) Add(report, ScanCategory.Malware, file, "windows-amsi-binary", "AMSI classified an untrusted binary as malware.", hash, scope, 100, DetectionKind.Confirmed);
                if (IsPortableExecutable(bytes)) Add(report, ScanCategory.Suspicious, file, "untrusted-portable-executable", "An untrusted mod contains a Windows PE binary; format and entropy heuristics were inspected. PE imports were not inspected.", hash, scope, 45);
                if (ShannonEntropy(bytes) >= 7.2) Add(report, ScanCategory.Suspicious, file, "high-entropy-binary", "The untrusted binary has high entropy consistent with packing or obfuscation.", hash, scope, 45);
                var signature = AuthenticodeService.Inspect(file);
                if (!signature.Signed) Add(report, ScanCategory.Suspicious, file, "unsigned-native-binary", "The untrusted native binary has no Authenticode signature.", hash, scope, 25);
                else if (!signature.Trusted) Add(report, ScanCategory.Suspicious, file, "untrusted-authenticode", $"The native binary signature chain is not trusted: {signature.Subject}.", hash, scope, 30);
                content = ExtractStrings(bytes);
            }
        }
        catch { report.Errors.Add($"Could not inspect {file}."); }
        if (string.IsNullOrEmpty(content)) return;
        var amsiBytes = Encoding.UTF8.GetBytes(content);
        if (!AmsiScanner.TryScan(amsiBytes, file, out var amsiMalware, out var textAmsiError)) { report.Errors.Add($"AMSI inspection failed for {file}: {textAmsiError}"); return; }
        if (amsiMalware) { Add(report, ScanCategory.Malware, file, "windows-amsi", "Windows Antimalware Scan Interface classified the content as malware.", hash, scope, 100, DetectionKind.Confirmed); return; }
        if (KnownMalware.IsMatch(content)) { Add(report, ScanCategory.Malware, file, "known-ppg-malware-signature", "Contains a known PPG malware marker.", hash, scope, 100, DetectionKind.Confirmed); return; }
        if (LooksObfuscated(content)) Add(report, ScanCategory.Suspicious, file, "obfuscated-text-payload", "Text content contains a long encoded/obfuscated payload pattern.", hash, scope, 35);
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
            InspectArchiveEntries(zip, file, scope, hash, report, 0);
        }
        catch (InvalidDataException) { Add(report, ScanCategory.Suspicious, file, "invalid-archive", "Archive is malformed or unreadable.", hash, scope, 50); }
    }

    private static void InspectArchiveEntries(ZipArchive zip, string file, ScanScope scope, string hash, ScanReport report, int depth)
    {
        if (depth > 3) { report.Errors.Add($"Nested archive depth exceeded the limit: {file}"); report.SkippedPaths.Add(file); return; }
        if (zip.Entries.Count > 4096) { report.Errors.Add($"Archive entry count exceeded the limit: {file}"); report.SkippedPaths.Add(file); return; }
        foreach (var entry in zip.Entries)
        {
            try
            {
                var normalized = entry.FullName.Replace('\\', '/');
                if (normalized.StartsWith('/') || normalized.Split('/').Contains("..") || Path.IsPathRooted(entry.FullName))
                    Add(report, ScanCategory.Malware, file, "archive-path-traversal", $"Archive entry escapes its destination: {entry.FullName}", hash, scope, 100, DetectionKind.Confirmed);
                if (PayloadExtensions.Contains(Path.GetExtension(entry.Name)))
                    Add(report, ScanCategory.Malware, file, "archive-executable-payload", $"Archive contains executable/script entry: {entry.FullName}", hash, scope, 90, DetectionKind.Confirmed);
                if (entry.Length > 256L * 1024 * 1024 || entry.CompressedLength > 0 && entry.Length / Math.Max(1, entry.CompressedLength) > 200)
                    Add(report, ScanCategory.Suspicious, file, "archive-bomb", $"Archive entry has dangerous expansion characteristics: {entry.FullName}", hash, scope, 60);
                if (entry.Length > 256L * 1024 * 1024) { report.Errors.Add($"Archive entry exceeded the expansion limit: {entry.FullName}"); report.SkippedPaths.Add(file); continue; }
                if (Path.GetExtension(entry.Name).Equals(".zip", StringComparison.OrdinalIgnoreCase) && entry.Length <= 64L * 1024 * 1024)
                {
                    using var nestedStream = new MemoryStream(); using (var input = entry.Open()) input.CopyTo(nestedStream); nestedStream.Position = 0;
                    using var nested = new ZipArchive(nestedStream, ZipArchiveMode.Read);
                    InspectArchiveEntries(nested, file, scope, hash, report, depth + 1);
                }
            }
            catch (InvalidDataException) { Add(report, ScanCategory.Suspicious, file, "invalid-nested-archive", $"Nested archive is malformed: {entry.FullName}", hash, scope, 55); }
        }
    }

    private static ScanScope ScopeFor(string root, string path)
    {
        var parts = Path.GetRelativePath(root, path).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Any(p => p.Equals("Mods", StringComparison.OrdinalIgnoreCase))) return ScanScope.LocalMods;
        if (parts.Any(p => p.Equals("Workshop", StringComparison.OrdinalIgnoreCase))) return ScanScope.SteamWorkshop;
        return ScanScope.GameCore;
    }
    private static string ExtractStrings(byte[] bytes)
    {
        var ascii = Encoding.UTF8.GetString(bytes.Select(b => b is >= 32 and <= 126 ? b : (byte)' ').ToArray());
        var wide = Encoding.Unicode.GetString(bytes).Replace('\0', ' ');
        return ascii + "\n" + wide;
    }
    private static bool IsPortableExecutable(byte[] bytes) => bytes.Length > 0x40 && bytes[0] == (byte)'M' && bytes[1] == (byte)'Z' && BitConverter.ToInt32(bytes, 0x3C) > 0 && BitConverter.ToInt32(bytes, 0x3C) < bytes.Length - 4 && bytes[BitConverter.ToInt32(bytes, 0x3C)] == (byte)'P' && bytes[BitConverter.ToInt32(bytes, 0x3C) + 1] == (byte)'E';
    private static double ShannonEntropy(byte[] bytes)
    {
        if (bytes.Length == 0) return 0;
        var counts = new int[256]; foreach (var value in bytes) counts[value]++;
        return counts.Where(x => x > 0).Sum(x => { var p = (double)x / bytes.Length; return -p * Math.Log2(p); });
    }
    private static bool LooksObfuscated(string content) => Regex.IsMatch(content, @"[A-Za-z0-9+/]{240,}={0,2}") || (ShannonEntropy(Encoding.UTF8.GetBytes(content)) >= 5.5 && content.Length > 512);
    private static Regex Rx(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static void Add(ScanReport r, ScanCategory c, string f, string rule, string d, string h, ScanScope s, int score, DetectionKind detection = DetectionKind.Heuristic) => r.Findings.Add(new(c, f, rule, d, h, s, score, detection));
    private static string Hash(string file) { try { using var stream = File.OpenRead(file); return Convert.ToHexString(SHA256.HashData(stream)); } catch { return string.Empty; } }
}

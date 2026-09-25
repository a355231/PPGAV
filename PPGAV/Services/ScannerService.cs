using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using PPGAV.Models;

namespace PPGAV.Services;

/// <summary>
/// Bounded static/content scanner. Heuristic capability combinations are intentionally
/// labeled as heuristics; this scanner is not a substitute for Defender or isolation.
/// </summary>
public sealed class ScannerService
{
    private const long MaxTotalBytes = 8L * 1024 * 1024 * 1024;
    private const long MaxSingleFileBytes = 512L * 1024 * 1024;
    private const long MaxInspectableFileBytes = 32L * 1024 * 1024;
    private const long MaxArchiveEntryBytes = 32L * 1024 * 1024;
    private const long MaxArchiveExpansionBytes = 512L * 1024 * 1024;
    private const int MaxFiles = 250_000;
    private const int MaxArchiveEntries = 4096;
    private static readonly TimeSpan MaxScanDuration = TimeSpan.FromMinutes(2);
    private sealed record Rule(string Name, Regex Pattern, int Score, string Detail);
    // Inputs can be up to 32 MB; 100 ms timed out on ordinary large mod files and failed the whole scan.
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);
    private static Regex Rx(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex KnownMalware = Rx(@"FPS\s*\+{2,5}|FPSPlusPlus|jJ9aatj9|RejectShadyCode\s*=\s*false|FPSPlusPlusPlusPlusPlus");
    private static readonly Rule[] Rules =
    [
        // Bare "discord"/"token" matched community links and CancellationToken; only secret-store artifacts count.
        new("credential-theft", Rx(@"Login Data|Local State|Cookies|Web Data|passwords?|Local Storage[\\/]+leveldb|dQw4w9WgXcQ:|discord\w*[^\r\n]{0,40}\btokens?\b|\btokens?\b[^\r\n]{0,40}discord|wallet\.dat|Steam\\config|ssfn\d+"), 55, "References credentials, browser, Discord token, wallet, or Steam secrets."),
        new("network-access/data-exfiltration", Rx(@"webhook|HttpClient|WebClient|HttpWebRequest|TcpClient|UdpClient|Socket|Upload(String|Data|File)|PostAsync"), 25, "Can communicate with or upload data to the network."),
        new("persistence", Rx(@"CurrentVersion\\Run|Startup|schtasks|TaskScheduler|CreateService|ServiceController|Winlogon|Registry.*(SetValue|CreateSubKey)"), 55, "Can establish Windows persistence."),
        new("delayed-execution", Rx(@"Timer|Task\.Delay|Thread\.Sleep|DateTime\.(Now|UtcNow)|Environment\.TickCount|Mutex|NamedPipe"), 20, "Contains delayed-trigger, mutex, or synchronization behavior."),
        new("process-injection", Rx(@"OpenProcess|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|SetThreadContext|NtMapViewOfSection"), 80, "Contains process-injection primitives."),
        new("security-tampering", Rx(@"Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|WinDefend|SecurityHealth|firewall.*(disable|off)|bcdedit|NtRaiseHardError"), 80, "Attempts to weaken Windows security or system stability."),
        new("destructive-io", Rx(@"(File|Directory)\s*\.\s*(Delete|Move)\b|DeleteFile|SHFileOperation|Format-Volume|Remove-Item\s+-Recurse"), 35, "Can delete or destructively move files."),
        new("dynamic-code", Rx(@"Assembly\s*\.\s*(Load|LoadFrom)|AppDomain\s*\.\s*Load|Reflection\.Emit|CSharpCodeProvider|DynamicMethod|LoadLibrary|GetProcAddress"), 30, "Dynamically loads or generates code."),
        new("encoded-payload", Rx(@"FromBase64String|DeflateStream|GZipStream|BinaryFormatter|Invoke-Expression|powershell(.exe)?\s+.*-(enc|encodedcommand)"), 30, "Contains an encoded, compressed, or interpreted payload chain."),
        new("process-launch", Rx(@"Process\s*\.\s*Start|ProcessStartInfo|CreateProcess|ShellExecute|cmd\.exe|powershell\.exe|rundll32|regsvr32|mshta"), 25, "Can launch external programs or living-off-the-land tools."),
        new("workshop-modification", Rx(@"CreateCommunityFile|SubmitItemUpdate|SteamUGC|workshop\\content|ResetAll|WithContent"), 30, "Can modify Steam Workshop content or data."),
        new("user-data-discovery", Rx(@"SpecialFolder\s*\.\s*(UserProfile|ApplicationData|LocalApplicationData|MyDocuments)|GetFolderPath|EnvironmentVariable"), 20, "Discovers personal data outside the game."),
        new("native-code", Rx(@"DllImport|Marshal\s*\.\s*GetDelegateForFunctionPointer|VirtualAlloc|WriteProcessMemory"), 25, "Loads, invokes, or manipulates native code."),
        new("anti-analysis", Rx(@"IsDebuggerPresent|CheckRemoteDebuggerPresent|VirtualMachine|sandboxie|SbieDll"), 20, "Contains anti-analysis or sandbox-awareness logic."),
        new("api-smuggling", Rx(@"Type\s*\.\s*GetType\s*\(\s*@?""System\.(IO|Diagnostics|Net|Reflection|Runtime\.InteropServices)\b"), 45, "Resolves restricted System.IO/Diagnostics/Net APIs by name, a common way to bypass the PPG mod compiler's API restrictions.")
    ];
    private static readonly HashSet<string> PayloadExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".com", ".scr", ".msi", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk", ".jar", ".class", ".wasm", ".so" };
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".cs", ".json", ".xml", ".txt", ".config", ".ini", ".md", ".yaml", ".yml", ".shader", ".bytes", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".js", ".vbs", ".lua", ".py", ".html", ".htm", ".toml", ".props", ".targets", ".manifest" };

    private sealed class ScanBudget(CancellationToken token, DateTimeOffset deadline)
    {
        public long TotalBytes;
        public long ExpandedBytes;
        public int FileCount;
        public void Check()
        {
            token.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= deadline) throw new ScanLimitException("The maximum scan time was reached before inspection completed.");
        }
        public void Consume(long count, bool archiveExpansion = false)
        {
            Check();
            var total = Interlocked.Add(ref TotalBytes, count);
            if (total > MaxTotalBytes) throw new ScanLimitException("The total inspected-byte limit was reached before inspection completed.");
            if (archiveExpansion && Interlocked.Add(ref ExpandedBytes, count) > MaxArchiveExpansionBytes)
                throw new ScanLimitException("The total archive expansion limit was reached before inspection completed.");
        }
    }
    private sealed class ScanLimitException(string message) : IOException(message);

    public ScanReport Scan(string rootPath, CancellationToken token = default) => ScanInstallation(rootPath, [], token);

    /// <summary>
    /// Inspects one changed file while the game may still be writing it. Shared read access is
    /// used so the scan never fails (or blocks the game) on a file the game holds open, and a file
    /// that was deleted before inspection has nothing left to load, so it is not an error.
    /// </summary>
    public ScanReport ScanFile(string filePath, ScanScope scope = ScanScope.Unknown, bool compiledModCache = false)
    {
        var report = NewReport(filePath);
        var budget = new ScanBudget(CancellationToken.None, DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30));
        if (File.Exists(filePath)) { report.FilesInspected++; InspectFile(filePath, scope, report, budget, FileShare.ReadWrite | FileShare.Delete, compiledModCache); }
        CorrelateCrossFileCapabilities(report);
        Finish(report);
        return report;
    }

    public ScanReport ScanInstallation(string gameRoot, IEnumerable<string> workshopRoots, CancellationToken token = default)
    {
        var report = NewReport(gameRoot);
        var budget = new ScanBudget(token, DateTimeOffset.UtcNow + MaxScanDuration);
        var roots = new List<(string Path, ScanScope Scope)> { (gameRoot, ScanScope.GameCore) };
        roots.AddRange(workshopRoots.Select(x => (x, ScanScope.SteamWorkshop)));
        try
        {
            foreach (var (path, forcedScope) in roots.DistinctBy(x => Path.GetFullPath(x.Path), StringComparer.OrdinalIgnoreCase))
            {
                budget.Check();
                if (!Directory.Exists(path)) { report.Errors.Add($"Scan root is unavailable: {path}"); report.SkippedPaths.Add(path); continue; }
                var safeRoot = SecurePathService.RequireExistingDirectory(path, "scan root");
                report.ScannedRoots.Add(safeRoot);
                foreach (var file in EnumerateFiles(safeRoot, report, budget))
                {
                    budget.Check();
                    if (++budget.FileCount > MaxFiles) throw new ScanLimitException("The maximum file-count limit was reached before inspection completed.");
                    report.FilesInspected++;
                    var scope = forcedScope == ScanScope.SteamWorkshop ? forcedScope : GameLayout.ScopeFor(safeRoot, file);
                    InspectFile(file, scope, report, budget, compiledModCache: forcedScope != ScanScope.SteamWorkshop && GameLayout.IsCompiledModCache(safeRoot, file));
                }
            }
        }
        catch (OperationCanceledException) { report.Cancelled = true; report.Errors.Add("The scan was cancelled before inspection completed."); }
        catch (Exception ex) { report.Errors.Add($"The scan failed closed: {ex.Message}"); }
        CorrelateCrossFileCapabilities(report);
        Finish(report);
        return report;
    }

    private static ScanReport NewReport(string root) => new() { RootPath = Path.GetFullPath(root), StartedAt = DateTimeOffset.Now };

    /// <summary>Re-hashes the exact inspected file/root set immediately before launch.</summary>
    public static bool VerifySnapshot(ScanReport report, IEnumerable<string> currentAdditionalRoots, out string error)
        => VerifySnapshotCore(report, currentAdditionalRoots, [], out error);

    /// <summary>
    /// Revalidates every inspected path except explicitly named roots that the
    /// caller will atomically disable before launching (Safe Mode only).
    /// </summary>
    public static bool VerifySnapshotExcludingRoots(ScanReport report, IEnumerable<string> currentAdditionalRoots,
        IEnumerable<string> rootsToDisable, out string error, bool allowMissingExcludedRoots = false)
        => VerifySnapshotCore(report, currentAdditionalRoots, rootsToDisable, out error, allowMissingExcludedRoots);

    private static bool VerifySnapshotCore(ScanReport report, IEnumerable<string> currentAdditionalRoots,
        IEnumerable<string> rootsToDisable, out string error, bool allowMissingExcludedRoots = false)
    {
        error = string.Empty;
        if (!report.IsComplete || report.ScannedRoots.Count == 0 || report.ScannedHashes.Count == 0)
        { error = "The previous inspection is incomplete or has no hash snapshot."; return false; }
        try
        {
            var roots = new[] { report.RootPath }.Concat(currentAdditionalRoots).Select(x => Path.GetFullPath(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (!roots.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(report.ScannedRoots))
            { error = "The set of game/Workshop scan roots changed after inspection."; return false; }
            var excluded = rootsToDisable.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            foreach (var excludedRoot in excluded)
            {
                var containingRoot = roots.FirstOrDefault(root => IsSameOrChildPath(root, excludedRoot));
                if (containingRoot is null || excludedRoot.Equals(report.RootPath, StringComparison.OrdinalIgnoreCase))
                    throw new UnauthorizedAccessException($"Safe Mode may not exclude a scan root or a path outside inspected roots: {excludedRoot}");
                var excludedExists = Directory.Exists(excludedRoot);
                if (!excludedExists && !allowMissingExcludedRoots) throw new DirectoryNotFoundException($"Safe Mode content root disappeared before it was disabled: {excludedRoot}");
                if (excludedRoot.Equals(containingRoot, StringComparison.OrdinalIgnoreCase))
                {
                    if (excludedExists) SecurePathService.RequireExistingDirectory(excludedRoot, "Safe Mode excluded content root");
                }
                else
                {
                    SecurePathService.RequireContained(containingRoot, excludedRoot, excludedExists, "Safe Mode excluded content root");
                    if (excludedExists) SecurePathService.RequireExistingDirectory(excludedRoot, "Safe Mode excluded content root");
                }
            }

            var expected = report.ScannedHashes
                .Where(x => !IsUnderAnyRoot(Path.GetFullPath(x.Key), excluded))
                .ToDictionary(x => Path.GetFullPath(x.Key), x => x.Value, StringComparer.OrdinalIgnoreCase);
            var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(3);
            foreach (var root in roots)
            {
                if (excluded.Any(x => x.Equals(root, StringComparison.OrdinalIgnoreCase)))
                {
                    if (!Directory.Exists(root) && allowMissingExcludedRoots) continue;
                    SecurePathService.RequireExistingDirectory(root, "Safe Mode excluded scan root");
                    continue;
                }
                SecurePathService.RequireExistingDirectory(root, "snapshot root");
                var pending = new Stack<string>([root]);
                while (pending.TryPop(out var directory))
                {
                    if (DateTimeOffset.UtcNow >= deadline) throw new TimeoutException("Snapshot revalidation exceeded its time limit.");
                    SecurePathService.RejectReparse(directory, "snapshot directory");
                    foreach (var path in Directory.EnumerateFileSystemEntries(directory))
                    {
                        var attributes = File.GetAttributes(path);
                        if (attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"Reparse point appeared after scan: {path}");
                        if (attributes.HasFlag(FileAttributes.Directory))
                        {
                            if (excluded.Any(x => x.Equals(Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase)))
                            {
                                SecurePathService.RequireExistingDirectory(path, "Safe Mode excluded content root");
                                continue;
                            }
                            pending.Push(path);
                        }
                        else
                        {
                            if (IsUnderAnyRoot(Path.GetFullPath(path), excluded)) continue;
                            if (current.Count >= MaxFiles) throw new IOException("Snapshot file-count limit exceeded.");
                            current.Add(Path.GetFullPath(path), root);
                        }
                    }
                }
            }
            if (!current.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(expected.Keys))
            { error = "Files were added or removed after inspection; launch is aborted."; return false; }
            long total = 0;
            var snapshotBudget = new ScanBudget(CancellationToken.None, deadline);
            foreach (var (path, root) in current)
            {
                if (DateTimeOffset.UtcNow >= deadline) throw new TimeoutException("Snapshot revalidation exceeded its time limit.");
                using var stream = SecurePathService.OpenContainedRead(root, path, "snapshot file");
                total = checked(total + stream.Length);
                if (total > MaxTotalBytes) throw new IOException("Snapshot revalidation exceeded the total byte limit.");
                var hash = HashBounded(stream, snapshotBudget);
                if (!hash.Equals(expected[path], StringComparison.OrdinalIgnoreCase))
                { error = $"Inspected content changed before launch: {path}"; return false; }
            }
            return true;
        }
        catch (Exception ex) { error = $"Snapshot revalidation failed closed: {ex.Message}"; return false; }
    }

    private static bool IsUnderAnyRoot(string path, IEnumerable<string> roots) => roots.Any(root => IsSameOrChildPath(root, path));

    private static bool IsSameOrChildPath(string root, string path)
    {
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return fullPath.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) ||
            fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void Finish(ScanReport report)
    {
        report.IsComplete = !report.Cancelled && report.Errors.Count == 0 && report.SkippedPaths.Count == 0;
        report.CompletedAt = DateTimeOffset.Now;
    }

    private static IEnumerable<string> EnumerateFiles(string root, ScanReport report, ScanBudget budget)
    {
        var pending = new Stack<string>(); pending.Push(Path.GetFullPath(root));
        while (pending.TryPop(out var directory))
        {
            budget.Check();
            try { SecurePathService.RejectReparse(directory, "scan directory"); }
            catch (Exception ex) { report.SkippedPaths.Add(directory); report.Errors.Add($"Could not safely inspect directory {directory}: {ex.Message}"); continue; }
            using var enumerator = Directory.EnumerateFileSystemEntries(directory).GetEnumerator();
            while (true)
            {
                budget.Check();
                string entry;
                try { if (!enumerator.MoveNext()) break; entry = enumerator.Current; }
                catch (Exception ex) { report.Errors.Add($"Could not enumerate directory {directory}: {ex.Message}"); report.SkippedPaths.Add(directory); break; }
                FileAttributes attributes;
                try { attributes = File.GetAttributes(entry); }
                catch (Exception ex) { report.Errors.Add($"Could not inspect entry {entry}: {ex.Message}"); report.SkippedPaths.Add(entry); continue; }
                if (attributes.HasFlag(FileAttributes.ReparsePoint)) { report.SkippedPaths.Add(entry); report.Errors.Add($"Skipped reparse point: {entry}"); continue; }
                if (attributes.HasFlag(FileAttributes.Directory)) pending.Push(entry);
                else yield return entry;
            }
        }
    }

    private static void InspectFile(string file, ScanScope scope, ScanReport report, ScanBudget budget, FileShare share = FileShare.Read, bool compiledModCache = false)
    {
        try
        {
            budget.Check();
            using var stream = SecurePathService.OpenContainedRead(Path.GetDirectoryName(file)!, file, "scan file", share);
            var length = stream.Length;
            if (length > MaxSingleFileBytes) throw new ScanLimitException($"File is larger than the per-file inspection limit ({MaxSingleFileBytes} bytes).");
            var hash = HashBounded(stream, budget);
            report.ScannedHashes[Path.GetFullPath(file)] = hash;
            if (KnownMalware.IsMatch(Path.GetFileName(file)))
            {
                Add(report, ScanCategory.Malware, file, "known-ppg-malware-name", "Matches a known PPG malware family.", hash, scope, 100, DetectionKind.Confirmed);
                return;
            }
            if (length > MaxInspectableFileBytes)
            {
                // Large vendor assets (e.g. sharedassets*.resS) are pinned by the approved integrity baseline
                // and covered by the Defender preflight scan; treating them as uninspected blocked every launch.
                // Oversized untrusted content is flagged so it is disabled by Safe Mode rather than trusted.
                if (scope != ScanScope.GameCore)
                    Add(report, ScanCategory.Suspicious, file, "oversized-uninspected-content", $"Untrusted content exceeds the {MaxInspectableFileBytes / (1024 * 1024)} MB static/AMSI inspection limit and could not be analyzed.", hash, scope, 50);
                return;
            }

            stream.Position = 0;
            var contentBytes = ReadBounded(stream, checked((int)MaxInspectableFileBytes), budget);
            InspectContent(contentBytes, Path.GetFileName(file), file, scope, hash, report, compiledModCache);
            if (file.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) InspectArchive(contentBytes, file, scope, hash, report, budget);
        }
        catch (Exception ex)
        {
            report.Errors.Add($"Could not completely inspect {file}: {ex.Message}");
            report.SkippedPaths.Add(file);
        }
    }

    private static string HashBounded(Stream stream, ScanBudget budget)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024]; int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) { budget.Consume(read); hash.AppendData(buffer, 0, read); }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static byte[] ReadBounded(Stream stream, int maximum, ScanBudget budget)
    {
        using var memory = new MemoryStream(); var buffer = new byte[64 * 1024]; int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            budget.Consume(read);
            if (memory.Length + read > maximum) throw new ScanLimitException("Content exceeded its inspection limit.");
            memory.Write(buffer, 0, read);
        }
        return memory.ToArray();
    }

    private static void InspectContent(byte[] bytes, string entryName, string displayPath, ScanScope scope, string hash, ScanReport report, bool compiledModCache = false)
    {
        var extension = Path.GetExtension(entryName);
        var isText = TextExtensions.Contains(extension);
        // Vendor game files (Unity, Mono, the .NET runtime in ppgModCompiler) legitimately contain every
        // API name the capability heuristics look for, so scoring them produced hundreds of false
        // "Malware" results on a clean install. Core files are covered by the approved integrity
        // baseline, known-malware markers, AMSI, and Defender instead.
        if (scope == ScanScope.GameCore)
        {
            if (!TryAmsi(bytes, displayPath, hash, scope, report)) return;
            var coreText = isText ? DecodeText(bytes) : ExtractStrings(bytes);
            if (KnownMalware.IsMatch(coreText))
                Add(report, ScanCategory.Malware, displayPath, "known-ppg-malware-signature", "Contains a known PPG malware marker.", hash, scope, 100, DetectionKind.Confirmed);
            return;
        }

        var nativeExtension = extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase);
        var isPortableExecutable = IsPortableExecutable(bytes);
        var gameCompiledAssembly = compiledModCache && isPortableExecutable && extension.Equals(".dll", StringComparison.OrdinalIgnoreCase);
        if (PayloadExtensions.Contains(extension) && !gameCompiledAssembly)
            Add(report, ScanCategory.Malware, displayPath, "untrusted-executable-payload", "Untrusted mod content contains executable/script payload code; this is a high-confidence policy detection, not an AV signature match.", hash, scope, 85, DetectionKind.Heuristic);
        if (isPortableExecutable && !nativeExtension)
            Add(report, ScanCategory.Suspicious, displayPath, "disguised-portable-executable", "A Windows PE image is stored under a non-executable extension in untrusted mod/Workshop content; this may indicate a renamed payload.", hash, scope, 65);
        if (nativeExtension && isPortableExecutable && !gameCompiledAssembly)
        {
            Add(report, ScanCategory.Suspicious, displayPath, "untrusted-portable-executable", "Untrusted mod contains a Windows PE image; the PE header and entropy were inspected, but PE imports were not inspected.", hash, scope, 45);
            if (ShannonEntropy(bytes) >= 7.2) Add(report, ScanCategory.Suspicious, displayPath, "high-entropy-binary", "The untrusted PE has high entropy consistent with packing or obfuscation.", hash, scope, 45);
            if (!displayPath.Contains("!/", StringComparison.Ordinal) && File.Exists(displayPath))
            {
                var signature = AuthenticodeService.Inspect(displayPath);
                if (!signature.Signed) Add(report, ScanCategory.Suspicious, displayPath, "unsigned-native-binary", "The untrusted native PE has no valid embedded Authenticode signature.", hash, scope, 25);
                else if (!signature.Trusted) Add(report, ScanCategory.Suspicious, displayPath, "untrusted-authenticode", $"The native PE signature chain is not trusted: {signature.Subject}.", hash, scope, 30);
            }
        }

        if (!TryAmsi(bytes, displayPath, hash, scope, report)) return;

        var text = isText ? DecodeText(bytes) : ExtractStrings(bytes);
        if (string.IsNullOrWhiteSpace(text)) return;
        var amsiBytes = Encoding.UTF8.GetBytes(text);
        var stringMalware = false;
        if (OperatingSystem.IsWindows() && !AmsiScanner.TryScan(amsiBytes, displayPath + " (extracted strings)", out stringMalware, out var textAmsiError))
        {
            report.Errors.Add($"AMSI string inspection failed for {displayPath}: {textAmsiError}"); report.SkippedPaths.Add(displayPath);
        }
        else if (OperatingSystem.IsWindows() && stringMalware)
        {
            Add(report, ScanCategory.Malware, displayPath, "windows-amsi-strings", "Windows AMSI classified extracted strings as malware.", hash, scope, 100, DetectionKind.Confirmed); return;
        }
        if (KnownMalware.IsMatch(text)) { Add(report, ScanCategory.Malware, displayPath, "known-ppg-malware-signature", "Contains a known PPG malware marker.", hash, scope, 100, DetectionKind.Confirmed); return; }

        // Capability rules describe code. Applied to arbitrary binary data (images, audio, .git/.vs caches)
        // they matched random substrings; such files are still covered by AMSI, known markers, the
        // disguised-PE check, and the encoded-run check below.
        var matched = isText || isPortableExecutable ? Rules.Where(rule => rule.Pattern.IsMatch(text)).ToArray() : [];
        var names = matched.Select(x => x.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var score = Math.Min(100, matched.Sum(x => x.Score));
        var chainDetails = new List<string>();
        if (names.Contains("credential-theft") && names.Contains("network-access/data-exfiltration")) { score = Math.Max(score, 95); chainDetails.Add("Capability chain: credential discovery plus outbound transfer."); }
        if (names.Contains("persistence") && names.Contains("process-launch") && names.Contains("encoded-payload")) { score = Math.Max(score, 90); chainDetails.Add("Capability chain: encoded payload, execution, and persistence."); }
        if (names.Contains("process-injection") && (names.Contains("dynamic-code") || names.Contains("native-code"))) { score = Math.Max(score, 95); chainDetails.Add("Capability chain: process injection combined with dynamic/native code."); }
        if (names.Contains("security-tampering") && (names.Contains("persistence") || names.Contains("process-launch"))) { score = Math.Max(score, 90); chainDetails.Add("Capability chain: security tampering combined with execution or persistence."); }
        if (matched.Any(x => x.Score >= 80)) score = Math.Max(score, 90);
        if (LooksObfuscated(text, isText))
        {
            score = Math.Min(100, score + 20);
            chainDetails.Add("Long encoded/high-entropy strings indicate possible obfuscation.");
        }
        if (matched.Length == 0 && chainDetails.Count == 0) return;
        var details = matched.Select(x => x.Detail).Concat(chainDetails).Distinct();
        // A lone weak indicator (e.g. Task.Delay or DateTime.Now, score 20) is ordinary game-mod code. It is
        // recorded as informational evidence for cross-file correlation but no longer forces Safe Mode.
        var category = score >= 70 ? ScanCategory.Malware : score >= 25 || chainDetails.Count > 0 ? ScanCategory.Suspicious : ScanCategory.Safe;
        Add(report, category, displayPath, string.Join(", ", matched.Select(x => x.Name).DefaultIfEmpty("obfuscated-payload")), string.Join(" ", details), hash, scope, score, DetectionKind.Heuristic);
    }

    /// <summary>Returns false when AMSI already classified the content as malware (no further scoring needed).</summary>
    private static bool TryAmsi(byte[] bytes, string displayPath, string hash, ScanScope scope, ScanReport report)
    {
        if (!OperatingSystem.IsWindows()) return true;
        if (!AmsiScanner.TryScan(bytes, displayPath, out var malware, out var amsiError))
        {
            report.Errors.Add($"AMSI inspection failed for {displayPath}: {amsiError}");
            report.SkippedPaths.Add(displayPath);
            return true;
        }
        if (!malware) return true;
        Add(report, ScanCategory.Malware, displayPath, "windows-amsi", "Windows Antimalware Scan Interface classified the content as malware.", hash, scope, 100, DetectionKind.Confirmed);
        return false;
    }

    private static void InspectArchive(byte[] archiveBytes, string file, ScanScope scope, string hash, ScanReport report, ScanBudget budget)
    {
        try
        {
            using var stream = new MemoryStream(archiveBytes, writable: false);
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            InspectArchiveEntries(zip, file, scope, hash, report, budget, 0, seen);
        }
        catch (InvalidDataException) { Add(report, ScanCategory.Suspicious, file, "invalid-archive", "Archive is malformed or unreadable.", hash, scope, 60); }
        catch (ScanLimitException ex) { report.Errors.Add($"Archive inspection was incomplete for {file}: {ex.Message}"); report.SkippedPaths.Add(file); }
    }

    private static void InspectArchiveEntries(ZipArchive zip, string file, ScanScope scope, string hash, ScanReport report, ScanBudget budget, int depth, HashSet<string> seen)
    {
        if (depth >= 3) throw new ScanLimitException($"Nested archive depth exceeded the limit: {file}");
        if (zip.Entries.Count > MaxArchiveEntries || zip.Entries.Count + seen.Count > MaxArchiveEntries)
            throw new ScanLimitException($"Archive entry count exceeded the limit: {file}");
        foreach (var entry in zip.Entries)
        {
            budget.Check();
            var normalized = entry.FullName.Replace('\\', '/');
            if (!seen.Add(normalized)) Add(report, ScanCategory.Suspicious, file, "duplicate-archive-entry", $"Archive repeats entry path: {entry.FullName}", hash, scope, 55);
            if (normalized.StartsWith('/') || normalized.Split('/').Contains("..") || Path.IsPathRooted(entry.FullName) || normalized.Contains(':'))
                Add(report, ScanCategory.Malware, file, "archive-path-traversal", $"Archive entry escapes its destination: {entry.FullName}", hash, scope, 100, DetectionKind.Confirmed);
            if (scope != ScanScope.GameCore && PayloadExtensions.Contains(Path.GetExtension(entry.Name)))
                Add(report, ScanCategory.Malware, file, "archive-executable-payload", $"Archive contains executable/script entry: {entry.FullName}", hash, scope, 90, DetectionKind.Heuristic);
            if (entry.Length > MaxArchiveEntryBytes || entry.CompressedLength > 0 && entry.Length / Math.Max(1, entry.CompressedLength) > 200)
            {
                Add(report, ScanCategory.Suspicious, file, "archive-bomb", $"Archive entry exceeds safe expansion characteristics: {entry.FullName}", hash, scope, 70);
                throw new ScanLimitException($"Archive entry exceeded the expansion limit: {entry.FullName}");
            }
            if (entry.FullName.EndsWith('/')) continue;
            byte[] data;
            using (var input = entry.Open()) data = ReadArchiveEntry(input, budget);
            var display = $"{file}!/{entry.FullName}";
            InspectContent(data, entry.Name, display, scope, hash, report);
            if (Path.GetExtension(entry.Name).Equals(".zip", StringComparison.OrdinalIgnoreCase))
            {
                using var nestedMemory = new MemoryStream(data, writable: false);
                using var nested = new ZipArchive(nestedMemory, ZipArchiveMode.Read);
                InspectArchiveEntries(nested, display, scope, hash, report, budget, depth + 1, seen);
            }
        }
    }

    private static byte[] ReadArchiveEntry(Stream input, ScanBudget budget)
    {
        using var memory = new MemoryStream(); var buffer = new byte[64 * 1024]; int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            budget.Consume(read, archiveExpansion: true);
            if (memory.Length + read > MaxArchiveEntryBytes) throw new ScanLimitException("Archive entry expanded beyond the per-entry limit.");
            memory.Write(buffer, 0, read);
        }
        return memory.ToArray();
    }

    private static string DecodeText(byte[] bytes)
    {
        if (bytes.AsSpan().StartsWith(Encoding.Unicode.GetPreamble())) return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.AsSpan().StartsWith(Encoding.BigEndianUnicode.GetPreamble())) return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.AsSpan().StartsWith(Encoding.UTF8.GetPreamble())) return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>
    /// Extracts printable ASCII and UTF-16LE runs (like the Sysinternals "strings" tool). Decoding the
    /// whole buffer as UTF-16 instead turned every compressed byte pair into a random character,
    /// which inflated the text several-fold and made all binaries look high-entropy.
    /// </summary>
    private static string ExtractStrings(byte[] bytes)
    {
        const int minimumRun = 5;
        var output = new StringBuilder();
        var run = new StringBuilder();
        void Flush() { if (run.Length >= minimumRun) output.Append(run).Append('\n'); run.Clear(); }

        foreach (var value in bytes)
        {
            if (value is >= 32 and <= 126) run.Append((char)value);
            else Flush();
        }
        Flush();
        for (var offset = 0; offset < 2; offset++)
        {
            for (var index = offset; index + 1 < bytes.Length; index += 2)
            {
                if (bytes[index + 1] == 0 && bytes[index] is >= 32 and <= 126) run.Append((char)bytes[index]);
                else Flush();
            }
            Flush();
        }
        return output.ToString();
    }

    private static void CorrelateCrossFileCapabilities(ScanReport report)
    {
        var evidence = report.Findings.Where(f => f.Detection == DetectionKind.Heuristic && f.Scope is ScanScope.LocalMods or ScanScope.SteamWorkshop)
            .GroupBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
            .Select(group => new
            {
                File = group.Key,
                Hash = group.First().Sha256,
                Scope = group.First().Scope,
                Rules = string.Join(",", group.Select(f => f.Rule)),
                Package = ModPackageKey(report, group.Key)
            }).ToArray();
        var chains = new[]
        {
            ("credential-theft", "network-access/data-exfiltration", "credential collection and outbound transfer across separate mod files"),
            ("persistence", "process-launch", "persistence and external execution split across separate mod files"),
            ("process-injection", "native-code", "process injection and native-code loading split across separate mod files"),
            ("security-tampering", "process-launch", "security tampering and external execution split across separate mod files"),
            ("anti-analysis", "encoded-payload", "anti-analysis and concealed payload staging split across separate mod files"),
            ("delayed-execution", "process-launch", "delayed triggering and external execution split across separate mod files"),
            ("user-data-discovery", "network-access/data-exfiltration", "personal-data discovery and network transfer split across separate mod files")
        };
        var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (leftRule, rightRule, detail) in chains)
        {
            var left = evidence.Where(x => x.Rules.Contains(leftRule, StringComparison.OrdinalIgnoreCase)).ToArray();
            var right = evidence.Where(x => x.Rules.Contains(rightRule, StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var first in left)
            foreach (var second in right)
            {
                // Capabilities only chain within one mod; pairing unrelated mods flagged both as malware.
                if (first.File.Equals(second.File, StringComparison.OrdinalIgnoreCase) ||
                    !first.Package.Equals(second.Package, StringComparison.OrdinalIgnoreCase)) continue;
                var rule = $"cross-file-{leftRule}-{rightRule}";
                foreach (var item in new[] { first, second })
                {
                    if (!emitted.Add(rule + "|" + item.File)) continue;
                    Add(report, ScanCategory.Malware, item.File, rule,
                        $"Novel-threat capability correlation: {detail}. This is a heuristic correlation and requires analyst confirmation.",
                        item.Hash, item.Scope, 90, DetectionKind.Heuristic);
                }
            }
        }
    }

    /// <summary>Archive-entry findings are reported as "archive.zip!/entry"; the file on disk is the archive.</summary>
    public static string ContainingFile(string findingPath)
    {
        var separator = findingPath.IndexOf("!/", StringComparison.Ordinal);
        return separator < 0 ? findingPath : findingPath[..separator];
    }

    /// <summary>
    /// The mod package a file belongs to: the folder directly below a local mod directory
    /// (&lt;game&gt;\Mods\&lt;package&gt;) or directly below an external Workshop root (&lt;root&gt;\&lt;itemId&gt;).
    /// </summary>
    private static string ModPackageKey(ScanReport report, string findingPath)
    {
        var file = Path.GetFullPath(ContainingFile(findingPath));
        var root = report.ScannedRoots.Where(x => IsSameOrChildPath(x, file)).OrderByDescending(x => x.Length).FirstOrDefault();
        if (root is null) return Path.GetDirectoryName(file) ?? file;
        var parts = Path.GetRelativePath(root, file).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var depth = root.Equals(report.RootPath, StringComparison.OrdinalIgnoreCase) ? 2 : 1;
        return Path.Combine([root, .. parts[..Math.Min(depth, parts.Length - 1)]]);
    }

    // Character entropy is only meaningful for real text; strings pulled out of compressed media
    // (PNG, MP3, WAV) are always high-entropy, so binaries are judged on long encoded runs alone.
    private static readonly Regex EncodedRun = new(@"[A-Za-z0-9+/]{240,}={0,2}", RegexOptions.CultureInvariant | RegexOptions.Compiled, RegexTimeout);

    private static bool LooksObfuscated(string content, bool isText)
    {
        // Real base64 payloads use most of the alphabet; fill bytes such as LAME MP3 padding ("UUUU…")
        // form long runs of one or two characters and are not encoded content.
        var inspected = 0;
        for (var match = EncodedRun.Match(content); match.Success && inspected++ < 10_000; match = match.NextMatch())
            if (match.ValueSpan.ToArray().Distinct().Count() >= 32) return true;
        return isText && content.Length > 512 && ShannonEntropy(Encoding.UTF8.GetBytes(content)) >= 5.5;
    }

    private static bool IsPortableExecutable(byte[] bytes)
    {
        if (bytes.Length < 0x40 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z') return false;
        var offset = BitConverter.ToInt32(bytes, 0x3C);
        return offset >= 0x40 && offset <= bytes.Length - 4 && bytes[offset] == (byte)'P' && bytes[offset + 1] == (byte)'E' && bytes[offset + 2] == 0 && bytes[offset + 3] == 0;
    }

    private static double ShannonEntropy(byte[] bytes)
    {
        if (bytes.Length == 0) return 0;
        var counts = new int[256]; foreach (var value in bytes) counts[value]++;
        return counts.Where(x => x > 0).Sum(x => { var probability = (double)x / bytes.Length; return -probability * Math.Log2(probability); });
    }

    private static void Add(ScanReport report, ScanCategory category, string file, string rule, string detail, string hash, ScanScope scope, int score, DetectionKind detection = DetectionKind.Heuristic) =>
        report.Findings.Add(new ScanFinding(category, file, rule, detail, hash, scope, score, detection));
}

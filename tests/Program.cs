using System.IO.Compression;
using System.Xml.Linq;
using PPGAV.Models;
using PPGAV.Services;

static class SmokeTests
{
    private static int _passed;

    public static async Task<int> Main()
    {
        var root = Path.Combine(Path.GetTempPath(), "ppgav-smoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            TestScannerClassifiesSafeSuspiciousAndMalware(root);
            TestScannerDetectsCredentialTheftInjectionAndPersistence(root);
            TestScannerInspectsArchiveEntries(root);
            TestScannerIncludesExternalWorkshop(root);
            TestPreflightRoutesUntrustedAndCoreFindings();
            TestSandboxProviderSelection();
            TestIntegrityBaselineDetectsChangedCore(root);
            TestQuarantineMovesOnlySelectedFiles(root);
            TestQuarantineLeavesCoreFilesInPlace(root);
            TestBinaryModIsFlagged(root);
            TestNetworkEndpointParser();
            TestUpdateVerificationHelpers(root);
            TestModulePathClassification(root);
            TestRecursiveArchiveDetection(root);
            await TestBackupRoundTrip(root);
            TestBackupRejectsTraversal(root);
            TestSandboxProfileIsIsolated(root);
            TestFirewallRuleNameIsStable(root);
            TestSafeModeMovesAndRestoresMods(root);
            await TestDefenderCommandStarts(root);
            Console.WriteLine($"PASS: {_passed} smoke tests");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL: " + ex.Message);
            Console.Error.WriteLine(ex);
            return 1;
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static void TestScannerDetectsCredentialTheftInjectionAndPersistence(string root)
    {
        var mods = Path.Combine(root, "advanced-threats", "Mods");
        Directory.CreateDirectory(mods);
        File.WriteAllText(Path.Combine(mods, "stealer.cs"), "new HttpClient(); File.ReadAllText(\"Login Data\"); Environment.GetFolderPath(SpecialFolder.ApplicationData); Registry.CurrentUser.CreateSubKey(\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\"); OpenProcess(0, false, 1); WriteProcessMemory(); CreateRemoteThread();");
        var report = new ScannerService().Scan(Path.Combine(root, "advanced-threats"));
        Assert(report.Category == ScanCategory.Malware, "combined credential theft, persistence, and injection was not Malware");
        Assert(report.Findings.Any(f => f.RiskScore >= 80), "high-risk detection did not retain a risk score");
        _passed++;
    }

    private static void TestScannerInspectsArchiveEntries(string root)
    {
        var mods = Path.Combine(root, "archive-threat", "Mods");
        Directory.CreateDirectory(mods);
        using (var archive = ZipFile.Open(Path.Combine(mods, "payload.zip"), ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("../dropper.ps1");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("powershell -enc AAAA");
        }
        var report = new ScannerService().Scan(Path.Combine(root, "archive-threat"));
        Assert(report.Category == ScanCategory.Malware, "archive traversal/script payload was not Malware");
        Assert(report.Findings.Any(f => f.Rule.Contains("archive")), "archive evidence was omitted");
        _passed++;
    }

    private static void TestScannerIncludesExternalWorkshop(string root)
    {
        var library = Path.Combine(root, "steam-library");
        var game = Path.Combine(library, "steamapps", "common", "People Playground");
        var workshop = Path.Combine(library, "steamapps", "workshop", "content", "1118200");
        Directory.CreateDirectory(game);
        Directory.CreateDirectory(workshop);
        File.WriteAllText(Path.Combine(workshop, "evil.ps1"), "powershell -encodedcommand AAAA");
        var discovered = GamePathDiscovery.FindWorkshopDirectories(game);
        Assert(discovered.Contains(workshop, StringComparer.OrdinalIgnoreCase), "external Steam Workshop root was not discovered");
        var report = new ScannerService().ScanInstallation(game, discovered);
        Assert(report.Findings.Any(f => f.Scope == ScanScope.SteamWorkshop && f.Category == ScanCategory.Malware), "external Workshop payload was not scanned as malware");
        _passed++;
    }

    private static void TestPreflightRoutesUntrustedAndCoreFindings()
    {
        var clean = new ScanReport();
        Assert(PreflightDecisionEngine.Decide(clean) == PreflightAction.AllowSecure, "clean preflight was not allowed");
        var mod = new ScanReport();
        mod.Findings.Add(new ScanFinding(ScanCategory.Malware, "mod", "test", "test", "", ScanScope.LocalMods, 100));
        Assert(PreflightDecisionEngine.Decide(mod) == PreflightAction.LaunchSafeMode, "mod malware did not route to safe mode");
        var core = new ScanReport();
        core.Findings.Add(new ScanFinding(ScanCategory.Suspicious, "core", "test", "test", "", ScanScope.GameCore, 50));
        Assert(PreflightDecisionEngine.Decide(core) == PreflightAction.BlockAll, "core compromise did not fail closed");
        _passed++;
    }

    private static void TestSandboxProviderSelection()
    {
        Assert(SandboxProviderSelector.Choose(true, true) == SandboxProvider.WindowsSandbox, "Windows Sandbox was not preferred");
        Assert(SandboxProviderSelector.Choose(false, true) == SandboxProvider.SandboxieClassic, "Sandboxie fallback was not selected");
        Assert(SandboxProviderSelector.Choose(false, false) == SandboxProvider.None, "missing sandbox was not reported");
        _passed++;
    }

    private static void TestIntegrityBaselineDetectsChangedCore(string root)
    {
        var game = Path.Combine(root, "integrity-game");
        Directory.CreateDirectory(game);
        var file = Path.Combine(game, "People Playground.exe");
        File.WriteAllText(file, "trusted-fixture");
        var baseline = Path.Combine(root, "integrity-baseline.json");
        var service = new IntegrityBaselineService(baseline);
        Assert(service.CheckAndUpdate(game).Count == 0, "initial integrity baseline was not created cleanly");
        File.WriteAllText(file, "changed-fixture");
        Assert(service.CheckAndUpdate(game).Any(f => f.Rule == "trusted-file-changed"), "changed core file was not detected");
        File.WriteAllText(file, "changed-again");
        Assert(service.CheckAndUpdate(game).Any(f => f.Rule == "trusted-file-changed"), "changed baseline was incorrectly replaced");
        _passed++;
    }

    private static void TestQuarantineMovesOnlySelectedFiles(string root)
    {
        var content = Path.Combine(root, "quarantine-mod");
        var quarantine = Path.Combine(root, "quarantine-store");
        Directory.CreateDirectory(content);
        var bad = Path.Combine(content, "bad.ps1");
        var good = Path.Combine(content, "good.txt");
        File.WriteAllText(bad, "bad"); File.WriteAllText(good, "good");
        var report = new ScanReport();
        report.Findings.Add(new ScanFinding(ScanCategory.Malware, bad, "test", "bad", "hash", ScanScope.LocalMods, 100));
        var moved = new QuarantineService(quarantine).Quarantine(report);
        Assert(moved.Count == 1 && !File.Exists(bad) && File.Exists(good), "quarantine moved the wrong files");
        Assert(File.Exists(moved[0].QuarantinedPath), "quarantine copy was not created");
        _passed++;
    }

    private static void TestNetworkEndpointParser()
    {
        var lines = new[] { "TCP    127.0.0.1:1234    8.8.8.8:443    ESTABLISHED    456", "UDP    0.0.0.0:5353    *:*    456" };
        var endpoints = NetworkActivityMonitor.ParseNetstat(lines);
        Assert(endpoints.Count == 2 && endpoints.All(x => x.ProcessId == 456), "network endpoint parser missed process ownership");
        _passed++;
    }

    private static void TestQuarantineLeavesCoreFilesInPlace(string root)
    {
        var core = Path.Combine(root, "core.exe"); File.WriteAllText(core, "core");
        var report = new ScanReport();
        report.Findings.Add(new ScanFinding(ScanCategory.Malware, core, "test", "core", "hash", ScanScope.GameCore, 100));
        Assert(new QuarantineService(Path.Combine(root, "core-quarantine")).Quarantine(report).Count == 0 && File.Exists(core), "core game file was quarantined");
        _passed++;
    }

    private static void TestBinaryModIsFlagged(string root)
    {
        var mods = Path.Combine(root, "binary-mod", "Mods"); Directory.CreateDirectory(mods);
        var bytes = new byte[1024]; bytes[0] = (byte)'M'; bytes[1] = (byte)'Z'; BitConverter.GetBytes(512).CopyTo(bytes, 0x3C); bytes[512] = (byte)'P'; bytes[513] = (byte)'E';
        File.WriteAllBytes(Path.Combine(mods, "native.dll"), bytes);
        var report = new ScannerService().Scan(Path.Combine(root, "binary-mod"));
        Assert(report.Findings.Any(f => f.Rule == "untrusted-portable-executable"), "untrusted PE mod was not flagged");
        _passed++;
    }

    private static void TestUpdateVerificationHelpers(string root)
    {
        Assert(UpdateService.IsNewerVersion(new Version(1, 3), new Version(1, 2)), "newer update was not recognized");
        Assert(!UpdateService.IsNewerVersion(new Version(1, 2), new Version(1, 2)), "same update was treated as newer");
        var file = Path.Combine(root, "update.msi"); File.WriteAllText(file, "signed release fixture");
        var digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file)));
        Assert(UpdateService.VerifySha256(file, digest), "release digest verification failed");
        Assert(!UpdateService.VerifySha256(file, new string('0', 64)), "bad release digest was accepted");
        _passed++;
    }

    private static void TestModulePathClassification(string root)
    {
        Assert(BehaviorMonitor.IsSuspiciousModulePath(Path.Combine(root, "AppData", "Temp", "evil.dll")), "user temp module was not classified suspicious");
        Assert(!BehaviorMonitor.IsSuspiciousModulePath(Path.Combine(Environment.SystemDirectory, "kernel32.dll")), "Windows system module was classified suspicious");
        _passed++;
    }

    private static void TestRecursiveArchiveDetection(string root)
    {
        var mods = Path.Combine(root, "nested-archive", "Mods"); Directory.CreateDirectory(mods);
        var nestedPath = Path.Combine(root, "nested.zip");
        using (var nested = ZipFile.Open(nestedPath, ZipArchiveMode.Create))
        {
            var payload = nested.CreateEntry("dropper.ps1"); using var writer = new StreamWriter(payload.Open()); writer.Write("powershell -enc AAAA");
        }
        using (var outer = ZipFile.Open(Path.Combine(mods, "outer.zip"), ZipArchiveMode.Create))
        {
            var entry = outer.CreateEntry("nested.zip"); using var source = File.OpenRead(nestedPath); using var target = entry.Open(); source.CopyTo(target);
        }
        var report = new ScannerService().Scan(Path.Combine(root, "nested-archive"));
        Assert(report.Findings.Any(f => f.Rule == "archive-executable-payload"), "nested archive executable payload was not detected");
        _passed++;
    }

    private static void TestScannerClassifiesSafeSuspiciousAndMalware(string root)
    {
        var scanner = new ScannerService();
        var safeRoot = Path.Combine(root, "safe");
        Directory.CreateDirectory(safeRoot);
        File.WriteAllText(Path.Combine(safeRoot, "Safe.cs"), "public sealed class SafeMod { public void PerformAfterSpawn() { } }");
        Assert(scanner.Scan(safeRoot).Category == ScanCategory.Safe, "safe source was not classified Safe");

        var suspiciousRoot = Path.Combine(root, "suspicious", "Mods");
        Directory.CreateDirectory(suspiciousRoot);
        File.WriteAllText(Path.Combine(suspiciousRoot, "Review.cs"), "using System.Net.Http; class Review { void Go() => new HttpClient(); }");
        var suspicious = scanner.Scan(Path.Combine(root, "suspicious"));
        Assert(suspicious.Category == ScanCategory.Suspicious, "network-capable source was not classified Suspicious");
        Assert(suspicious.Findings.Any(f => f.Rule.Contains("network-access")), "suspicious scan did not retain the rule evidence");

        var malwareRoot = Path.Combine(root, "malware", "Mods");
        Directory.CreateDirectory(malwareRoot);
        File.WriteAllText(Path.Combine(malwareRoot, "FPSPlusPlus.cs"), "// FPS++ known marker");
        var malware = scanner.Scan(Path.Combine(root, "malware"));
        Assert(malware.Category == ScanCategory.Malware, "known FPS++ marker was not classified Malware");
        Assert(malware.Findings.Any(f => f.Sha256.Length == 64), "malware finding did not include a SHA-256 hash");
        _passed++;
    }

    private static async Task TestBackupRoundTrip(string root)
    {
        var game = Path.Combine(root, "game");
        var backups = Path.Combine(root, "backups");
        Directory.CreateDirectory(Path.Combine(game, "Mods"));
        File.WriteAllText(Path.Combine(game, "settings.json"), "original");
        File.WriteAllText(Path.Combine(game, "Mods", "one.cs"), "original mod");
        var service = new BackupService(new EventLogService());
        var backup = await service.CreateBackupAsync(game, backups, 4);
        File.WriteAllText(Path.Combine(game, "settings.json"), "changed");
        await service.RestoreAsync(backup.Path, game, backups);
        Assert(File.ReadAllText(Path.Combine(game, "settings.json")) == "original", "backup restore did not restore original content");
        Assert(File.Exists(Path.Combine(game, "Mods", "one.cs")), "backup restore omitted nested content");
        _passed++;
    }

    private static void TestBackupRejectsTraversal(string root)
    {
        var game = Path.Combine(root, "traversal-game");
        var backups = Path.Combine(root, "traversal-backups");
        Directory.CreateDirectory(game);
        Directory.CreateDirectory(backups);
        var archivePath = Path.Combine(backups, "evil.ppgbackup.zip");
        using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("../escaped.txt");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("bad");
        }

        var service = new BackupService(new EventLogService());
        try
        {
            service.RestoreAsync(archivePath, game, backups).GetAwaiter().GetResult();
            throw new InvalidOperationException("path traversal archive was accepted");
        }
        catch (InvalidDataException)
        {
            _passed++;
        }
    }

    private static void TestSandboxProfileIsIsolated(string root)
    {
        var service = new WindowsSandboxService(new EventLogService());
        var game = Path.Combine(root, "sandbox-game");
        Directory.CreateDirectory(game);
        var executable = Path.Combine(game, "People Playground.exe");
        File.WriteAllText(executable, "placeholder");
        var xml = service.BuildConfiguration(game, executable);
        Assert(xml.Root?.Element("Networking")?.Value == "Disable", "sandbox networking is not disabled");
        Assert(xml.Root?.Element("ClipboardRedirection")?.Value == "Disable", "sandbox clipboard is not disabled");
        Assert(xml.Root?.Element("vGPU")?.Value == "Disable", "sandbox vGPU is not disabled");
        Assert(xml.Descendants("ReadOnly").Single().Value == "false", "sandbox staging copy is not writable for normal save/config behavior");
        _passed++;
    }

    private static void TestFirewallRuleNameIsStable(string root)
    {
        var service = new FirewallService(new EventLogService());
        var path = Path.Combine(root, "People Playground.exe");
        var first = service.RuleNameFor(path);
        var second = service.RuleNameFor(path);
        Assert(first == second && first.StartsWith("PPGAV Safe Mode "), "firewall rule name is not deterministic");
        _passed++;
    }

    private static void TestSafeModeMovesAndRestoresMods(string root)
    {
        var game = Path.Combine(root, "safe-mode-game");
        Directory.CreateDirectory(Path.Combine(game, "Mods"));
        File.WriteAllText(Path.Combine(game, "Mods", "test.cs"), "safe mode fixture");
        var executable = Path.Combine(game, "People Playground.exe");
        File.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"), executable);
        var blocker = new FakeBlocker();
        var launcher = new SafeModeLauncher(blocker, new EventLogService());
        var settings = new AppSettings
        {
            GameDirectory = game,
            PpgExecutablePath = executable,
            RequireNetworkBlockInSafeMode = true
        };
        var session = launcher.Launch(settings);
        Assert(blocker.Blocked, "safe mode did not request outbound network blocking");
        Assert(!Directory.Exists(Path.Combine(game, "Mods")), "safe mode left the Mods directory active");
        try { session.Process.Kill(true); } catch { }
        session.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Assert(Directory.Exists(Path.Combine(game, "Mods")), "safe mode did not restore the Mods directory");
        Assert(File.Exists(Path.Combine(game, "Mods", "test.cs")), "safe mode restore lost mod content");
        _passed++;
    }

    private static async Task TestDefenderCommandStarts(string root)
    {
        var target = Path.Combine(root, "defender-check.txt");
        File.WriteAllText(target, "PPGAV Defender integration smoke test");
        var result = await new DefenderService(new EventLogService()).RunFullScanAsync(target);
        Assert(result.Started, "Windows Defender command-line scan did not start");
        Assert(result.ExitCode == 0, $"Windows Defender returned exit code {result.ExitCode}");
        _passed++;
    }

    private sealed class FakeBlocker : IOutboundNetworkBlocker
    {
        public bool Blocked { get; private set; }
        public bool TryBlockOutbound(string executablePath, out string ruleName)
        {
            Blocked = true;
            ruleName = "test-rule";
            return true;
        }

        public bool TryRemove(string executablePath) => true;
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}

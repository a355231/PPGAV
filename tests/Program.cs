using System.IO.Compression;
using System.Xml.Linq;
using System.Text.Json.Nodes;
using PPGAV.Models;
using PPGAV.Services;

static class SmokeTests
{
    private static int _passed;
    private static EventLogService TestEvents(string root) => new(Path.Combine(root, "test-logs", "events.jsonl"));

    private static void TestEventLogCanBeIsolated(string root)
    {
        var path = Path.Combine(root, "isolated-events", "events.jsonl");
        var events = new EventLogService(path);
        events.Log("test-only", "This event must remain under the disposable test root.");
        Assert(File.Exists(path) && File.ReadAllText(path).Contains("test-only", StringComparison.Ordinal), "custom EventLogService path was not respected");
        _passed++;
    }

    public static async Task<int> Main()
    {
        var root = Path.Combine(Path.GetTempPath(), "ppgav-smoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            TestScannerClassifiesSafeSuspiciousAndMalware(root);
            TestEventLogCanBeIsolated(root);
            TestScannerDetectsCredentialTheftInjectionAndPersistence(root);
            TestScannerCorrelatesSplitModCapabilities(root);
            TestScannerCorrelatesNovelCapabilityPair(root);
            TestScannerInspectsArchiveEntries(root);
            TestScannerIncludesExternalWorkshop(root);
            TestPreflightRoutesUntrustedAndCoreFindings();
            TestSandboxProviderSelection();
            TestIntegrityBaselineDetectsChangedCore(root);
            TestIntegrityBaselineFailsClosed(root);
            TestIntegrityBaselineAuthenticatesAllMetadata(root);
            TestIntegrityBaselineApprovalBoundToScan(root);
            TestQuarantineMovesOnlySelectedFiles(root);
            TestQuarantineRollsBackPartialMove(root);
            TestQuarantineLeavesCoreFilesInPlace(root);
            TestBinaryModIsFlagged(root);
            TestNetworkEndpointParser();
            TestUpdateVerificationHelpers(root);
            TestModulePathClassification(root);
            TestRecursiveArchiveDetection(root);
            await TestBackupRoundTrip(root);
            TestBackupRejectsTraversal(root);
            await TestBackupRejectsOverlappingDirectories(root);
            await TestBackupCancellationIsClean(root);
            await TestBackupTamperingIsRejected(root);
            TestSandboxProfileIsIsolated(root);
            TestFirewallRuleNameIsStable(root);
            TestSafeModeMovesAndRestoresMods(root);
            TestSafeModeLaunchAfterQuarantine(root);
            TestSafeModeCrashRecoveryAndIgnoresArbitraryDisabledFolders(root);
            TestSafeModeRollsBackPartialMoves(root);
            await TestDefenderCommandStarts(root);
            TestAmsiRecoversAfterEmptyFile(root);
            TestCoreVendorBinariesAreNotHeuristicallyScored(root);
            TestNestedModsFolderInCoreStaysCore(root);
            TestCompressedMediaIsNotObfuscation(root);
            TestCredentialRuleIgnoresDiscordLinksAndCancellationTokens(root);
            TestCrossFileCorrelationStaysWithinOneMod(root);
            TestLoneWeakIndicatorIsInformational(root);
            TestCompiledModCacheIsModScopeWithoutDllPolicy(root);
            TestIntegrityBaselineIgnoresRuntimeData(root);
            TestQuarantineMovesArchiveForEntryFinding(root);
            TestDefenderThreatRequiresConfirmation();
            TestWatcherScanToleratesOpenAndDeletedFiles(root);
            await TestScheduledBackupDetectsUnchangedGame(root);
            TestSafeModeDisablesCompiledMods(root);
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

    private static void TestScannerCorrelatesSplitModCapabilities(string root)
    {
        var mods = Path.Combine(root, "split-capabilities", "Mods");
        Directory.CreateDirectory(mods);
        File.WriteAllText(Path.Combine(mods, "collect.cs"), "File.ReadAllText(\"Login Data\");");
        File.WriteAllText(Path.Combine(mods, "send.cs"), "new HttpClient().PostAsync(url, payload);");
        var report = new ScannerService().Scan(Path.GetDirectoryName(mods)!);
        Assert(report.Findings.Any(f => f.Rule.StartsWith("cross-file-credential-theft-network-access", StringComparison.Ordinal) && f.Category == ScanCategory.Malware),
            "scanner missed a credential-theft/exfiltration capability chain split across mod files");
        _passed++;
    }

    private static void TestScannerCorrelatesNovelCapabilityPair(string root)
    {
        var mods = Path.Combine(root, "novel-capability-pair", "Mods");
        Directory.CreateDirectory(mods);
        File.WriteAllText(Path.Combine(mods, "evasion.cs"), "if (IsDebuggerPresent()) return;");
        File.WriteAllText(Path.Combine(mods, "loader.cs"), "Convert.FromBase64String(payload);");
        var report = new ScannerService().Scan(Path.GetDirectoryName(mods)!);
        Assert(report.Findings.Any(f => f.Rule == "cross-file-anti-analysis-encoded-payload" && f.Category == ScanCategory.Malware && f.Detection == DetectionKind.Heuristic),
            "scanner missed an evasion-plus-payload-staging capability chain split across mod files");
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
        var report = new ScannerService().ScanInstallation(game, [workshop]);
        Assert(report.Findings.Any(f => f.Scope == ScanScope.SteamWorkshop && f.Category == ScanCategory.Malware), "external Workshop payload was not scanned as malware");
        _passed++;
    }

    private static void TestPreflightRoutesUntrustedAndCoreFindings()
    {
        var clean = new ScanReport { IsComplete = true };
        Assert(PreflightDecisionEngine.Decide(clean, true) == PreflightAction.AllowSecure, "clean preflight was not allowed");
        var mod = new ScanReport { IsComplete = true };
        mod.Findings.Add(new ScanFinding(ScanCategory.Malware, "mod", "test", "test", "", ScanScope.LocalMods, 100));
        Assert(PreflightDecisionEngine.Decide(mod, true) == PreflightAction.LaunchSafeMode, "mod malware did not route to safe mode");
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
        Assert(service.Check(game, file).Any(f => f.Rule == "baseline-missing"), "missing integrity baseline was not fail-closed");
        TrustBaselineFromCurrentScan(service, game, file, "smoke-test approval");
        Assert(service.Check(game, file).Count == 0, "approved integrity baseline was not clean");
        File.WriteAllText(file, "changed-fixture");
        Assert(service.Check(game, file).Any(f => f.Rule == "trusted-file-changed"), "changed core file was not detected");
        File.WriteAllText(file, "changed-again");
        Assert(service.Check(game, file).Any(f => f.Rule == "trusted-file-changed"), "changed baseline was incorrectly replaced");
        _passed++;
    }

    private static void TestIntegrityBaselineFailsClosed(string root)
    {
        var game = Path.Combine(root, "integrity-fail-closed"); Directory.CreateDirectory(game);
        var executable = Path.Combine(game, "People Playground.exe"); File.WriteAllText(executable, "identity");
        var baseline = Path.Combine(root, "integrity-fail-closed.json"); var service = new IntegrityBaselineService(baseline);
        TrustBaselineFromCurrentScan(service, game, executable, "corruption-test approval");
        File.WriteAllText(baseline, "tampered"); Assert(service.Check(game, executable).Any(f => f.Rule == "baseline-invalid"), "corrupt baseline was not blocked");
        File.Delete(baseline); Assert(service.Check(game, executable).Any(f => f.Rule == "baseline-missing"), "deleted baseline was not blocked");
        TrustBaselineFromCurrentScan(service, game, executable, "moved-test approval");
        var moved = Path.Combine(root, "integrity-moved"); Directory.CreateDirectory(moved); var movedExecutable = Path.Combine(moved, "People Playground.exe"); File.Copy(executable, movedExecutable);
        Assert(service.Check(moved, movedExecutable).Any(f => f.Rule == "baseline-installation-changed"), "moved installation was incorrectly trusted");
        _passed++;
    }

    private static void TestQuarantineMovesOnlySelectedFiles(string root)
    {
        var content = Path.Combine(root, "quarantine-mod");
        var quarantine = Path.Combine(root, "quarantine-store");
        var mods = Path.Combine(content, "Mods");
        Directory.CreateDirectory(mods);
        var bad = Path.Combine(mods, "bad.ps1");
        var good = Path.Combine(mods, "good.txt");
        File.WriteAllText(bad, "bad"); File.WriteAllText(good, "good");
        var report = new ScanReport { IsComplete = true };
        report.ScannedRoots.Add(content);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(bad)));
        report.ScannedHashes[bad] = hash;
        report.Findings.Add(new ScanFinding(ScanCategory.Malware, bad, "test", "bad", hash, ScanScope.LocalMods, 100, DetectionKind.Confirmed));
        var service = new QuarantineService(quarantine, TestEvents(root));
        var moved = service.Quarantine(report);
        Assert(moved.Count == 1 && !File.Exists(bad) && File.Exists(good), "quarantine moved the wrong files");
        Assert(File.Exists(moved[0].QuarantinedPath), "quarantine copy was not created");
        service.Restore(moved[0].ManifestPath!);
        Assert(File.Exists(bad) && !File.Exists(moved[0].QuarantinedPath), "quarantine restore did not return the validated file");
        _passed++;
    }

    private static void TestNetworkEndpointParser()
    {
        var lines = new[] { "TCP    127.0.0.1:1234    8.8.8.8:443    ESTABLISHED    456", "UDP    0.0.0.0:5353    *:*    456" };
        var endpoints = NetworkActivityMonitor.ParseNetstat(lines);
        Assert(endpoints.Count == 2 && endpoints.All(x => x.ProcessId == 456), "network endpoint parser missed process ownership");
        _passed++;
    }

    private static void TestQuarantineRollsBackPartialMove(string root)
    {
        var content = Path.Combine(root, "quarantine-rollback");
        var mods = Path.Combine(content, "Mods");
        var quarantine = Path.Combine(root, "quarantine-rollback-store");
        Directory.CreateDirectory(mods);
        var files = new[] { Path.Combine(mods, "one.dll"), Path.Combine(mods, "two.dll") };
        foreach (var path in files) File.WriteAllText(path, Path.GetFileName(path));
        var report = new ScanReport { IsComplete = true };
        report.ScannedRoots.Add(content);
        foreach (var path in files)
        {
            var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)));
            report.ScannedHashes[path] = hash;
            report.Findings.Add(new ScanFinding(ScanCategory.Malware, path, "test", "test", hash, ScanScope.LocalMods, 100, DetectionKind.Confirmed));
        }
        var service = new QuarantineService(quarantine, TestEvents(root), beforeMove: (index, _) =>
        {
            if (index == 1) throw new IOException("fault injection after first quarantine move");
        });
        try
        {
            service.Quarantine(report);
            throw new InvalidOperationException("injected quarantine failure was ignored");
        }
        catch (IOException ex) when (ex.Message.Contains("every moved file was restored", StringComparison.Ordinal)) { }
        Assert(files.All(File.Exists), "partial quarantine did not roll back every source file");
        Assert(!Directory.EnumerateFiles(Path.Combine(quarantine, "files"), "*", SearchOption.AllDirectories).Any(), "partial quarantine left payload files in quarantine");
        _passed++;
    }

    private static void TestQuarantineLeavesCoreFilesInPlace(string root)
    {
        var core = Path.Combine(root, "core.exe"); File.WriteAllText(core, "core");
        var report = new ScanReport();
        report.Findings.Add(new ScanFinding(ScanCategory.Malware, core, "test", "core", "hash", ScanScope.GameCore, 100));
        Assert(new QuarantineService(Path.Combine(root, "core-quarantine"), TestEvents(root)).Quarantine(report).Count == 0 && File.Exists(core), "core game file was quarantined");
        _passed++;
    }

    private static void TestIntegrityBaselineAuthenticatesAllMetadata(string root)
    {
        var game = Path.Combine(root, "integrity-metadata-game"); Directory.CreateDirectory(game);
        var executable = Path.Combine(game, "People Playground.exe"); File.WriteAllText(executable, "baseline metadata fixture");
        var baselinePath = Path.Combine(root, "integrity-metadata.json");
        var service = new IntegrityBaselineService(baselinePath);
        TrustBaselineFromCurrentScan(service, game, executable, "metadata-tamper regression test");
        var json = JsonNode.Parse(File.ReadAllText(baselinePath))!;
        json["Files"]![0]!["Hash"] = new string('A', 64);
        File.WriteAllText(baselinePath, json.ToJsonString());
        var findings = service.Check(game, executable);
        Assert(findings.Any(x => x.Rule == "baseline-tampered") && service.LastStatus == IntegrityBaselineStatus.Tampered,
            "baseline file-list metadata changed without authentication failure");
        _passed++;
    }

    private static void TestIntegrityBaselineApprovalBoundToScan(string root)
    {
        var game = Path.Combine(root, "integrity-scan-bound-game");
        Directory.CreateDirectory(game);
        var executable = Path.Combine(game, "People Playground.exe");
        File.WriteAllText(executable, "approved scan version");
        var baselinePath = Path.Combine(root, "integrity-scan-bound.json");
        var service = new IntegrityBaselineService(baselinePath);
        var scan = new ScannerService().Scan(game);
        Assert(scan.IsComplete, "baseline approval fixture scan was incomplete");
        File.WriteAllText(executable, "changed after the approval scan");
        try
        {
            service.TrustCurrent(game, executable, "scan-binding regression", scan);
            throw new InvalidOperationException("baseline approval trusted core content changed after inspection");
        }
        catch (IOException) { }
        Assert(!File.Exists(baselinePath), "failed baseline approval wrote a trusted baseline");
        _passed++;
    }

    private static void TrustBaselineFromCurrentScan(IntegrityBaselineService service, string game, string executable, string reason)
    {
        var scan = new ScannerService().Scan(game);
        Assert(scan.IsComplete, "integrity baseline fixture scan was incomplete");
        service.TrustCurrent(game, executable, reason, scan);
    }

    private static void TestBinaryModIsFlagged(string root)
    {
        var mods = Path.Combine(root, "binary-mod", "Mods"); Directory.CreateDirectory(mods);
        var bytes = new byte[1024]; bytes[0] = (byte)'M'; bytes[1] = (byte)'Z'; BitConverter.GetBytes(512).CopyTo(bytes, 0x3C); bytes[512] = (byte)'P'; bytes[513] = (byte)'E';
        File.WriteAllBytes(Path.Combine(mods, "native.dll"), bytes);
        File.WriteAllBytes(Path.Combine(mods, "settings.dat"), bytes);
        var report = new ScannerService().Scan(Path.Combine(root, "binary-mod"));
        Assert(report.Findings.Any(f => f.Rule == "untrusted-portable-executable"), "untrusted PE mod was not flagged");
        Assert(report.Findings.Any(f => f.Rule == "disguised-portable-executable"), "PE payload renamed with a data extension was not flagged");
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
        var service = new BackupService(TestEvents(root), Path.Combine(root, "backup-safety"));
        var backup = await service.CreateBackupAsync(game, backups, 4);
        File.WriteAllText(Path.Combine(game, "settings.json"), "changed");
        await service.RestoreAsync(backup.Path, game, backups);
        Assert(File.ReadAllText(Path.Combine(game, "settings.json")) == "original", "backup restore did not restore original content");
        Assert(File.Exists(Path.Combine(game, "Mods", "one.cs")), "backup restore omitted nested content");
        _passed++;
    }

    private static async Task TestBackupRejectsOverlappingDirectories(string root)
    {
        var game = Path.Combine(root, "overlap-game");
        Directory.CreateDirectory(game);
        File.WriteAllText(Path.Combine(game, "game.dat"), "fixture");
        var service = new BackupService(TestEvents(root), Path.Combine(root, "overlap-safety"));
        foreach (var backupPath in new[] { game, root, Path.Combine(game, "nested-backups") })
        {
            try
            {
                await service.CreateBackupAsync(game, backupPath, 3);
                throw new InvalidOperationException("overlapping backup directory was accepted");
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("completely separate", StringComparison.Ordinal)) { }
        }
        _passed++;
    }

    private static async Task TestBackupCancellationIsClean(string root)
    {
        var game = Path.Combine(root, "cancel-game");
        var backups = Path.Combine(root, "cancel-backups");
        Directory.CreateDirectory(game);
        File.WriteAllText(Path.Combine(game, "game.dat"), "fixture");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try
        {
            await new BackupService(TestEvents(root), Path.Combine(root, "cancel-safety"))
                .CreateBackupAsync(game, backups, 3, cancellation.Token);
            throw new InvalidOperationException("cancelled backup unexpectedly completed");
        }
        catch (OperationCanceledException) { }
        Assert(!Directory.Exists(backups) || !Directory.EnumerateFiles(backups).Any(), "cancelled backup left a partial archive");
        _passed++;
    }

    private static async Task TestBackupTamperingIsRejected(string root)
    {
        var game = Path.Combine(root, "tamper-game");
        var backups = Path.Combine(root, "tamper-backups");
        Directory.CreateDirectory(game);
        File.WriteAllText(Path.Combine(game, "game.dat"), "fixture");
        var service = new BackupService(TestEvents(root), Path.Combine(root, "tamper-safety"));
        var backup = await service.CreateBackupAsync(game, backups, 3);
        using (var archive = ZipFile.Open(backup.Path, ZipArchiveMode.Update))
        {
            var entry = archive.GetEntry("game.dat") ?? throw new InvalidDataException("test backup entry is missing");
            entry.Delete();
            using var writer = new StreamWriter(archive.CreateEntry("game.dat").Open());
            writer.Write("tampered payload");
        }
        Assert(service.ListBackups(backups).Count == 1, "authenticated backup manifest was unexpectedly lost");
        try
        {
            await service.RestoreAsync(backup.Path, game, backups);
            throw new InvalidOperationException("tampered backup was restored");
        }
        catch (IOException) { }
        Assert(File.ReadAllText(Path.Combine(game, "game.dat")) == "fixture", "tampered backup changed the game before rejection");
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

        var service = new BackupService(TestEvents(root));
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
        var service = new WindowsSandboxService(TestEvents(root));
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
        var service = new FirewallService(TestEvents(root));
        var path = Path.Combine(root, "People Playground.exe");
        var first = service.RuleNameFor(path);
        var second = service.RuleNameFor(path);
        Assert(first != second && first.StartsWith("PPGAV Safe Mode ") && second.StartsWith("PPGAV Safe Mode "), "firewall rule name is not uniquely owned");
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
        var launcher = new SafeModeLauncher(blocker, TestEvents(root), Path.Combine(root, "safe-mode-state"), workshopRootProvider: _ => []);
        var settings = new AppSettings
        {
            GameDirectory = game,
            PpgExecutablePath = executable
        };
        var report = new ScannerService().Scan(game);
        Assert(report.IsComplete, "safe-mode fixture scan was incomplete");
        var session = launcher.Launch(settings, report);
        Assert(blocker.Blocked, "safe mode did not request outbound network blocking");
        Assert(!Directory.Exists(Path.Combine(game, "Mods")), "safe mode left the Mods directory active");
        try { session.Process.Kill(true); } catch { }
        try { session.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch (Exception ex) { throw new InvalidOperationException($"safe mode cleanup exception: {ex.Message}; failure={session.CleanupFailure}", ex); }
        Assert(Directory.Exists(Path.Combine(game, "Mods")), $"safe mode did not restore the Mods directory; cleanup={session.CleanupFailure}; remaining={string.Join(",", Directory.GetFileSystemEntries(game))}");
        Assert(File.Exists(Path.Combine(game, "Mods", "test.cs")), "safe mode restore lost mod content");
        _passed++;
    }

    private static void TestSafeModeLaunchAfterQuarantine(string root)
    {
        var game = Path.Combine(root, "safe-mode-quarantine-game");
        var mods = Path.Combine(game, "Mods");
        Directory.CreateDirectory(mods);
        var malware = Path.Combine(mods, "FPSPlusPlus.cs");
        File.WriteAllText(malware, "// FPS++ known marker");
        File.WriteAllText(Path.Combine(mods, "ordinary.txt"), "ordinary fixture content");
        var executable = Path.Combine(game, "People Playground.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), executable);

        var report = new ScannerService().ScanInstallation(game, []);
        Assert(report.IsComplete && report.Findings.Any(f => f.Category == ScanCategory.Malware), "Safe Mode quarantine fixture was not completely scanned as malware");
        var quarantine = new QuarantineService(Path.Combine(root, "safe-mode-launch-quarantine"), TestEvents(root));
        var moved = quarantine.Quarantine(report);
        Assert(moved.Count == 1 && !File.Exists(malware) && File.Exists(moved[0].QuarantinedPath), "confirmed mod malware was not quarantined transactionally");
        Assert(!ScannerService.VerifySnapshot(report, [], out _), "ordinary snapshot verification unexpectedly accepted the quarantined source tree");
        Assert(ScannerService.VerifySnapshotExcludingRoots(report, [], [mods], out var snapshotError), $"Safe Mode could not revalidate unchanged game files after quarantine: {snapshotError}");

        var blocker = new FakeBlocker();
        var launcher = new SafeModeLauncher(blocker, TestEvents(root), Path.Combine(root, "safe-mode-quarantine-state"), workshopRootProvider: _ => []);
        var session = launcher.Launch(new AppSettings { GameDirectory = game, PpgExecutablePath = executable }, report);
        Assert(blocker.Blocked && !Directory.Exists(mods), "Safe Mode did not relaunch with the infected mod tree disabled");
        try { session.Process.Kill(true); } catch { }
        session.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Assert(Directory.Exists(mods) && File.Exists(Path.Combine(mods, "ordinary.txt")), "Safe Mode did not restore the remaining mod tree");
        Assert(!File.Exists(malware) && File.Exists(moved[0].QuarantinedPath), "Safe Mode restored quarantined malware into the active mod tree");
        _passed++;
    }

    private static void TestSafeModeCrashRecoveryAndIgnoresArbitraryDisabledFolders(string root)
    {
        var game = Path.Combine(root, "safe-mode-crash-game");
        var mods = Path.Combine(game, "Mods"); Directory.CreateDirectory(mods);
        File.WriteAllText(Path.Combine(mods, "kept.txt"), "fixture");
        var arbitrary = Path.Combine(game, "Mods.ppgav-disabled-not-a-guid"); Directory.CreateDirectory(arbitrary);
        File.WriteAllText(Path.Combine(arbitrary, "user.txt"), "must not be restored/deleted");
        var executable = Path.Combine(game, "People Playground.exe"); File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), executable);
        var state = Path.Combine(root, "safe-mode-crash-state");
        var blocker = new FakeBlocker();
        var launcher = new SafeModeLauncher(blocker, TestEvents(root), state, workshopRootProvider: _ => []);
        var settings = new AppSettings { GameDirectory = game, PpgExecutablePath = executable };
        var report = new ScannerService().Scan(game);
        var session = launcher.Launch(settings, report);
        try { session.Process.Kill(true); } catch { }
        var changedConfiguredGame = Path.Combine(root, "safe-mode-crash-other-game"); Directory.CreateDirectory(changedConfiguredGame);
        launcher.RecoverStaleDisabledMods(changedConfiguredGame);
        Assert(Directory.Exists(mods) && File.Exists(Path.Combine(mods, "kept.txt")), "startup recovery did not restore the authenticated moved folder");
        Assert(File.Exists(Path.Combine(arbitrary, "user.txt")), "recovery touched an arbitrary .ppgav-disabled-* folder");
        Assert(blocker.RemovedRules.Count > 0, "crash recovery did not remove the owned firewall rule");
        Assert(!Directory.EnumerateFiles(state, "*.json").Any(), "recovered manifest was not removed");
        _passed++;
    }

    private static void TestSafeModeRollsBackPartialMoves(string root)
    {
        var game = Path.Combine(root, "safe-mode-rollback-game");
        var mods = Path.Combine(game, "Mods"); var workshop = Path.Combine(game, "Workshop");
        Directory.CreateDirectory(mods); Directory.CreateDirectory(workshop);
        File.WriteAllText(Path.Combine(mods, "one.txt"), "one"); File.WriteAllText(Path.Combine(workshop, "two.txt"), "two");
        var executable = Path.Combine(game, "People Playground.exe"); File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), executable);
        var moves = 0; var blocker = new FakeBlocker();
        var launcher = new SafeModeLauncher(blocker, TestEvents(root), Path.Combine(root, "safe-mode-rollback-state"),
            beforeMove: (_, _) => { if (++moves == 2) throw new IOException("fault-injected second move failure"); }, workshopRootProvider: _ => []);
        var report = new ScannerService().Scan(game);
        try { launcher.Launch(new AppSettings { GameDirectory = game, PpgExecutablePath = executable }, report); throw new InvalidOperationException("fault-injected partial move unexpectedly launched"); }
        catch (IOException ex) when (ex.Message.Contains("fault-injected", StringComparison.Ordinal)) { }
        Assert(Directory.Exists(mods) && Directory.Exists(workshop), "transactional rollback did not restore every original mod directory");
        Assert(File.Exists(Path.Combine(mods, "one.txt")) && File.Exists(Path.Combine(workshop, "two.txt")), "transactional rollback lost content");
        Assert(blocker.RemovedRules.Count > 0, "failed Safe Mode launch did not remove its firewall rule");
        Assert(!Directory.EnumerateFiles(Path.Combine(root, "safe-mode-rollback-state"), "*.json").Any(), "successful rollback retained an unnecessary recovery manifest");
        _passed++;
    }

    private static async Task TestDefenderCommandStarts(string root)
    {
        var target = Path.Combine(root, "defender-check.txt");
        File.WriteAllText(target, "PPGAV Defender integration smoke test");
        var result = await new DefenderService(TestEvents(root)).RunFullScanAsync(target);
        Assert(result.Started, "Windows Defender command-line scan did not start");
        Assert(result.ExitCode == 0, $"Windows Defender returned exit code {result.ExitCode}");
        _passed++;
    }

    private static void TestAmsiRecoversAfterEmptyFile(string root)
    {
        // An empty file made AMSI return E_INVALIDARG and leaked its in-progress gate, so every later
        // AMSI call failed and every scan (and therefore every launch) was incomplete.
        var game = Path.Combine(root, "amsi-empty"); Directory.CreateDirectory(game);
        File.WriteAllBytes(Path.Combine(game, "externalactives"), []);
        File.WriteAllText(Path.Combine(game, "attribution.txt"), "ordinary text");
        var report = new ScannerService().Scan(game);
        Assert(report.IsComplete && report.Errors.Count == 0, $"AMSI failure after an empty file left the scan incomplete: {string.Join(" | ", report.Errors)}");
        _passed++;
    }

    private static void TestCoreVendorBinariesAreNotHeuristicallyScored(string root)
    {
        // Real Unity/.NET runtime files contain every API name the capability rules look for.
        const string apiNames = "OpenProcess WriteProcessMemory CreateRemoteThread passwords Socket HttpClient CurrentVersion\\Run";
        var game = Path.Combine(root, "vendor-core"); Directory.CreateDirectory(Path.Combine(game, "Mods"));
        File.WriteAllText(Path.Combine(game, "UnityPlayer.dll"), apiNames);
        File.WriteAllText(Path.Combine(game, "Mods", "payload.cs"), apiNames);
        var report = new ScannerService().Scan(game);
        Assert(report.IsComplete && !report.Findings.Any(f => f.Scope == ScanScope.GameCore), "vendor core binary was heuristically flagged");
        Assert(report.Findings.Any(f => f.Scope == ScanScope.LocalMods && f.Category == ScanCategory.Malware), "identical mod content was not flagged");
        Assert(PreflightDecisionEngine.Decide(report, true) == PreflightAction.LaunchSafeMode, "mod-only threat did not route to Safe Mode");
        _passed++;
    }

    private static void TestNestedModsFolderInCoreStaysCore(string root)
    {
        var game = Path.Combine(root, "nested-mods-core");
        var nested = Path.Combine(game, "People Playground_Data", "Mods"); Directory.CreateDirectory(nested);
        File.WriteAllText(Path.Combine(nested, "FPSPlusPlus.cs"), "// FPS++ marker");
        var report = new ScannerService().Scan(game);
        Assert(report.Findings.Any(f => f.Scope == ScanScope.GameCore), "a nested Mods folder inside core data was treated as disposable mod content");
        Assert(PreflightDecisionEngine.Decide(report, true) == PreflightAction.BlockAll, "core-data malware did not fail closed");
        _passed++;
    }

    private static void TestCompressedMediaIsNotObfuscation(string root)
    {
        var game = Path.Combine(root, "media-mod"); var mod = Path.Combine(game, "Mods", "sounds"); Directory.CreateDirectory(mod);
        var mp3 = new byte[64 * 1024]; new Random(7).NextBytes(mp3); Array.Fill(mp3, (byte)'U', 1000, 4000); // LAME padding
        File.WriteAllBytes(Path.Combine(mod, "shot.mp3"), mp3);
        var png = new byte[64 * 1024]; new Random(11).NextBytes(png);
        File.WriteAllBytes(Path.Combine(mod, "sprite.png"), png);
        var report = new ScannerService().Scan(game);
        Assert(report.IsComplete && !report.Findings.Any(), $"compressed media was flagged: {string.Join(", ", report.Findings.Select(f => f.Rule))}");
        _passed++;
    }

    private static void TestCredentialRuleIgnoresDiscordLinksAndCancellationTokens(string root)
    {
        var game = Path.Combine(root, "benign-words"); var mod = Path.Combine(game, "Mods", "a"); Directory.CreateDirectory(mod);
        File.WriteAllText(Path.Combine(mod, "Mod.cs"), "// join our discord server! https://discord.gg/x\nvoid Run(CancellationToken token) { }");
        var report = new ScannerService().Scan(game);
        Assert(!report.Findings.Any(f => f.Rule.Contains("credential-theft")), "a Discord invite or CancellationToken was treated as credential theft");
        File.WriteAllText(Path.Combine(mod, "Stealer.cs"), "var path = roaming + \"\\\\discord\\\\Local Storage\\\\leveldb\"; // grab discord token");
        Assert(new ScannerService().Scan(game).Findings.Any(f => f.Rule.Contains("credential-theft")), "Discord token theft artifacts were not detected");
        _passed++;
    }

    private static void TestCrossFileCorrelationStaysWithinOneMod(string root)
    {
        var game = Path.Combine(root, "cross-mod");
        Directory.CreateDirectory(Path.Combine(game, "Mods", "A")); Directory.CreateDirectory(Path.Combine(game, "Mods", "B"));
        File.WriteAllText(Path.Combine(game, "Mods", "A", "collect.cs"), "File.ReadAllText(\"Login Data\");");
        File.WriteAllText(Path.Combine(game, "Mods", "B", "send.cs"), "new HttpClient().PostAsync(url, payload);");
        var report = new ScannerService().Scan(game);
        Assert(!report.Findings.Any(f => f.Rule.StartsWith("cross-file-", StringComparison.Ordinal)), "capabilities from two unrelated mods were correlated as one threat");
        _passed++;
    }

    private static void TestLoneWeakIndicatorIsInformational(string root)
    {
        var game = Path.Combine(root, "weak-indicator"); var mod = Path.Combine(game, "Mods", "timer"); Directory.CreateDirectory(mod);
        File.WriteAllText(Path.Combine(mod, "Mod.cs"), "async void Blink() { await Task.Delay(100); }");
        var report = new ScannerService().Scan(game);
        Assert(report.Findings.All(f => f.Category == ScanCategory.Safe), "a lone Task.Delay was reported as suspicious");
        Assert(PreflightDecisionEngine.Decide(report, true) == PreflightAction.AllowSecure, "informational evidence forced Safe Mode");
        _passed++;
    }

    private static void TestCompiledModCacheIsModScopeWithoutDllPolicy(string root)
    {
        var game = Path.Combine(root, "compiled-cache"); var cache = Path.Combine(game, "CompiledMods"); Directory.CreateDirectory(cache);
        var pe = new byte[1024]; pe[0] = (byte)'M'; pe[1] = (byte)'Z'; BitConverter.GetBytes(512).CopyTo(pe, 0x3C); pe[512] = (byte)'P'; pe[513] = (byte)'E';
        File.WriteAllBytes(Path.Combine(cache, "Author-Mod-123.dll"), pe);
        var report = new ScannerService().Scan(game);
        Assert(report.IsComplete && !report.Findings.Any(f => f.Category != ScanCategory.Safe), "a game-generated CompiledMods assembly was flagged as an untrusted payload");
        File.WriteAllText(Path.Combine(cache, "FPSPlusPlus.cs"), "// FPS++");
        report = new ScannerService().Scan(game);
        Assert(report.Findings.Any(f => f.Scope == ScanScope.LocalMods && f.Category == ScanCategory.Malware), "CompiledMods content was not inspected as mod content");
        _passed++;
    }

    private static void TestIntegrityBaselineIgnoresRuntimeData(string root)
    {
        var game = Path.Combine(root, "runtime-data-game"); Directory.CreateDirectory(Path.Combine(game, "Logs")); Directory.CreateDirectory(Path.Combine(game, "Contraptions"));
        var executable = Path.Combine(game, "People Playground.exe"); File.WriteAllText(executable, "core");
        File.WriteAllText(Path.Combine(game, "config.json"), "{\"volume\":1}");
        File.WriteAllText(Path.Combine(game, "Logs", "Main.log"), "started");
        var service = new IntegrityBaselineService(Path.Combine(root, "runtime-data-baseline.json"));
        TrustBaselineFromCurrentScan(service, game, executable, "runtime-data regression");
        File.WriteAllText(Path.Combine(game, "config.json"), "{\"volume\":0.5}");
        File.WriteAllText(Path.Combine(game, "Logs", "Main.log"), "started\nplayed");
        File.WriteAllText(Path.Combine(game, "Contraptions", "tank.json"), "{}");
        Assert(service.Check(game, executable).Count == 0 && service.LastStatus == IntegrityBaselineStatus.Valid, "normal play (settings/log/save writes) broke the core baseline");
        File.WriteAllText(executable, "tampered core");
        Assert(service.Check(game, executable).Any(f => f.Rule == "trusted-file-changed" && IntegrityBaselineService.IsIntegrityRule(f.Rule)), "a changed core executable was not detected");
        Assert(service.LastStatus == IntegrityBaselineStatus.ContentChanged, "changed core content did not report ContentChanged for re-approval");
        _passed++;
    }

    private static void TestQuarantineMovesArchiveForEntryFinding(string root)
    {
        var game = Path.Combine(root, "archive-quarantine"); var mods = Path.Combine(game, "Mods"); Directory.CreateDirectory(mods);
        var archivePath = Path.Combine(mods, "pack.zip");
        using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        using (var writer = new StreamWriter(archive.CreateEntry("inner.txt").Open())) writer.Write("// FPS++ marker");
        var report = new ScannerService().Scan(game);
        Assert(report.Findings.Any(f => f.FilePath.Contains("!/", StringComparison.Ordinal) && f.Detection == DetectionKind.Confirmed), "archive entry malware was not reported");
        var moved = new QuarantineService(Path.Combine(root, "archive-quarantine-store"), TestEvents(root)).Quarantine(report);
        Assert(moved.Count == 1 && !File.Exists(archivePath) && File.Exists(moved[0].QuarantinedPath), "an archive-entry finding did not quarantine its archive");
        _passed++;
    }

    private static void TestDefenderThreatRequiresConfirmation()
    {
        Assert(!new DefenderScanResult(false, -1, "", "MpCmdRun.exe was not found.").ThreatConfirmed, "an unavailable Defender was reported as an active threat");
        Assert(!new DefenderScanResult(true, 0, "", "", StatusVerified: false).ThreatConfirmed, "an unverifiable Defender status was reported as an active threat");
        Assert(new DefenderScanResult(true, 2, "", "").ThreatConfirmed, "MpCmdRun threat exit code was not treated as a detection");
        Assert(new DefenderScanResult(true, 0, "", "", StatusVerified: true, ThreatsDetected: true).ThreatConfirmed, "a verified active threat was not reported");
        _passed++;
    }

    private static void TestWatcherScanToleratesOpenAndDeletedFiles(string root)
    {
        var game = Path.Combine(root, "watcher-game"); Directory.CreateDirectory(Path.Combine(game, "Logs"));
        var log = Path.Combine(game, "Logs", "Main.log");
        using (var writer = new FileStream(log, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            writer.Write("game is running"u8);
            writer.Flush();
            var report = new ScannerService().ScanFile(log, GameLayout.ScopeFor(game, log));
            Assert(report.IsComplete, $"a log the game holds open made the runtime watcher stop the session: {string.Join(" | ", report.Errors)}");
        }
        var gone = new ScannerService().ScanFile(Path.Combine(game, "Logs", "deleted.tmp"), ScanScope.GameCore);
        Assert(gone.IsComplete && gone.Findings.Count == 0, "a deleted temporary file made the runtime watcher stop the session");
        _passed++;
    }

    private static async Task TestScheduledBackupDetectsUnchangedGame(string root)
    {
        var game = Path.Combine(root, "dedupe-game"); var backups = Path.Combine(root, "dedupe-backups");
        Directory.CreateDirectory(game); File.WriteAllText(Path.Combine(game, "game.dat"), "v1");
        var service = new BackupService(TestEvents(root), Path.Combine(root, "dedupe-safety"));
        Assert(!await service.MatchesLatestBackupAsync(game, backups), "a missing backup was treated as up to date");
        await service.CreateBackupAsync(game, backups, 4);
        Assert(await service.MatchesLatestBackupAsync(game, backups), "an unchanged game was not recognized as already backed up");
        File.WriteAllText(Path.Combine(game, "game.dat"), "v2");
        Assert(!await service.MatchesLatestBackupAsync(game, backups), "a changed file was treated as already backed up");
        File.WriteAllText(Path.Combine(game, "game.dat"), "v1"); File.WriteAllText(Path.Combine(game, "new.dat"), "added");
        Assert(!await service.MatchesLatestBackupAsync(game, backups), "an added file was treated as already backed up");
        _passed++;
    }

    private static void TestSafeModeDisablesCompiledMods(string root)
    {
        var game = Path.Combine(root, "safe-mode-compiled"); var compiled = Path.Combine(game, "CompiledMods");
        Directory.CreateDirectory(compiled); File.WriteAllText(Path.Combine(compiled, "cache.hash"), "fixture");
        var executable = Path.Combine(game, "People Playground.exe"); File.Copy(Path.Combine(Environment.SystemDirectory, "cmd.exe"), executable);
        var launcher = new SafeModeLauncher(new FakeBlocker(), TestEvents(root), Path.Combine(root, "safe-mode-compiled-state"), workshopRootProvider: _ => []);
        var session = launcher.Launch(new AppSettings { GameDirectory = game, PpgExecutablePath = executable }, new ScannerService().Scan(game));
        Assert(!Directory.Exists(compiled), "Safe Mode left compiled mod assemblies loadable");
        try { session.Process.Kill(true); } catch { }
        session.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Assert(File.Exists(Path.Combine(compiled, "cache.hash")), "Safe Mode did not restore CompiledMods");
        _passed++;
    }

    private sealed class FakeBlocker : IOutboundNetworkBlocker
    {
        public bool Blocked { get; private set; }
        public List<string> RemovedRules { get; } = [];
        public bool TryBlockOutbound(string executablePath, out string ruleName)
        {
            Blocked = true;
            ruleName = "PPGAV Safe Mode test-rule";
            return true;
        }

        public bool TryRemove(string executablePath) => true;
        public bool TryRemoveRule(string ruleName) { RemovedRules.Add(ruleName); return true; }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}

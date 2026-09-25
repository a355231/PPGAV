using System.Collections.ObjectModel;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using Forms = System.Windows.Forms;
using MessageBox = System.Windows.MessageBox;
using PPGAV.Interop;
using PPGAV.Models;
using PPGAV.Services;

namespace PPGAV;

public partial class MainWindow : Window
{
    private readonly SettingsService _settingsService;
    private readonly AppSettings _settings;
    private readonly EventLogService _events;
    private readonly StartupService _startup;
    private readonly ScannerService _scanner;
    private readonly IntegrityBaselineService _integrity;
    private readonly QuarantineService _quarantine;
    private readonly UpdateService _updates;
    private readonly BackupService _backup;
    private readonly DefenderService _defender;
    private readonly WindowsSandboxService _sandbox;
    private readonly SandboxieService _sandboxie;
    private readonly SafeModeLauncher _safeMode;
    private readonly BehaviorMonitor _monitor;
    private readonly CancellationTokenSource _appCancellation = new();
    private readonly ConcurrentDictionary<long, Task> _uiOperations = new();
    private readonly Forms.NotifyIcon _trayIcon;
    private readonly Forms.ContextMenuStrip _trayMenu;
    private LaunchSession? _session;
    private ScanReport _lastReport = new();
    private CancellationTokenSource? _sessionCancellation;
    private Task? _sessionTask;
    private Task? _backupLoopTask;
    private Task? _updateLoopTask;
    private Task? _sandboxAvailabilityTask;
    private Task? _shutdownTask;
    private Task? _launchTask;
    private Task? _sessionStopTask;
    private bool _allowClose;
    private bool _lastPreflightVerified;
    private long _nextUiOperationId;

    public MainWindow(
        SettingsService settingsService,
        AppSettings settings,
        EventLogService events,
        StartupService startup,
        ScannerService scanner,
        IntegrityBaselineService integrity,
        QuarantineService quarantine,
        UpdateService updates,
        BackupService backup,
        DefenderService defender,
        WindowsSandboxService sandbox,
        SandboxieService sandboxie,
        SafeModeLauncher safeMode,
        BehaviorMonitor monitor)
    {
        InitializeComponent();
        _settingsService = settingsService;
        _settings = settings;
        _events = events;
        _startup = startup;
        _scanner = scanner;
        _integrity = integrity;
        _quarantine = quarantine;
        _updates = updates;
        _backup = backup;
        _defender = defender;
        _sandbox = sandbox;
        _sandboxie = sandboxie;
        _safeMode = safeMode;
        _monitor = monitor;
        try { _startup.SetEnabled(_settings.StartWithWindows); } catch (Exception ex) { _events.Log("Startup integration unavailable", ex.Message, ScanCategory.Suspicious); }

        _trayMenu = new Forms.ContextMenuStrip();
        _trayMenu.Items.Add("Open dashboard", null, (_, _) => ShowDashboard());
        _trayMenu.Items.Add("Launch in Secure Sandbox", null, (_, _) => RunTrayActionAsync("Secure launch", SecureLaunch_ClickAsync));
        _trayMenu.Items.Add("Malware Safe Mode", null, (_, _) => RunTrayActionAsync("Malware Safe Mode", SafeLaunch_ClickAsync));
        _trayMenu.Items.Add("Inspect PPG now", null, (_, _) => RunTrayActionAsync("Inspection", ScanNow_ClickAsync));
        _trayMenu.Items.Add("Create backup now", null, (_, _) => RunTrayActionAsync("Backup", BackupNow_ClickAsync));
        _trayMenu.Items.Add(new Forms.ToolStripSeparator());
        _trayMenu.Items.Add("Exit PPGAV", null, (_, _) => ExitApplication());
        _trayIcon = new Forms.NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Shield,
            Text = "PPGAV · People Playground Antivirus Guard",
            Visible = true,
            ContextMenuStrip = _trayMenu
        };
        _trayIcon.DoubleClick += (_, _) => ShowDashboard();

        _events.EventAdded += Events_EventAdded;
        EventList.Items.Clear();
        foreach (var item in _events.Events) EventList.Items.Add(item);
        BackupList.DisplayMemberPath = nameof(BackupInfo.Path);
        PopulateSettingsControls();
        RefreshBackups();
        SandboxAvailabilityText.Text = "Checking Windows Sandbox and Sandboxie eligibility…";
        _sandboxAvailabilityTask = RefreshSandboxAvailabilityAsync();
        _backupLoopTask = BackupLoopAsync();
        _updateLoopTask = UpdateLoopAsync();
    }

    public bool StartHidden { get; set; }
    public bool StartupRecoverySucceeded { get; set; } = true;

    private async Task RunUiActionAsync(string operation, Func<Task> action)
    {
        Task? actionTask = null;
        var operationId = Interlocked.Increment(ref _nextUiOperationId);
        try
        {
            actionTask = action();
            _uiOperations.TryAdd(operationId, actionTask);
            await actionTask;
        }
        catch (Exception ex)
        {
            _events.Log($"{operation} failed", ex.Message, ScanCategory.Suspicious);
            if (IsLoaded && !_allowClose)
                MessageBox.Show(this, ex.Message, operation, MessageBoxButton.OK, MessageBoxImage.Error);
            else
                _trayIcon.ShowBalloonTip(4000, $"{operation} failed", ex.Message, Forms.ToolTipIcon.Warning);
        }
        finally { _uiOperations.TryRemove(operationId, out _); }
    }

    private async void RunTrayActionAsync(string operation, Func<Task> action)
    {
        try { await RunUiActionAsync(operation, action); }
        catch (Exception ex) { try { _events.Log($"{operation} callback failed", ex.Message, ScanCategory.Suspicious); } catch { } }
    }

    private async Task RefreshSandboxAvailabilityAsync()
    {
        try
        {
            await _sandbox.CheckAvailabilityAsync();
            SandboxAvailabilityText.Text = _sandbox.IsAvailable
                ? _settings.UseWindowsSandbox ? "Windows Sandbox executable is installed and hardware checks passed." : "Windows Sandbox is available but disabled in your settings."
                : _sandboxie.IsAvailable ? $"Sandboxie fallback is available. {_sandbox.AvailabilityReason}"
                : $"No supported secure sandbox is available. {_sandbox.AvailabilityReason} {_sandboxie.AvailabilityReason}";
        }
        catch (Exception ex)
        {
            _events.Log("Sandbox eligibility query failed", ex.Message, ScanCategory.Suspicious);
            SandboxAvailabilityText.Text = $"Sandbox eligibility could not be verified: {ex.Message}";
        }
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (StartHidden) Hide();
    }

    private void PopulateSettingsControls()
    {
        GameDirectoryBox.Text = _settings.GameDirectory;
        ExecutableBox.Text = _settings.PpgExecutablePath;
        BackupDirectoryBox.Text = _settings.BackupDirectory;
        StartWithWindowsBox.IsChecked = _settings.StartWithWindows;
        StartMinimizedBox.IsChecked = _settings.StartMinimized;
        ScanBeforeLaunchBox.IsChecked = _settings.ScanBeforeLaunch;
        WatchProcessBox.IsChecked = _settings.WatchProcess;
        UseWindowsSandboxBox.IsChecked = _settings.UseWindowsSandbox;
        AutomaticUpdatesBox.IsChecked = _settings.AutomaticUpdates;
        SandboxSavePathsBox.Text = string.Join(Environment.NewLine, _settings.SandboxSavePaths ?? []);
        BackupIntervalBox.Text = _settings.BackupIntervalHours.ToString();
        BackupRetentionBox.Text = _settings.BackupRetentionCount.ToString();
    }

    private void SaveSettingsFromControls()
    {
        _settings.GameDirectory = GameDirectoryBox.Text.Trim();
        _settings.PpgExecutablePath = ExecutableBox.Text.Trim();
        _settings.BackupDirectory = BackupDirectoryBox.Text.Trim();
        if (int.TryParse(BackupIntervalBox.Text, out var interval)) _settings.BackupIntervalHours = interval;
        if (int.TryParse(BackupRetentionBox.Text, out var retention)) _settings.BackupRetentionCount = retention;
        _settings.StartWithWindows = StartWithWindowsBox.IsChecked == true;
        _settings.StartMinimized = StartMinimizedBox.IsChecked == true;
        _settings.ScanBeforeLaunch = true;
        _settings.WatchProcess = WatchProcessBox.IsChecked == true;
        _settings.UseWindowsSandbox = UseWindowsSandboxBox.IsChecked == true;
        _settings.AutomaticUpdates = AutomaticUpdatesBox.IsChecked == true;
        _settings.SandboxSavePaths = ParseSandboxSavePaths(SandboxSavePathsBox.Text);
        _settings.Normalize();
        _settingsService.Save(_settings);
        _startup.SetEnabled(_settings.StartWithWindows);
        _events.Log("Settings saved", "Protection settings were written locally.");
    }

    private static List<string> ParseSandboxSavePaths(string text)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".json", ".sav", ".dat", ".cfg", ".ini" };
        var paths = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (paths.Length > 64) throw new InvalidDataException("Configure at most 64 sandbox save paths.");
        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var path in paths)
        {
            var normalized = path.Replace('/', Path.DirectorySeparatorChar);
            var parts = normalized.Split(Path.DirectorySeparatorChar, StringSplitOptions.None);
            if (normalized.Length > 512 || Path.IsPathRooted(normalized) || parts.Length == 0 ||
                parts.Any(part => string.IsNullOrWhiteSpace(part) || part is "." or ".." || part.Contains(':') || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) ||
                !allowed.Contains(Path.GetExtension(normalized)))
                throw new InvalidDataException($"Invalid sandbox save path. Use a safe relative path with .json, .sav, .dat, .cfg, or .ini: {path}");
            if (!unique.Add(normalized)) throw new InvalidDataException($"Sandbox save path is duplicated: {path}");
            result.Add(normalized);
        }
        return result;
    }

    private async void SecureLaunch_Click(object sender, RoutedEventArgs e) => await RunUiActionAsync("Secure launch", SecureLaunch_ClickAsync);

    private Task SecureLaunch_ClickAsync() => RunLaunchOperationAsync(SecureLaunchCoreAsync);

    private Task SafeLaunch_ClickAsync() => RunLaunchOperationAsync(SafeLaunchCoreAsync);

    private async Task RunLaunchOperationAsync(Func<Task> launch)
    {
        if (_launchTask is { IsCompleted: false } || _session is not null)
        {
            MessageBox.Show(this, "A People Playground launch or session is already active.", "PPGAV", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var task = launch();
        _launchTask = task;
        try { await task; }
        finally { if (ReferenceEquals(_launchTask, task)) _launchTask = null; }
    }

    private async Task SecureLaunchCoreAsync()
    {
        if (_session is not null)
        {
            MessageBox.Show(this, "A People Playground session is already being watched.", "PPGAV", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            SaveSettingsFromControls();
            var decision = await RunPreflightAsync();
            if (decision == PreflightAction.BlockAll || _appCancellation.IsCancellationRequested) return;
            if (decision == PreflightAction.LaunchSafeMode)
            {
                var allowHeuristicQuarantine = ConfirmHeuristicQuarantine(_lastReport);
                try
                {
                    var quarantined = await Task.Run(() => _quarantine.Quarantine(_lastReport, allowHeuristicQuarantine), _appCancellation.Token);
                    if (quarantined.Count > 0) _events.Log("Malware quarantined", $"Moved {quarantined.Count} malicious file(s) out of mod/Workshop content before safe launch.", ScanCategory.Malware);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // Safe Mode disables every mod/Workshop folder regardless, so a quarantine failure must not
                    // also prevent the protected launch; the quarantine recovery manifest is handled at startup.
                    _events.Log("Quarantine skipped", $"Findings were left in place and will be disabled by Malware Safe Mode: {ex.Message}", ScanCategory.Suspicious);
                }
                if (_appCancellation.IsCancellationRequested) return;
                MessageBox.Show(this, "Threats were found in mod or Workshop content. Normal startup was aborted; PPGAV is relaunching without mods or Workshop. Windows Firewall blocks the game executable, but this is not session-wide isolation and child processes may still access the network.", "Malware Safe Mode", MessageBoxButton.OK, MessageBoxImage.Warning);
                var safeSession = await Task.Run(() => _safeMode.Launch(_settings, _lastReport), _appCancellation.Token);
                if (_appCancellation.IsCancellationRequested) { await StopUnobservedSessionAsync(safeSession); return; }
                await StartAndObserveAsync(safeSession);
                return;
            }
            var windowsSandboxAvailable = _settings.UseWindowsSandbox && await _sandbox.CheckAvailabilityAsync();
            if (_appCancellation.IsCancellationRequested) return;
            var provider = SandboxProviderSelector.Choose(windowsSandboxAvailable, _sandboxie.IsAvailable);
            LaunchSession session;
            if (provider == SandboxProvider.WindowsSandbox)
            {
                try { session = await _sandbox.LaunchAsync(_settings, _lastReport, _appCancellation.Token); }
                catch (WindowsSandboxUnavailableException ex) when (_sandboxie.IsAvailable)
                {
                    _events.Log("Windows Sandbox unavailable", $"{ex.Message} PPGAV is using the verified Sandboxie fallback.", ScanCategory.Suspicious);
                    session = await Task.Run(() => _sandboxie.Launch(_settings, _lastReport), _appCancellation.Token);
                }
            }
            else if (provider == SandboxProvider.SandboxieClassic)
                session = await Task.Run(() => _sandboxie.Launch(_settings, _lastReport), _appCancellation.Token);
            else throw new InvalidOperationException("Secure launch requires Windows Sandbox or the free open-source Sandboxie Classic fallback.");
            if (_appCancellation.IsCancellationRequested)
            {
                await StopUnobservedSessionAsync(session);
                return;
            }
            await StartAndObserveAsync(session);
        }
        catch (OperationCanceledException) when (_appCancellation.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _events.Log("Secure launch failed", ex.Message, ScanCategory.Suspicious);
            MessageBox.Show(this, ex.Message, "Secure launch failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void SafeLaunch_Click(object sender, RoutedEventArgs e) => await RunUiActionAsync("Malware Safe Mode", SafeLaunch_ClickAsync);

    private async Task SafeLaunchCoreAsync()
    {
        if (_session is not null)
        {
            MessageBox.Show(this, "A People Playground session is already being watched.", "PPGAV", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            SaveSettingsFromControls();
            if (await RunPreflightAsync() == PreflightAction.BlockAll || _appCancellation.IsCancellationRequested) return;
            var session = await Task.Run(() => _safeMode.Launch(_settings, _lastReport), _appCancellation.Token);
            if (_appCancellation.IsCancellationRequested) { await StopUnobservedSessionAsync(session); return; }
            await StartAndObserveAsync(session);
        }
        catch (OperationCanceledException) when (_appCancellation.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _events.Log("Malware Safe Mode failed", ex.Message, ScanCategory.Suspicious);
            MessageBox.Show(this, ex.Message, "Malware Safe Mode failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task<PreflightAction> RunPreflightAsync()
    {
        _lastPreflightVerified = false;
        var report = await ScanAsync();
        if (!StartupRecoverySucceeded)
        {
            report.IsComplete = false;
            report.Errors.Add("PPGAV could not verify cleanup of an interrupted previous session. Restart/recovery is required before any launch.");
            report.SkippedPaths.Add("PPGAV startup recovery");
            ApplyReport(report);
        }
        var integrityFindings = await Task.Run(() => _integrity.Check(_settings.GameDirectory, _settings.PpgExecutablePath), _appCancellation.Token);
        report.Findings.AddRange(integrityFindings);
        _lastReport = report;
        ApplyReport(report);
        SetStatus("Defender preflight", SuspiciousBrushKey());
        var defender = await _defender.RunFullScanAsync(_settings.GameDirectory, _appCancellation.Token);
        var defenderClean = defender.IsClean;
        if (!defenderClean)
        {
            var threatDetected = defender.ThreatConfirmed;
            report.Findings.Add(new ScanFinding(threatDetected ? ScanCategory.Malware : ScanCategory.Suspicious,
                _settings.GameDirectory, threatDetected ? "defender-threat-active" : "defender-state-unverified",
                threatDetected ? "Microsoft Defender reported an active threat." : "A completed Defender scan with enabled protection, current signatures, and no active threats could not be verified.",
                string.Empty, ScanScope.Unknown, 100, threatDetected ? DetectionKind.Confirmed : DetectionKind.Heuristic));
        }
        // ContentChanged/InstallationChanged must also be re-approvable: otherwise every Steam update of
        // the game (or moving the library) blocked all launches permanently with no way forward.
        var baselineStatus = _integrity.LastStatus;
        var baselineNeedsApproval = baselineStatus is IntegrityBaselineStatus.Missing or IntegrityBaselineStatus.Corrupt or IntegrityBaselineStatus.Tampered
            or IntegrityBaselineStatus.ContentChanged or IntegrityBaselineStatus.InstallationChanged;
        var nonBaselineCoreFinding = report.Findings.Any(f => f.Scope is (ScanScope.GameCore or ScanScope.Unknown) && !IntegrityBaselineService.IsIntegrityRule(f.Rule));
        if (defenderClean && baselineNeedsApproval && !nonBaselineCoreFinding && report.IsComplete)
        {
            var prompt = baselineStatus switch
            {
                IntegrityBaselineStatus.ContentChanged =>
                    $"{integrityFindings.Count} core game file(s) differ from the baseline you approved. This is expected after a Steam update of People Playground, but it can also mean the game was modified.\n\n" +
                    "PPGAV and Microsoft Defender found no threats in the current files. Trust them as the new baseline? Choose No if you did not expect the game to change.",
                IntegrityBaselineStatus.InstallationChanged =>
                    "The game folder or executable differs from the installation you approved. PPGAV and Microsoft Defender found no threats in the current files.\n\nTrust this installation as the new baseline?",
                _ => "PPGAV has no valid approved core baseline for this installation. Trust the currently scanned files as the new baseline? This records an approval and is required before launch."
            };
            var answer = MessageBox.Show(this, prompt, "Approve core baseline", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (answer == MessageBoxResult.Yes)
            {
                var approvalRoots = GamePathDiscovery.FindWorkshopDirectories(_settings.GameDirectory);
                if (!ScannerService.VerifySnapshot(report, approvalRoots, out var snapshotError))
                {
                    report.Errors.Add(snapshotError); report.SkippedPaths.Add(_settings.GameDirectory); report.IsComplete = false;
                    _events.Log("Baseline approval blocked", snapshotError, ScanCategory.Suspicious); ApplyReport(report);
                    return PreflightAction.BlockAll;
                }
                await Task.Run(() => _integrity.TrustCurrent(_settings.GameDirectory, _settings.PpgExecutablePath,
                    "Explicit approval in PPGAV dashboard", report), _appCancellation.Token);
                report.Findings.RemoveAll(f => IntegrityBaselineService.IsIntegrityRule(f.Rule));
                report.Findings.AddRange(await Task.Run(() => _integrity.Check(_settings.GameDirectory, _settings.PpgExecutablePath), _appCancellation.Token));
                ApplyReport(report);
            }
        }
        var workshopRoots = GamePathDiscovery.FindWorkshopDirectories(_settings.GameDirectory);
        if (!ScannerService.VerifySnapshot(report, workshopRoots, out var revalidationError))
        {
            report.Errors.Add(revalidationError); report.SkippedPaths.Add(_settings.GameDirectory); report.IsComplete = false;
            report.Findings.Add(new ScanFinding(ScanCategory.Suspicious, _settings.GameDirectory, "scan-to-launch-change", revalidationError, string.Empty, ScanScope.Unknown, 90));
            _events.Log("Launch blocked", revalidationError, ScanCategory.Suspicious); ApplyReport(report);
        }
        _lastReport = report;
        var decision = PreflightDecisionEngine.Decide(report, defenderClean);
        if (decision == PreflightAction.BlockAll)
        {
            if (report.Findings.Any(f => f.Category == ScanCategory.Malware)) await RespondToMalwareAsync(report);
            else
            {
                SetStatus("Launch blocked", SuspiciousBrushKey());
                MessageBox.Show(this, "PPGAV could not verify a complete, current clean scan and Defender state. Game startup was blocked; review the findings and skipped content before retrying.", "Launch blocked", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            return decision;
        }
        _lastPreflightVerified = decision == PreflightAction.AllowSecure && _integrity.LastStatus == IntegrityBaselineStatus.Valid && defender.IsClean;
        return decision;
    }

    private async void ScanNow_Click(object sender, RoutedEventArgs e) => await RunUiActionAsync("Inspection", ScanNow_ClickAsync);

    private async Task ScanNow_ClickAsync()
    {
        SaveSettingsFromControls();
        var report = await ScanAsync();
        if (report.HasMalware) await RespondToMalwareAsync(report);
    }

    private async Task<ScanReport> ScanAsync()
    {
        SetStatus("Inspecting", SuspiciousBrushKey());
        var workshops = GamePathDiscovery.FindWorkshopDirectories(_settings.GameDirectory);
        var report = await Task.Run(() => _scanner.ScanInstallation(_settings.GameDirectory, workshops, _appCancellation.Token));
        _lastReport = report;
        ApplyReport(report);
        LatestScanText.Text = $"Last scan {report.CompletedAt:HH:mm:ss} · {report.FilesInspected} files inspected · {report.Category} · {(report.IsComplete ? "complete" : "INCOMPLETE")} · {report.SkippedPaths.Count} skipped · {report.Errors.Count} errors";
        _events.Log("Inspection complete", $"Inspected {report.FilesInspected} files: {report.Category}, {report.Findings.Count} finding(s).", report.Category);
        if (!report.HasMalware) SetStatus(report.Category == ScanCategory.Suspicious ? "Review needed" : "Scan complete · preflight required", report.Category == ScanCategory.Suspicious ? SuspiciousBrushKey() : AccentBrushKey());
        return report;
    }

    private async Task RespondToMalwareAsync(ScanReport report)
    {
        SetStatus("Malware detected · stopping game", MalwareBrushKey());
        _events.Log("Malware detected", "A malware-level finding was reported; PPGAV is stopping any active session before quarantine/Defender response.", ScanCategory.Malware);
        _trayIcon.ShowBalloonTip(4000, "PPGAV malware alert", "A malware-level finding was detected. PPGAV is stopping the game and starting the Defender response.", Forms.ToolTipIcon.Error);
        var sessionStopped = true;
        string stopNote = string.Empty;
        var activeSession = _session;
        if (activeSession is not null)
        {
            sessionStopped = false;
            try
            {
                await RequestSessionStop(activeSession);
                var activeSessionTask = _sessionTask;
                if (activeSessionTask is not null) await activeSessionTask;
                sessionStopped = true;
            }
            catch (Exception ex)
            {
                stopNote = $"\n\nThe active game session could not be confirmed stopped: {ex.Message}";
                _events.Log("Malware stop failed", stopNote, ScanCategory.Malware);
            }
        }

        string quarantineNote = string.Empty;
        if (!sessionStopped)
        {
            quarantineNote = "\n\nQuarantine was skipped because the active session could not be confirmed stopped.";
        }
        else
        {
            try
            {
                var allowHeuristic = ConfirmHeuristicQuarantine(report);
                var quarantined = await Task.Run(() => _quarantine.Quarantine(report, allowHeuristic), _appCancellation.Token);
                if (quarantined.Count > 0) _events.Log("Malware quarantined", $"Moved {quarantined.Count} malicious file(s) into the local quarantine store.", ScanCategory.Malware);
            }
            catch (Exception ex)
            {
                quarantineNote = $"\n\nQuarantine could not complete; original files were preserved or a recovery manifest was retained. {ex.Message}";
                _events.Log("Quarantine action failed", ex.Message, ScanCategory.Malware);
            }
        }
        if (!_allowClose) MessageBox.Show(this, "PPGAV found a malware-level detection. Game startup is blocked. A Windows Defender full scan is starting now." + stopNote + quarantineNote, "Malware detected", MessageBoxButton.OK, MessageBoxImage.Error);
        _events.Log("Malware response started", "Launch was blocked; any active session was stopped before quarantine, followed by a Windows Defender full scan." + stopNote, ScanCategory.Malware);
        _ = await _defender.RunFullScanAsync(null, _appCancellation.Token);
    }

    private async void DefenderScan_Click(object sender, RoutedEventArgs e) => await RunUiActionAsync("Defender scan", DefenderScan_ClickAsync);

    private async Task DefenderScan_ClickAsync()
    {
        try
        {
            SaveSettingsFromControls(); SetStatus("Defender scanning", SuspiciousBrushKey());
            var result = await _defender.RunFullScanAsync(_settings.GameDirectory, _appCancellation.Token);
            if (!_allowClose) MessageBox.Show(this, result.IsClean ? "Windows Defender completed a verified clean scan." : string.IsNullOrWhiteSpace(result.Output) ? "Defender did not establish a verified clean state." : result.Output, "Windows Defender", MessageBoxButton.OK, result.IsClean ? MessageBoxImage.Information : MessageBoxImage.Warning);
            SetStatus(result.IsClean ? "Defender clean · preflight required" : "Review needed", result.IsClean ? AccentBrushKey() : SuspiciousBrushKey());
        }
        catch (Exception ex) { _events.Log("Defender scan failed", ex.Message, ScanCategory.Suspicious); if (!_allowClose) MessageBox.Show(this, ex.Message, "Windows Defender", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private async void BackupNow_Click(object sender, RoutedEventArgs e) => await RunUiActionAsync("Backup", BackupNow_ClickAsync);

    private async Task BackupNow_ClickAsync()
    {
        try
        {
            if (_launchTask is not null || _session is not null) throw new InvalidOperationException("A game launch/session is active; create the backup after it ends.");
            SaveSettingsFromControls();
            SetStatus("Creating backup", AccentBrushKey());
            await _backup.CreateBackupAsync(_settings.GameDirectory, _settings.BackupDirectory, _settings.BackupRetentionCount, _appCancellation.Token);
            RefreshBackups();
            SetStatus("Backup complete", AccentBrushKey());
        }
        catch (Exception ex)
        {
            _events.Log("Backup failed", ex.Message, ScanCategory.Suspicious);
            if (!_allowClose) MessageBox.Show(this, ex.Message, "Backup failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            SetStatus("Review needed", SuspiciousBrushKey());
        }
    }

    private async void RestoreBackup_Click(object sender, RoutedEventArgs e) => await RunUiActionAsync("Backup restore", RestoreBackup_ClickAsync);

    private async Task RestoreBackup_ClickAsync()
    {
        if (_launchTask is not null || _session is not null)
        {
            MessageBox.Show(this, "Stop the active launch/session before restoring a backup.", "Restore backup", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (BackupList.SelectedItem is not BackupInfo selected)
        {
            MessageBox.Show(this, "Select a backup first.", "Restore backup", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var answer = MessageBox.Show(this, $"Restore {Path.GetFileName(selected.Path)} into the configured game directory? Close People Playground first. Existing files may be overwritten.", "Restore backup", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;

        try
        {
            await _backup.RestoreAsync(selected.Path, _settings.GameDirectory, _settings.BackupDirectory, _appCancellation.Token);
            if (!_allowClose) MessageBox.Show(this, "The backup was restored.", "Restore backup", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _events.Log("Restore failed", ex.Message, ScanCategory.Suspicious);
            if (!_allowClose) MessageBox.Show(this, ex.Message, "Restore failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        TryStopSessionProcess();
    }

    private void StopSessionProcess(LaunchSession session)
    {
        if (session.Provider == SandboxProvider.WindowsSandbox) WindowsSandboxService.Stop(session);
        else if (session.Provider == SandboxProvider.SandboxieClassic) _sandboxie.Stop(session);
        else ProcessTree.KillTree(session.Process);
        if (!session.Process.HasExited && !session.Process.WaitForExit(5000) && !session.Process.HasExited)
            throw new TimeoutException("The launch/session process did not exit after the stop request.");
        _events.Log("Session stop requested", "PPGAV requested termination of the active game/container session.", ScanCategory.Suspicious);
    }

    private async Task StopUnobservedSessionAsync(LaunchSession session)
    {
        try
        {
            if (session.Provider == SandboxProvider.WindowsSandbox) await Task.Run(() => WindowsSandboxService.Stop(session));
            else if (session.Provider == SandboxProvider.SandboxieClassic) await Task.Run(() => _sandboxie.Stop(session));
            else await Task.Run(() => ProcessTree.KillTree(session.Process));
            await Task.Run(async () => await session.DisposeAsync());
        }
        catch (Exception ex) { _events.Log("Cancelled launch cleanup failed", ex.Message, ScanCategory.Suspicious); }
    }

    private void TryStopSessionProcess()
    {
        var session = _session;
        if (session is null) return;
        _ = RequestSessionStop(session);
    }

    private Task RequestSessionStop(LaunchSession session)
    {
        if (_sessionStopTask is { IsCompleted: false } active && ReferenceEquals(_session, session)) return active;
        var task = Task.Run(() => StopSessionProcess(session));
        if (ReferenceEquals(_session, session)) _sessionStopTask = task;
        _ = task.ContinueWith(completed =>
        {
            if (completed.Exception is { } exception)
                _events.Log("Session stop failed", exception.GetBaseException().Message, ScanCategory.Suspicious);
        }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return task;
    }

    private async Task StartAndObserveAsync(LaunchSession session)
    {
        var task = ObserveSessionAsync(session);
        _sessionTask = task;
        try { await task; }
        finally { if (ReferenceEquals(_sessionTask, task)) _sessionTask = null; }
    }

    private async Task ObserveSessionAsync(LaunchSession session)
    {
        _session = session;
        Task? monitorTask = null;
        Task? processWait = null;
        var monitorHealthy = _settings.WatchProcess;
        var cleanupSucceeded = false;
        try
        {
            _sessionCancellation = CancellationTokenSource.CreateLinkedTokenSource(_appCancellation.Token);
            SetStatus(session.Mode == LaunchMode.SecureSandbox ? "Sandbox active" : "Safe Mode active", AccentBrushKey());
            monitorTask = _settings.WatchProcess
                ? Task.Run(() => _monitor.MonitorAsync(session, _settings.GameDirectory, alert => _ = HandleBehaviorAlertAsync(alert, session), _sessionCancellation.Token, GamePathDiscovery.FindWorkshopDirectories(_settings.GameDirectory)), _sessionCancellation.Token)
                : Task.CompletedTask;
            processWait = session.Process.WaitForExitAsync();
            if (_settings.WatchProcess)
            {
                var completed = await Task.WhenAny(processWait, monitorTask);
                if (completed == monitorTask && !processWait.IsCompleted && !_sessionCancellation.IsCancellationRequested)
                {
                    monitorHealthy = false;
                    try { await monitorTask; }
                    catch (Exception ex) { _events.Log("Behavior monitor failed", ex.Message, ScanCategory.Suspicious); }
                    if (!processWait.IsCompleted)
                    {
                        _events.Log("Behavior monitor stopped", "Monitoring ended unexpectedly while the session was active; PPGAV is stopping the session.", ScanCategory.Suspicious);
                        TryStopSessionProcess();
                    }
                }
            }
            await processWait;
        }
        catch (Exception ex)
        {
            monitorHealthy = false;
            _events.Log("Session wait failed", ex.Message, ScanCategory.Suspicious);
            TryStopSessionProcess();
        }
        finally
        {
            if (processWait?.IsCompletedSuccessfully == true && _settings.WatchProcess && monitorTask is not null && !monitorTask.IsCompleted)
                await Task.WhenAny(monitorTask, Task.Delay(TimeSpan.FromSeconds(2)));
            try { _sessionCancellation?.Cancel(); } catch (Exception ex) { monitorHealthy = false; _events.Log("Session monitor cancellation failed", ex.Message, ScanCategory.Suspicious); }
            if (processWait is null || !processWait.IsCompleted) TryStopSessionProcess();
            if (processWait is not null)
            {
                try { await processWait; } catch (Exception ex) { _events.Log("Session termination wait failed", ex.Message, ScanCategory.Suspicious); }
            }
            if (monitorTask is not null)
            {
                try { await monitorTask; } catch (OperationCanceledException) { } catch (Exception ex) { monitorHealthy = false; _events.Log("Behavior monitor failed", ex.Message, ScanCategory.Suspicious); }
            }
            if (_sessionStopTask is not null)
            {
                try { await _sessionStopTask; }
                catch (Exception ex) { monitorHealthy = false; _events.Log("Session stop task failed", ex.Message, ScanCategory.Suspicious); }
            }
            try { await Task.Run(async () => await session.DisposeAsync()); }
            catch (Exception ex) { _events.Log("Session cleanup failed", ex.Message, ScanCategory.Suspicious); }
            cleanupSucceeded = session.CleanupSucceeded;
            _sessionCancellation?.Dispose();
            _sessionCancellation = null;
            _session = null;
            _sessionStopTask = null;
            if (_lastPreflightVerified && monitorHealthy && cleanupSucceeded && session.Mode == LaunchMode.SecureSandbox)
            {
                SetStatus("Protected", SafeBrushKey());
                _events.Log("Game session ended", "Session ended cleanly; preflight, monitoring, and provider cleanup succeeded.");
            }
            else
            {
                SetStatus("Review needed", SuspiciousBrushKey());
                _events.Log("Game session ended", $"Session ended; preflight verified={_lastPreflightVerified}, monitor healthy={monitorHealthy}, cleanup succeeded={cleanupSucceeded}.", ScanCategory.Suspicious);
            }
        }
    }

    private async Task HandleBehaviorAlertAsync(BehaviorAlert alert, LaunchSession session)
    {
        if (!ReferenceEquals(_session, session)) return;
        try
        {
            Task? stopTask = null;
            Task? sessionTask = null;
            await Dispatcher.InvokeAsync(() =>
            {
                SetStatus(alert.Category == ScanCategory.Malware ? "Malware blocked" : "Review needed", alert.Category == ScanCategory.Malware ? MalwareBrushKey() : SuspiciousBrushKey());
                if ((alert.StopRequired || alert.Category == ScanCategory.Malware) && ReferenceEquals(_session, session))
                {
                    stopTask = RequestSessionStop(session);
                    sessionTask = _sessionTask;
                }
            });
            if (stopTask is not null)
            {
                try { await stopTask; if (alert.Category == ScanCategory.Malware && sessionTask is not null) await sessionTask; }
                catch (Exception ex) { _events.Log("Malware session stop could not be verified", ex.Message, ScanCategory.Malware); }
            }
            if (alert.Category == ScanCategory.Malware)
            {
                await _defender.RunFullScanAsync(null, _appCancellation.Token);
        }
        }
        catch (Exception ex) { _events.Log("Behavior response failed", ex.Message, ScanCategory.Suspicious); if (ReferenceEquals(_session, session)) TryStopSessionProcess(); }
    }

    private bool ConfirmHeuristicQuarantine(ScanReport report)
    {
        if (!report.Findings.Any(f => f.Category == ScanCategory.Malware && f.Detection == DetectionKind.Heuristic)) return false;
        return MessageBox.Show(this, "Some malware-level findings are heuristic rather than confirmed. Move those mod/Workshop files into PPGAV quarantine?", "Confirm heuristic quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes;
    }

    private void ApplyReport(ScanReport report)
    {
        var uniqueFindingFiles = report.Findings.Select(f => f.FilePath).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        SafeCountText.Text = report.IsComplete && report.Errors.Count == 0 && report.SkippedPaths.Count == 0
            ? Math.Max(0, report.FilesInspected - uniqueFindingFiles).ToString()
            : "—";
        SuspiciousCountText.Text = report.Count(ScanCategory.Suspicious).ToString();
        MalwareCountText.Text = report.Count(ScanCategory.Malware).ToString();
        FindingsList.Items.Clear();
        foreach (var finding in report.Findings.Take(250))
            FindingsList.Items.Add($"[{finding.Category}/{finding.Detection}] {finding.FilePath} · {finding.Rule}: {finding.Detail}");
        foreach (var path in report.SkippedPaths.Take(100)) FindingsList.Items.Add($"[NOT INSPECTED] {path}");
        foreach (var error in report.Errors.Take(100)) FindingsList.Items.Add($"[SCAN ERROR] {error}");
        if (!report.IsComplete || report.Cancelled) FindingsList.Items.Insert(0, "[INCOMPLETE] This scan cannot authorize a protected launch.");
        if (report.Findings.Count + report.SkippedPaths.Count + report.Errors.Count > 350)
            FindingsList.Items.Add("Additional scan entries were omitted from this view; check the event log for the full report.");
    }

    private void RefreshBackups()
    {
        BackupList.Items.Clear();
        foreach (var item in _backup.ListBackups(_settings.BackupDirectory)) BackupList.Items.Add(item);
    }

    private async Task BackupLoopAsync()
    {
        while (!_appCancellation.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromHours(_settings.BackupIntervalHours), _appCancellation.Token); }
            catch (OperationCanceledException) { return; }
            if (_session is null && _launchTask is null && Directory.Exists(_settings.GameDirectory))
            {
                try
                {
                    if (await _backup.MatchesLatestBackupAsync(_settings.GameDirectory, _settings.BackupDirectory, _appCancellation.Token))
                    {
                        _events.Log("Scheduled backup skipped", "The game directory is unchanged since the newest verified backup.");
                        continue;
                    }
                    await _backup.CreateBackupAsync(_settings.GameDirectory, _settings.BackupDirectory, _settings.BackupRetentionCount, _appCancellation.Token);
                    await Dispatcher.InvokeAsync(RefreshBackups);
                }
                catch (OperationCanceledException) when (_appCancellation.IsCancellationRequested) { return; }
                catch (Exception ex) { _events.Log("Scheduled backup failed", ex.Message, ScanCategory.Suspicious); }
            }
        }
    }

    private async Task UpdateLoopAsync()
    {
        try { await Task.Delay(TimeSpan.FromSeconds(15), _appCancellation.Token); }
        catch (OperationCanceledException) { return; }
        while (!_appCancellation.IsCancellationRequested)
        {
            if (_settings.AutomaticUpdates && _session is null && _launchTask is null)
            {
                try
                {
                    var current = typeof(MainWindow).Assembly.GetName().Version ?? new Version(1, 0);
                    var update = await _updates.CheckLatestAsync(_appCancellation.Token);
                    if (update is not null && UpdateService.IsNewerVersion(update.Version, current))
                    {
                        _events.Log("Update available", $"PPGAV {update.Tag} matched the GitHub release SHA-256 digest and will be installed. This digest is not an independent publisher signature.");
                        _trayIcon.ShowBalloonTip(3000, "PPGAV update", $"Installing {update.Tag} after GitHub digest verification.", Forms.ToolTipIcon.Info);
                        var msi = await _updates.DownloadAndVerifyAsync(update, _appCancellation.Token);
                        if (_appCancellation.IsCancellationRequested) return;
                        if (_session is not null || _launchTask is not null)
                        {
                            _events.Log("Update deferred", "A launch or game session began during download; the verified update will wait until the next update check.", ScanCategory.Suspicious);
                        }
                        else
                        {
                            using var installerProcess = StartUpdateInstaller(msi);
                            await ShutdownApplicationAsync(initiatedByUpdateLoop: true);
                            return;
                        }
                    }
                }
                catch (OperationCanceledException) { return; }
                catch (Exception ex) { _events.Log("Automatic update check failed", ex.Message, ScanCategory.Suspicious); }
            }
            try { await Task.Delay(TimeSpan.FromHours(_settings.UpdateCheckIntervalHours), _appCancellation.Token); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>
    /// Starts a detached helper that waits for this process to exit (so the MSI can replace the
    /// running executable without a reboot), installs the verified MSI, and restarts the tray app.
    /// </summary>
    private static Process StartUpdateInstaller(string msi)
    {
        static string Quote(string value) => "'" + value.Replace("'", "''") + "'";
        var msiexec = SecurePathService.RequireExistingFile(Path.Combine(Environment.SystemDirectory, "msiexec.exe"), "Windows Installer");
        var powershell = SecurePathService.RequireExistingFile(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), "Windows PowerShell");
        var relaunch = Environment.ProcessPath ?? throw new InvalidOperationException("The PPGAV executable path is unavailable.");
        var script =
            $"Wait-Process -Id {Environment.ProcessId} -Timeout 120 -ErrorAction SilentlyContinue; " +
            $"$installer = Start-Process -FilePath {Quote(msiexec)} -ArgumentList '/i',{Quote("\"" + msi + "\"")},'/quiet','/norestart' -Wait -PassThru; " +
            $"if ($installer.ExitCode -in 0,3010) {{ Start-Process -FilePath {Quote(relaunch)} -ArgumentList '--startup' }}";
        var info = new ProcessStartInfo(powershell) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Environment.SystemDirectory };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script }) info.ArgumentList.Add(argument);
        return Process.Start(info) ?? throw new InvalidOperationException("Windows Installer could not be started.");
    }

    private void BrowseGameDirectory_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.FolderBrowserDialog { SelectedPath = GameDirectoryBox.Text };
        if (dialog.ShowDialog() == Forms.DialogResult.OK)
        {
            GameDirectoryBox.Text = dialog.SelectedPath;
            var discovered = GamePathDiscovery.FindExecutable(dialog.SelectedPath);
            if (discovered is not null) ExecutableBox.Text = discovered;
        }
    }

    private void BrowseExecutable_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.OpenFileDialog { Filter = "People Playground|People Playground.exe|Executable files|*.exe", FileName = "People Playground.exe" };
        if (dialog.ShowDialog() == Forms.DialogResult.OK)
        {
            ExecutableBox.Text = dialog.FileName;
            GameDirectoryBox.Text = Path.GetDirectoryName(dialog.FileName) ?? GameDirectoryBox.Text;
        }
    }

    private void BrowseBackupDirectory_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.FolderBrowserDialog { SelectedPath = BackupDirectoryBox.Text };
        if (dialog.ShowDialog() == Forms.DialogResult.OK) BackupDirectoryBox.Text = dialog.SelectedPath;
    }

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            SaveSettingsFromControls();
            RefreshBackups();
            MessageBox.Show(this, "Settings saved.", "PPGAV", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Settings", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void Events_EventAdded(object? sender, AppEvent item)
    {
        _ = Dispatcher.InvokeAsync(() =>
        {
            EventList.Items.Add(item);
            while (EventList.Items.Count > 200) EventList.Items.RemoveAt(0);
            if (EventList.Items.Count > 0) EventList.ScrollIntoView(EventList.Items[^1]);
        });
    }

    private void SetStatus(string text, System.Windows.Media.Brush brush)
    {
        StatusText.Text = text;
        StatusText.Foreground = brush;
    }

    private static System.Windows.Media.Brush SafeBrushKey() => (System.Windows.Media.Brush)System.Windows.Application.Current.Resources["SafeBrush"];
    private static System.Windows.Media.Brush SuspiciousBrushKey() => (System.Windows.Media.Brush)System.Windows.Application.Current.Resources["SuspiciousBrush"];
    private static System.Windows.Media.Brush MalwareBrushKey() => (System.Windows.Media.Brush)System.Windows.Application.Current.Resources["MalwareBrush"];
    private static System.Windows.Media.Brush AccentBrushKey() => (System.Windows.Media.Brush)System.Windows.Application.Current.Resources["AccentBrush"];

    private void ShowDashboard()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_allowClose) return;
        e.Cancel = true;
        Hide();
        _trayIcon.ShowBalloonTip(1500, "PPGAV is still protecting you", "The antivirus guard remains active in the system tray.", Forms.ToolTipIcon.Info);
    }

    private async void ExitApplication()
    {
        try { await ShutdownApplicationAsync(); }
        catch (Exception ex) { try { _events.Log("Shutdown cleanup failed", ex.Message, ScanCategory.Suspicious); } catch { } }
    }

    private Task ShutdownApplicationAsync(bool initiatedByUpdateLoop = false)
    {
        if (_shutdownTask is not null) return _shutdownTask;
        _shutdownTask = ShutdownApplicationCoreAsync(initiatedByUpdateLoop);
        return _shutdownTask;
    }

    private async Task ShutdownApplicationCoreAsync(bool initiatedByUpdateLoop)
    {
        _allowClose = true;
        _appCancellation.Cancel();
        LaunchSession? lastStopAttempt = null;
        var nextStopRetry = DateTimeOffset.MinValue;
        var launchTask = _launchTask;
        while (launchTask is { IsCompleted: false })
        {
            if (_session is { } active && (!ReferenceEquals(active, lastStopAttempt) || DateTimeOffset.UtcNow >= nextStopRetry))
            {
                TryStopSessionProcess();
                lastStopAttempt = active;
                nextStopRetry = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
            }
            await Task.WhenAny(launchTask, Task.Delay(TimeSpan.FromMilliseconds(250)));
            launchTask = _launchTask;
        }
        if (_session is not null) TryStopSessionProcess();
        await AwaitShutdownTaskAsync(_launchTask, "launch cleanup");
        await AwaitShutdownTaskAsync(_sessionTask, "session cleanup");
        await AwaitShutdownTaskAsync(_sessionStopTask, "session stop");
        await AwaitShutdownTaskAsync(_backupLoopTask, "scheduled backup cleanup");
        await AwaitShutdownTaskAsync(_sandboxAvailabilityTask, "sandbox eligibility check");
        if (!initiatedByUpdateLoop) await AwaitShutdownTaskAsync(_updateLoopTask, "update task shutdown");
        await AwaitPendingUiOperationsAsync();

        System.Windows.Application.Current.Shutdown();
    }

    private async Task AwaitPendingUiOperationsAsync()
    {
        while (!_uiOperations.IsEmpty)
        {
            var pending = _uiOperations.Values.ToArray();
            if (pending.Length == 0) continue;
            try { await Task.WhenAll(pending); }
            catch (Exception ex) { _events.Log("User operation failed during shutdown", ex.GetBaseException().Message, ScanCategory.Suspicious); }
        }
    }

    private async Task AwaitShutdownTaskAsync(Task? task, string operation)
    {
        if (task is null) return;
        try { await task; }
        catch (OperationCanceledException) when (_appCancellation.IsCancellationRequested) { }
        catch (Exception ex) { _events.Log($"{operation} failed during shutdown", ex.Message, ScanCategory.Suspicious); }
    }

    public void DisposeTray()
    {
        try
        {
            _appCancellation.Cancel();
            _events.EventAdded -= Events_EventAdded;
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _trayMenu.Dispose();
        }
        catch { }
    }
}

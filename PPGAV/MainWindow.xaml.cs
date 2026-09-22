using System.Collections.ObjectModel;
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
    private readonly BackupService _backup;
    private readonly DefenderService _defender;
    private readonly WindowsSandboxService _sandbox;
    private readonly SandboxieService _sandboxie;
    private readonly SafeModeLauncher _safeMode;
    private readonly BehaviorMonitor _monitor;
    private readonly CancellationTokenSource _appCancellation = new();
    private readonly Forms.NotifyIcon _trayIcon;
    private readonly Forms.ContextMenuStrip _trayMenu;
    private LaunchSession? _session;
    private ScanReport _lastReport = new();
    private CancellationTokenSource? _sessionCancellation;
    private bool _allowClose;

    public MainWindow(
        SettingsService settingsService,
        AppSettings settings,
        EventLogService events,
        StartupService startup,
        ScannerService scanner,
        IntegrityBaselineService integrity,
        QuarantineService quarantine,
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
        _backup = backup;
        _defender = defender;
        _sandbox = sandbox;
        _sandboxie = sandboxie;
        _safeMode = safeMode;
        _monitor = monitor;
        try { _startup.SetEnabled(_settings.StartWithWindows); } catch (Exception ex) { _events.Log("Startup integration unavailable", ex.Message, ScanCategory.Suspicious); }

        _trayMenu = new Forms.ContextMenuStrip();
        _trayMenu.Items.Add("Open dashboard", null, (_, _) => ShowDashboard());
        _trayMenu.Items.Add("Launch in Secure Sandbox", null, async (_, _) => await SecureLaunch_ClickAsync());
        _trayMenu.Items.Add("Malware Safe Mode", null, async (_, _) => await SafeLaunch_ClickAsync());
        _trayMenu.Items.Add("Inspect PPG now", null, async (_, _) => await ScanNow_ClickAsync());
        _trayMenu.Items.Add("Create backup now", null, async (_, _) => await BackupNow_ClickAsync());
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
        SandboxAvailabilityText.Text = _sandbox.IsAvailable
            ? "Windows Sandbox detected · Secure Sandbox is available."
            : "Windows Sandbox is not enabled · Malware Safe Mode remains available with UAC network blocking.";
        SandboxAvailabilityText.Text = _sandbox.IsAvailable
            ? "Windows Sandbox detected - mandatory preflight is active."
            : _sandboxie.IsAvailable ? "Sandboxie Classic detected - open-source fallback containment is active."
            : "No supported sandbox detected - install Sandboxie Classic for secure launch.";
        _ = BackupLoopAsync();
    }

    public bool StartHidden { get; set; }

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
        RequireNetworkBlockBox.IsChecked = _settings.RequireNetworkBlockInSafeMode;
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
        _settings.RequireNetworkBlockInSafeMode = RequireNetworkBlockBox.IsChecked == true;
        _settings.Normalize();
        _settingsService.Save(_settings);
        _startup.SetEnabled(_settings.StartWithWindows);
        _events.Log("Settings saved", "Protection settings were written locally.");
    }

    private async void SecureLaunch_Click(object sender, RoutedEventArgs e) => await SecureLaunch_ClickAsync();

    private async Task SecureLaunch_ClickAsync()
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
            if (decision == PreflightAction.BlockAll) return;
            if (decision == PreflightAction.LaunchSafeMode)
            {
                var quarantined = _quarantine.Quarantine(_lastReport);
                if (quarantined.Count > 0) _events.Log("Malware quarantined", $"Moved {quarantined.Count} malicious file(s) out of mod/Workshop content before safe launch.", ScanCategory.Malware);
                MessageBox.Show(this, "Threats were found in mod or Workshop content. Normal startup was aborted; PPGAV is relaunching without mods, Steam connectivity, or network access.", "Malware Safe Mode", MessageBoxButton.OK, MessageBoxImage.Warning);
                await ObserveSessionAsync(_safeMode.Launch(_settings));
                return;
            }
            var provider = SandboxProviderSelector.Choose(_sandbox.IsAvailable, _sandboxie.IsAvailable);
            var session = provider switch
            {
                SandboxProvider.WindowsSandbox => await _sandbox.LaunchAsync(_settings),
                SandboxProvider.SandboxieClassic => _sandboxie.Launch(_settings),
                _ => throw new InvalidOperationException("Secure launch requires Windows Sandbox or the free open-source Sandboxie Classic fallback.")
            };
            await ObserveSessionAsync(session);
        }
        catch (Exception ex)
        {
            _events.Log("Secure launch failed", ex.Message, ScanCategory.Suspicious);
            MessageBox.Show(this, ex.Message, "Secure launch failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void SafeLaunch_Click(object sender, RoutedEventArgs e) => await SafeLaunch_ClickAsync();

    private async Task SafeLaunch_ClickAsync()
    {
        if (_session is not null)
        {
            MessageBox.Show(this, "A People Playground session is already being watched.", "PPGAV", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            SaveSettingsFromControls();
            if (await RunPreflightAsync() == PreflightAction.BlockAll) return;
            var session = _safeMode.Launch(_settings);
            await ObserveSessionAsync(session);
        }
        catch (Exception ex)
        {
            _events.Log("Malware Safe Mode failed", ex.Message, ScanCategory.Suspicious);
            MessageBox.Show(this, ex.Message, "Malware Safe Mode failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task<PreflightAction> RunPreflightAsync()
    {
        var report = await ScanAsync();
        foreach (var finding in await Task.Run(() => _integrity.Check(_settings.GameDirectory), _appCancellation.Token)) report.Findings.Add(finding);
        _lastReport = report;
        ApplyReport(report);
        SetStatus("Defender preflight", SuspiciousBrushKey());
        var defender = await _defender.RunFullScanAsync(_settings.GameDirectory, _appCancellation.Token);
        var defenderClean = defender.Started && defender.ExitCode == 0;
        var decision = PreflightDecisionEngine.Decide(report, defenderClean);
        if (decision == PreflightAction.BlockAll)
        {
            await RespondToMalwareAsync(report);
            return decision;
        }
        if (defenderClean && !report.HasCoreFinding) await Task.Run(() => _integrity.TrustCurrent(_settings.GameDirectory), _appCancellation.Token);
        return decision;
    }

    private async void ScanNow_Click(object sender, RoutedEventArgs e) => await ScanNow_ClickAsync();

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
        LatestScanText.Text = $"Last scan {report.CompletedAt:HH:mm:ss} · {report.FilesInspected} files inspected · {report.Category}";
        _events.Log("Inspection complete", $"Inspected {report.FilesInspected} files: {report.Category}, {report.Findings.Count} finding(s).", report.Category);
        if (!report.HasMalware) SetStatus(report.Category == ScanCategory.Suspicious ? "Review needed" : "Protected", report.Category == ScanCategory.Suspicious ? SuspiciousBrushKey() : SafeBrushKey());
        return report;
    }

    private async Task RespondToMalwareAsync(ScanReport report)
    {
        SetStatus("Malware blocked", MalwareBrushKey());
        var quarantined = _quarantine.Quarantine(report);
        if (quarantined.Count > 0) _events.Log("Malware quarantined", $"Moved {quarantined.Count} malicious file(s) into the local quarantine store.", ScanCategory.Malware);
        MessageBox.Show(this, "PPGAV found a malware-level signature. The game will not be launched. A Windows Defender full scan is starting now.", "Malware detected", MessageBoxButton.OK, MessageBoxImage.Error);
        if (_session is not null) StopSessionProcess();
        _events.Log("Malware response started", "Launch was blocked and Windows Defender full scan was requested.", ScanCategory.Malware);
        _ = await _defender.RunFullScanAsync(null, _appCancellation.Token);
    }

    private async void DefenderScan_Click(object sender, RoutedEventArgs e)
    {
        SaveSettingsFromControls();
        SetStatus("Defender scanning", SuspiciousBrushKey());
        var result = await _defender.RunFullScanAsync(_settings.GameDirectory, _appCancellation.Token);
        MessageBox.Show(this, result.Started ? $"Windows Defender finished with exit code {result.ExitCode}." : result.Output, "Windows Defender", MessageBoxButton.OK, result.Started && result.ExitCode == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
        SetStatus("Protected", SafeBrushKey());
    }

    private async void BackupNow_Click(object sender, RoutedEventArgs e) => await BackupNow_ClickAsync();

    private async Task BackupNow_ClickAsync()
    {
        SaveSettingsFromControls();
        try
        {
            SetStatus("Creating backup", AccentBrushKey());
            await _backup.CreateBackupAsync(_settings.GameDirectory, _settings.BackupDirectory, _settings.BackupRetentionCount, _appCancellation.Token);
            RefreshBackups();
            SetStatus("Protected", SafeBrushKey());
        }
        catch (Exception ex)
        {
            _events.Log("Backup failed", ex.Message, ScanCategory.Suspicious);
            MessageBox.Show(this, ex.Message, "Backup failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            SetStatus("Review needed", SuspiciousBrushKey());
        }
    }

    private async void RestoreBackup_Click(object sender, RoutedEventArgs e)
    {
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
            MessageBox.Show(this, "The backup was restored.", "Restore backup", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _events.Log("Restore failed", ex.Message, ScanCategory.Suspicious);
            MessageBox.Show(this, ex.Message, "Restore failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        StopSessionProcess();
    }

    private void StopSessionProcess()
    {
        if (_session is null) return;
        if (_session.Mode == LaunchMode.SecureSandbox) WindowsSandboxService.Stop(_session);
        else ProcessTree.KillTree(_session.Process);
        _events.Log("Game stopped", "The active People Playground session was force-closed by PPGAV.", ScanCategory.Suspicious);
    }

    private async Task ObserveSessionAsync(LaunchSession session)
    {
        _session = session;
        _sessionCancellation = CancellationTokenSource.CreateLinkedTokenSource(_appCancellation.Token);
        SetStatus(session.Mode == LaunchMode.SecureSandbox ? "Sandbox active" : "Safe Mode active", AccentBrushKey());
        var monitorTask = _settings.WatchProcess
            ? _monitor.MonitorAsync(session, _settings.GameDirectory, alert => _ = HandleBehaviorAlertAsync(alert, session), _sessionCancellation.Token, GamePathDiscovery.FindWorkshopDirectories(_settings.GameDirectory))
            : Task.CompletedTask;
        try
        {
            await session.Process.WaitForExitAsync(_sessionCancellation.Token);
        }
        catch (OperationCanceledException) { }
        finally
        {
            _sessionCancellation.Cancel();
            try { await monitorTask; } catch (OperationCanceledException) { }
            await session.DisposeAsync();
            _sessionCancellation.Dispose();
            _sessionCancellation = null;
            _session = null;
            SetStatus("Protected", SafeBrushKey());
            _events.Log("Game session ended", "The protected People Playground session ended.");
        }
    }

    private async Task HandleBehaviorAlertAsync(BehaviorAlert alert, LaunchSession session)
    {
        await Dispatcher.InvokeAsync(() =>
        {
            SetStatus(alert.Category == ScanCategory.Malware ? "Malware blocked" : "Review needed", alert.Category == ScanCategory.Malware ? MalwareBrushKey() : SuspiciousBrushKey());
            if (alert.StopRequired || alert.Category == ScanCategory.Malware) StopSessionProcess();
        });
        if (alert.Category == ScanCategory.Malware)
        {
            await _defender.RunFullScanAsync(null, _appCancellation.Token);
        }
    }

    private void ApplyReport(ScanReport report)
    {
        var uniqueFindingFiles = report.Findings.Select(f => f.FilePath).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        SafeCountText.Text = Math.Max(0, report.FilesInspected - uniqueFindingFiles).ToString();
        SuspiciousCountText.Text = report.Count(ScanCategory.Suspicious).ToString();
        MalwareCountText.Text = report.Count(ScanCategory.Malware).ToString();
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
            if (_session is null && Directory.Exists(_settings.GameDirectory))
            {
                try
                {
                    await _backup.CreateBackupAsync(_settings.GameDirectory, _settings.BackupDirectory, _settings.BackupRetentionCount, _appCancellation.Token);
                    await Dispatcher.InvokeAsync(RefreshBackups);
                }
                catch (Exception ex) { _events.Log("Scheduled backup failed", ex.Message, ScanCategory.Suspicious); }
            }
        }
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

    private void ExitApplication()
    {
        _allowClose = true;
        _appCancellation.Cancel();
        if (_session is not null) StopSessionProcess();
        System.Windows.Application.Current.Shutdown();
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

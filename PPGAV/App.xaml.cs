using System.Windows;
using PPGAV.Services;
using WpfApplication = System.Windows.Application;

namespace PPGAV;

public partial class App : WpfApplication
{
    private Mutex? _singleInstanceMutex;
    private MainWindow? _mainWindow;
    private bool _ownsMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var cleanupRequested = e.Args.Any(arg => arg.Equals("--cleanup-owned-state", StringComparison.OrdinalIgnoreCase));
        _singleInstanceMutex = new Mutex(true, "Local\\PPGAV-single-instance", out var created);
        _ownsMutex = created;
        if (!created)
        {
            Shutdown(cleanupRequested ? 2 : 0);
            return;
        }

        var settingsService = new SettingsService();
        var settings = settingsService.Load();
        var events = new EventLogService();
        var startup = new StartupService();
        var scanner = new ScannerService();
        var integrity = new IntegrityBaselineService();
        var quarantine = new QuarantineService(events: events);
        var updates = new UpdateService();
        var backup = new BackupService(events);
        var defender = new DefenderService(events);
        var firewall = new FirewallService(events);
        var sandbox = new WindowsSandboxService(events);
        var sandboxie = new SandboxieService(events);
        var safeMode = new SafeModeLauncher(firewall, events);
        var recoverySucceeded = true;
        try { safeMode.RecoverStaleDisabledMods(settings.GameDirectory); }
        catch (Exception ex) { recoverySucceeded = false; events.Log("Safe Mode recovery unavailable", ex.Message, PPGAV.Models.ScanCategory.Suspicious); }
        recoverySucceeded &= safeMode.RecoverySucceeded;
        try { sandbox.CleanupAbandonedSessions(); }
        catch (Exception ex) { recoverySucceeded = false; events.Log("Windows Sandbox recovery unavailable", ex.Message, PPGAV.Models.ScanCategory.Suspicious); }
        recoverySucceeded &= sandbox.RecoverySucceeded;
        try { sandboxie.CleanupAbandonedSessions(); }
        catch (Exception ex) { recoverySucceeded = false; events.Log("Sandboxie recovery unavailable", ex.Message, PPGAV.Models.ScanCategory.Suspicious); }
        recoverySucceeded &= sandboxie.RecoverySucceeded;
        try { quarantine.RecoverPendingTransactions(); }
        catch (Exception ex) { recoverySucceeded = false; events.Log("Quarantine recovery unavailable", ex.Message, PPGAV.Models.ScanCategory.Suspicious); }
        recoverySucceeded &= quarantine.RecoverySucceeded;
        if (cleanupRequested)
        {
            Shutdown(recoverySucceeded ? 0 : 1);
            return;
        }
        var monitor = new BehaviorMonitor(events, scanner);

        _mainWindow = new MainWindow(settingsService, settings, events, startup, scanner, integrity, quarantine, updates, backup, defender, sandbox, sandboxie, safeMode, monitor)
        {
            StartHidden = e.Args.Any(arg => arg.Equals("--startup", StringComparison.OrdinalIgnoreCase)) || settings.StartMinimized,
            StartupRecoverySucceeded = recoverySucceeded
        };
        MainWindow = _mainWindow;
        _mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _mainWindow?.DisposeTray();
        if (_ownsMutex) _singleInstanceMutex?.ReleaseMutex();
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }
}

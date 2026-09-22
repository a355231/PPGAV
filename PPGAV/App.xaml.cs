using System.Windows;
using PPGAV.Services;
using WpfApplication = System.Windows.Application;

namespace PPGAV;

public partial class App : WpfApplication
{
    private Mutex? _singleInstanceMutex;
    private MainWindow? _mainWindow;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _singleInstanceMutex = new Mutex(true, "Local\\PPGAV-single-instance", out var created);
        if (!created)
        {
            Shutdown();
            return;
        }

        var settingsService = new SettingsService();
        var settings = settingsService.Load();
        var events = new EventLogService();
        var startup = new StartupService();
        var scanner = new ScannerService();
        var integrity = new IntegrityBaselineService();
        var quarantine = new QuarantineService();
        var updates = new UpdateService();
        var backup = new BackupService(events);
        var defender = new DefenderService(events);
        var firewall = new FirewallService(events);
        var sandbox = new WindowsSandboxService(events);
        var sandboxie = new SandboxieService(events);
        var safeMode = new SafeModeLauncher(firewall, events);
        safeMode.RecoverStaleDisabledMods(settings.GameDirectory);
        sandbox.CleanupAbandonedSessions();
        var monitor = new BehaviorMonitor(events, scanner);

        _mainWindow = new MainWindow(settingsService, settings, events, startup, scanner, integrity, quarantine, updates, backup, defender, sandbox, sandboxie, safeMode, monitor)
        {
            StartHidden = e.Args.Any(arg => arg.Equals("--startup", StringComparison.OrdinalIgnoreCase)) || settings.StartMinimized
        };
        MainWindow = _mainWindow;
        _mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _mainWindow?.DisposeTray();
        _singleInstanceMutex?.ReleaseMutex();
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }
}

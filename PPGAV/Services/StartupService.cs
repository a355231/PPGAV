namespace PPGAV.Services;

public sealed class StartupService
{
    public bool IsEnabled => File.Exists(AppPaths.StartupShortcut);

    public void SetEnabled(bool enabled)
    {
        if (enabled)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(AppPaths.StartupShortcut)!);
            var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new PlatformNotSupportedException("Windows Script Host is unavailable.");
            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic shortcut = shell.CreateShortcut(AppPaths.StartupShortcut);
            shortcut.TargetPath = Environment.ProcessPath ?? throw new InvalidOperationException("Application path is unavailable.");
            shortcut.Arguments = "--startup";
            shortcut.WorkingDirectory = AppContext.BaseDirectory;
            shortcut.Description = "People Playground Antivirus Guard";
            shortcut.Save();
        }
        else if (File.Exists(AppPaths.StartupShortcut))
        {
            File.Delete(AppPaths.StartupShortcut);
        }
    }
}

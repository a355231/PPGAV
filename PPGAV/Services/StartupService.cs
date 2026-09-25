namespace PPGAV.Services;

public sealed class StartupService
{
    public bool IsEnabled
    {
        get
        {
            try { return File.Exists(AppPaths.StartupShortcut) && IsOwnedShortcut(AppPaths.StartupShortcut); }
            catch { return false; }
        }
    }

    public void SetEnabled(bool enabled)
    {
        var startupDirectory = Path.GetDirectoryName(AppPaths.StartupShortcut)!;
        if (enabled)
        {
            if (!Directory.Exists(startupDirectory)) Directory.CreateDirectory(startupDirectory);
            SecurePathService.RequireExistingDirectory(startupDirectory, "Windows Startup folder");
            SecurePathService.RejectReparse(AppPaths.StartupShortcut, "PPGAV Startup shortcut");
            if (File.Exists(AppPaths.StartupShortcut) && !IsOwnedShortcut(AppPaths.StartupShortcut))
                throw new IOException("A non-PPGAV shortcut already occupies the PPGAV Startup shortcut path; it was not overwritten.");
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
            SecurePathService.RequireExistingDirectory(startupDirectory, "Windows Startup folder");
            SecurePathService.RequireExistingFile(AppPaths.StartupShortcut, "PPGAV Startup shortcut");
            if (IsOwnedShortcut(AppPaths.StartupShortcut)) File.Delete(AppPaths.StartupShortcut);
            else throw new IOException("The Startup shortcut at the PPGAV path is not owned by this PPGAV installation and was not removed.");
        }
    }

    private static bool IsOwnedShortcut(string path)
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new PlatformNotSupportedException("Windows Script Host is unavailable.");
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic shortcut = shell.CreateShortcut(path);
        var target = (string)shortcut.TargetPath;
        var arguments = (string)shortcut.Arguments;
        var description = (string)shortcut.Description;
        var workingDirectory = (string)shortcut.WorkingDirectory;
        var current = Environment.ProcessPath;
        return !string.IsNullOrWhiteSpace(current) && !string.IsNullOrWhiteSpace(target) &&
            Path.GetFullPath(target).Equals(Path.GetFullPath(current), StringComparison.OrdinalIgnoreCase) &&
            arguments.Trim().Equals("--startup", StringComparison.OrdinalIgnoreCase) &&
            description.Equals("People Playground Antivirus Guard", StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(workingDirectory) &&
            Path.GetFullPath(workingDirectory).Equals(Path.GetFullPath(AppContext.BaseDirectory), StringComparison.OrdinalIgnoreCase);
    }
}

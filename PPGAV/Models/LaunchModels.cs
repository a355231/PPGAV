using System.Diagnostics;

namespace PPGAV.Models;

public enum LaunchMode
{
    SecureSandbox,
    MalwareSafe
}

public sealed class LaunchSession : IAsyncDisposable
{
    private readonly Func<ValueTask> _cleanup;
    private int _cleaned;

    public LaunchSession(LaunchMode mode, Process process, Func<ValueTask> cleanup, string? sandboxConfigPath = null, SandboxProvider provider = SandboxProvider.None, string? providerResourceName = null)
    {
        Mode = mode;
        Process = process;
        _cleanup = cleanup;
        SandboxConfigPath = sandboxConfigPath;
        Provider = provider;
        ProviderResourceName = providerResourceName;
    }

    public LaunchMode Mode { get; }
    public Process Process { get; }
    public string? SandboxConfigPath { get; }
    public SandboxProvider Provider { get; }
    public string? ProviderResourceName { get; }
    public bool CleanupSucceeded { get; private set; }
    public string? CleanupFailure { get; private set; }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _cleaned, 1) == 0)
        {
            try { await _cleanup(); CleanupSucceeded = true; }
            catch (Exception ex) { CleanupFailure = ex.Message; throw; }
        }
    }
}

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

    public LaunchSession(LaunchMode mode, Process process, Func<ValueTask> cleanup, string? sandboxConfigPath = null)
    {
        Mode = mode;
        Process = process;
        _cleanup = cleanup;
        SandboxConfigPath = sandboxConfigPath;
    }

    public LaunchMode Mode { get; }
    public Process Process { get; }
    public string? SandboxConfigPath { get; }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _cleaned, 1) == 0)
        {
            await _cleanup();
        }
    }
}

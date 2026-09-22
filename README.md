# PPGAV · People Playground Antivirus Guard

PPGAV is a Windows tray utility for launching and monitoring People Playground with an assume-compromise security model. Every launch receives a mandatory static, AMSI, and Microsoft Defender preflight covering the game, local mods, and Steam Workshop content. It reports `Safe`, `Suspicious`, or `Malware`, keeps full game-directory backups, and fails closed when inspection cannot finish.

## Protection modes

- **Secure Sandbox** prefers Windows Sandbox. It stages a disposable writable copy asynchronously, rejects reparse points, checks free space, records and verifies staged hashes immediately before launch, and persists only explicitly configured `.json`, `.sav`, `.dat`, `.cfg`, or `.ini` save paths. The real game directory is not mapped. If Windows Sandbox is unavailable, PPGAV can use an already-installed open-source Sandboxie build in a unique PPGAV-owned box; it refuses to modify or delete an existing user box and verifies ownership/settings.
- **Malware Safe Mode** automatically replaces normal startup when a threat is confined to mod or Workshop content. It uses a crash-recoverable, allow-listed transaction manifest for local and external Workshop moves, removes Steam launch environment variables, and requires a uniquely owned Windows Firewall rule for the main executable. Core-game findings block every launch mode. The firewall rule is not claimed to be session-wide; child-process and host-side monitoring are best-effort user-mode controls.

The scanner does not execute mods. Its risk engine covers known PPG malware markers, credential theft, persistence, process injection, Defender tampering, destructive I/O, dynamic/encoded payloads, process launch, network exfiltration, native code, anti-analysis, and Workshop modification. It also inspects untrusted assemblies, scripts, ZIP entry paths, expansion ratios, and executable payloads. A `Safe` result means none of these layers found a threat; it is not a mathematical proof that arbitrary code is benign.

Additional unknown-threat defenses include a DPAPI-protected, versioned core-file integrity baseline, quarantine of confirmed mod/Workshop malware only, explicit confirmation for heuristic quarantine, runtime endpoint observation, dangerous-child-process blocking, delayed-execution/mutex indicators, binary PE/entropy and UTF-16 string heuristics, bounded archive inspection, and continuous rescanning of game and Workshop changes while PPG is running. Missing, corrupt, tampered, moved, changed, or incomplete baselines fail closed. A new baseline requires an explicit dashboard approval that is logged under `%LocalAppData%\\PPGAV`.

PPGAV also checks the official GitHub release feed every six hours by default. It accepts only HTTPS MSI assets from the pinned repository, requires the GitHub-provided SHA-256 release digest to match, downloads to a private update directory, and launches Windows Installer only after verification. Automatic installation can be disabled in the dashboard.

## Build and install

Requirements: Windows 10/11 and the .NET 10 SDK. Windows Sandbox is used when enabled and selected. The installer does not enable startup or install Sandboxie by default. Sandboxie installation requires explicit `-InstallSandboxie`, `-SandboxieVersion`, and `-SandboxieSha256` parameters and publisher/signature/hash checks. Pass `-SkipSandboxDependency` for offline packaging.

```powershell
dotnet build .\PPGAV\PPGAV.csproj -c Release
dotnet run --project .\tests\PPGAV.SmokeTests.csproj -c Release
powershell -ExecutionPolicy Bypass -File .\Installer\Install-PpgAV.ps1
```

The installer publishes a self-contained executable to `%LocalAppData%\PPGAV\app`, creates a Start Menu shortcut, registers uninstall metadata, and starts the tray process unless `-NoStart` is used. It creates the single per-user Startup shortcut only with `-EnableStartup`; the application settings UI uses that same mechanism. User data is preserved by the uninstaller unless `-RemoveData` is explicitly supplied.

## Operational limits

Windows Sandbox requires supported Windows hardware and editions. PPGAV cannot verify Windows Sandbox guest processes from the host, so its behavior monitor does not claim visibility inside the guest; preflight, staged-hash verification, guest networking disablement, and session cleanup are the controls used there. Malware Safe Mode requires permission to create and remove a temporary main-executable Windows Firewall rule. The behavior monitor is a user-mode containment layer, not a replacement for endpoint protection; keep Windows Defender enabled. Clean-VM testing with both providers remains a release acceptance requirement.

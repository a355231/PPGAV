# PPGAV · People Playground Antivirus Guard

PPGAV is a Windows tray utility for launching and monitoring People Playground with an assume-compromise security model. Every launch receives a mandatory static, AMSI, and Microsoft Defender preflight covering the game, local mods, and Steam Workshop content. It reports `Safe`, `Suspicious`, or `Malware`, keeps full game-directory backups, and fails closed when inspection cannot finish.

## Protection modes

- **Secure Sandbox** prefers Windows Sandbox. It stages a disposable writable copy of the game so saves/configuration behave normally during the session, persists only safe configuration/save extensions afterward, and never maps the real game directory into the sandbox. If Windows Sandbox is unavailable, PPGAV uses the free, GPL-licensed Sandboxie Classic fallback in a dedicated `PPGAV` box with administrator rights, recovery, and network endpoints disabled. It never deletes or changes the user's other Sandboxie boxes.
- **Malware Safe Mode** automatically replaces normal startup when a threat is confined to mod or Workshop content. It transactionally disables local and external Steam Workshop directories, removes Steam launch environment variables, requires an outbound Windows Firewall block, and monitors the process tree and game-directory changes. Core-game findings block every launch mode.

The scanner does not execute mods. Its risk engine covers known PPG malware markers, credential theft, persistence, process injection, Defender tampering, destructive I/O, dynamic/encoded payloads, process launch, network exfiltration, native code, anti-analysis, and Workshop modification. It also inspects untrusted assemblies, scripts, ZIP entry paths, expansion ratios, and executable payloads. A `Safe` result means none of these layers found a threat; it is not a mathematical proof that arbitrary code is benign.

Additional unknown-threat defenses include a trusted core-file integrity baseline, quarantine of confirmed mod/Workshop malware only, runtime network endpoint observation with external-network termination, dangerous-child-process blocking in every launch mode, delayed-execution/mutex indicators, binary PE/entropy analysis, and continuous rescanning of game and Workshop changes while PPG is running. The baseline is stored locally under `%LocalAppData%\\PPGAV`; changed core files never replace the baseline automatically and fail closed until reviewed.

## Build and install

Requirements: Windows 10/11 and the .NET 10 SDK. The installer uses Windows Sandbox when present; otherwise it provisions Sandboxie Classic from WinGet. Pass `-SkipSandboxDependency` only for offline packaging.

```powershell
dotnet build .\PPGAV\PPGAV.csproj -c Release
dotnet run --project .\tests\PPGAV.SmokeTests.csproj -c Release
powershell -ExecutionPolicy Bypass -File .\Installer\Install-PpgAV.ps1
```

The installer publishes a self-contained executable to `%LocalAppData%\PPGAV\app`, creates a Start Menu shortcut and a per-user Startup shortcut, registers uninstall metadata, and starts the tray process. PPGAV stores settings, event logs, and backups under `%LocalAppData%\PPGAV` by default.

## Operational limits

Windows Sandbox requires supported Windows hardware and editions. Sandboxie Classic is the automatic fallback, but its driver installation may require elevation or a reboot. Malware Safe Mode requires permission to create and remove a temporary Windows Firewall rule. The behavior monitor is a user-mode containment layer, not a replacement for endpoint protection; keep Windows Defender enabled.

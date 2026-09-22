# PPGAV acceptance criteria

These are the observable checks used for the implementation and final verification.

1. The Windows application and smoke-test project compile in Release configuration with zero errors.
2. The scanner returns Safe, Suspicious, and Malware for representative mod files, with evidence-based reasons and no execution of the scanned code.
3. A full game-directory backup can be created and restored without allowing archive path traversal, and the backup scheduler can run at the configured interval.
4. Secure launch produces a Windows Sandbox configuration with a verified writable disposable copy, networking/clipboard/vGPU disabled, and immediate staged-hash verification; Malware Safe Mode launches without the Mods directory and blocks the main executable with an owned firewall rule.
5. The app provides a persistent system-tray process, a GUI with relevant paths/settings/status/actions, startup shortcut support, and user-visible incident logging.
6. Malware response can stop the game/sandbox, launch a Windows Defender scan command, and offer restore from a backup.
7. An installer can publish/copy the app, create a Start Menu shortcut, register uninstall metadata, and start the tray app; startup and Sandboxie installation are explicit opt-ins and user data is preserved by default.

## Hardening acceptance criteria

1. Every normal or safe launch performs a mandatory preflight before creating a People Playground process; no setting can bypass it.
2. Known malware, credential theft, persistence, process injection, destructive Steam/Workshop behavior, encoded payload chains, executable/script payloads, and malicious archive entries produce evidence-scored Suspicious or Malware findings.
3. Preflight scans the game directory plus discovered local Mods and Steam Workshop content, and uses AMSI and Microsoft Defender when available without executing mod code.
4. Malware or suspicious content confined to Mods/Workshop aborts normal launch and automatically routes to Malware Safe Mode; a core-game finding fails closed and launches nothing.
5. Malware Safe Mode transactionally disables every allow-listed mod/Workshop directory, restores content after exit/crash recovery, removes only its owned firewall rule, and reports cleanup failures. The firewall claim is limited to the main executable; this is not session-wide isolation.
6. Secure launch honors the Windows Sandbox preference and otherwise selects installed Sandboxie; Sandboxie receives a unique verified PPGAV-owned box and no user sandbox is deleted. Host monitoring does not claim visibility into Windows Sandbox guests.
7. Missing/corrupt/tampered/moved baselines block until explicit approval; backups and quarantine use validated manifests, hashes, temporary trees, rollback support, and cancellation-safe cleanup.
8. Release build and smoke suite pass. Clean-VM tests, Windows Sandbox guest behavior, Sandboxie driver behavior, signed MSI verification, and full installer/uninstaller lifecycle remain environment-dependent release gates unless separately executed.

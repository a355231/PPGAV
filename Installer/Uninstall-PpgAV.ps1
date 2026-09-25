param([switch]$RemoveData)

$ErrorActionPreference = 'Stop'
$installDir = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$appDir = [IO.Path]::GetFullPath((Join-Path $installDir 'app'))
$appExe = Join-Path $appDir 'PPGAV.exe'
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PPGAV'
$shortcutDescription = 'People Playground Antivirus Guard'

function Assert-NoReparsePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to operate through a reparse point: $current"
            }
        }
        $parent = [IO.Directory]::GetParent($current)
        if (-not $parent) { break }
        $current = $parent.FullName
    }
}

function Test-OwnedShortcut([string]$Path, [string]$Arguments) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    Assert-NoReparsePath $Path
    $shellType = [Type]::GetTypeFromProgID('WScript.Shell')
    if (-not $shellType) { throw 'Windows Script Host is unavailable; refusing to remove shortcuts without verifying ownership.' }
    $shell = [Activator]::CreateInstance($shellType)
    $shortcut = $shell.CreateShortcut($Path)
    try {
        return [IO.Path]::GetFullPath([string]$shortcut.TargetPath).Equals($appExe, [StringComparison]::OrdinalIgnoreCase) -and
            ([string]$shortcut.Arguments).Trim().Equals($Arguments, [StringComparison]::OrdinalIgnoreCase) -and
            ([string]$shortcut.Description).Equals($shortcutDescription, [StringComparison]::Ordinal) -and
            [IO.Path]::GetFullPath([string]$shortcut.WorkingDirectory).Equals($appDir, [StringComparison]::OrdinalIgnoreCase)
    }
    finally {
        if ([Runtime.InteropServices.Marshal]::IsComObject($shortcut)) { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) | Out-Null }
        if ([Runtime.InteropServices.Marshal]::IsComObject($shell)) { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null }
    }
}

function Remove-OwnedShortcut([string]$Path, [string]$Arguments) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    if (Test-OwnedShortcut $Path $Arguments) { Remove-Item -LiteralPath $Path -Force }
    else { Write-Warning "Preserving shortcut that does not match this PPGAV install: $Path" }
}

function Get-OwnedProcessIds {
    $ids = @()
    try { $processes = Get-CimInstance Win32_Process -Filter "Name = 'PPGAV.exe'" -ErrorAction Stop }
    catch { throw 'Could not establish PPGAV process identities; refusing to stop processes or remove files.' }
    foreach ($process in $processes) {
        if (-not $process.ExecutablePath) { throw "Could not establish the executable path for PPGAV PID $($process.ProcessId); refusing to remove files." }
        if ([IO.Path]::GetFullPath($process.ExecutablePath).Equals($appExe, [StringComparison]::OrdinalIgnoreCase)) {
            $ids += [int]$process.ProcessId
        }
    }
    return $ids
}

# Require the installer record to bind this script to its registered location.
if (-not (Test-Path -LiteralPath $uninstallKey)) { throw 'The PPGAV uninstall registration is missing; refusing to infer ownership of files or shortcuts.' }
$registration = Get-ItemProperty -LiteralPath $uninstallKey
$registeredInstall = [IO.Path]::GetFullPath([string]$registration.InstallLocation).TrimEnd([IO.Path]::DirectorySeparatorChar)
$registeredScript = [string]$registration.UninstallString
if (-not $registeredInstall.Equals($installDir, [StringComparison]::OrdinalIgnoreCase) -or
    [string]$registration.Publisher -ne 'PPGAV' -or
    $registeredScript -notmatch [regex]::Escape($PSCommandPath)) {
    throw 'The uninstall registration does not match this PPGAV install script; no files were changed.'
}

Assert-NoReparsePath $installDir
Assert-NoReparsePath $appDir
if (Test-Path -LiteralPath $appExe) { Assert-NoReparsePath $appExe }

# Stop only processes whose current executable path still identifies this install.
foreach ($processId in Get-OwnedProcessIds) {
    $before = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if (-not $before) { continue }
    $startTime = $before.StartTime
    $stillOwned = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
    if ($stillOwned -and $stillOwned.Name -eq 'PPGAV.exe' -and $stillOwned.ExecutablePath -and
        [IO.Path]::GetFullPath($stillOwned.ExecutablePath).Equals($appExe, [StringComparison]::OrdinalIgnoreCase)) {
        $current = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($current) {
            try {
                if ($current.StartTime -eq $startTime) {
                    $current.Kill()
                    [void]$current.WaitForExit(5000)
                }
            }
            finally { $current.Dispose() }
        }
    }
}

$deadline = [DateTime]::UtcNow.AddSeconds(15)
while ((Get-OwnedProcessIds).Count -gt 0 -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
if ((Get-OwnedProcessIds).Count -gt 0) { throw 'The PPGAV process is still running; application files were retained.' }

# Let PPGAV remove only authenticated, application-owned firewall/sandbox state.
if (Test-Path -LiteralPath $appExe -PathType Leaf) {
    $cleanup = Start-Process -FilePath $appExe -ArgumentList '--cleanup-owned-state' -PassThru -Wait -WindowStyle Hidden
    if ($cleanup.ExitCode -ne 0) { throw 'PPGAV could not verify cleanup of its owned sandbox/firewall/quarantine state. Application files were retained; review %LOCALAPPDATA%\PPGAV\events.jsonl and retry.' }
}

$startupShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'PPGAV.lnk'
$startMenuShortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'PPGAV\PPGAV.lnk'
Remove-OwnedShortcut $startupShortcut '--startup'
Remove-OwnedShortcut $startMenuShortcut ''

# Remove only known executable payload; never recursively delete the install tree.
if (Test-Path -LiteralPath $appExe -PathType Leaf) { Remove-Item -LiteralPath $appExe -Force }
if ((Test-Path -LiteralPath $appDir -PathType Container) -and -not (Get-ChildItem -LiteralPath $appDir -Force | Select-Object -First 1)) {
    Remove-Item -LiteralPath $appDir -Force
}

# Remove only known registration values; retain user-added values/subkeys.
$knownValues = @('DisplayName', 'DisplayVersion', 'InstallLocation', 'Publisher', 'UninstallString')
foreach ($name in $knownValues) {
    if ($registration.PSObject.Properties.Name -contains $name) {
        Remove-ItemProperty -LiteralPath $uninstallKey -Name $name -ErrorAction SilentlyContinue
    }
}
$remaining = Get-Item -LiteralPath $uninstallKey
$remainingValues = @($remaining.GetValueNames() | Where-Object { $_ -ne '' })
if ($remaining.SubKeyCount -eq 0 -and $remainingValues.Count -eq 0) { Remove-Item -LiteralPath $uninstallKey -Force }

if ([IO.Path]::GetFullPath($PSCommandPath).Equals([IO.Path]::GetFullPath((Join-Path $installDir 'Uninstall-PpgAV.ps1')), [StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $PSCommandPath -Force
}

$programsPpgav = Split-Path -Parent $startMenuShortcut
if ((Test-Path -LiteralPath $programsPpgav -PathType Container) -and -not (Get-ChildItem -LiteralPath $programsPpgav -Force | Select-Object -First 1)) {
    Remove-Item -LiteralPath $programsPpgav -Force
}

if ($RemoveData) {
    $dataDir = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'PPGAV'))
    $localAppData = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (-not [IO.Path]::GetDirectoryName($dataDir).Equals($localAppData, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFileName($dataDir).Equals('PPGAV', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove data outside the PPGAV user-data directory.'
    }
    Assert-NoReparsePath $dataDir
    if (Test-Path -LiteralPath $dataDir -PathType Container) {
        $pending = [Collections.Generic.Stack[string]]::new()
        $pending.Push($dataDir)
        while ($pending.Count -gt 0) {
            foreach ($item in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Refusing explicit data removal because a reparse point exists: $($item.FullName)"
                }
                if ($item.PSIsContainer) { $pending.Push($item.FullName) }
            }
        }
        Remove-Item -LiteralPath $dataDir -Recurse -Force
    }
}

Write-Host 'PPGAV uninstall completed. Unknown files, unrelated shortcuts, and user data were preserved unless -RemoveData was supplied.'

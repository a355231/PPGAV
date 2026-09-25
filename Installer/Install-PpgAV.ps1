param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'PPGAV'),
    [switch]$SkipSandboxDependency,
    [switch]$InstallSandboxie,
    [string]$SandboxieVersion,
    [string]$SandboxieSha256,
    [switch]$EnableStartup,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$project = Join-Path $sourceRoot 'PPGAV\PPGAV.csproj'
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$installRoot = [IO.Path]::GetPathRoot($InstallDir)
if ($InstallDir.TrimEnd([IO.Path]::DirectorySeparatorChar).Equals($installRoot.TrimEnd([IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to install into a volume root.'
}
$InstallDir = $InstallDir.TrimEnd([IO.Path]::DirectorySeparatorChar)
$publishDir = Join-Path $InstallDir 'app'
$target = Join-Path $publishDir 'PPGAV.exe'
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PPGAV'
$uninstallScript = Join-Path $InstallDir 'Uninstall-PpgAV.ps1'

function Assert-NoReparsePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to install through a reparse point: $current"
            }
        }
        $parent = [IO.Directory]::GetParent($current)
        if (-not $parent) { break }
        $current = $parent.FullName
    }
}

Assert-NoReparsePath $InstallDir
$registeredHere = $false
if (Test-Path -LiteralPath $uninstallKey) {
    $registration = Get-ItemProperty -LiteralPath $uninstallKey
    $registeredLocation = [IO.Path]::GetFullPath([string]$registration.InstallLocation).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ([string]$registration.Publisher -ne 'PPGAV' -or [string]$registration.UninstallString -notmatch [regex]::Escape($uninstallScript)) {
        throw 'The existing uninstall registration does not identify this PPGAV installer; refusing to overwrite it.'
    }
    if (-not $registeredLocation.Equals($InstallDir, [StringComparison]::OrdinalIgnoreCase)) {
        throw "PPGAV is already registered at '$registeredLocation'; uninstall that copy before installing to another location."
    }
    $registeredHere = $true
}
if ((Test-Path -LiteralPath $publishDir -PathType Container) -and -not $registeredHere -and
    (Get-ChildItem -LiteralPath $publishDir -Force | Select-Object -First 1)) {
    throw "The target app directory is nonempty but is not registered as this PPGAV install; refusing to overwrite its contents."
}
if ((Test-Path -LiteralPath $uninstallScript -PathType Leaf) -and -not $registeredHere) {
    throw "An uninstall script already exists at '$uninstallScript' without a matching PPGAV install record; refusing to overwrite it."
}
$runningProcesses = Get-CimInstance Win32_Process -Filter "Name = 'PPGAV.exe'" -ErrorAction Stop
if ($runningProcesses | Where-Object { -not $_.ExecutablePath }) { throw 'A PPGAV process path could not be verified; close PPGAV and retry without force-stopping it.' }
$runningInstall = $runningProcesses | Where-Object { [IO.Path]::GetFullPath($_.ExecutablePath).Equals([IO.Path]::GetFullPath($target), [StringComparison]::OrdinalIgnoreCase) }
if ($runningInstall) { throw 'Close PPGAV from the system tray before installing or updating it; no process was stopped.' }

New-Item -ItemType Directory -Force -Path $InstallDir, $publishDir | Out-Null
Assert-NoReparsePath $publishDir
if (Test-Path -LiteralPath $target) { Assert-NoReparsePath $target }
dotnet publish $project -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $publishDir --nologo
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $target)) {
    throw "PPGAV publish failed."
}

# Windows Sandbox is preferred. On systems where it is absent, install the
# free GPL-3.0 Sandboxie Classic fallback from the Microsoft WinGet catalog.
if ($InstallSandboxie -and -not $SkipSandboxDependency -and -not (Test-Path (Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'))) {
    if ([string]::IsNullOrWhiteSpace($SandboxieVersion) -or [string]::IsNullOrWhiteSpace($SandboxieSha256)) { throw 'Sandboxie installation requires an explicit pinned version and SHA-256 hash.' }
    $sandboxieStart = Join-Path $env:ProgramFiles 'Sandboxie\Start.exe'
    if (-not (Test-Path $sandboxieStart)) {
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if (-not $winget) { throw 'Windows Sandbox is unavailable and WinGet was not found. Install Sandboxie Classic before secure launch.' }
        $metadata = & $winget.Source show --id Sandboxie.Classic --exact --source winget
        if ($LASTEXITCODE -ne 0 -or ($metadata -notmatch 'Sandboxie')) { throw 'Sandboxie publisher metadata could not be verified.' }
        & $winget.Source install --id Sandboxie.Classic --exact --version $SandboxieVersion --source winget --silent --disable-interactivity --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) { throw 'Sandboxie Classic fallback installation failed.' }
    }
    if (-not (Test-Path $sandboxieStart)) { throw 'Pinned Sandboxie installation did not produce the expected executable.' }
    $signature = Get-AuthenticodeSignature $sandboxieStart
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Sandboxie') { throw 'Sandboxie publisher signature verification failed.' }
    if ((Get-FileHash $sandboxieStart -Algorithm SHA256).Hash -ne $SandboxieSha256.ToUpperInvariant()) { throw 'Sandboxie installed executable hash does not match the pinned hash.' }
}

function New-Shortcut([string]$Path, [string]$TargetPath, [string]$Arguments, [string]$Description) {
    $shell = New-Object -ComObject WScript.Shell
    if (Test-Path -LiteralPath $Path) {
        $existing = $shell.CreateShortcut($Path)
        if ([IO.Path]::GetFullPath($existing.TargetPath) -ne [IO.Path]::GetFullPath($TargetPath) -or
            $existing.Description -ne $Description -or $existing.Arguments -ne $Arguments -or
            [IO.Path]::GetFullPath($existing.WorkingDirectory) -ne [IO.Path]::GetFullPath((Split-Path $TargetPath))) {
            throw "Refusing to overwrite a non-PPGAV shortcut at $Path"
        }
    }
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $TargetPath
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = Split-Path $TargetPath
    $shortcut.Description = $Description
    $shortcut.Save()
}

$startupDir = [Environment]::GetFolderPath('Startup')
$startMenuDir = Join-Path ([Environment]::GetFolderPath('Programs')) 'PPGAV'
New-Item -ItemType Directory -Force -Path $startupDir, $startMenuDir | Out-Null
if ($EnableStartup) { New-Shortcut (Join-Path $startupDir 'PPGAV.lnk') $target '--startup' 'People Playground Antivirus Guard' }
New-Shortcut (Join-Path $startMenuDir 'PPGAV.lnk') $target '' 'People Playground Antivirus Guard'

Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-PpgAV.ps1') -Destination (Join-Path $InstallDir 'Uninstall-PpgAV.ps1') -Force
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayName -Value 'PPGAV · People Playground Antivirus Guard' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value '1.4.0' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $InstallDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name Publisher -Value 'PPGAV' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name UninstallString -Value "powershell.exe -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'Uninstall-PpgAV.ps1')`"" -PropertyType String -Force | Out-Null

if (-not $NoStart) {
    Start-Process -FilePath $target -ArgumentList '--startup'
}
Write-Host "PPGAV installed to $InstallDir"

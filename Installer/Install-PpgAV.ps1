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
$publishDir = Join-Path $InstallDir 'app'
$target = Join-Path $publishDir 'PPGAV.exe'

New-Item -ItemType Directory -Force -Path $InstallDir, $publishDir | Out-Null
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

$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PPGAV'
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayName -Value 'PPGAV · People Playground Antivirus Guard' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value '1.4.0' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $InstallDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name Publisher -Value 'PPGAV' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name UninstallString -Value "powershell.exe -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'Uninstall-PpgAV.ps1')`"" -PropertyType String -Force | Out-Null

$uninstaller = @'
param([switch]$RemoveData)
$ErrorActionPreference = 'Stop'
$installDir = Split-Path $PSScriptRoot
Get-Process -Name PPGAV -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item (Join-Path ([Environment]::GetFolderPath('Startup')) 'PPGAV.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('Programs')) 'PPGAV\PPGAV.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PPGAV' -Recurse -Force -ErrorAction SilentlyContinue
try { Get-NetFirewallRule -DisplayName 'PPGAV Safe Mode *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop } catch { Write-Warning "PPGAV firewall cleanup failed: $($_.Exception.Message)" }
if ($RemoveData) { Remove-Item (Join-Path $env:LOCALAPPDATA 'PPGAV') -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'PPGAV was uninstalled. User data was preserved unless -RemoveData was supplied.'
'@
Set-Content -Path (Join-Path $InstallDir 'Uninstall-PpgAV.ps1') -Value $uninstaller -Encoding UTF8

if (-not $NoStart) {
    Start-Process -FilePath $target -ArgumentList '--startup'
}
Write-Host "PPGAV installed to $InstallDir"

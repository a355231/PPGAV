param([switch]$KeepData)
$ErrorActionPreference = 'Stop'
$installDir = Split-Path $PSScriptRoot
Get-Process -Name PPGAV -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item (Join-Path ([Environment]::GetFolderPath('Startup')) 'PPGAV.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('Programs')) 'PPGAV\PPGAV.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PPGAV' -Recurse -Force -ErrorAction SilentlyContinue
if (-not $KeepData) { Remove-Item (Join-Path $env:LOCALAPPDATA 'PPGAV') -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'PPGAV was uninstalled.'

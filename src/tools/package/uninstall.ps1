[CmdletBinding()]
param([switch]$ConfirmKdbgServices)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $ConfirmKdbgServices) {
    throw "Removal requires -ConfirmKdbgServices."
}
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

foreach ($Service in @("KDBGProbe", "KDBG")) {
    & sc.exe stop $Service 2>&1 | ForEach-Object { Write-Host $_ }
    & sc.exe delete $Service 2>&1 | ForEach-Object { Write-Host $_ }
}
Write-Host "KDBG and KDBGProbe service registrations were requested for removal."

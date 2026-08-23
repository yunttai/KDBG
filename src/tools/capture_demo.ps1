[CmdletBinding()]
param(
    [string]$Executable,

    [switch]$ConfirmDedicatedVm,

    [switch]$ConfirmSnapshot,

    [switch]$ConfirmFixtureReset
)

$ErrorActionPreference = "Stop"

if (-not $ConfirmDedicatedVm -or
    -not $ConfirmSnapshot -or
    -not $ConfirmFixtureReset) {
    throw "Dedicated VM, snapshot, and fixture reset confirmations are required."
}

if ([string]::IsNullOrWhiteSpace($Executable) -or
    -not (Test-Path $Executable)) {
    throw "Provide a valid release executable path."
}

Write-Host "Recording checklist:"
Write-Host "1. Backend/ABI/WRITE LOCKED"
Write-Host "2. PFN Read 4096/4096"
Write-Host "3. Edit and diff"
Write-Host "4. Unlock and Apply"
Write-Host "5. Read-back verification PASS"
Write-Host "6. PID/VA mapping"
Write-Host "7. PML4/PDPT/PD/PT"
Write-Host "8. Rollback"

Start-Process -FilePath $Executable -Verb RunAs

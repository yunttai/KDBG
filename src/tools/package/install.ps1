[CmdletBinding()]
param(
    [switch]$Start,
    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot) {
    throw "Installation requires -ConfirmDedicatedVm and -ConfirmSnapshot."
}
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator in a disposable snapshot VM."
}

$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([IO.Path]::GetFileName($PackageRoot) -ne "KDBG-1.0.0-win-x64") {
    throw "Unexpected package directory name: $([IO.Path]::GetFileName($PackageRoot))"
}

function Invoke-Sc([string[]]$Arguments, [switch]$AllowFailure) {
    $Output = & sc.exe @Arguments 2>&1
    $Code = $LASTEXITCODE
    if ($Output) { $Output | ForEach-Object { Write-Host $_ } }
    if ($Code -ne 0 -and -not $AllowFailure) {
        throw "sc.exe failed with exit code $Code."
    }
    return $Code
}

& (Join-Path $PSScriptRoot "diagnose.ps1") -VerifyPackage
if ($LASTEXITCODE -ne 0) { throw "Package diagnostics failed; no service was changed." }

$Drivers = @(
    @{ Service = "KDBG"; File = "KDbgDriver.sys"; Display = "KDBG Physical Memory Driver" },
    @{ Service = "KDBGProbe"; File = "KDbgProbe.sys"; Display = "KDBG Probe Fixture Driver" }
)
foreach ($Driver in $Drivers) {
    $Path = Join-Path $PackageRoot "drivers\$($Driver.File)"
    $Existing = Invoke-Sc @("query", $Driver.Service) -AllowFailure
    if ($Existing -eq 0) {
        Invoke-Sc @("config", $Driver.Service, "type=", "kernel", "start=", "demand",
            "binPath=", $Path, "DisplayName=", $Driver.Display) | Out-Null
    } else {
        Invoke-Sc @("create", $Driver.Service, "type=", "kernel", "start=", "demand",
            "binPath=", $Path, "DisplayName=", $Driver.Display) | Out-Null
    }
}
if ($Start) {
    foreach ($Driver in $Drivers) { Invoke-Sc @("start", $Driver.Service) | Out-Null }
}
Write-Host "KDBG services installed. Driver signatures were inspected, not asserted."

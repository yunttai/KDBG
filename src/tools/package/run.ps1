[CmdletBinding()]
param(
    [switch]$StartDrivers,
    [switch]$StopDriversOnExit,
    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot,
    [ValidateSet("DisposableVm", "LocalHost")]
    [string]$TargetProfile,
    [ValidateSet("DistributionSource", "InstalledProduct")]
    [string]$PackageRootMode = "DistributionSource"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ResolvedTargetProfile = if ([string]::IsNullOrWhiteSpace($TargetProfile)) {
    if ($ConfirmDedicatedVm -and $ConfirmSnapshot) { "DisposableVm" }
    else { "LocalHost" }
} else { $TargetProfile }
if ($ResolvedTargetProfile -eq "DisposableVm" -and
    (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot)) {
    throw "Running KDBG requires -ConfirmDedicatedVm and -ConfirmSnapshot."
}
Import-Module (Join-Path $PSScriptRoot "TargetProfile.psm1") -Force
$null = Assert-KdbgTargetProfile `
    -TargetProfile $ResolvedTargetProfile `
    -ConfirmDedicatedVm:$ConfirmDedicatedVm `
    -ConfirmSnapshot:$ConfirmSnapshot
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator on the selected target."
}
$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$Executable = Join-Path $PackageRoot "KDBG.exe"

if ($StartDrivers) {
    & (Join-Path $PSScriptRoot "start.ps1") `
        -TargetProfile $ResolvedTargetProfile `
        -ConfirmDedicatedVm:$ConfirmDedicatedVm `
        -ConfirmSnapshot:$ConfirmSnapshot `
        -PackageRootMode $PackageRootMode
    if ($LASTEXITCODE -ne 0) { throw "Driver start failed." }
} else {
    & (Join-Path $PSScriptRoot "diagnose.ps1") `
        -VerifyPackage -RequireAdministrator -RequireRunning `
        -PackageRootMode $PackageRootMode
    if ($LASTEXITCODE -ne 0) { throw "KDBG is not ready to run." }
}

try {
    $Process = Start-Process -FilePath $Executable -PassThru -Wait
    if ($Process.ExitCode -ne 0) {
        throw "KDBG exited with code $($Process.ExitCode)."
    }
} finally {
    if ($StopDriversOnExit) {
        & (Join-Path $PSScriptRoot "stop.ps1")
    }
}
exit 0

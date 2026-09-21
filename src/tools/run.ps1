[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [switch]$NoBuild,
    [switch]$ConfirmDisposableVm,
    [switch]$ConfirmSnapshot,
    [ValidateSet("DisposableVm", "LocalHost")]
    [string]$TargetProfile
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ($env:OS -ne "Windows_NT") { throw "KDBG GUI runs on Windows only." }
$ResolvedTargetProfile = if ([string]::IsNullOrWhiteSpace($TargetProfile)) {
    if ($ConfirmDisposableVm -and $ConfirmSnapshot) { "DisposableVm" }
    else { "LocalHost" }
} else { $TargetProfile }
if ($ResolvedTargetProfile -eq "DisposableVm" -and
    (-not $ConfirmDisposableVm -or -not $ConfirmSnapshot)) {
    throw "KDBG live mode requires -ConfirmDisposableVm and -ConfirmSnapshot."
}
Import-Module (Join-Path $PSScriptRoot "package\TargetProfile.psm1") -Force
$null = Assert-KdbgTargetProfile `
    -TargetProfile $ResolvedTargetProfile `
    -ConfirmDedicatedVm:$ConfirmDisposableVm `
    -ConfirmSnapshot:$ConfirmSnapshot
$Preset = if ($Configuration -eq "Release") { "windows-release" } else { "windows-debug" }
if (-not $NoBuild) {
    & (Join-Path $PSScriptRoot "build.ps1") -Preset $Preset
}
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Executable = Join-Path $RepositoryRoot "out\build\$Preset\KDBG.exe"
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw "KDBG.exe was not found for preset $Preset."
}
$Process = Start-Process -FilePath $Executable -Verb RunAs -PassThru -Wait
if ($Process.ExitCode -ne 0) { throw "KDBG exited with code $($Process.ExitCode)." }

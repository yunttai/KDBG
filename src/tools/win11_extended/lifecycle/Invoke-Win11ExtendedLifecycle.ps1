[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WorkspaceRoot,
    [Parameter(Mandatory)][Guid]$VmId,
    [Parameter(Mandatory)][string]$CheckpointName,
    [Parameter(Mandatory)][Guid]$CheckpointId,
    [Parameter(Mandatory)][string]$CredentialPath,
    [Parameter(Mandatory)][string]$PreviousPackageZipPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedPreviousPackageSha256,
    [Parameter(Mandatory)][string]$PreviousCertificatePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedPreviousCertificateSha256,
    [Parameter(Mandatory)][string]$BenchmarkExecutablePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedBenchmarkSha256,
    [Parameter(Mandatory)][switch]$ConfirmDisposableVm,
    [Parameter(Mandatory)][switch]$ConfirmCheckpointRestore,
    [ValidateRange(30, 900)][int]$ConnectionTimeoutSeconds = 300,
    [switch]$SkipLifecycle,
    [switch]$SkipSoak,
    [switch]$SkipBenchmarks,
    [ValidateRange(60, 1800)][int]$SoakDurationSeconds = 1800,
    [switch]$AllowCalibrationDuration,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Win11ExtendedLifecycle.psm1') -Force
Invoke-KdbgWin11ExtendedLifecycle @PSBoundParameters

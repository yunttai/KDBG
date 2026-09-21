[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PackageZipPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedPackageSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSourceSnapshotSha256,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CertificatePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedCertificateSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$VMName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$EpochName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Win11ValidationHarness.psm1') -Force

New-KdbgWin11ValidationWorkspace @PSBoundParameters

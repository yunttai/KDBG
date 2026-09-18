[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RunRoot,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PackageZipPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CertificatePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BindingPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CheckpointId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Win11ValidationHarness.psm1') -Force

Invoke-KdbgWin11GuestValidation @PSBoundParameters

[CmdletBinding()]
param(
    [Parameter()][switch]$GuestCredentialAvailable,
    [Parameter()][string]$OutputPath = (Join-Path $PSScriptRoot 'readiness.json'),
    [Parameter()][switch]$FailIfNotReady
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Win11ValidationHarness.psm1') -Force

Test-KdbgWin11Readiness `
    -WorkspaceRoot $PSScriptRoot `
    -GuestCredentialAvailable:$GuestCredentialAvailable `
    -OutputPath $OutputPath `
    -FailIfNotReady:$FailIfNotReady

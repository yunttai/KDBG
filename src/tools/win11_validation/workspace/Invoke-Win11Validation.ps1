[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CheckpointName,
    [Parameter(Mandatory)][Guid]$CheckpointId,
    [Parameter(Mandatory)][PSCredential]$GuestCredential,
    [Parameter(Mandatory)][switch]$ConfirmDisposableVm,
    [Parameter(Mandatory)][switch]$ConfirmCheckpointRestore,
    [Parameter()][ValidateRange(30, 600)][int]$ConnectionTimeoutSeconds = 240
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Win11ValidationHarness.psm1') -Force

Invoke-KdbgWin11Validation `
    -WorkspaceRoot $PSScriptRoot `
    -CheckpointName $CheckpointName `
    -CheckpointId $CheckpointId `
    -GuestCredential $GuestCredential `
    -ConfirmDisposableVm:$ConfirmDisposableVm `
    -ConfirmCheckpointRestore:$ConfirmCheckpointRestore `
    -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds

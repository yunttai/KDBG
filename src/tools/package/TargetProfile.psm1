Set-StrictMode -Version Latest

function Assert-KdbgTargetProfile {
    [CmdletBinding()]
    param(
        [ValidateSet('DisposableVm', 'LocalHost')]
        [string]$TargetProfile = 'LocalHost',
        [switch]$ConfirmDedicatedVm,
        [switch]$ConfirmSnapshot
    )

    if ($TargetProfile -eq 'DisposableVm') {
        if (-not $ConfirmDedicatedVm.IsPresent -or
            -not $ConfirmSnapshot.IsPresent) {
            throw 'DisposableVm requires -ConfirmDedicatedVm and -ConfirmSnapshot.'
        }
    } elseif ($ConfirmDedicatedVm.IsPresent -or $ConfirmSnapshot.IsPresent) {
        throw 'LocalHost and DisposableVm confirmations are mutually exclusive.'
    }

    return [pscustomobject]@{ TargetProfile = $TargetProfile }
}

function Get-KdbgMachineBindingSha256 {
    [CmdletBinding()]
    param(
        [string]$MachineGuid,
        [string]$ComputerName
    )

    if (-not $PSBoundParameters.ContainsKey('MachineGuid')) {
        $MachineGuid = [string](Get-ItemPropertyValue `
            -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
            -Name MachineGuid -ErrorAction Stop)
    }
    if (-not $PSBoundParameters.ContainsKey('ComputerName')) {
        $ComputerName = [Environment]::MachineName
    }
    if ([string]::IsNullOrWhiteSpace($MachineGuid) -or
        [string]::IsNullOrWhiteSpace($ComputerName)) {
        throw 'Automatic machine identity inputs are unavailable.'
    }

    # Only the digest leaves this helper. The source identifiers are normalized
    # in memory and are never written to evidence or used as a product gate.
    $material = "kdbg.machine-binding.v1`n" +
        "machine-guid=$($MachineGuid.Trim().ToLowerInvariant())`n" +
        "computer-name=$($ComputerName.Trim().ToUpperInvariant())`n"
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($material))
        return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

Export-ModuleMember -Function Assert-KdbgTargetProfile, Get-KdbgMachineBindingSha256

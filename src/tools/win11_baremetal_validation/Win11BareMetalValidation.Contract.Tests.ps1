Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$producerPath = Join-Path $PSScriptRoot 'Invoke-Win11BareMetalValidation.ps1'
$text = Get-Content -LiteralPath $producerPath -Raw
foreach ($required in @(
        'kdbg.win11-baremetal-validation.v1', '-TargetProfile LocalHost',
        '--artifact-directory', '--baremetal-evidence', '--confirm-probe-pfn',
        'kdbg.live-verify.v2', 'baseline.bin', 'independent-reload.bin',
        'rollback.bin', 'Get-AuthenticodeSignature', 'cleanup-report.json',
        "operation = 'compare-write-page-v1'", 'Write-KdbgAtomicJson',
        'Get-KdbgHostFacts', 'HypervisorPresent', '$hostFacts.execution_context',
        'ConvertTo-KdbgLowerHex', 'Get-KdbgByteSha256',
        '[BitConverter]::ToString', '$algorithm.ComputeHash',
        '$live.backend.supports_physical_page_compare_write')) {
    if ($text -notmatch [regex]::Escape($required)) {
        throw "Local-host producer is missing contract token: $required"
    }
}
foreach ($removedPolicy in @(
        'ConfirmDedicated', 'ConfirmSnapshot', 'FinalizeAfterReboot',
        'Restart-Computer', 'recovery-plan', 'recovery-journal')) {
    if ($text -match [regex]::Escape($removedPolicy)) {
        throw "Local-host producer retained removed policy gate: $removedPolicy"
    }
}
foreach ($unsupportedApi in @('[Convert]::ToHexString', '::HashData(')) {
    if ($text -match [regex]::Escape($unsupportedApi)) {
        throw "Local-host producer uses a PowerShell 5.1-incompatible API: $unsupportedApi"
    }
}
if ($text -match [regex]::Escape("architecture = 'x64'") -or
    $text -match [regex]::Escape("is_virtual_machine = `$false")) {
    throw 'Local-host producer must observe architecture and virtualization state.'
}
Write-Output 'Win11 local-host evidence producer contract tests passed.'

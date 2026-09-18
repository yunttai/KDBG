[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Win11ExtendedLifecycle.psm1') -Force

$script:Checks = 0
function Assert-True([bool]$Condition, [string]$Message) {
    $script:Checks++
    if (-not $Condition) { throw $Message }
}

$static = Test-KdbgWin11ExtendedContract -Root $PSScriptRoot
Assert-True ($static.success -eq $true) "Static contract failed: $($static.errors -join ', ')"
Assert-True ($static.live_execution_performed -eq $false) 'Static contract must not claim live execution.'

$finalPlan = New-KdbgExtendedExecutionPlan
Assert-True ($finalPlan.lifecycle.cycles -eq 2) 'Final plan must contain two lifecycle cycles.'
Assert-True ($finalPlan.lifecycle.total_stop_start -eq 10) 'Final plan must contain ten stop/start operations.'
Assert-True ($finalPlan.lifecycle.reboot_boundaries -eq 4) 'Final plan must contain four reboot boundaries.'
Assert-True ($finalPlan.soak.duration_seconds -eq 1800) 'Final soak must be 1800 seconds.'
Assert-True ($finalPlan.soak.report_count -eq 61) 'Final soak must contain 61 reports.'
Assert-True ($finalPlan.soak.total_scheduled_reads -eq 488) 'Final soak must schedule 488 reads.'
Assert-True ($finalPlan.soak.calibration_only -eq $false) 'Final soak must not be marked calibration.'
Assert-True ($finalPlan.benchmarks.run_count -eq 7) 'Final benchmark plan must contain seven runs.'
Assert-True ($finalPlan.live_execution_performed -eq $false) 'Planning must not claim live execution.'

$shortRejected = $false
try { [void](New-KdbgExtendedExecutionPlan -SoakDurationSeconds 60) }
catch { $shortRejected = $true }
Assert-True $shortRejected 'Short soak must require the explicit calibration override.'

$calibration = New-KdbgExtendedExecutionPlan -SoakDurationSeconds 60 -AllowCalibrationDuration
Assert-True ($calibration.soak.calibration_only -eq $true) 'Short soak must be marked calibration-only.'
Assert-True ($calibration.soak.duration_seconds -eq 60) 'Calibration duration was not preserved.'
Assert-True ($calibration.soak.report_count -eq 7) '60-second calibration must schedule seven reports.'
Assert-True ($calibration.soak.total_scheduled_reads -eq 56) '60-second calibration must schedule 56 reads.'

$percentile = Get-KdbgPercentileSummary -Values ([double[]](1, 2, 3, 4, 100, 6, 7))
Assert-True ($percentile.count -eq 7) 'Percentile summary count mismatch.'
Assert-True ($percentile.median -eq 4) 'Percentile summary median mismatch.'
Assert-True ($percentile.p95_nearest_rank -eq 100) 'Nearest-rank p95 mismatch.'

$skip = New-KdbgExtendedExecutionPlan -SkipLifecycle -SkipSoak -SkipBenchmarks
Assert-True ($skip.phases.Count -eq 2) 'Fully skipped plan must retain only baseline and finalize.'
Assert-True ($skip.phases[0].name -ceq 'baseline') 'Skipped plan must begin with baseline.'
Assert-True ($skip.phases[1].name -ceq 'finalize') 'Skipped plan must end with finalize.'

$guestScript = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot 'Invoke-Win11ExtendedGuest.ps1') -Raw
Assert-True ($guestScript.Contains("`$currentPackageLeaf = 'KDBG-1.1.0-win-x64'")) `
    'Guest lifecycle must bind the current 1.1.0 package root.'
Assert-True ($guestScript.Contains("`$previousPackageLeaf = 'KDBG-1.0.0-win-x64'")) `
    'Guest lifecycle must retain the previous 1.0.0 package root for rollback.'
Assert-True ($guestScript.Contains('$ExpectedCurrentPackageSha256 $currentPackageLeaf')) `
    'Current archive extraction must validate the 1.1.0 root independently.'
Assert-True ($guestScript.Contains('$ExpectedPreviousPackageSha256 $previousPackageLeaf')) `
    'Previous archive extraction must validate the 1.0.0 root independently.'
Assert-True ($guestScript.Contains('$genericRead = [uint32]2147483648')) `
    'CreateFile GENERIC_READ must be passed as a positive UInt32.'
Assert-True (-not $guestScript.Contains('"\\.\$Name", 0x80000000')) `
    'CreateFile must not receive PowerShell''s negative Int32 0x80000000 literal.'
Assert-True ($guestScript.Contains('New-CanonicalEvidenceArchive $archiveParent $evidenceArchive')) `
    'Guest finalize must emit a canonical forward-slash evidence archive.'
Assert-True (-not $guestScript.Contains('Compress-Archive -Path $archiveParent')) `
    'Guest evidence must not rely on platform-specific Compress-Archive entry separators.'
Assert-True (-not $guestScript.Contains('[IO.Path]::GetRelativePath')) `
    'Guest script must remain compatible with Windows PowerShell 5.1/.NET Framework.'
$tokens = $null
$parseErrors = $null
$guestAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'Invoke-Win11ExtendedGuest.ps1'),
    [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) 'Guest lifecycle script must parse without errors.'
$postInstallFunction = $guestAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-PostInstallReboot'
    }, $true)
Assert-True ($null -ne $postInstallFunction) 'Post-install reboot function is missing.'
$postInstallText = $postInstallFunction.Extent.Text
$demandStartOffset = $postInstallText.IndexOf(
    "Invoke-PackageScript `$currentPackage 'start.ps1'",
    [StringComparison]::Ordinal)
$readinessOffset = $postInstallText.IndexOf(
    'Invoke-Readiness $currentPackage', [StringComparison]::Ordinal)
Assert-True ($demandStartOffset -ge 0) `
    'Post-install reboot validation must explicitly start the demand-start drivers.'
Assert-True ($postInstallText.Contains("'-ConfirmDedicatedVm', '-ConfirmSnapshot'")) `
    'Post-install reboot demand start must retain both dedicated-VM confirmations.'
Assert-True ($readinessOffset -gt $demandStartOffset) `
    'Independent readiness must remain after the explicit post-reboot demand start.'
Assert-True ($postInstallText.Contains('explicit_demand_start = $start')) `
    'Post-install reboot evidence must retain the explicit demand-start record.'

[pscustomobject]@{
    schema = 'kdbg.win11-extended-contract-test.v1'
    success = $true
    checks = $script:Checks
    static_invariants = $static.invariant_count
    live_execution_performed = $false
} | ConvertTo-Json -Depth 5

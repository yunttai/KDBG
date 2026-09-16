[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$OutputPath,
    [Parameter(Mandatory)] [string]$PackageDirectory,
    [Parameter(Mandatory)] [string]$OsBuild,
    [Parameter(Mandatory)] [string]$Pfn,
    [Parameter(Mandatory)] [UInt64]$PhysicalAddress,
    [Parameter(Mandatory)] [string]$BaselinePage,
    [Parameter(Mandatory)] [string]$PreflightPage,
    [Parameter(Mandatory)] [string]$ExpectedAfterPage,
    [Parameter(Mandatory)] [string]$ReadbackPage,
    [Parameter(Mandatory)] [string]$IndependentReloadPage,
    [Parameter(Mandatory)] [string]$RollbackPage,
    [Parameter(Mandatory)] [UInt64]$ProbeGenerationBefore,
    [Parameter(Mandatory)] [UInt64]$ProbeGenerationAfterWrite,
    [Parameter(Mandatory)] [UInt64]$ProbeGenerationAfterRollback,
    [Parameter(Mandatory)] [ValidatePattern('^0x[0-9A-Fa-f]{8}$')] [string]$ProbeCrc32Before,
    [Parameter(Mandatory)] [ValidatePattern('^0x[0-9A-Fa-f]{8}$')] [string]$ProbeCrc32AfterWrite,
    [Parameter(Mandatory)] [ValidatePattern('^0x[0-9A-Fa-f]{8}$')] [string]$ProbeCrc32AfterRollback,
    [Parameter(Mandatory)] [string[]]$DirtyRun,
    [Parameter(Mandatory)] [UInt32]$OwnershipPid,
    [Parameter(Mandatory)] [UInt64]$OwnershipVa,
    [Parameter(Mandatory)] [UInt64]$OwnershipPte,
    [Parameter(Mandatory)] [string]$OwnershipSource,
    [Parameter(Mandatory)] [UInt64]$PageTableVa,
    [Parameter(Mandatory)] [UInt64]$PageTableFinalPa,
    [Parameter(Mandatory)] [string[]]$PageTableLevels,
    [Parameter(Mandatory)] [string]$CommandLog,
    [Parameter(Mandatory)] [string]$Video,
    [switch]$DedicatedVmConfirmed,
    [switch]$SnapshotConfirmed,
    [switch]$ProbeTargetConfirmed,
    [switch]$WriteGateRelocked,
    [switch]$PrivatePathsRedacted,
    [switch]$UnrelatedProcessDataRedacted,
    [switch]$VideoReviewed,
    [switch]$ConfirmRequiredScenes
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PackageDirectory = [IO.Path]::GetFullPath($PackageDirectory)
if ([IO.Path]::GetFileName($PackageDirectory) -ne "KDBG-1.0.0-win-x64") {
    throw "Package directory must be named KDBG-1.0.0-win-x64."
}
foreach ($Confirmation in @(
    $DedicatedVmConfirmed, $SnapshotConfirmed, $ProbeTargetConfirmed,
    $WriteGateRelocked, $PrivatePathsRedacted, $UnrelatedProcessDataRedacted,
    $VideoReviewed, $ConfirmRequiredScenes)) {
    if (-not $Confirmation) {
        throw "All VM, target, relock, redaction, review, and scene confirmations are required."
    }
}

function Get-PageEvidence([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label is missing." }
    if ((Get-Item -LiteralPath $Path).Length -ne 4096) { throw "$Label must be exactly 4096 bytes." }
    return [ordered]@{
        bytes = 4096
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    }
}

$OutputFull = [IO.Path]::GetFullPath($OutputPath)
$EvidenceDirectory = Split-Path -Parent $OutputFull
if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    throw "Evidence output directory does not exist."
}
foreach ($Artifact in @($CommandLog, $Video)) {
    $Full = [IO.Path]::GetFullPath($Artifact)
    if (-not (Test-Path -LiteralPath $Full -PathType Leaf) -or
        (Get-Item -LiteralPath $Full).Length -eq 0) { throw "Evidence artifact is missing or empty." }
    if ((Split-Path -Parent $Full) -ne $EvidenceDirectory) {
        throw "Command log and video must be siblings of the evidence JSON."
    }
}

$PfnBase = if ($Pfn -match '^0x') { 16 } else { 10 }
$PfnValue = [Convert]::ToUInt64(($Pfn -replace '^0x', ''), $PfnBase)
if ($PfnValue -eq 0 -or $PfnValue -gt [UInt64]::MaxValue / 4096) {
    throw "PFN is zero or overflows PFN << 12."
}
if ($PhysicalAddress -ne $PfnValue * 4096) { throw "PhysicalAddress must equal PFN << 12." }

$Baseline = Get-PageEvidence $BaselinePage "BaselinePage"
$Preflight = Get-PageEvidence $PreflightPage "PreflightPage"
$Expected = Get-PageEvidence $ExpectedAfterPage "ExpectedAfterPage"
$Readback = Get-PageEvidence $ReadbackPage "ReadbackPage"
$Reload = Get-PageEvidence $IndependentReloadPage "IndependentReloadPage"
$Rollback = Get-PageEvidence $RollbackPage "RollbackPage"
if ($Preflight.sha256 -ne $Baseline.sha256) { throw "Preflight differs from baseline." }
if ($Readback.sha256 -ne $Expected.sha256) { throw "Read-back differs from expected bytes." }
if ($Reload.sha256 -ne $Expected.sha256) { throw "Independent reload differs from expected bytes." }
if ($Rollback.sha256 -ne $Baseline.sha256) { throw "Rollback differs from baseline bytes." }
if ($ProbeCrc32AfterRollback -ne $ProbeCrc32Before) { throw "Rollback CRC differs from baseline CRC." }

$DirtyRuns = @()
foreach ($Run in $DirtyRun) {
    if ($Run -notmatch '^(0x[0-9A-Fa-f]+|[0-9]+):(0x[0-9A-Fa-f]+|[0-9]+)$') {
        throw "DirtyRun must use offset:length, for example 0x100:4."
    }
    $OffsetText = $Matches[1]
    $LengthText = $Matches[2]
    $OffsetBase = if ($OffsetText.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) { 16 } else { 10 }
    $LengthBase = if ($LengthText.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) { 16 } else { 10 }
    $Offset = [Convert]::ToUInt32(($OffsetText -replace '^0x', ''), $OffsetBase)
    $Length = [Convert]::ToUInt32(($LengthText -replace '^0x', ''), $LengthBase)
    if ($Length -eq 0 -or $Offset + $Length -gt 4096) { throw "DirtyRun is outside the page." }
    $DirtyRuns += [ordered]@{ offset = [int]$Offset; length = [int]$Length }
}

$ArtifactHashes = [ordered]@{}
foreach ($Relative in @(
    "KDBG.exe", "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
    "drivers/KDbgDriver.sys", "drivers/KDbgProbe.sys")) {
    $Artifact = Join-Path $PackageDirectory $Relative
    if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) { throw "Package artifact missing: $Relative" }
    $ArtifactHashes[$Relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $Artifact).Hash.ToLowerInvariant()
}

$Scenes = @(
    "driver_probe_ready", "probe_pfn_discovery", "physical_read_4096",
    "hex_edit_and_diff", "undo_redo", "typed_pfn_unlock",
    "write_and_readback", "independent_reload", "rollback_baseline",
    "pfn_owner_pid_va_pte", "page_table_walk", "process_first_next_scan",
    "address_list_verified_freeze", "pointer_scan", "zydis_disassembly",
    "snapshot_diff", "about_version"
)
$Evidence = [ordered]@{
    schema = "kdbg.live-evidence.v2"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    os_build = $OsBuild
    package_version = "1.0.0"
    abi_version = 6
    pfn = "0x$($PfnValue.ToString('x'))"
    physical_address = "0x$($PhysicalAddress.ToString('x'))"
    page_size = 4096
    artifact_sha256 = $ArtifactHashes
    baseline_bytes = 4096; preflight_bytes = 4096; readback_bytes = 4096
    reload_bytes = 4096; rollback_bytes = 4096
    baseline_sha256 = $Baseline.sha256
    expected_after_sha256 = $Expected.sha256
    readback_sha256 = $Readback.sha256
    independent_reload_sha256 = $Reload.sha256
    rollback_sha256 = $Rollback.sha256
    probe_generation_before = $ProbeGenerationBefore
    probe_generation_after_write = $ProbeGenerationAfterWrite
    probe_generation_after_rollback = $ProbeGenerationAfterRollback
    probe_crc32_before = $ProbeCrc32Before.ToLowerInvariant()
    probe_crc32_after_write = $ProbeCrc32AfterWrite.ToLowerInvariant()
    probe_crc32_after_rollback = $ProbeCrc32AfterRollback.ToLowerInvariant()
    dirty_runs = $DirtyRuns
    dedicated_vm_confirmed = $true; snapshot_confirmed = $true
    probe_target_confirmed = $true; preflight_match = $true
    write_gate_relocked = $true; full_readback_match = $true
    independent_reload_match = $true; rollback_match = $true
    ownership_evidence = [ordered]@{
        pfn = "0x$($PfnValue.ToString('x'))"; pid = $OwnershipPid
        va = "0x$($OwnershipVa.ToString('x'))"; pte = "0x$($OwnershipPte.ToString('x'))"
        source = $OwnershipSource
    }
    page_table_evidence = [ordered]@{
        va = "0x$($PageTableVa.ToString('x'))"
        final_pa = "0x$($PageTableFinalPa.ToString('x'))"
        final_pfn = "0x$($PfnValue.ToString('x'))"; levels = $PageTableLevels
    }
    command_log_file = [IO.Path]::GetFileName($CommandLog)
    command_log_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $CommandLog).Hash.ToLowerInvariant()
    video_file = [IO.Path]::GetFileName($Video)
    video_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Video).Hash.ToLowerInvariant()
    demo_scenes = $Scenes
    private_paths_redacted = $true
    unrelated_process_data_redacted = $true
    video_reviewed = $true
}
$Evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutputFull -Encoding utf8
& python (Join-Path $PSScriptRoot "validate_release.py") --windows-package $PackageDirectory --live-evidence $OutputFull
if ($LASTEXITCODE -ne 0) { throw "Generated live evidence did not validate." }
Write-Host "Validated live evidence: $([IO.Path]::GetFileName($OutputFull))"

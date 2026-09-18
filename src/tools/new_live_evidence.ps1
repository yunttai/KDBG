[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$OutputPath,
    [Parameter(Mandatory)] [string]$PackageDirectory,
    [Parameter(Mandatory)] [string]$SymbolsDirectory,
    [Parameter(Mandatory)] [string]$GuiMetadata,
    [Parameter(Mandatory)] [string]$AnalysisMetadata,
    [Parameter(Mandatory)] [string]$CommandLog,
    [Parameter(Mandatory)] [string]$Video,
    [Parameter(Mandatory)] [string]$SceneReview,
    [Parameter(Mandatory)] [string]$LiveRunReport,
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
$SymbolsDirectory = [IO.Path]::GetFullPath($SymbolsDirectory)
if ([IO.Path]::GetFileName($PackageDirectory) -ne "KDBG-1.1.0-win-x64") {
    throw "Package directory must be named KDBG-1.1.0-win-x64."
}
if ([IO.Path]::GetFileName($SymbolsDirectory) -ne "KDBG-1.1.0-win-x64-symbols") {
    throw "Symbols directory must be named KDBG-1.1.0-win-x64-symbols."
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
$PackagePrefix = $PackageDirectory.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
$SymbolsPrefix = $SymbolsDirectory.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if ($OutputFull.Equals($PackageDirectory, [StringComparison]::OrdinalIgnoreCase) -or
    $OutputFull.Equals($SymbolsDirectory, [StringComparison]::OrdinalIgnoreCase) -or
    $OutputFull.StartsWith($PackagePrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $OutputFull.StartsWith($SymbolsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Evidence output must remain outside the immutable main and symbols packages."
}

function Convert-EvidenceUInt64([object]$Value, [string]$Label) {
    $Text = [string]$Value
    try {
        if ($Text -match '^0x[0-9a-fA-F]+$') {
            return [Convert]::ToUInt64($Text.Substring(2), 16)
        }
        return [Convert]::ToUInt64($Text, 10)
    } catch {
        throw "$Label must be an unsigned integer or 0x-prefixed hexadecimal integer."
    }
}
$EvidenceDirectory = Split-Path -Parent $OutputFull
if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    throw "Evidence output directory does not exist."
}
$GuiMetadataFull = [IO.Path]::GetFullPath($GuiMetadata)
if (-not (Test-Path -LiteralPath $GuiMetadataFull -PathType Leaf) -or
    (Split-Path -Parent $GuiMetadataFull) -ne $EvidenceDirectory) {
    throw "GuiMetadata must be a sibling file in the evidence output directory."
}
$Gui = Get-Content -LiteralPath $GuiMetadataFull -Raw | ConvertFrom-Json
if ($Gui.schema -ne "kdbg-physical-live-evidence-v1" -or
    [UInt32]$Gui.page_size -ne 4096 -or
    [UInt32]$Gui.driver_abi_version -ne 6 -or
    [UInt32]$Gui.edit_offset -ne 0x100 -or
    [UInt32]$Gui.edit_length -ne 8 -or
    [string]$Gui.edit_xor_mask -cne "4b444247a55a3cc3" -or
    $Gui.dirty_runs.Count -ne 1 -or
    [UInt32]$Gui.dirty_runs[0].offset -ne 0x100 -or
    [UInt32]$Gui.dirty_runs[0].length -ne 8 -or
    $Gui.write_gate_relocked -ne $true -or $Gui.preflight_match -ne $true -or
    $Gui.full_readback_match -ne $true -or
    $Gui.independent_reload_match -ne $true -or $Gui.rollback_match -ne $true) {
    throw "GuiMetadata does not prove the exact locked v4 Probe transaction."
}
$AnalysisMetadataFull = [IO.Path]::GetFullPath($AnalysisMetadata)
if (-not (Test-Path -LiteralPath $AnalysisMetadataFull -PathType Leaf) -or
    (Split-Path -Parent $AnalysisMetadataFull) -ne $EvidenceDirectory) {
    throw "AnalysisMetadata must be a sibling file in the evidence output directory."
}
$Analysis = Get-Content -LiteralPath $AnalysisMetadataFull -Raw | ConvertFrom-Json
if ($Analysis.schema -ne "kdbg-analysis-live-evidence-v1") {
    throw "AnalysisMetadata schema must be kdbg-analysis-live-evidence-v1."
}
function Resolve-GuiPage([string]$Name, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Name) -or
        [IO.Path]::GetFileName($Name) -cne $Name) {
        throw "GuiMetadata $Label page path must be a safe sibling filename."
    }
    $Resolved = Join-Path $EvidenceDirectory $Name
    if (-not (Test-Path -LiteralPath $Resolved -PathType Leaf)) {
        throw "GuiMetadata $Label page is missing."
    }
    return $Resolved
}
$BaselinePage = Resolve-GuiPage ([string]$Gui.page_files.baseline) "baseline"
$PreflightPage = Resolve-GuiPage ([string]$Gui.page_files.preflight) "preflight"
$ExpectedAfterPage = Resolve-GuiPage ([string]$Gui.page_files.expected_after) "expected_after"
$ReadbackPage = Resolve-GuiPage ([string]$Gui.page_files.readback) "readback"
$IndependentReloadPage = Resolve-GuiPage ([string]$Gui.page_files.independent_reload) "independent_reload"
$RollbackPage = Resolve-GuiPage ([string]$Gui.page_files.rollback) "rollback"
$Pfn = [string]$Gui.pfn
$PfnBase = if ($Pfn -match '^0x') { 16 } else { 10 }
$PfnValue = [Convert]::ToUInt64(($Pfn -replace '^0x', ''), $PfnBase)
$PhysicalText = [string]$Gui.physical_address
$PhysicalBase = if ($PhysicalText -match '^0x') { 16 } else { 10 }
$PhysicalAddress = [Convert]::ToUInt64(($PhysicalText -replace '^0x', ''), $PhysicalBase)
if ($PfnValue -eq 0 -or $PfnValue -gt [UInt64]::MaxValue / 4096) {
    throw "GuiMetadata PFN is zero or overflows PFN << 12."
}
if ($PhysicalAddress -ne $PfnValue * 4096) {
    throw "GuiMetadata physical address must equal PFN << 12."
}
$ProbeGenerationBefore = [UInt64]$Gui.probe.baseline.generation
$ProbeGenerationAfterWrite = [UInt64]$Gui.probe.after_write.generation
$ProbeGenerationAfterRollback = [UInt64]$Gui.probe.after_rollback.generation
$ProbeCrc32Before = ([string]$Gui.probe.baseline.crc32).ToLowerInvariant()
$ProbeCrc32AfterWrite = ([string]$Gui.probe.after_write.crc32).ToLowerInvariant()
$ProbeCrc32AfterRollback = ([string]$Gui.probe.after_rollback.crc32).ToLowerInvariant()
foreach ($Crc in @($ProbeCrc32Before, $ProbeCrc32AfterWrite, $ProbeCrc32AfterRollback)) {
    if ($Crc -notmatch '^0x[0-9a-f]{8}$') { throw "GuiMetadata Probe CRC32 is invalid." }
}
$SeenArtifacts = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($Artifact in @(
    $BaselinePage, $PreflightPage, $ExpectedAfterPage, $ReadbackPage,
    $IndependentReloadPage, $RollbackPage, $GuiMetadataFull, $AnalysisMetadataFull,
    $CommandLog, $Video,
    $SceneReview, $LiveRunReport)) {
    $Full = [IO.Path]::GetFullPath($Artifact)
    if ($Full -eq $OutputFull) { throw "Evidence output cannot replace an input artifact." }
    if (-not $SeenArtifacts.Add($Full)) { throw "Evidence input artifacts must be distinct files." }
    if (-not (Test-Path -LiteralPath $Full -PathType Leaf) -or
        (Get-Item -LiteralPath $Full).Length -eq 0) { throw "Evidence artifact is missing or empty." }
    if ((Split-Path -Parent $Full) -ne $EvidenceDirectory) {
        throw "Raw pages, command log, video, and live run report must be siblings of the evidence JSON."
    }
}

$LiveRun = Get-Content -LiteralPath $LiveRunReport -Raw | ConvertFrom-Json
if ($LiveRun.schema -ne "kdbg.live-verify.v1" -or
    $LiveRun.mode -ne "probe-write-rollback" -or
    $LiveRun.success -ne $true -or
    $LiveRun.cancelled -ne $false -or
    $LiveRun.write_cleanup.rollback_verified -ne $true -or
    $LiveRun.write_cleanup.final_gate_locked -ne $true) {
    throw "LiveRunReport is not a successful Probe write/read-back/rollback run."
}
if ([UInt64]$LiveRun.probe_before.pfn -ne $PfnValue) {
    throw "LiveRunReport Probe PFN does not match the evidence PFN."
}
$ProbeBindings = @(
    @("probe_before", $ProbeGenerationBefore, $ProbeCrc32Before),
    @("probe_after_write", $ProbeGenerationAfterWrite, $ProbeCrc32AfterWrite),
    @("probe_after_rollback", $ProbeGenerationAfterRollback, $ProbeCrc32AfterRollback)
)
foreach ($Binding in $ProbeBindings) {
    $ProbeRecord = $LiveRun.($Binding[0])
    $CrcValue = [Convert]::ToUInt32(([string]$Binding[2]).Substring(2), 16)
    if ([UInt64]$ProbeRecord.pfn -ne $PfnValue -or
        [UInt64]$ProbeRecord.physical_address -ne $PhysicalAddress -or
        [UInt64]$ProbeRecord.generation -ne [UInt64]$Binding[1] -or
        [UInt32]$ProbeRecord.crc32 -ne $CrcValue) {
        throw "LiveRunReport Probe PFN/PA/generation/CRC does not match the evidence input."
    }
}
$OsBuild = [UInt32]$LiveRun.system.os_build
if ($OsBuild -lt 19041) {
    throw "LiveRunReport requires Windows build 19041 or newer."
}
[UInt64]$GuiProbeVa = 0
foreach ($GuiProbeName in @("baseline", "after_write", "after_reload", "after_rollback")) {
    $GuiProbe = $Gui.probe.$GuiProbeName
    $GuiPfnText = [string]$GuiProbe.pfn
    $GuiPfnBase = if ($GuiPfnText -match '^0x') { 16 } else { 10 }
    $GuiPfn = [Convert]::ToUInt64(($GuiPfnText -replace '^0x', ''), $GuiPfnBase)
    $GuiPaText = [string]$GuiProbe.physical_address
    $GuiPaBase = if ($GuiPaText -match '^0x') { 16 } else { 10 }
    $GuiPa = [Convert]::ToUInt64(($GuiPaText -replace '^0x', ''), $GuiPaBase)
    $GuiVaText = [string]$GuiProbe.virtual_address
    $GuiVaBase = if ($GuiVaText -match '^0x') { 16 } else { 10 }
    $GuiVa = [Convert]::ToUInt64(($GuiVaText -replace '^0x', ''), $GuiVaBase)
    if ($GuiProbeName -eq "baseline") { $GuiProbeVa = $GuiVa }
    if ([UInt32]$GuiProbe.byte_count -ne 4096 -or $GuiPfn -ne $PfnValue -or
        $GuiPa -ne $PhysicalAddress -or $GuiVa -ne $GuiProbeVa) {
        throw "GuiMetadata Probe PFN/PA/VA/byte count is inconsistent."
    }
}
if ([UInt64]$Gui.probe.after_reload.generation -ne $ProbeGenerationAfterWrite -or
    ([string]$Gui.probe.after_reload.crc32).ToLowerInvariant() -ne $ProbeCrc32AfterWrite) {
    throw "GuiMetadata after-reload Probe generation/CRC does not match after-write."
}
if ([UInt64]$LiveRun.probe_before.virtual_address -ne $GuiProbeVa -or
    [UInt64]$LiveRun.probe_after_write.virtual_address -ne $GuiProbeVa -or
    [UInt64]$LiveRun.probe_after_rollback.virtual_address -ne $GuiProbeVa) {
    throw "GUI and live-run metadata do not share a stable Probe virtual address."
}
$AnalysisPfn = Convert-EvidenceUInt64 $Analysis.ownership.pfn "Analysis ownership PFN"
$AnalysisVa = Convert-EvidenceUInt64 $Analysis.ownership.virtual_address "Analysis ownership VA"
if ($AnalysisPfn -eq $PfnValue -or $AnalysisVa -eq $GuiProbeVa) {
    throw "Analysis ownership target must be distinct from the Probe transaction."
}
$EditOffset = [UInt64]$LiveRun.write_cleanup.edit_offset
$EditLength = [UInt64]$LiveRun.write_cleanup.edit_length
if ($EditOffset -ne 0x100 -or $EditLength -ne 8 -or
    $EditOffset + $EditLength -gt 4096) {
    throw "LiveRunReport does not bind the expected 8-byte Probe edit at offset 0x100."
}

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
[byte[]]$BaselineRaw = [IO.File]::ReadAllBytes($BaselinePage)
[byte[]]$ExpectedRaw = [IO.File]::ReadAllBytes($ExpectedAfterPage)
[byte[]]$EditMask = @(0x4B, 0x44, 0x42, 0x47, 0xA5, 0x5A, 0x3C, 0xC3)
for ($Index = 0; $Index -lt 4096; $Index++) {
    $ExpectedByte = if ($Index -ge 0x100 -and $Index -lt 0x108) {
        $BaselineRaw[$Index] -bxor $EditMask[$Index - 0x100]
    } else {
        $BaselineRaw[$Index]
    }
    if ($ExpectedRaw[$Index] -ne $ExpectedByte) {
        throw "ExpectedAfterPage does not contain the exact Probe 8-byte XOR pattern."
    }
}
$DirtyRuns = @([ordered]@{
    offset = [int]$EditOffset
    length = [int]$EditLength
})

$ArtifactHashes = [ordered]@{}
foreach ($Relative in @(
    "KDBG.exe", "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
    "tools/kdbg_live_verify.exe", "tools/kdbg_process_fixture.exe",
    "drivers/KDbgDriver.sys", "drivers/KDbgProbe.sys")) {
    $Artifact = Join-Path $PackageDirectory $Relative
    if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) { throw "Package artifact missing: $Relative" }
    $ArtifactHashes[$Relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $Artifact).Hash.ToLowerInvariant()
}
$SymbolHashes = [ordered]@{}
foreach ($Relative in @(
    "KDBG.pdb", "KDBGSetup.pdb",
    "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.pdb",
    "tools/kdbg_live_verify.pdb", "tools/kdbg_process_fixture.pdb",
    "drivers/KDbgDriver.pdb",
    "drivers/KDbgProbe.pdb")) {
    $Artifact = Join-Path $SymbolsDirectory $Relative
    if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) { throw "Symbols artifact missing: $Relative" }
    $SymbolHashes[$Relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $Artifact).Hash.ToLowerInvariant()
}
$PackageManifest = Join-Path $PackageDirectory "SHA256SUMS.txt"
$SymbolsManifest = Join-Path $SymbolsDirectory "SHA256SUMS.txt"
foreach ($Manifest in @($PackageManifest, $SymbolsManifest)) {
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf) -or
        (Get-Item -LiteralPath $Manifest).Length -eq 0) {
        throw "Validated package manifest is missing or empty."
    }
}

function Get-GifMetadata([string]$Path) {
    [byte[]]$Bytes = [IO.File]::ReadAllBytes($Path)
    if ($Bytes.Length -lt 14) { throw "Video is not a complete GIF container." }
    $Signature = [Text.Encoding]::ASCII.GetString($Bytes, 0, 6)
    if ($Signature -notin @("GIF87a", "GIF89a")) { throw "Video must be GIF87a or GIF89a." }
    $Width = [BitConverter]::ToUInt16($Bytes, 6)
    $Height = [BitConverter]::ToUInt16($Bytes, 8)
    if ($Width -lt 320 -or $Height -lt 180 -or $Width -gt 7680 -or $Height -gt 4320) {
        throw "GIF logical dimensions must be between 320x180 and 7680x4320."
    }
    [int]$Cursor = 13
    if (($Bytes[10] -band 0x80) -ne 0) {
        $Cursor += 3 * (1 -shl (($Bytes[10] -band 0x07) + 1))
    }
    if ($Cursor -gt $Bytes.Length) { throw "GIF global color table is truncated." }
    [int]$Frames = 0
    [UInt64]$DurationMs = 0
    [UInt64]$PendingDelayMs = 0
    $SawTrailer = $false
    while ($Cursor -lt $Bytes.Length) {
        $Marker = $Bytes[$Cursor++]
        if ($Marker -eq 0x3B) {
            if ($Cursor -ne $Bytes.Length) { throw "GIF has bytes after its trailer." }
            $SawTrailer = $true
            break
        }
        if ($Marker -eq 0x21) {
            if ($Cursor -ge $Bytes.Length) { throw "GIF extension label is truncated." }
            $Label = $Bytes[$Cursor++]
            if ($Label -eq 0xF9) {
                if ($Cursor + 6 -gt $Bytes.Length -or
                    $Bytes[$Cursor] -ne 4 -or $Bytes[$Cursor + 5] -ne 0) {
                    throw "GIF graphic control extension is malformed."
                }
                $PendingDelayMs = [UInt64][BitConverter]::ToUInt16($Bytes, $Cursor + 2) * 10
                $Cursor += 6
            } else {
                while ($true) {
                    if ($Cursor -ge $Bytes.Length) { throw "GIF extension is unterminated." }
                    $Size = [int]$Bytes[$Cursor++]
                    if ($Size -eq 0) { break }
                    if ($Cursor + $Size -gt $Bytes.Length) { throw "GIF extension is truncated." }
                    $Cursor += $Size
                }
            }
            continue
        }
        if ($Marker -ne 0x2C) { throw "GIF contains an unexpected block marker." }
        if ($Cursor + 9 -gt $Bytes.Length) { throw "GIF image descriptor is truncated." }
        $Left = [BitConverter]::ToUInt16($Bytes, $Cursor)
        $Top = [BitConverter]::ToUInt16($Bytes, $Cursor + 2)
        $FrameWidth = [BitConverter]::ToUInt16($Bytes, $Cursor + 4)
        $FrameHeight = [BitConverter]::ToUInt16($Bytes, $Cursor + 6)
        $ImagePacked = $Bytes[$Cursor + 8]
        $Cursor += 9
        if ($FrameWidth -eq 0 -or $FrameHeight -eq 0 -or
            $Left + $FrameWidth -gt $Width -or $Top + $FrameHeight -gt $Height) {
            throw "GIF frame rectangle is empty or outside the logical screen."
        }
        if (($ImagePacked -band 0x80) -ne 0) {
            $Cursor += 3 * (1 -shl (($ImagePacked -band 0x07) + 1))
        }
        if ($Cursor -ge $Bytes.Length) { throw "GIF image data is truncated." }
        $CodeSize = $Bytes[$Cursor++]
        if ($CodeSize -lt 2 -or $CodeSize -gt 8) { throw "GIF LZW code size is invalid." }
        [int]$PayloadBytes = 0
        while ($true) {
            if ($Cursor -ge $Bytes.Length) { throw "GIF image data is unterminated." }
            $Size = [int]$Bytes[$Cursor++]
            if ($Size -eq 0) { break }
            if ($Cursor + $Size -gt $Bytes.Length) { throw "GIF image data is truncated." }
            $PayloadBytes += $Size
            $Cursor += $Size
        }
        if ($PayloadBytes -eq 0) { throw "GIF frame has no compressed data." }
        $Frames++
        if ($Frames -gt 100000) { throw "GIF has too many frames." }
        $DurationMs += $PendingDelayMs
        $PendingDelayMs = 0
        if ($DurationMs -gt 28800000) { throw "GIF duration exceeds eight hours." }
    }
    if (-not $SawTrailer) { throw "GIF trailer is missing." }
    if ($Frames -lt 2) { throw "GIF must contain at least two frames." }
    if ($DurationMs -lt 1000) { throw "GIF duration must be at least one second." }
    return [ordered]@{
        format = "gif"; width = [int]$Width; height = [int]$Height
        frame_count = $Frames; duration_ms = [UInt64]$DurationMs
    }
}

$VideoMedia = Get-GifMetadata $Video

$Scenes = @(
    "driver_probe_ready", "probe_pfn_discovery", "physical_read_4096",
    "hex_edit_and_diff", "undo_redo", "typed_pfn_unlock",
    "write_and_readback", "independent_reload", "rollback_baseline",
    "pfn_owner_pid_va_pte", "page_table_walk", "process_first_next_scan",
    "address_list_verified_freeze", "pointer_scan", "zydis_disassembly",
    "snapshot_diff", "kernel_module_catalog", "kernel_symbol_resolution",
    "kernel_read_disassembly", "about_version"
)
$Evidence = [ordered]@{
    schema = "kdbg.live-evidence.v4"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    os_build = $OsBuild
    package_version = "1.1.0"
    abi_version = 6
    pfn = "0x$($PfnValue.ToString('x'))"
    physical_address = "0x$($PhysicalAddress.ToString('x'))"
    page_size = 4096
    artifact_sha256 = $ArtifactHashes
    symbol_sha256 = $SymbolHashes
    package_manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PackageManifest).Hash.ToLowerInvariant()
    symbols_manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SymbolsManifest).Hash.ToLowerInvariant()
    baseline_bytes = 4096; preflight_bytes = 4096; readback_bytes = 4096
    reload_bytes = 4096; rollback_bytes = 4096
    baseline_sha256 = $Baseline.sha256
    expected_after_sha256 = $Expected.sha256
    readback_sha256 = $Readback.sha256
    independent_reload_sha256 = $Reload.sha256
    rollback_sha256 = $Rollback.sha256
    baseline_file = [IO.Path]::GetFileName($BaselinePage)
    preflight_file = [IO.Path]::GetFileName($PreflightPage)
    expected_after_file = [IO.Path]::GetFileName($ExpectedAfterPage)
    readback_file = [IO.Path]::GetFileName($ReadbackPage)
    independent_reload_file = [IO.Path]::GetFileName($IndependentReloadPage)
    rollback_file = [IO.Path]::GetFileName($RollbackPage)
    probe_generation_before = $ProbeGenerationBefore
    probe_generation_after_write = $ProbeGenerationAfterWrite
    probe_generation_after_rollback = $ProbeGenerationAfterRollback
    probe_crc32_before = $ProbeCrc32Before.ToLowerInvariant()
    probe_crc32_after_write = $ProbeCrc32AfterWrite.ToLowerInvariant()
    probe_crc32_after_rollback = $ProbeCrc32AfterRollback.ToLowerInvariant()
    edit_xor_mask = "4b444247a55a3cc3"
    dirty_runs = $DirtyRuns
    dedicated_vm_confirmed = $true; snapshot_confirmed = $true
    probe_target_confirmed = $true; preflight_match = $true
    write_gate_relocked = $true; full_readback_match = $true
    independent_reload_match = $true; rollback_match = $true
    gui_metadata_file = [IO.Path]::GetFileName($GuiMetadataFull)
    gui_metadata_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $GuiMetadataFull).Hash.ToLowerInvariant()
    analysis_metadata_file = [IO.Path]::GetFileName($AnalysisMetadataFull)
    analysis_metadata_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $AnalysisMetadataFull).Hash.ToLowerInvariant()
    command_log_file = [IO.Path]::GetFileName($CommandLog)
    command_log_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $CommandLog).Hash.ToLowerInvariant()
    video_file = [IO.Path]::GetFileName($Video)
    video_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Video).Hash.ToLowerInvariant()
    video_media = $VideoMedia
    scene_review_file = [IO.Path]::GetFileName($SceneReview)
    scene_review_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SceneReview).Hash.ToLowerInvariant()
    live_run_report_file = [IO.Path]::GetFileName($LiveRunReport)
    live_run_report_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $LiveRunReport).Hash.ToLowerInvariant()
    demo_scenes = $Scenes
    private_paths_redacted = $true
    unrelated_process_data_redacted = $true
    video_reviewed = $true
}
$TemporaryOutput = Join-Path $EvidenceDirectory (
    ".{0}.{1}.tmp" -f [IO.Path]::GetFileName($OutputFull), [Guid]::NewGuid().ToString("N"))
try {
    $Json = ($Evidence | ConvertTo-Json -Depth 12) + [Environment]::NewLine
    $Bytes = ([Text.UTF8Encoding]::new($false)).GetBytes($Json)
    $Stream = [IO.FileStream]::new(
        $TemporaryOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
    try {
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    } finally {
        $Stream.Dispose()
    }

    & python (Join-Path $PSScriptRoot "validate_release.py") `
        --windows-package $PackageDirectory `
        --symbols-package $SymbolsDirectory `
        --live-run-report $LiveRunReport `
        --live-evidence $TemporaryOutput
    if ($LASTEXITCODE -ne 0) { throw "Generated live evidence did not validate." }

    if (Test-Path -LiteralPath $OutputFull -PathType Leaf) {
        [IO.File]::Replace($TemporaryOutput, $OutputFull, $null, $true)
    } else {
        [IO.File]::Move($TemporaryOutput, $OutputFull)
    }
} finally {
    if (Test-Path -LiteralPath $TemporaryOutput -PathType Leaf) {
        Remove-Item -LiteralPath $TemporaryOutput -Force
    }
}
Write-Host "Validated live evidence: $([IO.Path]::GetFileName($OutputFull))"

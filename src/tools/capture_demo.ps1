[CmdletBinding()]
param(
    [string]$Executable,

    [Parameter(Mandatory)]
    [string]$SceneReviewTemplate,

    [Parameter(Mandatory)]
    [string]$Reviewer,

    [switch]$ConfirmDedicatedVm,

    [switch]$ConfirmSnapshot,

    [switch]$ConfirmFixtureReset,

    [switch]$TemplateOnly,

    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $ConfirmDedicatedVm -or
    -not $ConfirmSnapshot -or
    -not $ConfirmFixtureReset) {
    throw "Dedicated VM, snapshot, and fixture reset confirmations are required."
}

if ([string]::IsNullOrWhiteSpace($Executable) -or
    -not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw "Provide a valid release executable path."
}
if ([string]::IsNullOrWhiteSpace($Reviewer) -or $Reviewer.Length -lt 2 -or
    $Reviewer -match '(?i)(?:<|replace|placeholder|unknown|fixture|todo)') {
    throw "Provide the real human reviewer name or handle."
}

$ExecutableFull = [IO.Path]::GetFullPath($Executable)
$PackageRoot = Split-Path -Parent $ExecutableFull
$ReviewFull = [IO.Path]::GetFullPath($SceneReviewTemplate)
$ReviewParent = Split-Path -Parent $ReviewFull
if (-not (Test-Path -LiteralPath $ReviewParent -PathType Container)) {
    throw "The scene-review output directory must already exist."
}
$PackagePrefix = $PackageRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if ($ReviewFull.StartsWith($PackagePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Scene review must be written outside the immutable package directory."
}
if ((Test-Path -LiteralPath $ReviewFull) -and -not $Force) {
    throw "Scene review template already exists; use -Force only after preserving the reviewed copy."
}

$SceneIds = @(
    "driver_probe_ready", "probe_pfn_discovery", "physical_read_4096",
    "hex_edit_and_diff", "undo_redo", "typed_pfn_unlock",
    "write_and_readback", "independent_reload", "rollback_baseline",
    "pfn_owner_pid_va_pte", "page_table_walk", "process_first_next_scan",
    "address_list_verified_freeze", "pointer_scan", "zydis_disassembly",
    "snapshot_diff", "kernel_module_catalog", "kernel_symbol_resolution",
    "kernel_read_disassembly", "about_version"
)
$Review = [ordered]@{
    schema = "kdbg.demo-scene-review.v1"
    video_file = "<replace-with-sibling-gif-name>"
    video_sha256 = "<replace-with-lowercase-sha256>"
    reviewer = $Reviewer
    reviewed_utc = "<replace-with-UTC-timestamp>"
    private_paths_redacted = $false
    unrelated_process_data_redacted = $false
    scenes = @($SceneIds | ForEach-Object {
        [ordered]@{
            id = $_
            start_ms = $null
            end_ms = $null
            observed = $false
            notes = ""
        }
    })
}
$Temporary = Join-Path $ReviewParent (
    ".{0}.{1}.tmp" -f [IO.Path]::GetFileName($ReviewFull),
    [Guid]::NewGuid().ToString("N"))
try {
    $Review | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $Temporary -Encoding utf8
    Move-Item -LiteralPath $Temporary -Destination $ReviewFull -Force:$Force
} finally {
    if (Test-Path -LiteralPath $Temporary -PathType Leaf) {
        Remove-Item -LiteralPath $Temporary -Force
    }
}

Write-Host "Recording checklist and review identifiers:"
for ($Index = 0; $Index -lt $SceneIds.Count; ++$Index) {
    Write-Host ("{0,2}. {1}" -f ($Index + 1), $SceneIds[$Index])
}
Write-Host "Scene review template: $ReviewFull"
Write-Host "After recording, fill non-overlapping ordered ranges of at least 500 ms, observed=true, concrete notes, video name/hash, UTC review time, and both redaction confirmations. The GIF must have at least 20 frames and 20 seconds."

if ($TemplateOnly) {
    Write-Host "Template-only mode: KDBG was not launched."
    return
}
Start-Process -FilePath $ExecutableFull -Verb RunAs

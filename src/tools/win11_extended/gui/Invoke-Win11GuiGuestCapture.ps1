[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunRoot,
    [Parameter(Mandatory = $true)][ValidateSet('calibration-smoke','full')][string]$CaptureMode,
    [string]$InteractiveUser = 'kdbgtest'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 24) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}
function Convert-HexUInt64([string]$Value) {
    if ($Value -notmatch '^0x[0-9A-Fa-f]+$') { throw "Invalid hexadecimal address: $Value" }
    [Convert]::ToUInt64($Value.Substring(2),16)
}
function Invoke-FixtureCommand([string]$PipePath, [string]$Command) {
    $prefix = '\\.\pipe\'
    if (-not $PipePath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Fixture pipe path is invalid.'
    }
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $PipePath.Substring($prefix.Length),
        [IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::None)
    try {
        $pipe.Connect(5000)
        $encoding = [Text.UTF8Encoding]::new($false)
        $writer = [IO.StreamWriter]::new($pipe,$encoding,1024,$true)
        $reader = [IO.StreamReader]::new($pipe,$encoding,$false,1024,$true)
        try {
            $writer.NewLine = "`n"
            $writer.WriteLine($Command)
            $writer.Flush()
            $line = $reader.ReadLine()
        } finally { $writer.Dispose(); $reader.Dispose() }
    } finally { $pipe.Dispose() }
    if ([string]::IsNullOrWhiteSpace($line)) { throw "Fixture command returned no response: $Command" }
    $response = $line | ConvertFrom-Json
    if ($response.ok -ne $true) { throw "Fixture command failed: $Command" }
    $response
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Guest capture orchestration requires Administrator.'
}
$resolvedRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$evidenceRoot = Join-Path $resolvedRoot 'evidence'
$preparedPath = Join-Path $resolvedRoot 'guest-prepared.json'
$fixturePath = Join-Path $evidenceRoot 'fixture-info.json'
$bootstrapPath = Join-Path $evidenceRoot 'interactive-bootstrap.json'
foreach ($path in @($preparedPath,$fixturePath,$bootstrapPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing guest capture input: $path" }
}
$prepared = Get-Content -LiteralPath $preparedPath -Raw -Encoding UTF8 | ConvertFrom-Json
$fixture = Get-Content -LiteralPath $fixturePath -Raw -Encoding UTF8 | ConvertFrom-Json
$bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($prepared.success -ne $true -or $bootstrap.success -ne $true -or
    [string]$fixture.schema -cne 'kdbg.process-fixture.v1' -or $fixture.ok -ne $true) {
    throw 'Guest prepared/bootstrap/fixture identity is invalid.'
}
if ($null -eq (Get-Process -Id ([uint32]$fixture.pid) -ErrorAction SilentlyContinue)) {
    throw 'Fresh process fixture is no longer running.'
}

$freezeOffset = [string]$fixture.corpus.freeze_value
$snapshotOffset = [string]$fixture.corpus.aob
$freezeCrc = [string]$fixture.baseline_crc32
if ($CaptureMode -ceq 'full') {
    $freezeMutation = Invoke-FixtureCommand ([string]$fixture.pipe_name) "MUTATE $freezeOffset 78563412"
    $freezeCrc = [string]$freezeMutation.current_crc32
    $restoreMutation = Invoke-FixtureCommand ([string]$fixture.pipe_name) "MUTATE $freezeOffset E0AC6824"
    if ([string]$restoreMutation.current_crc32 -ine [string]$fixture.baseline_crc32) {
        throw 'Fixture baseline restoration failed before GUI capture.'
    }
}
$fixtureVa = Convert-HexUInt64 ([string]$fixture.virtual_address)
$pointerTarget = $fixtureVa + [uint64]$fixture.corpus.pointer_target
$codeAddress = $fixtureVa + [uint64]$fixture.corpus.x64_code

$parameters = @{
    PackageRoot=[string]$prepared.package_root
    EvidenceRoot=$evidenceRoot
    ProbePfn=[uint64]$prepared.probe_pfn
    FixturePid=[uint32]$fixture.pid
    FixtureVirtualAddress=$fixtureVa
    FixturePointerTarget=$pointerTarget
    FixtureCodeAddress=$codeAddress
    FixtureScanValue='610839776'
    FixturePipeName=[string]$fixture.pipe_name
    FixtureScanOffset=$freezeOffset
    FixtureSnapshotOffset=$snapshotOffset
    FixtureBaselineCrc32=[string]$fixture.baseline_crc32
    FixtureFreezeExpectedCrc32=$freezeCrc
    KernelPdbPath=[string]$prepared.driver_pdb_path
    InteractiveUser=$InteractiveUser
    PlanPath=(Join-Path $resolvedRoot 'capture-plan.json')
    CalibrationPath=(Join-Path $resolvedRoot 'calibration.win11-1024x768-v1.json')
    ConfirmDedicatedVm=$true
    ConfirmSnapshot=$true
}
if ($CaptureMode -ceq 'calibration-smoke') { $parameters.CalibrationSmoke = $true }
& (Join-Path $resolvedRoot 'guest-run.ps1') @parameters | Out-Null

$captureResultPath = Join-Path $evidenceRoot 'capture-run.json'
if (-not (Test-Path -LiteralPath $captureResultPath -PathType Leaf)) { throw 'GUI capture result is missing.' }
$capture = Get-Content -LiteralPath $captureResultPath -Raw -Encoding UTF8 | ConvertFrom-Json
$expectedStatus = if ($CaptureMode -ceq 'calibration-smoke') {
    'CALIBRATION_SMOKE_NOT_EVIDENCE'
} else { 'CAPTURED_UNREVIEWED' }
if ($capture.harness_valid -ne $true -or [string]$capture.live_capture_status -cne $expectedStatus -or
    $capture.evidence_pass -ne $false -or $capture.human_review_complete -ne $false) {
    throw 'GUI capture result violated the unreviewed-evidence boundary.'
}
$summary = [ordered]@{
    schema='kdbg.win11-extended-gui-guest-capture.v1'
    success=$true
    completed_utc=[DateTime]::UtcNow.ToString('o')
    mode=$CaptureMode
    capture_status=[string]$capture.live_capture_status
    capture_count=[uint32]$capture.capture_count
    scene_count=[uint32]$capture.scene_count
    probe_pfn=[uint64]$prepared.probe_pfn
    fixture_pid=[uint32]$fixture.pid
    package_sha256=[string]$prepared.package_sha256
    source_snapshot_sha256=[string]$prepared.source_snapshot_sha256
    evidence_pass=$false
    human_review_complete=$false
    credential_serialized=$false
}
Write-Json (Join-Path $evidenceRoot 'guest-capture-summary.json') $summary
$summary | ConvertTo-Json -Depth 24

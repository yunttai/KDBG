[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageRoot,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [Parameter(Mandatory = $true)][string]$SessionPath,
    [string]$PlanPath = (Join-Path $PSScriptRoot 'capture-plan.json'),
    [string]$CalibrationPath = (Join-Path $PSScriptRoot 'calibration.win11-1024x768-v1.json'),
    [string]$ResultPath = '',
    [string]$ErrorPath = '',
    [switch]$DryRun,
    [switch]$CalibrationSmoke
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Json([string]$Path, [object]$Value) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText(
        [IO.Path]::GetFullPath($Path),
        ($Value | ConvertTo-Json -Depth 30) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Property([object]$Value, [string]$Name, [object]$DefaultValue = $null) {
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $DefaultValue }
    $property.Value
}

function Assert-SafeLeaf([string]$Name) {
    if ([IO.Path]::GetFileName($Name) -cne $Name -or [IO.Path]::GetExtension($Name) -cne '.png') {
        throw "Capture file must be a PNG leaf name: $Name"
    }
}

function Resolve-TokenText([string]$Value, [object]$Session) {
    $resolved = $Value
    $map = [ordered]@{
        '${session.fixture_pid}' = [string]$Session.fixture_pid
        '${session.probe_pfn_hex}' = [string]$Session.probe_pfn_hex
        '${session.fixture_virtual_address_hex}' = [string]$Session.fixture_virtual_address_hex
        '${session.fixture_pointer_target_hex}' = [string]$Session.fixture_pointer_target_hex
        '${session.fixture_code_address_hex}' = [string]$Session.fixture_code_address_hex
        '${session.fixture_scan_value}' = [string]$Session.fixture_scan_value
        '${session.fixture_scan_offset}' = [string]$Session.fixture_scan_offset
        '${session.fixture_snapshot_offset}' = [string]$Session.fixture_snapshot_offset
        '${session.fixture_freeze_expected_crc32}' = [string]$Session.fixture_freeze_expected_crc32
        '${session.fixture_baseline_crc32}' = [string]$Session.fixture_baseline_crc32
        '${session.fixture_info_path}' = [string]$Session.fixture_info_path
        '${session.kernel_pdb_path}' = [string]$Session.kernel_pdb_path
    }
    foreach ($entry in $map.GetEnumerator()) {
        $resolved = $resolved.Replace([string]$entry.Key, [string]$entry.Value)
    }
    if ($resolved -match '\$\{') { throw "Unresolved runtime token: $resolved" }
    $resolved
}

function Assert-Plan([object]$Plan, [object]$Calibration, [object]$Session) {
    if ([string]$Plan.schema -cne 'kdbg.win11-extended-gui-capture-plan.v1') {
        throw 'Unsupported capture plan schema.'
    }
    if ([string]$Calibration.schema -cne [string]$Plan.minimum_calibration_schema) {
        throw 'Capture plan and calibration schema do not match.'
    }
    if ([string]$Session.schema -cne 'kdbg.win11-extended-gui-session.v1') {
        throw 'Unsupported session schema.'
    }
    $steps = @($Plan.steps)
    if ($steps.Count -eq 0) { throw 'Capture plan has no steps.' }
    $ids = @($steps | ForEach-Object { [string]$_.id })
    $files = @($steps | ForEach-Object { [string]$_.file })
    if (@($ids | Select-Object -Unique).Count -ne $ids.Count) { throw 'Capture step ids must be unique.' }
    if (@($files | Select-Object -Unique).Count -ne $files.Count) { throw 'Capture files must be unique.' }
    foreach ($step in $steps) {
        Assert-SafeLeaf ([string]$step.file)
        foreach ($action in @($step.actions)) {
            $type = [string]$action.type
            if ($type -notin @(
                    'wait_window_responsive','click','double_click','replace_text','send_keys','wait',
                    'wait_region_change','wait_region_stable','fixture_command','wait_fixture_crc','capture',
                    'drag','scroll','drag_until_region_change','click_until_region_change',
                    'click_until_region_stable','send_keys_until_region_change',
                    'click_saved_region_until_change','click_until_checkbox_state',
                    'click_unchecked_checkbox_until_checked','click_saved_checkbox_until_state',
                    'assert_region_blue_pixels','save_relative_region_hash',
                    'wait_relative_region_change')) {
                throw "Unsupported action type: $type"
            }
            $pointName = [string](Get-Property $action 'point' '')
            if (-not [string]::IsNullOrWhiteSpace($pointName) -and
                $null -eq $Calibration.points.PSObject.Properties[$pointName]) {
                throw "Unknown calibration point: $pointName"
            }
            $regionValue = Get-Property $action 'region' $null
            if ($regionValue -is [string] -and
                -not [string]::IsNullOrWhiteSpace([string]$regionValue) -and
                $null -eq $Calibration.regions.PSObject.Properties[[string]$regionValue]) {
                throw "Unknown calibration region: $regionValue"
            }
            $textValue = [string](Get-Property $action 'value' '')
            if (-not [string]::IsNullOrWhiteSpace($textValue)) {
                [void](Resolve-TokenText $textValue $Session)
            }
            $commandValue = [string](Get-Property $action 'command' '')
            if (-not [string]::IsNullOrWhiteSpace($commandValue)) {
                [void](Resolve-TokenText $commandValue $Session)
            }
        }
    }
    $requiredScenes = @($Plan.required_scene_order | ForEach-Object { [string]$_ })
    $observedScenes = @($steps | ForEach-Object { [string]$_.scene_id } | Select-Object -Unique)
    if (Compare-Object -ReferenceObject $requiredScenes -DifferenceObject $observedScenes -SyncWindow 0) {
        throw 'Capture plan scene order does not match required_scene_order.'
    }
    if ($steps.Count -ne 24 -or $requiredScenes.Count -ne 20) {
        throw 'The full GUI plan must contain exactly 24 frames and 20 ordered scenes.'
    }
    $plannedDuration = [int](($steps | Measure-Object -Property duration_ms -Sum).Sum)
    if ($plannedDuration -ne 40500) {
        throw "The full GUI plan duration must remain exactly 40500 ms; actual $plannedDuration."
    }
    if ([int]$Plan.reference_size.width -ne [int]$Calibration.client.width -or
        [int]$Plan.reference_size.height -ne [int]$Calibration.client.height) {
        throw 'Capture-plan reference dimensions must exactly match the calibration client dimensions.'
    }
    foreach ($step in $steps) {
        if (@($step.actions | Where-Object { [string]$_.type -ceq 'capture' }).Count -ne 1) {
            throw "Every full-plan step must contain exactly one explicit capture action: $($step.id)"
        }
    }
    $physicalRead = @($steps | Where-Object { [string]$_.id -ceq '03-physical-read-4096' })[0]
    if ($null -eq $physicalRead -or
        -not @($physicalRead.actions | Where-Object {
                [string]$_.type -ceq 'replace_text' -and
                [string]$_.value -ceq '${session.probe_pfn_hex}'
            })) {
        throw 'The physical-read frame must explicitly enter the session Probe PFN.'
    }
    $attach = @($steps | Where-Object { [string]$_.id -ceq '12-pfn-owner-pid-va-pte' })[0]
    if ($null -eq $attach -or
        -not @($attach.actions | Where-Object {
                [string]$_.type -ceq 'replace_text' -and
                [string]$_.value -ceq '${session.fixture_pid}'
            })) {
        throw 'The ownership frame must filter and attach the session fixture PID.'
    }
    $addressStep = @($steps | Where-Object { [string]$_.id -ceq '16-address-list-freeze' })[0]
    if ($null -eq $addressStep -or
        -not @($addressStep.actions | Where-Object {
                [string]$_.type -ceq 'click_unchecked_checkbox_until_checked'
            })) {
        throw 'The address-list frame must use the proven fail-closed checkbox-state locator.'
    }
    $addIndex = -1
    $armIndex = -1
    for ($index = 0; $index -lt @($addressStep.actions).Count; ++$index) {
        $candidate = @($addressStep.actions)[$index]
        if ([string](Get-Property $candidate 'assertion' '') -ceq
            'scan_result_added_to_address_list') { $addIndex = $index }
        if ([string](Get-Property $candidate 'assertion' '') -ceq
            'arm_modal_open') { $armIndex = $index }
    }
    if ($addIndex -lt 0 -or $armIndex -lt 0 -or $addIndex -ge $armIndex) {
        throw 'A verified scan-result Add action must precede address-list write arming.'
    }
    $pointerStep = @($steps | Where-Object { [string]$_.id -ceq '18-pointer-scan' })[0]
    $pointerOffsetIndex = -1
    $pointerStaticIndex = -1
    $pointerStartIndex = -1
    for ($index = 0; $index -lt @($pointerStep.actions).Count; ++$index) {
        $candidate = @($pointerStep.actions)[$index]
        if ([string](Get-Property $candidate 'assertion' '') -ceq
            'pointer_maximum_offset_zero') { $pointerOffsetIndex = $index }
        if ([string](Get-Property $candidate 'assertion' '') -ceq
            'pointer_static_roots_unchecked') { $pointerStaticIndex = $index }
        if ([string](Get-Property $candidate 'assertion' '') -ceq
            'pointer_scan_start') { $pointerStartIndex = $index }
    }
    if ($pointerOffsetIndex -lt 0 -or $pointerStaticIndex -lt 0 -or
        $pointerStartIndex -lt 0 -or $pointerOffsetIndex -ge $pointerStartIndex -or
        $pointerStaticIndex -ge $pointerStartIndex) {
        throw 'The pointer frame must configure deterministic heap roots before starting the scan.'
    }
    $exportStep = @($steps | Where-Object { [string]$_.id -ceq '23-kernel-read-disassembly' })[0]
    $fixturePathIndex = -1
    $exportIndex = -1
    for ($index = 0; $index -lt @($exportStep.actions).Count; ++$index) {
        $candidate = @($exportStep.actions)[$index]
        if ([string](Get-Property $candidate 'assertion' '') -ceq
            'analysis_fixture_info_path') { $fixturePathIndex = $index }
        if ([string](Get-Property $candidate 'assertion' '') -ceq
            'analysis_evidence_export') { $exportIndex = $index }
    }
    if ($fixturePathIndex -lt 0 -or $exportIndex -lt 0 -or
        $fixturePathIndex -ge $exportIndex) {
        throw 'The analysis export must bind the run fixture INFO path before export.'
    }
}

$packageFull = [IO.Path]::GetFullPath($PackageRoot)
$evidenceFull = [IO.Path]::GetFullPath($EvidenceRoot)
$planFull = [IO.Path]::GetFullPath($PlanPath)
$calibrationFull = [IO.Path]::GetFullPath($CalibrationPath)
$sessionFull = [IO.Path]::GetFullPath($SessionPath)
if ([string]::IsNullOrWhiteSpace($ResultPath)) { $ResultPath = Join-Path $evidenceFull 'capture-run.json' }
if ([string]::IsNullOrWhiteSpace($ErrorPath)) { $ErrorPath = Join-Path $evidenceFull 'capture-run-error.txt' }
$resultFull = [IO.Path]::GetFullPath($ResultPath)
$errorFull = [IO.Path]::GetFullPath($ErrorPath)

foreach ($required in @($planFull,$calibrationFull,$sessionFull)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing harness input: $required" }
}
$plan = Get-Content -LiteralPath $planFull -Raw -Encoding UTF8 | ConvertFrom-Json
$calibration = Get-Content -LiteralPath $calibrationFull -Raw -Encoding UTF8 | ConvertFrom-Json
$session = Get-Content -LiteralPath $sessionFull -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-Plan $plan $calibration $session

$staticResult = [ordered]@{
    schema = 'kdbg.win11-extended-gui-capture-result.v1'
    harness_valid = $true
    live_capture_status = 'NOT_RUN'
    dry_run = [bool]$DryRun
    calibration_smoke = [bool]$CalibrationSmoke
    evidence_pass = $false
    human_review_complete = $false
    plan_sha256 = Get-Sha256 $planFull
    calibration_sha256 = Get-Sha256 $calibrationFull
    calibration_status = [string]$calibration.calibration_status
    calibration_calibrated = [bool]$calibration.calibrated
    session_sha256 = Get-Sha256 $sessionFull
    step_count = @($plan.steps).Count
    scene_count = @($plan.required_scene_order).Count
    completed_utc = [DateTime]::UtcNow.ToString('o')
}
if ($DryRun) {
    Write-Json $resultFull $staticResult
    $staticResult | ConvertTo-Json -Depth 20
    return
}

if (-not (Test-Path -LiteralPath $packageFull -PathType Container)) { throw "PackageRoot is missing: $packageFull" }
$exePath = Join-Path $packageFull 'KDBG.exe'
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { throw "KDBG.exe is missing: $exePath" }
if ($session.dedicated_vm -ne $true -or $session.snapshot_confirmed -ne $true -or $session.test_signing -ne $true) {
    throw 'Live GUI capture requires the dedicated-VM, snapshot, and test-signing session assertions.'
}
if (-not [bool]$calibration.calibrated -and -not $CalibrationSmoke) {
    throw 'Win11 coordinate profile is uncalibrated. Run -CalibrationSmoke first; do not treat it as evidence.'
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KdbgGuiNative {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int command);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr hWnd, ref POINT point);
  [DllImport("user32.dll")] public static extern bool IsHungAppWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, int data, UIntPtr extra);
}
'@

function Wait-Window([Diagnostics.Process]$Process, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 250
        $Process.Refresh()
        if ($Process.HasExited) { throw 'KDBG exited before its main window became ready.' }
        if ($Process.MainWindowHandle -ne [IntPtr]::Zero -and
            -not [KdbgGuiNative]::IsHungAppWindow($Process.MainWindowHandle)) {
            return $Process.MainWindowHandle
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "KDBG window was not responsive within $TimeoutSeconds seconds."
}

function Wait-GuiReadinessDiagnostics(
    [int]$GuiProcessId,
    [string]$LogPath,
    [int]$TimeoutSeconds = 15) {
    $required = @(
        'driver.connect_succeeded',
        'probe.device_open_succeeded',
        'probe.query_succeeded'
    )
    $failurePattern = 'event=(driver\.connect_failed|probe\.device_open_failed|probe\.query_failed)'
    $pidToken = "pid=$GuiProcessId "
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $LogPath -PathType Leaf) {
            $processLines = @(Get-Content -LiteralPath $LogPath | Where-Object { $_.Contains($pidToken) })
            $failure = @($processLines | Where-Object { $_ -match $failurePattern } | Select-Object -First 1)
            if ($failure.Count -ne 0) {
                throw "KDBG GUI live-readiness diagnostics reported failure: $($failure[0])"
            }
            $observed = @($processLines | ForEach-Object {
                    if ($_ -match 'event=([^ ]+)') { $Matches[1] }
                } | Select-Object -Unique)
            $missing = @($required | Where-Object { $_ -notin $observed })
            if ($missing.Count -eq 0) {
                return [ordered]@{
                    process_id = $GuiProcessId
                    required_events = $required
                    observed_events = $observed
                }
            }
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "KDBG GUI did not reach live Probe readiness within $TimeoutSeconds seconds."
}

function Get-ClientGeometry([IntPtr]$Window) {
    $rect = [KdbgGuiNative+RECT]::new()
    if (-not [KdbgGuiNative]::GetClientRect($Window, [ref]$rect)) { throw 'GetClientRect failed.' }
    $origin = [KdbgGuiNative+POINT]::new()
    if (-not [KdbgGuiNative]::ClientToScreen($Window, [ref]$origin)) { throw 'ClientToScreen failed.' }
    [ordered]@{ x=$origin.X; y=$origin.Y; width=$rect.Right-$rect.Left; height=$rect.Bottom-$rect.Top }
}

function Get-Point([string]$Name, [object]$CalibrationValue, [object]$Geometry) {
    $point = $CalibrationValue.points.PSObject.Properties[$Name].Value
    [Drawing.Point]::new([int]$Geometry.x + [int]$point.x, [int]$Geometry.y + [int]$point.y)
}

function Get-Region([string]$Name, [object]$CalibrationValue, [object]$Geometry) {
    $region = $CalibrationValue.regions.PSObject.Properties[$Name].Value
    [Drawing.Rectangle]::new(
        [int]$Geometry.x + [int]$region.x,
        [int]$Geometry.y + [int]$region.y,
        [int]$region.width,
        [int]$region.height)
}

function Save-ScreenRegion([Drawing.Rectangle]$Bounds, [string]$Path) {
    $bitmap = [Drawing.Bitmap]::new($Bounds.Width, $Bounds.Height)
    try {
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try { $graphics.CopyFromScreen($Bounds.Location, [Drawing.Point]::Empty, $Bounds.Size) }
        finally { $graphics.Dispose() }
        $bitmap.Save($Path, [Drawing.Imaging.ImageFormat]::Png)
    } finally { $bitmap.Dispose() }
}

function Get-RegionHash([Drawing.Rectangle]$Bounds) {
    $bitmap = [Drawing.Bitmap]::new($Bounds.Width, $Bounds.Height)
    try {
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try { $graphics.CopyFromScreen($Bounds.Location, [Drawing.Point]::Empty, $Bounds.Size) }
        finally { $graphics.Dispose() }
        $stream = [IO.MemoryStream]::new()
        try {
            $bitmap.Save($stream, [Drawing.Imaging.ImageFormat]::Png)
            $stream.Position = 0
            $sha = [Security.Cryptography.SHA256]::Create()
            try { ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
            finally { $sha.Dispose() }
        } finally { $stream.Dispose() }
    } finally { $bitmap.Dispose() }
}

function Invoke-Click([Drawing.Point]$Point) {
    if (-not [KdbgGuiNative]::SetCursorPos($Point.X, $Point.Y)) {
        throw 'SetCursorPos failed at the click target.'
    }
    Start-Sleep -Milliseconds 80
    [KdbgGuiNative]::mouse_event(0x0002,0,0,0,[UIntPtr]::Zero)
    Start-Sleep -Milliseconds 50
    [KdbgGuiNative]::mouse_event(0x0004,0,0,0,[UIntPtr]::Zero)
}

function Get-ReferencePoint(
    [double]$X,
    [double]$Y,
    [object]$Geometry,
    [object]$CalibrationValue) {
    $screenX = [int][Math]::Round(
        [double]$Geometry.x + ($X / [double]$CalibrationValue.client.width) *
        [double]$Geometry.width)
    $screenY = [int][Math]::Round(
        [double]$Geometry.y + ($Y / [double]$CalibrationValue.client.height) *
        [double]$Geometry.height)
    [Drawing.Point]::new($screenX, $screenY)
}

function ConvertTo-ReferenceRegion(
    [object]$Region,
    [object]$CalibrationValue,
    [object]$Geometry) {
    $value = $Region
    if ($Region -is [string]) {
        $property = $CalibrationValue.regions.PSObject.Properties[[string]$Region]
        if ($null -eq $property) { throw "Unknown calibration region: $Region" }
        $value = $property.Value
    }
    if ($null -eq $value -or $null -eq $value.PSObject.Properties['x'] -or
        $null -eq $value.PSObject.Properties['y'] -or
        $null -eq $value.PSObject.Properties['width'] -or
        $null -eq $value.PSObject.Properties['height']) {
        throw 'A UI-state assertion requires a complete reference region.'
    }
    $topLeft = Get-ReferencePoint ([double]$value.x) ([double]$value.y) `
        $Geometry $CalibrationValue
    $bottomRight = Get-ReferencePoint `
        ([double]$value.x + [double]$value.width) `
        ([double]$value.y + [double]$value.height) `
        $Geometry $CalibrationValue
    [Drawing.Rectangle]::new(
        $topLeft.X, $topLeft.Y,
        [Math]::Max(1, $bottomRight.X - $topLeft.X),
        [Math]::Max(1, $bottomRight.Y - $topLeft.Y))
}

function Invoke-ReferenceClick(
    [double]$X,
    [double]$Y,
    [object]$Geometry,
    [object]$CalibrationValue,
    [int]$Count = 1,
    [int]$IntervalMilliseconds = 110) {
    if ($Count -lt 1 -or $Count -gt 32) {
        throw "Click count is outside the supported range: $Count"
    }
    $point = Get-ReferencePoint $X $Y $Geometry $CalibrationValue
    for ($index = 1; $index -le $Count; ++$index) {
        Invoke-Click $point
        if ($index -lt $Count) { Start-Sleep -Milliseconds $IntervalMilliseconds }
    }
}

function Invoke-ReferenceDrag(
    [double]$X,
    [double]$Y,
    [double]$EndX,
    [double]$EndY,
    [object]$Geometry,
    [object]$CalibrationValue) {
    $start = Get-ReferencePoint $X $Y $Geometry $CalibrationValue
    $finish = Get-ReferencePoint $EndX $EndY $Geometry $CalibrationValue
    if (-not [KdbgGuiNative]::SetCursorPos($start.X, $start.Y)) {
        throw 'SetCursorPos failed at the drag origin.'
    }
    Start-Sleep -Milliseconds 100
    [KdbgGuiNative]::mouse_event(0x0002,0,0,0,[UIntPtr]::Zero)
    foreach ($part in 1..16) {
        $nextX = [int][Math]::Round($start.X + (($finish.X - $start.X) * $part / 16.0))
        $nextY = [int][Math]::Round($start.Y + (($finish.Y - $start.Y) * $part / 16.0))
        [void][KdbgGuiNative]::SetCursorPos($nextX, $nextY)
        Start-Sleep -Milliseconds 30
    }
    [KdbgGuiNative]::mouse_event(0x0004,0,0,0,[UIntPtr]::Zero)
}

function Invoke-ReferenceScroll(
    [double]$X,
    [double]$Y,
    [int]$Delta,
    [object]$Geometry,
    [object]$CalibrationValue) {
    $point = Get-ReferencePoint $X $Y $Geometry $CalibrationValue
    if (-not [KdbgGuiNative]::SetCursorPos($point.X, $point.Y)) {
        throw 'SetCursorPos failed at the scroll target.'
    }
    Start-Sleep -Milliseconds 100
    [KdbgGuiNative]::mouse_event(0x0800,0,0,$Delta,[UIntPtr]::Zero)
    Start-Sleep -Milliseconds 180
}

function Get-StableReferenceRegionHash(
    [object]$Region,
    [object]$CalibrationValue,
    [object]$Geometry) {
    $away = Get-ReferencePoint 100 350 $Geometry $CalibrationValue
    if (-not [KdbgGuiNative]::SetCursorPos($away.X, $away.Y)) {
        throw 'SetCursorPos failed while stabilizing a UI-state region.'
    }
    Start-Sleep -Milliseconds 120
    Get-RegionHash (ConvertTo-ReferenceRegion $Region $CalibrationValue $Geometry)
}

function Get-StableReferenceBluePixelCount(
    [object]$Region,
    [object]$CalibrationValue,
    [object]$Geometry) {
    $away = Get-ReferencePoint 100 350 $Geometry $CalibrationValue
    if (-not [KdbgGuiNative]::SetCursorPos($away.X,$away.Y)) {
        throw 'SetCursorPos failed while stabilizing a blue-pixel assertion region.'
    }
    Start-Sleep -Milliseconds 120
    $bounds = ConvertTo-ReferenceRegion $Region $CalibrationValue $Geometry
    $bitmap = [Drawing.Bitmap]::new(
        $bounds.Width, $bounds.Height, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
    try {
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try { $graphics.CopyFromScreen($bounds.Location,[Drawing.Point]::Empty,$bounds.Size) }
        finally { $graphics.Dispose() }
        $count = 0
        for ($y = 0; $y -lt $bitmap.Height; ++$y) {
            for ($x = 0; $x -lt $bitmap.Width; ++$x) {
                $color = $bitmap.GetPixel($x,$y)
                if ($color.B -ge 100 -and
                    ([int]$color.B * 100) -gt ([int]$color.R * 135) -and
                    ([int]$color.B * 100) -gt ([int]$color.G * 110)) {
                    ++$count
                }
            }
        }
        $count
    } finally { $bitmap.Dispose() }
}

function Invoke-ClickUntilReferenceRegionChange(
    [object[]]$Candidates,
    [object]$DefaultRegion,
    [int]$MaximumAttempts,
    [int]$SettleMilliseconds,
    [object]$CalibrationValue,
    [object]$Geometry) {
    if ($Candidates.Count -eq 0 -or $MaximumAttempts -lt 1 -or $MaximumAttempts -gt 12) {
        throw 'Bounded UI-state click has invalid candidates or attempt limit.'
    }
    for ($attempt = 1; $attempt -le $MaximumAttempts; ++$attempt) {
        $candidate = $Candidates[($attempt - 1) % $Candidates.Count]
        $candidateRegion = Get-Property $candidate 'region' $DefaultRegion
        if ($null -eq $candidateRegion) { throw 'Bounded UI-state click requires a comparison region.' }
        $before = Get-StableReferenceRegionHash $candidateRegion $CalibrationValue $Geometry
        Invoke-ReferenceClick ([double]$candidate.x) ([double]$candidate.y) $Geometry $CalibrationValue
        Start-Sleep -Milliseconds $SettleMilliseconds
        $after = Get-StableReferenceRegionHash $candidateRegion $CalibrationValue $Geometry
        if ($before -cne $after) {
            return [ordered]@{ changed=$true; attempts=$attempt; x=[double]$candidate.x; y=[double]$candidate.y; before_sha256=$before; after_sha256=$after }
        }
    }
    throw "UI-state region did not change within $MaximumAttempts bounded click attempt(s)."
}

function Invoke-DragUntilReferenceRegionChange(
    [object[]]$Candidates,
    [object]$Region,
    [int]$MaximumAttempts,
    [int]$SettleMilliseconds,
    [object]$CalibrationValue,
    [object]$Geometry) {
    if ($Candidates.Count -eq 0 -or $MaximumAttempts -lt 1 -or $MaximumAttempts -gt 8) {
        throw 'Bounded splitter-state drag has invalid candidates or attempt limit.'
    }
    for ($attempt = 1; $attempt -le $MaximumAttempts; ++$attempt) {
        $candidate = $Candidates[($attempt - 1) % $Candidates.Count]
        $before = Get-StableReferenceRegionHash $Region $CalibrationValue $Geometry
        Invoke-ReferenceDrag ([double]$candidate.x) ([double]$candidate.y) `
            ([double]$candidate.end_x) ([double]$candidate.end_y) $Geometry $CalibrationValue
        Start-Sleep -Milliseconds $SettleMilliseconds
        $after = Get-StableReferenceRegionHash $Region $CalibrationValue $Geometry
        if ($before -cne $after) {
            return [ordered]@{ changed=$true; attempts=$attempt; x=[double]$candidate.x; y=[double]$candidate.y; end_x=[double]$candidate.end_x; end_y=[double]$candidate.end_y; before_sha256=$before; after_sha256=$after }
        }
    }
    throw "Splitter region did not change within $MaximumAttempts bounded drag attempt(s)."
}

function Invoke-ClickUntilReferenceRegionStable(
    [double]$X,
    [double]$Y,
    [object]$Region,
    [object[]]$PreScrolls,
    [int]$ExpectedChanges,
    [int]$StableAttemptsRequired,
    [int]$MaximumAttempts,
    [int]$SettleMilliseconds,
    [object]$CalibrationValue,
    [object]$Geometry) {
    if ($ExpectedChanges -lt 1 -or $StableAttemptsRequired -lt 1 -or
        $MaximumAttempts -lt ($ExpectedChanges + $StableAttemptsRequired) -or
        $MaximumAttempts -gt 24) {
        throw 'Bounded target-state click has invalid limits.'
    }
    $changed = 0
    $stable = 0
    $final = ''
    for ($attempt = 1; $attempt -le $MaximumAttempts; ++$attempt) {
        foreach ($preScroll in $PreScrolls) {
            Invoke-ReferenceScroll ([double]$preScroll.x) ([double]$preScroll.y) `
                ([int]$preScroll.delta) $Geometry $CalibrationValue
        }
        $before = Get-StableReferenceRegionHash $Region $CalibrationValue $Geometry
        Invoke-ReferenceClick $X $Y $Geometry $CalibrationValue
        Start-Sleep -Milliseconds $SettleMilliseconds
        $final = Get-StableReferenceRegionHash $Region $CalibrationValue $Geometry
        if ($final -cne $before) {
            ++$changed
            $stable = 0
            if ($changed -gt $ExpectedChanges) {
                throw "Target-state click exceeded its exact expected changes: $changed > $ExpectedChanges"
            }
        } else { ++$stable }
        if ($changed -eq $ExpectedChanges -and $stable -ge $StableAttemptsRequired) {
            return [ordered]@{ changed=$true; attempts=$attempt; changes=$changed; stable_attempts=$stable; final_sha256=$final }
        }
    }
    throw "Target-state click did not reach $ExpectedChanges exact change(s) and $StableAttemptsRequired stable attempt(s): changes=$changed stable=$stable attempts=$MaximumAttempts."
}

function Invoke-KeysUntilReferenceRegionChange(
    [string]$Keys,
    [object]$Region,
    [int]$MaximumAttempts,
    [int]$SettleMilliseconds,
    [object]$CalibrationValue,
    [object]$Geometry) {
    if ($MaximumAttempts -lt 1 -or $MaximumAttempts -gt 4) {
        throw 'Bounded key-state action has an invalid attempt limit.'
    }
    for ($attempt = 1; $attempt -le $MaximumAttempts; ++$attempt) {
        $before = Get-StableReferenceRegionHash $Region $CalibrationValue $Geometry
        [Windows.Forms.SendKeys]::SendWait($Keys)
        Start-Sleep -Milliseconds $SettleMilliseconds
        $after = Get-StableReferenceRegionHash $Region $CalibrationValue $Geometry
        if ($before -cne $after) {
            return [ordered]@{ changed=$true; attempts=$attempt; before_sha256=$before; after_sha256=$after }
        }
    }
    throw "UI-state region did not change within $MaximumAttempts bounded key attempt(s)."
}

function Get-ReferenceCheckboxStripState(
    [double]$X,
    [double]$StartY,
    [double]$EndY,
    [int]$BoxSize,
    [object]$CalibrationValue,
    [object]$Geometry) {
    if ($EndY -le $StartY -or $BoxSize -lt 8 -or $BoxSize -gt 40) {
        throw 'Checkbox scan geometry is invalid.'
    }
    $away = Get-ReferencePoint 100 350 $Geometry $CalibrationValue
    if (-not [KdbgGuiNative]::SetCursorPos($away.X,$away.Y)) {
        throw 'SetCursorPos failed while stabilizing a checkbox-strip assertion.'
    }
    Start-Sleep -Milliseconds 120
    $region = [pscustomobject]@{ x=$X; y=$StartY; width=$BoxSize; height=$EndY-$StartY }
    $bounds = ConvertTo-ReferenceRegion $region $CalibrationValue $Geometry
    $bitmap = [Drawing.Bitmap]::new(
        $bounds.Width, $bounds.Height, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
    try {
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try { $graphics.CopyFromScreen($bounds.Location,[Drawing.Point]::Empty,$bounds.Size) }
        finally { $graphics.Dispose() }
        $capturedBox = [Math]::Max(1,[int][Math]::Round(
            $BoxSize * $Geometry.height / [double]$CalibrationValue.client.height))
        $bestNeutral = 0; $bestNeutralTop = 0
        $bestActive = 0; $bestActiveTop = 0
        $bestBlue = 0; $bestBlueTop = 0
        for ($top = 0; $top -le $bitmap.Height - $capturedBox; ++$top) {
            $neutral = 0; $active = 0; $blue = 0
            for ($py = $top; $py -lt $top + $capturedBox; ++$py) {
                for ($px = 0; $px -lt [Math]::Min($capturedBox,$bitmap.Width); ++$px) {
                    $color = $bitmap.GetPixel($px,$py)
                    if ([Math]::Abs([int]$color.R-23) -le 2 -and
                        [Math]::Abs([int]$color.G-34) -le 2 -and
                        [Math]::Abs([int]$color.B-50) -le 3) { ++$neutral }
                    if ([Math]::Abs([int]$color.R-29) -le 2 -and
                        [Math]::Abs([int]$color.G-47) -le 2 -and
                        [Math]::Abs([int]$color.B-73) -le 3) { ++$active }
                    if ($color.B -ge 100 -and
                        ([int]$color.B*100) -gt ([int]$color.R*135) -and
                        ([int]$color.B*100) -gt ([int]$color.G*110)) { ++$blue }
                }
            }
            if ($neutral -gt $bestNeutral) { $bestNeutral=$neutral; $bestNeutralTop=$top }
            if ($active -gt $bestActive) { $bestActive=$active; $bestActiveTop=$top }
            if ($blue -gt $bestBlue) { $bestBlue=$blue; $bestBlueTop=$top }
        }
        $referencePerPixel = ($EndY-$StartY) / [double]$bitmap.Height
        [ordered]@{
            neutral_pixels=$bestNeutral
            neutral_center_y=$StartY+(($bestNeutralTop+($capturedBox/2.0))*$referencePerPixel)
            active_unchecked_pixels=$bestActive
            active_unchecked_center_y=$StartY+(($bestActiveTop+($capturedBox/2.0))*$referencePerPixel)
            blue_pixels=$bestBlue
            blue_center_y=$StartY+(($bestBlueTop+($capturedBox/2.0))*$referencePerPixel)
        }
    } finally { $bitmap.Dispose() }
}

function Invoke-UncheckedReferenceCheckboxUntilChecked(
    [object]$Scan,
    [int]$NeutralThreshold,
    [int]$BlueThreshold,
    [int]$MaximumAttempts,
    [int]$SettleMilliseconds,
    [object]$CalibrationValue,
    [object]$Geometry) {
    if ($NeutralThreshold -lt 1 -or $BlueThreshold -lt 1 -or
        $MaximumAttempts -lt 1 -or $MaximumAttempts -gt 8) {
        throw 'Checkbox signature locator has invalid thresholds or attempt limit.'
    }
    for ($attempt = 1; $attempt -le $MaximumAttempts; ++$attempt) {
        $before = Get-ReferenceCheckboxStripState ([double]$Scan.x) `
            ([double]$Scan.start_y) ([double]$Scan.end_y) ([int]$Scan.box_size) `
            $CalibrationValue $Geometry
        if ([int]$before.blue_pixels -ge $BlueThreshold) {
            return [ordered]@{ checked=$true; attempts=$attempt-1; x=[double]$Scan.x+([int]$Scan.box_size/2.0); y=[double]$before.blue_center_y; before_unchecked_pixels=0; unchecked_signature='already-checked-blue'; after_blue_pixels=[int]$before.blue_pixels }
        }
        $pixels = [int]$before.neutral_pixels
        $centerY = [double]$before.neutral_center_y
        $signature = 'rgb-23-34-50'
        if ($pixels -lt $NeutralThreshold) {
            $pixels = [int]$before.active_unchecked_pixels
            $centerY = [double]$before.active_unchecked_center_y
            $signature = 'rgb-29-47-73'
        }
        if ($pixels -lt $NeutralThreshold) {
            throw "Unchecked checkbox signature was not found: neutral=$($before.neutral_pixels), active=$($before.active_unchecked_pixels), threshold=$NeutralThreshold"
        }
        $clickX = [double]$Scan.x + ([int]$Scan.box_size/2.0)
        Invoke-ReferenceClick $clickX $centerY $Geometry $CalibrationValue
        Start-Sleep -Milliseconds $SettleMilliseconds
        $after = Get-ReferenceCheckboxStripState ([double]$Scan.x) `
            ([double]$Scan.start_y) ([double]$Scan.end_y) ([int]$Scan.box_size) `
            $CalibrationValue $Geometry
        if ([int]$after.blue_pixels -ge $BlueThreshold) {
            return [ordered]@{ checked=$true; attempts=$attempt; x=$clickX; y=[double]$after.blue_center_y; before_unchecked_pixels=$pixels; unchecked_signature=$signature; after_blue_pixels=[int]$after.blue_pixels }
        }
    }
    throw "Checkbox signature locator did not reach checked state within $MaximumAttempts bounded attempt(s)."
}

function Invoke-ReferenceCheckboxUntilState(
    [object[]]$Candidates,
    [bool]$ExpectedChecked,
    [int]$BlueThreshold,
    [int]$MaximumAttempts,
    [int]$SettleMilliseconds,
    [object]$CalibrationValue,
    [object]$Geometry) {
    if ($Candidates.Count -eq 0 -or $BlueThreshold -lt 1 -or
        $MaximumAttempts -lt 1 -or $MaximumAttempts -gt 8) {
        throw 'Bounded checkbox-state action has invalid inputs.'
    }
    for ($attempt = 1; $attempt -le $MaximumAttempts; ++$attempt) {
        $candidate = $Candidates[($attempt-1)%$Candidates.Count]
        $region = Get-Property $candidate 'region' $null
        if ($null -eq $region) { throw 'Every checkbox candidate requires a tight comparison region.' }
        $beforeBlue = Get-StableReferenceBluePixelCount $region $CalibrationValue $Geometry
        $beforeChecked = $beforeBlue -ge $BlueThreshold
        Invoke-ReferenceClick ([double]$candidate.x) ([double]$candidate.y) $Geometry $CalibrationValue
        Start-Sleep -Milliseconds $SettleMilliseconds
        $afterBlue = Get-StableReferenceBluePixelCount $region $CalibrationValue $Geometry
        $afterChecked = $afterBlue -ge $BlueThreshold
        if ($afterChecked -eq $ExpectedChecked -and $afterChecked -ne $beforeChecked) {
            return [ordered]@{ changed=$true; checked=$afterChecked; attempts=$attempt; x=[double]$candidate.x; y=[double]$candidate.y; before_blue_pixels=$beforeBlue; after_blue_pixels=$afterBlue; blue_threshold=$BlueThreshold }
        }
    }
    throw "Checkbox did not reach expected state within $MaximumAttempts bounded attempt(s)."
}

function Invoke-FixtureCommand([string]$PipePath, [string]$Command) {
    $prefix = '\\.\pipe\'
    if (-not $PipePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Fixture pipe path is invalid: $PipePath"
    }
    $pipeName = $PipePath.Substring($prefix.Length)
    $pipe = [IO.Pipes.NamedPipeClientStream]::new(
        '.', $pipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None)
    try {
        $pipe.Connect(5000)
        $utf8NoBom = [Text.UTF8Encoding]::new($false)
        $writer = [IO.StreamWriter]::new($pipe,$utf8NoBom,1024,$true)
        $reader = [IO.StreamReader]::new($pipe,$utf8NoBom,$false,1024,$true)
        try {
            $writer.NewLine = "`n"
            $writer.WriteLine($Command)
            $writer.Flush()
            $line = $reader.ReadLine()
        } finally { $writer.Dispose(); $reader.Dispose() }
    } finally { $pipe.Dispose() }
    if ([string]::IsNullOrWhiteSpace($line)) { throw "Fixture command returned no response: $Command" }
    $response = $line | ConvertFrom-Json
    if ($response.ok -ne $true) { throw "Fixture command failed: $Command :: $line" }
    $response
}

function Wait-RegionChange([Drawing.Rectangle]$Bounds, [string]$Baseline, [int]$TimeoutMs) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        Start-Sleep -Milliseconds 200
        $current = Get-RegionHash $Bounds
        if ($current -cne $Baseline) { return $current }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for region change after ${TimeoutMs}ms."
}

function Wait-RegionStable([Drawing.Rectangle]$Bounds, [int]$StableSamples, [int]$TimeoutMs) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    $last = ''
    $stable = 0
    do {
        Start-Sleep -Milliseconds 250
        $current = Get-RegionHash $Bounds
        if ($current -ceq $last) { $stable++ } else { $last = $current; $stable = 1 }
        if ($stable -ge $StableSamples) { return $current }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for region stability after ${TimeoutMs}ms."
}

New-Item -ItemType Directory -Path $evidenceFull -Force | Out-Null
$capturesRoot = Join-Path $evidenceFull 'captures'
New-Item -ItemType Directory -Path $capturesRoot -Force | Out-Null
Remove-Item -LiteralPath $resultFull,$errorFull -Force -ErrorAction SilentlyContinue
$captures = [Collections.Generic.List[object]]::new()
$assertions = [Collections.Generic.List[object]]::new()
$fixtureCommands = [Collections.Generic.List[object]]::new()
$actionTrace = [Collections.Generic.List[object]]::new()
$recentRegionHashes = @{}
$stateRegionHashes = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$statePointY = [Collections.Generic.Dictionary[string,double]]::new([StringComparer]::Ordinal)
$plannedDurationMs = [int]((@($plan.steps) | Measure-Object -Property duration_ms -Sum).Sum)
$process = $null
$captureIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$capturePrincipal = [Security.Principal.WindowsPrincipal]::new($captureIdentity)
$captureExecution = [ordered]@{
    identity = $captureIdentity.Name
    is_administrator = $capturePrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    process_id = $PID
}
$diagnosticLogSource = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'KDBG\logs\kdbg.log'
$diagnosticLogEvidence = Join-Path $evidenceFull 'kdbg-ui.log'
$readinessDiagnostics = $null

try {
    $process = Start-Process -FilePath $exePath -WorkingDirectory $packageFull -PassThru
    $window = Wait-Window $process ([int]$plan.launch_timeout_seconds)
    [void][KdbgGuiNative]::ShowWindow($window, 3)
    [void][KdbgGuiNative]::SetForegroundWindow($window)
    Start-Sleep -Milliseconds 750
    $readinessDiagnostics = Wait-GuiReadinessDiagnostics $process.Id $diagnosticLogSource
    $geometry = Get-ClientGeometry $window
    $screen = [Windows.Forms.Screen]::PrimaryScreen.Bounds
    $dpi = [int][KdbgGuiNative]::GetDpiForWindow($window)
    if ($screen.Width -ne [int]$calibration.display.width -or
        $screen.Height -ne [int]$calibration.display.height -or
        $dpi -ne [int]$calibration.display.dpi) {
        throw "Display/DPI calibration mismatch: display=$($screen.Width)x$($screen.Height), dpi=$dpi."
    }
    $clientMatches = $geometry.width -eq [int]$calibration.client.width -and
        $geometry.height -eq [int]$calibration.client.height
    if (-not $clientMatches -and -not $CalibrationSmoke) {
        throw "Client calibration mismatch: client=$($geometry.width)x$($geometry.height)."
    }
    $assertions.Add([ordered]@{
        name='display_dpi_client_exact'; passed=$true
        display="$($screen.Width)x$($screen.Height)"; dpi=$dpi
        client="$($geometry.width)x$($geometry.height)"; client_matches_profile=$clientMatches
        calibration_smoke_allowed_client_measurement=[bool]$CalibrationSmoke
    })

    $steps = @($plan.steps)
    if ($CalibrationSmoke) {
        $steps = @($steps | Where-Object {
                $property = $_.PSObject.Properties['safe_for_uncalibrated_smoke']
                $null -ne $property -and $property.Value -eq $true
            })
    }
    foreach ($step in $steps) {
        [void][KdbgGuiNative]::SetForegroundWindow($window)
        foreach ($action in @($step.actions)) {
            $type = [string]$action.type
            if ($type -in @('click','replace_text','send_keys')) {
                foreach ($regionProperty in $calibration.regions.PSObject.Properties) {
                    $recentRegionHashes[$regionProperty.Name] = Get-RegionHash (Get-Region $regionProperty.Name $calibration $geometry)
                }
            }
            switch ($type) {
                'wait_window_responsive' {
                    [void](Wait-Window $process ([Math]::Max(1,[int]$action.timeout_ms / 1000)))
                }
                'click' {
                    $pointName = [string](Get-Property $action 'point' '')
                    if (-not [string]::IsNullOrWhiteSpace($pointName)) {
                        Invoke-Click (Get-Point $pointName $calibration $geometry)
                    } else {
                        Invoke-ReferenceClick ([double]$action.x) ([double]$action.y) `
                            $geometry $calibration `
                            ([int](Get-Property $action 'count' 1)) `
                            ([int](Get-Property $action 'interval_ms' 110))
                    }
                    Start-Sleep -Milliseconds 150
                }
                'double_click' {
                    Invoke-ReferenceClick ([double]$action.x) ([double]$action.y) `
                        $geometry $calibration 2 90
                }
                'drag' {
                    Invoke-ReferenceDrag ([double]$action.x) ([double]$action.y) `
                        ([double]$action.end_x) ([double]$action.end_y) `
                        $geometry $calibration
                }
                'scroll' {
                    Invoke-ReferenceScroll ([double]$action.x) ([double]$action.y) `
                        ([int]$action.delta) $geometry $calibration
                }
                'replace_text' {
                    $pointName = [string](Get-Property $action 'point' '')
                    if (-not [string]::IsNullOrWhiteSpace($pointName)) {
                        Invoke-Click (Get-Point $pointName $calibration $geometry)
                    } elseif ($null -ne $action.PSObject.Properties['x'] -and
                        $null -ne $action.PSObject.Properties['y']) {
                        Invoke-ReferenceClick ([double]$action.x) ([double]$action.y) `
                            $geometry $calibration
                    }
                    [Windows.Forms.SendKeys]::SendWait('^a')
                    [Windows.Forms.SendKeys]::SendWait('{BACKSPACE}')
                    [Windows.Forms.Clipboard]::SetText((Resolve-TokenText ([string]$action.value) $session))
                    [Windows.Forms.SendKeys]::SendWait('^v')
                    Start-Sleep -Milliseconds 150
                }
                'send_keys' {
                    [Windows.Forms.SendKeys]::SendWait((Resolve-TokenText ([string]$action.value) $session))
                    Start-Sleep -Milliseconds 150
                }
                'wait' { Start-Sleep -Milliseconds ([int]$action.milliseconds) }
                'drag_until_region_change' {
                    $changed = Invoke-DragUntilReferenceRegionChange @($action.candidates) `
                        $action.region ([int]$action.max_attempts) ([int]$action.settle_ms) `
                        $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; attempts=[int]$changed.attempts
                        x=[double]$changed.x; y=[double]$changed.y
                        end_x=[double]$changed.end_x; end_y=[double]$changed.end_y
                        before_sha256=[string]$changed.before_sha256
                        after_sha256=[string]$changed.after_sha256
                    })
                }
                'click_until_region_change' {
                    $candidates = @($action.candidates)
                    if ($candidates.Count -eq 0) {
                        $candidates = @([pscustomobject]@{ x=[double]$action.x; y=[double]$action.y })
                    }
                    $changed = Invoke-ClickUntilReferenceRegionChange $candidates `
                        $action.region ([int]$action.max_attempts) ([int]$action.settle_ms) `
                        $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; attempts=[int]$changed.attempts
                        x=[double]$changed.x; y=[double]$changed.y
                        before_sha256=[string]$changed.before_sha256
                        after_sha256=[string]$changed.after_sha256
                    })
                    $saveY = [string](Get-Property $action 'save_y_as' '')
                    if (-not [string]::IsNullOrWhiteSpace($saveY)) {
                        $statePointY[$saveY] = [double]$changed.y
                    }
                }
                'click_until_region_stable' {
                    $changed = Invoke-ClickUntilReferenceRegionStable `
                        ([double]$action.x) ([double]$action.y) $action.region `
                        @($action.pre_scrolls) ([int]$action.expected_changes) `
                        ([int]$action.stable_attempts) ([int]$action.max_attempts) `
                        ([int]$action.settle_ms) $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; attempts=[int]$changed.attempts
                        changes=[int]$changed.changes; stable_attempts=[int]$changed.stable_attempts
                        final_sha256=[string]$changed.final_sha256
                    })
                }
                'send_keys_until_region_change' {
                    $changed = Invoke-KeysUntilReferenceRegionChange `
                        (Resolve-TokenText ([string]$action.value) $session) `
                        $action.region ([int]$action.max_attempts) ([int]$action.settle_ms) `
                        $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; attempts=[int]$changed.attempts
                        before_sha256=[string]$changed.before_sha256
                        after_sha256=[string]$changed.after_sha256
                    })
                }
                'click_saved_region_until_change' {
                    $pointKey = [string]$action.point_key
                    if (-not $statePointY.ContainsKey($pointKey)) {
                        throw "Missing saved UI-state point: $pointKey"
                    }
                    $savedY = [double]$statePointY[$pointKey]
                    $candidate = [pscustomobject]@{
                        x=[double]$action.x; y=$savedY
                        region=[pscustomobject]@{
                            x=[double]$action.region_x
                            y=$savedY+[double]$action.region_y_offset
                            width=[double]$action.region_width
                            height=[double]$action.region_height
                        }
                    }
                    $changed = Invoke-ClickUntilReferenceRegionChange @($candidate) $null `
                        ([int]$action.max_attempts) ([int]$action.settle_ms) `
                        $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; attempts=[int]$changed.attempts
                        x=[double]$changed.x; y=[double]$changed.y
                        before_sha256=[string]$changed.before_sha256
                        after_sha256=[string]$changed.after_sha256
                    })
                }
                'click_until_checkbox_state' {
                    $changed = Invoke-ReferenceCheckboxUntilState @($action.candidates) `
                        ([bool]$action.expected_checked) ([int]$action.blue_threshold) `
                        ([int]$action.max_attempts) ([int]$action.settle_ms) `
                        $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; checked=[bool]$changed.checked
                        attempts=[int]$changed.attempts; x=[double]$changed.x; y=[double]$changed.y
                        before_blue_pixels=[int]$changed.before_blue_pixels
                        after_blue_pixels=[int]$changed.after_blue_pixels
                        blue_threshold=[int]$changed.blue_threshold
                    })
                    $saveY = [string](Get-Property $action 'save_y_as' '')
                    if (-not [string]::IsNullOrWhiteSpace($saveY)) {
                        $statePointY[$saveY] = [double]$changed.y
                    }
                }
                'click_unchecked_checkbox_until_checked' {
                    $changed = Invoke-UncheckedReferenceCheckboxUntilChecked $action.scan `
                        ([int]$action.neutral_threshold) ([int]$action.blue_threshold) `
                        ([int]$action.max_attempts) ([int]$action.settle_ms) `
                        $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; checked=[bool]$changed.checked
                        attempts=[int]$changed.attempts; x=[double]$changed.x; y=[double]$changed.y
                        before_unchecked_pixels=[int]$changed.before_unchecked_pixels
                        unchecked_signature=[string]$changed.unchecked_signature
                        after_blue_pixels=[int]$changed.after_blue_pixels
                        neutral_threshold=[int]$action.neutral_threshold
                        blue_threshold=[int]$action.blue_threshold
                    })
                    $saveY = [string](Get-Property $action 'save_y_as' '')
                    if (-not [string]::IsNullOrWhiteSpace($saveY)) {
                        $statePointY[$saveY] = [double]$changed.y
                    }
                }
                'click_saved_checkbox_until_state' {
                    $pointKey = [string]$action.point_key
                    if (-not $statePointY.ContainsKey($pointKey)) {
                        throw "Missing saved checkbox point: $pointKey"
                    }
                    $savedY = [double]$statePointY[$pointKey]
                    $candidate = [pscustomobject]@{
                        x=[double]$action.x; y=$savedY
                        region=[pscustomobject]@{
                            x=[double]$action.region_x
                            y=$savedY+[double]$action.region_y_offset
                            width=[double]$action.region_width
                            height=[double]$action.region_height
                        }
                    }
                    $changed = Invoke-ReferenceCheckboxUntilState @($candidate) `
                        ([bool]$action.expected_checked) ([int]$action.blue_threshold) `
                        ([int]$action.max_attempts) ([int]$action.settle_ms) `
                        $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; checked=[bool]$changed.checked
                        attempts=[int]$changed.attempts; x=[double]$changed.x; y=[double]$changed.y
                        before_blue_pixels=[int]$changed.before_blue_pixels
                        after_blue_pixels=[int]$changed.after_blue_pixels
                        blue_threshold=[int]$changed.blue_threshold
                    })
                }
                'assert_region_blue_pixels' {
                    $blue = Get-StableReferenceBluePixelCount $action.region $calibration $geometry
                    $minimum = [int](Get-Property $action 'minimum' 0)
                    $maximum = [int](Get-Property $action 'maximum' ([int]::MaxValue))
                    if ($blue -lt $minimum -or $blue -gt $maximum) {
                        throw "UI region blue-pixel assertion failed: $blue not in [$minimum,$maximum]"
                    }
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; assertion=[string]$action.assertion
                        kind=$type; success=$true; blue_pixels=$blue
                        minimum=$minimum; maximum=$maximum
                    })
                }
                'wait_region_change' {
                    $regionName = [string]$action.region
                    if (-not $recentRegionHashes.ContainsKey($regionName)) {
                        throw "No pre-action baseline exists for region: $regionName"
                    }
                    $currentHash = Wait-RegionChange (Get-Region $regionName $calibration $geometry) `
                        ([string]$recentRegionHashes[$regionName]) ([int]$action.timeout_ms)
                    $assertions.Add([ordered]@{ name="region_change:$regionName"; passed=$true; hash=$currentHash })
                }
                'wait_region_stable' {
                    $regionName = [string]$action.region
                    $stableHash = Wait-RegionStable (Get-Region $regionName $calibration $geometry) `
                        ([int]$action.stable_samples) ([int]$action.timeout_ms)
                    $assertions.Add([ordered]@{ name="region_stable:$regionName"; passed=$true; hash=$stableHash })
                }
                'fixture_command' {
                    $command = Resolve-TokenText ([string]$action.command) $session
                    $response = Invoke-FixtureCommand ([string]$session.fixture_pipe_name) $command
                    $fixtureCommands.Add([ordered]@{ step_id=[string]$step.id; command=$command; response=$response })
                    $saveCurrentCrcAs = [string](Get-Property $action 'save_current_crc_as' '')
                    if (-not [string]::IsNullOrWhiteSpace($saveCurrentCrcAs)) {
                        if ($saveCurrentCrcAs -ceq 'freeze_value_crc32' -and
                            [string]$response.current_crc32 -ine
                            [string]$session.fixture_freeze_expected_crc32) {
                            throw "Fixture mutation CRC does not match the session-bound freeze CRC: expected $($session.fixture_freeze_expected_crc32); actual $($response.current_crc32)"
                        }
                        $assertions.Add([ordered]@{
                            step=[string]$step.id
                            name="runtime_crc_bound:$saveCurrentCrcAs"
                            kind=$type; passed=$true; success=$true
                            actual=[string]$response.current_crc32
                        })
                    }
                }
                'wait_fixture_crc' {
                    $expected = Resolve-TokenText ([string]$action.expected_crc32) $session
                    $deadline = [DateTime]::UtcNow.AddMilliseconds([int]$action.timeout_ms)
                    $response = $null
                    do {
                        $response = Invoke-FixtureCommand ([string]$session.fixture_pipe_name) 'INFO'
                        if ([string]$response.current_crc32 -ieq $expected) { break }
                        Start-Sleep -Milliseconds ([int]$action.poll_ms)
                    } while ([DateTime]::UtcNow -lt $deadline)
                    if ([string]$response.current_crc32 -ine $expected) {
                        throw "Fixture CRC did not reach expected state: expected $expected; actual $($response.current_crc32)"
                    }
                    $fixtureCommands.Add([ordered]@{ step_id=[string]$step.id; command='INFO'; response=$response })
                    $assertions.Add([ordered]@{
                        step=[string]$step.id
                        name=if ($null -ne $action.PSObject.Properties['assertion']) { [string]$action.assertion } else { 'fixture_crc' }
                        kind=$type; passed=$true; success=$true; expected=$expected
                        actual=[string]$response.current_crc32
                    })
                }
                'save_relative_region_hash' {
                    $pointKey = [string]$action.point_key
                    if (-not $statePointY.ContainsKey($pointKey)) {
                        throw "Missing saved UI-state point: $pointKey"
                    }
                    $region = [pscustomobject]@{
                        x=[double]$action.x
                        y=[double]$statePointY[$pointKey]+[double]$action.y_offset
                        width=[double]$action.width; height=[double]$action.height
                    }
                    $regionKey = [string]$action.region_key
                    $stateRegionHashes[$regionKey] = Get-StableReferenceRegionHash `
                        $region $calibration $geometry
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; name=[string]$action.assertion
                        kind=$type; passed=$true; success=$true
                        region_sha256=[string]$stateRegionHashes[$regionKey]
                    })
                }
                'wait_relative_region_change' {
                    $pointKey = [string]$action.point_key
                    $regionKey = [string]$action.region_key
                    if (-not $statePointY.ContainsKey($pointKey) -or
                        -not $stateRegionHashes.ContainsKey($regionKey)) {
                        throw "Missing saved UI-state point or region: $pointKey / $regionKey"
                    }
                    $region = [pscustomobject]@{
                        x=[double]$action.x
                        y=[double]$statePointY[$pointKey]+[double]$action.y_offset
                        width=[double]$action.width; height=[double]$action.height
                    }
                    $before = [string]$stateRegionHashes[$regionKey]
                    $deadline = [DateTime]::UtcNow.AddMilliseconds([int]$action.timeout_ms)
                    $polls = 0
                    do {
                        Start-Sleep -Milliseconds ([int]$action.poll_ms)
                        $after = Get-StableReferenceRegionHash $region $calibration $geometry
                        ++$polls
                        if ($after -cne $before) { break }
                    } while ([DateTime]::UtcNow -lt $deadline)
                    if ($after -ceq $before) { throw "UI value region did not change: $regionKey" }
                    $assertions.Add([ordered]@{
                        step=[string]$step.id; name=[string]$action.assertion
                        kind=$type; passed=$true; success=$true; polls=$polls
                        before_sha256=$before; after_sha256=$after
                    })
                }
                'capture' {
                    $capturePath = Join-Path $capturesRoot ([string]$step.file)
                    Save-ScreenRegion ([Drawing.Rectangle]::new(0,0,$screen.Width,$screen.Height)) $capturePath
                    $captureHash = Get-Sha256 $capturePath
                    $expectVisualChange = [bool](Get-Property $step 'expect_visual_change' $true)
                    if ($captures.Count -gt 0 -and $expectVisualChange -and
                        [string]$captures[$captures.Count-1].sha256 -ceq $captureHash) {
                        throw "Semantic-transition frame is byte-identical to its predecessor: $($step.id)"
                    }
                    $captures.Add([ordered]@{
                        step_id=[string]$step.id; scene_id=[string]$step.scene_id
                        phase=[string]$step.phase; duration_ms=[int]$step.duration_ms
                        file=[string]$step.file; sha256=$captureHash
                        bytes=(Get-Item -LiteralPath $capturePath).Length
                        captured_utc=[DateTime]::UtcNow.ToString('o')
                        expect_visual_change=$expectVisualChange
                        width=$screen.Width; height=$screen.Height
                    })
                }
                default { throw "Unsupported capture-plan action: $type" }
            }
            $actionTrace.Add([ordered]@{
                step_id=[string]$step.id; type=$type
                completed_utc=[DateTime]::UtcNow.ToString('o')
            })
            Start-Sleep -Milliseconds 140
        }
    }

    if (Test-Path -LiteralPath $diagnosticLogSource -PathType Leaf) {
        Copy-Item -LiteralPath $diagnosticLogSource -Destination $diagnosticLogEvidence -Force
    }

    $archivePath = Join-Path $evidenceFull 'captures.zip'
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $capturesRoot '*.png') -DestinationPath $archivePath -CompressionLevel Optimal
    $status = if ($CalibrationSmoke) { 'CALIBRATION_SMOKE_NOT_EVIDENCE' } else { 'CAPTURED_UNREVIEWED' }
    $result = [ordered]@{
        schema='kdbg.win11-extended-gui-capture-result.v1'
        harness_valid=$true
        live_capture_status=$status
        evidence_pass=$false
        human_review_complete=$false
        calibration_smoke=[bool]$CalibrationSmoke
        package_root=$packageFull
        package_exe_sha256=Get-Sha256 $exePath
        plan_sha256=Get-Sha256 $planFull
        calibration_sha256=Get-Sha256 $calibrationFull
        session_sha256=Get-Sha256 $sessionFull
        capture_count=$captures.Count
        frame_count=$captures.Count
        scene_count=@($captures | ForEach-Object { $_.scene_id } | Select-Object -Unique).Count
        total_duration_ms=$plannedDurationMs
        execution_identity=$captureExecution
        live_readiness_diagnostics=$readinessDiagnostics
        diagnostic_log=if (Test-Path -LiteralPath $diagnosticLogEvidence -PathType Leaf) {
            [ordered]@{ file='kdbg-ui.log'; sha256=Get-Sha256 $diagnosticLogEvidence }
        } else { $null }
        captures=@($captures)
        fixture_commands=@($fixtureCommands)
        ui_state_assertions=@($assertions)
        action_trace=@($actionTrace)
        capture_archive=[ordered]@{ path=$archivePath; sha256=Get-Sha256 $archivePath }
        completed_utc=[DateTime]::UtcNow.ToString('o')
    }
    Write-Json $resultFull $result
    $result | ConvertTo-Json -Depth 30
} catch {
    try {
        if (Test-Path -LiteralPath $diagnosticLogSource -PathType Leaf) {
            Copy-Item -LiteralPath $diagnosticLogSource -Destination $diagnosticLogEvidence -Force
        }
    } catch {}
    $failurePath = Join-Path $evidenceFull 'capture-failure.png'
    try {
        $screen = [Windows.Forms.Screen]::PrimaryScreen.Bounds
        Save-ScreenRegion ([Drawing.Rectangle]::new(0,0,$screen.Width,$screen.Height)) $failurePath
    } catch {}
    $partialPath = Join-Path $evidenceFull 'capture-run-partial.json'
    $partial = [ordered]@{
        schema='kdbg.win11-extended-gui-capture-partial.v1'
        live_capture_status='FAILED'
        evidence_pass=$false
        human_review_complete=$false
        error=$_.Exception.Message
        execution_identity=$captureExecution
        live_readiness_diagnostics=$readinessDiagnostics
        diagnostic_log=if (Test-Path -LiteralPath $diagnosticLogEvidence -PathType Leaf) {
            [ordered]@{ file='kdbg-ui.log'; sha256=Get-Sha256 $diagnosticLogEvidence }
        } else { $null }
        captures=@($captures)
        fixture_commands=@($fixtureCommands)
        ui_state_assertions=@($assertions)
        action_trace=@($actionTrace)
        failure_capture=if (Test-Path -LiteralPath $failurePath -PathType Leaf) {
            [ordered]@{ path=$failurePath; sha256=Get-Sha256 $failurePath }
        } else { $null }
        completed_utc=[DateTime]::UtcNow.ToString('o')
    }
    try { Write-Json $partialPath $partial } catch {}
    [IO.File]::WriteAllText($errorFull, ($_ | Out-String), [Text.UTF8Encoding]::new($false))
    throw
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        try { [void][KdbgGuiNative]::PostMessage($process.MainWindowHandle,0x0010,[IntPtr]::Zero,[IntPtr]::Zero) } catch {}
        try { if (-not $process.WaitForExit(5000)) { $process.Kill() } } catch {}
    }
}

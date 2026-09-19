[CmdletBinding()]
param([string]$OutputPath = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Json([string]$Path, [object]$Value) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText(
        [IO.Path]::GetFullPath($Path),
        ($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

function Convert-PlanNumber([object]$Value, [string]$Context) {
    try { $number = [Convert]::ToDouble($Value,[Globalization.CultureInfo]::InvariantCulture) }
    catch { throw "$Context is not numeric." }
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
        throw "$Context is not a finite number."
    }
    $number
}

function Assert-PlanPoint([object]$Value, [object]$Calibration, [string]$Context,
        [Collections.Generic.List[double]]$Xs, [Collections.Generic.List[double]]$Ys) {
    if ($Value -is [string]) {
        $property = $Calibration.points.PSObject.Properties[[string]$Value]
        if ($null -eq $property) { throw "Unknown coordinate key: $Value" }
        $Value = $property.Value
    }
    if ($null -eq $Value -or $null -eq $Value.PSObject.Properties['x'] -or
        $null -eq $Value.PSObject.Properties['y']) {
        throw "$Context must be a named calibration point or an inline x/y point."
    }
    $x = Convert-PlanNumber $Value.x "$Context.x"
    $y = Convert-PlanNumber $Value.y "$Context.y"
    if ($x -lt 0 -or $x -ge [double]$Calibration.client.width -or
        $y -lt 0 -or $y -ge [double]$Calibration.client.height) {
        throw "$Context escaped the calibrated client bounds: ($x,$y)."
    }
    [void]$Xs.Add($x); [void]$Ys.Add($y)
}

function Assert-PlanRegion([object]$Value, [object]$Calibration, [string]$Context,
        [Collections.Generic.List[double]]$Xs, [Collections.Generic.List[double]]$Ys) {
    if ($Value -is [string]) {
        $property = $Calibration.regions.PSObject.Properties[[string]$Value]
        if ($null -eq $property) { throw "Unknown region key: $Value" }
        $Value = $property.Value
    }
    if ($null -eq $Value -or $null -eq $Value.PSObject.Properties['x'] -or
        $null -eq $Value.PSObject.Properties['y'] -or
        $null -eq $Value.PSObject.Properties['width'] -or
        $null -eq $Value.PSObject.Properties['height']) {
        throw "$Context must be a named calibration region or a complete inline rectangle."
    }
    $x = Convert-PlanNumber $Value.x "$Context.x"
    $y = Convert-PlanNumber $Value.y "$Context.y"
    $width = Convert-PlanNumber $Value.width "$Context.width"
    $height = Convert-PlanNumber $Value.height "$Context.height"
    $right = $x + $width; $bottom = $y + $height
    if ($x -lt 0 -or $y -lt 0 -or $width -le 0 -or $height -le 0 -or
        $right -gt [double]$Calibration.client.width -or
        $bottom -gt [double]$Calibration.client.height) {
        throw "$Context escaped the calibrated client bounds: ($x,$y,$width,$height)."
    }
    [void]$Xs.Add($x); [void]$Xs.Add($right)
    [void]$Ys.Add($y); [void]$Ys.Add($bottom)
}

$root = [IO.Path]::GetFullPath($PSScriptRoot)
$requiredFiles = @(
    'Invoke-HyperVWin11GuiCapture.ps1','guest-run.ps1','ui-task.ps1','ui-action.ps1',
    'Invoke-HyperVWin11GuiOrchestrator.ps1','Prepare-Win11GuiGuest.ps1',
    'Invoke-Win11GuiGuestCapture.ps1','interactive-bootstrap.ps1',
    'Clear-Win11AutoLogonAfterExplorer.ps1',
    'capture-plan.json','calibration.win11-1024x768-v1.json','README.md'
)
foreach ($name in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $name) -PathType Leaf)) {
        throw "Missing harness file: $name"
    }
}

$parseResults = [Collections.Generic.List[object]]::new()
$forbiddenAssignments = @('error','host','pid','home','pshome','psscriptroot','pscommandpath','true','false','null')
foreach ($script in @(Get-ChildItem -LiteralPath $root -Filter '*.ps1' -File | Sort-Object Name)) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $script.FullName,[ref]$tokens,[ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) {
        throw "PowerShell parse failed: $($script.Name): $($parseErrors -join '; ')"
    }
    foreach ($assignment in @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.AssignmentStatementAst]
            },$true))) {
        $left = ([string]$assignment.Left.Extent.Text).Trim()
        if ($left -match '^\$([A-Za-z][A-Za-z0-9]*)$' -and
            $forbiddenAssignments -contains $Matches[1].ToLowerInvariant()) {
            throw "Read-only/automatic variable assignment: $($script.Name): $left"
        }
    }
    $parseResults.Add([ordered]@{ file=$script.Name; parse_errors=0 })
}

$runtimeFiles = @('Invoke-HyperVWin11GuiCapture.ps1','Invoke-HyperVWin11GuiOrchestrator.ps1',
    'Prepare-Win11GuiGuest.ps1','Invoke-Win11GuiGuestCapture.ps1','interactive-bootstrap.ps1',
    'Clear-Win11AutoLogonAfterExplorer.ps1',
    'guest-run.ps1','ui-task.ps1','ui-action.ps1',
    'capture-plan.json','calibration.win11-1024x768-v1.json')
$allText = @($runtimeFiles | ForEach-Object {
        Get-Content -LiteralPath (Join-Path $root $_) -Raw
    }) -join "`n"
foreach ($forbidden in @('VMware','192.168.','public-symbols-r1-live-analysis')) {
    if ($allText.IndexOf($forbidden,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Harness retains a forbidden environment-specific value: $forbidden"
    }
}

$planPath = Join-Path $root 'capture-plan.json'
$calibrationPath = Join-Path $root 'calibration.win11-1024x768-v1.json'
$planText = Get-Content -LiteralPath $planPath -Raw
$plan = $planText | ConvertFrom-Json
$calibration = Get-Content -LiteralPath $calibrationPath -Raw | ConvertFrom-Json
if ([string]$plan.schema -cne 'kdbg.win11-extended-gui-capture-plan.v1') { throw 'Plan schema mismatch.' }
if ([string]$calibration.schema -cne 'kdbg.win11-gui-calibration.v1') { throw 'Calibration schema mismatch.' }
if ([bool]$calibration.calibrated) {
    if ([string]$calibration.calibration_status -cne 'CALIBRATED_WIN11_SMOKE_REVIEWED' -or
        [string]::IsNullOrWhiteSpace([string]$calibration.validated_utc) -or
        [string]::IsNullOrWhiteSpace([string]$calibration.validated_build_id)) {
        throw 'A calibrated profile requires reviewed status, UTC, and exact build identity.'
    }
} elseif ([string]$calibration.calibration_status -cne 'UNCALIBRATED_WIN11_SMOKE_REQUIRED') {
    throw 'An uncalibrated profile must retain the explicit smoke-required status.'
}
if ([int]$calibration.display.width -ne 1024 -or [int]$calibration.display.height -ne 768 -or
    [int]$calibration.display.dpi -ne 96 -or [int]$calibration.client.width -ne 1024 -or
    [int]$calibration.client.height -ne 697) {
    throw 'Calibration must retain the deterministic 1024x768/96-DPI/1024x697-client contract.'
}
if ([int]$plan.reference_size.width -ne 1024 -or [int]$plan.reference_size.height -ne 697 -or
    [int]$plan.expected_capture_size.width -ne 1024 -or
    [int]$plan.expected_capture_size.height -ne 768 -or
    [string]$plan.profile -cne 'windows-11-client-1024x697-capture-1024x768-default-dock-calibration-v2') {
    throw 'Capture plan and profile dimensions do not match the ported Win11 geometry.'
}

$profileXs = [Collections.Generic.List[double]]::new()
$profileYs = [Collections.Generic.List[double]]::new()
foreach ($property in @($calibration.points.PSObject.Properties)) {
    Assert-PlanPoint $property.Value $calibration "calibration.points.$($property.Name)" $profileXs $profileYs
}
foreach ($property in @($calibration.regions.PSObject.Properties)) {
    Assert-PlanRegion $property.Value $calibration "calibration.regions.$($property.Name)" $profileXs $profileYs
}

$steps = @($plan.steps)
$scenes = @($steps | ForEach-Object { [string]$_.scene_id } | Select-Object -Unique)
if ($steps.Count -ne 24 -or $scenes.Count -ne 20 -or @($plan.required_scene_order).Count -ne 20) {
    throw 'Capture plan must contain 24 frames covering 20 unique required scenes.'
}
if (Compare-Object -ReferenceObject @($plan.required_scene_order) -DifferenceObject $scenes -SyncWindow 0) {
    throw 'Capture step scene order does not match the required 20-scene order.'
}
$plannedDuration = [int](($steps | Measure-Object -Property duration_ms -Sum).Sum)
if ($plannedDuration -ne 40500) { throw "Capture plan duration must remain exactly 40500 ms; actual $plannedDuration." }
$files = @($steps | ForEach-Object { [string]$_.file })
if (@($files | Select-Object -Unique).Count -ne 24) { throw 'Capture PNG names must be unique.' }
foreach ($file in $files) {
    if ([IO.Path]::GetFileName($file) -cne $file -or [IO.Path]::GetExtension($file) -cne '.png') {
        throw "Unsafe capture file name: $file"
    }
}
$allActions = @($steps | ForEach-Object actions)
$observedActionTypes = @($allActions | ForEach-Object { [string]$_.type } | Sort-Object -Unique)
$expectedActionTypes = @(
    'assert_region_blue_pixels','capture','click','click_saved_checkbox_until_state',
    'click_unchecked_checkbox_until_checked','click_until_checkbox_state',
    'click_until_region_change','click_until_region_stable',
    'drag','drag_until_region_change','fixture_command','replace_text','save_relative_region_hash',
    'scroll','send_keys','send_keys_until_region_change','wait','wait_fixture_crc',
    'wait_relative_region_change','wait_window_responsive')
if (Compare-Object -ReferenceObject $expectedActionTypes -DifferenceObject $observedActionTypes) {
    throw 'Capture plan does not exercise the complete ported action-type set.'
}
$provenActionTypes = @($observedActionTypes | Where-Object { $_ -cne 'wait_window_responsive' })
if ($provenActionTypes.Count -ne 19 -or
    @($allActions | Where-Object type -eq 'wait_window_responsive').Count -ne 1 -or
    @($allActions | Where-Object type -eq 'capture').Count -ne 24) {
    throw 'Capture plan must retain 19 proven action types plus explicit readiness/capture coverage.'
}
$inlinePointCount = @($allActions | Where-Object {
        $null -ne $_.PSObject.Properties['x'] -and $null -ne $_.PSObject.Properties['y']
    }).Count
$inlineRegionCount = @($allActions | Where-Object {
        $value = $_.PSObject.Properties['region']
        $null -ne $value -and $value.Value -isnot [string]
    }).Count
$candidateSetCount = @($allActions | Where-Object { $null -ne $_.PSObject.Properties['candidates'] }).Count
$preScrollSetCount = @($allActions | Where-Object { $null -ne $_.PSObject.Properties['pre_scrolls'] }).Count
if ($inlinePointCount -lt 1 -or $inlineRegionCount -lt 1 -or
    $candidateSetCount -lt 1 -or $preScrollSetCount -lt 1) {
    throw 'Ported plan must exercise inline points, regions, candidates, and pre-scrolls.'
}
foreach ($step in $steps) {
    if (@($step.actions | Where-Object type -eq 'capture').Count -ne 1) {
        throw "Every plan step must contain exactly one capture action: $($step.id)"
    }
}

# Keep the two 1024-wide readability fixes source-bound. These pane changes are
# deliberately bracketed around capture so they do not leak into later scenes.
$scene03 = @($steps | Where-Object id -ceq '03-physical-read-4096')
$scene20 = @($steps | Where-Object id -ceq '20-snapshot-diff')
if ($scene03.Count -ne 1 -or $scene20.Count -ne 1) {
    throw 'Readability contract requires the exact scene 03 and scene 20 steps.'
}
$scene03Actions = @($scene03[0].actions)
$scene20Actions = @($scene20[0].actions)
$scene03Capture = [Array]::FindIndex(
    $scene03Actions, [Predicate[object]]{ param($action) [string]$action.type -ceq 'capture' })
$scene20Capture = [Array]::FindIndex(
    $scene20Actions, [Predicate[object]]{ param($action) [string]$action.type -ceq 'capture' })
if ($scene03Capture -lt 0 -or $scene20Capture -lt 0) {
    throw 'Readability contract requires capture actions in scene 03 and scene 20.'
}
function Test-ExactReadabilityDrag([object]$Action, [string]$Assertion,
        [int]$X, [int]$Y, [int]$EndX, [int]$EndY) {
    $Action.PSObject.Properties['assertion'] -and
        $Action.PSObject.Properties['x'] -and
        $Action.PSObject.Properties['y'] -and
        $Action.PSObject.Properties['end_x'] -and
        $Action.PSObject.Properties['end_y'] -and
        [string]$Action.type -ceq 'drag' -and
        [string]$Action.assertion -ceq $Assertion -and
        [int]$Action.x -eq $X -and [int]$Action.y -eq $Y -and
        [int]$Action.end_x -eq $EndX -and [int]$Action.end_y -eq $EndY
}
$readabilityContracts = [ordered]@{
    scene03_left_collapse_before_capture = @($scene03Actions | Select-Object -First $scene03Capture |
        Where-Object { Test-ExactReadabilityDrag $_ 'minimal_scene03_left_collapse' 259 350 72 350 }).Count -eq 1
    scene03_right_collapse_before_capture = @($scene03Actions | Select-Object -First $scene03Capture |
        Where-Object { Test-ExactReadabilityDrag $_ 'minimal_scene03_right_collapse' 777 350 992 350 }).Count -eq 1
    scene03_left_restore_after_capture = @($scene03Actions | Select-Object -Skip ($scene03Capture + 1) |
        Where-Object { Test-ExactReadabilityDrag $_ 'minimal_scene03_left_restore' 72 350 259 350 }).Count -eq 1
    scene03_right_restore_after_capture = @($scene03Actions | Select-Object -Skip ($scene03Capture + 1) |
        Where-Object { Test-ExactReadabilityDrag $_ 'minimal_scene03_right_restore' 992 350 777 350 }).Count -eq 1
    scene20_expand_before_capture = @($scene20Actions | Select-Object -First $scene20Capture |
        Where-Object { Test-ExactReadabilityDrag $_ 'minimal_scene20_bottom_expand' 600 427 600 250 }).Count -eq 1
    scene20_scroll_before_capture = @($scene20Actions | Select-Object -First $scene20Capture |
        Where-Object {
            $null -ne $_.PSObject.Properties['assertion'] -and
            [string]$_.assertion -ceq 'minimal_scene20_diff_scroll' -and
            [string]$_.type -ceq 'scroll' -and [int]$_.delta -eq -2400
        }).Count -eq 2
    scene20_restore_after_capture = @($scene20Actions | Select-Object -Skip ($scene20Capture + 1) |
        Where-Object { Test-ExactReadabilityDrag $_ 'minimal_scene20_bottom_restore' 600 250 600 427 }).Count -eq 1
}
foreach ($contract in $readabilityContracts.GetEnumerator()) {
    if ($contract.Value -ne $true) {
        throw "Source-bound 1024-wide readability contract failed: $($contract.Key)"
    }
}

$planXs = [Collections.Generic.List[double]]::new()
$planYs = [Collections.Generic.List[double]]::new()
foreach ($step in $steps) {
    foreach ($action in @($step.actions)) {
        $context = "$($step.id)/$($action.type)"
        $point = $action.PSObject.Properties['point']
        if ($null -ne $point) {
            Assert-PlanPoint $point.Value $calibration "$context.point" $planXs $planYs
        }
        $xProperty = $action.PSObject.Properties['x']; $yProperty = $action.PSObject.Properties['y']
        if ($null -ne $xProperty -and $null -ne $yProperty) {
            Assert-PlanPoint ([pscustomobject]@{ x=$xProperty.Value; y=$yProperty.Value }) `
                $calibration "$context.inline" $planXs $planYs
        } elseif ($null -ne $xProperty) {
            $x = Convert-PlanNumber $xProperty.Value "$context.x"
            if ($x -lt 0 -or $x -ge [double]$calibration.client.width) { throw "$context.x escaped client bounds." }
            [void]$planXs.Add($x)
        } elseif ($null -ne $yProperty) {
            $y = Convert-PlanNumber $yProperty.Value "$context.y"
            if ($y -lt 0 -or $y -ge [double]$calibration.client.height) { throw "$context.y escaped client bounds." }
            [void]$planYs.Add($y)
        }
        $endX = $action.PSObject.Properties['end_x']; $endY = $action.PSObject.Properties['end_y']
        if (($null -ne $endX) -xor ($null -ne $endY)) { throw "$context has an incomplete drag endpoint." }
        if ($null -ne $endX) {
            Assert-PlanPoint ([pscustomobject]@{ x=$endX.Value; y=$endY.Value }) `
                $calibration "$context.end" $planXs $planYs
        }
        $region = $action.PSObject.Properties['region']
        if ($null -ne $region) {
            Assert-PlanRegion $region.Value $calibration "$context.region" $planXs $planYs
        }
        $candidateProperty = $action.PSObject.Properties['candidates']
        $candidates = if ($null -eq $candidateProperty) { @() } else { @($candidateProperty.Value) }
        foreach ($candidate in $candidates) {
            Assert-PlanPoint $candidate $calibration "$context.candidate" $planXs $planYs
            $candidateEndX = $candidate.PSObject.Properties['end_x']
            $candidateEndY = $candidate.PSObject.Properties['end_y']
            if (($null -ne $candidateEndX) -xor ($null -ne $candidateEndY)) {
                throw "$context candidate has an incomplete drag endpoint."
            }
            if ($null -ne $candidateEndX) {
                Assert-PlanPoint ([pscustomobject]@{ x=$candidateEndX.Value; y=$candidateEndY.Value }) `
                    $calibration "$context.candidate.end" $planXs $planYs
            }
            $candidateRegion = $candidate.PSObject.Properties['region']
            if ($null -ne $candidateRegion) {
                Assert-PlanRegion $candidateRegion.Value $calibration "$context.candidate.region" $planXs $planYs
            }
        }
        $preScrollProperty = $action.PSObject.Properties['pre_scrolls']
        $preScrolls = if ($null -eq $preScrollProperty) { @() } else { @($preScrollProperty.Value) }
        foreach ($preScroll in $preScrolls) {
            Assert-PlanPoint $preScroll $calibration "$context.pre_scroll" $planXs $planYs
            if ($null -eq $preScroll.PSObject.Properties['delta'] -or
                [Math]::Abs([int]$preScroll.delta) -gt 4000 -or [int]$preScroll.delta -eq 0) {
                throw "$context has an invalid pre-scroll delta."
            }
        }
        $scan = $action.PSObject.Properties['scan']
        if ($null -ne $scan) {
            $scanValue = $scan.Value
            foreach ($scanY in @($scanValue.start_y,$scanValue.end_y)) {
                Assert-PlanPoint ([pscustomobject]@{ x=$scanValue.x; y=$scanY }) `
                    $calibration "$context.scan" $planXs $planYs
            }
            if ([double]$scanValue.end_y -le [double]$scanValue.start_y -or
                [double]$scanValue.box_size -le 0) { throw "$context has invalid scan bounds." }
        }
        $attempts = $action.PSObject.Properties['max_attempts']
        if ($null -ne $attempts) {
            $attemptLimit = switch ([string]$action.type) {
                'click_until_region_change' { 12 }
                'drag_until_region_change' { 8 }
                'click_until_region_stable' { 24 }
                'send_keys_until_region_change' { 4 }
                'click_unchecked_checkbox_until_checked' { 8 }
                'click_saved_checkbox_until_state' { 8 }
                default { 24 }
            }
            if ([int]$attempts.Value -lt 1 -or [int]$attempts.Value -gt $attemptLimit) {
                throw "$context max_attempts is outside its bounded 1..$attemptLimit range."
            }
        }
        $timeout = $action.PSObject.Properties['timeout_ms']
        if ($null -ne $timeout -and ([int]$timeout.Value -lt 1 -or [int]$timeout.Value -gt 30000)) {
            throw "$context timeout_ms is outside the bounded 1..30000 range."
        }
        $poll = $action.PSObject.Properties['poll_ms']
        if ($null -ne $poll -and ([int]$poll.Value -lt 1 -or
                ($null -ne $timeout -and [int]$poll.Value -gt [int]$timeout.Value))) {
            throw "$context poll_ms is invalid for its timeout."
        }
        $settle = $action.PSObject.Properties['settle_ms']
        if ($null -ne $settle -and ([int]$settle.Value -lt 1 -or [int]$settle.Value -gt 5000)) {
            throw "$context settle_ms is outside the bounded 1..5000 range."
        }
        $milliseconds = $action.PSObject.Properties['milliseconds']
        if ($null -ne $milliseconds -and ([int]$milliseconds.Value -lt 1 -or
                [int]$milliseconds.Value -gt 45000)) {
            throw "$context wait is outside the bounded 1..45000 ms range."
        }
    }
}
if ([int]$plan.execution_timeout_seconds -ne 3600 -or [int]$plan.launch_timeout_seconds -ne 90) {
    throw 'Plan execution and launch timeouts must retain the bounded 3600s/90s contract.'
}
$maxPlanY = [double](($planYs | Measure-Object -Maximum).Maximum)
$maxProfilePointY = [double](($calibration.points.PSObject.Properties.Value.y | Measure-Object -Maximum).Maximum)
$maxProfileRegionBottom = [double](($calibration.regions.PSObject.Properties.Value | ForEach-Object {
                [double]$_.y + [double]$_.height
            } | Measure-Object -Maximum).Maximum)
if ($maxPlanY -ne 680 -or $maxProfilePointY -ne 664 -or $maxProfileRegionBottom -ne 697) {
    throw "Ported bottom-coordinate/profile bounds changed: plan=$maxPlanY point=$maxProfilePointY region=$maxProfileRegionBottom."
}
$expectedPlanTokens = @(
    'session.fixture_baseline_crc32','session.fixture_code_address_hex',
    'session.fixture_freeze_expected_crc32','session.fixture_info_path','session.fixture_pid',
    'session.fixture_pointer_target_hex','session.fixture_scan_offset',
    'session.fixture_scan_value','session.fixture_snapshot_offset',
    'session.fixture_virtual_address_hex','session.kernel_pdb_path','session.probe_pfn_hex')
$planTokens = @([regex]::Matches($planText,'\$\{([^}]+)\}') | ForEach-Object {
        $_.Groups[1].Value
    } | Sort-Object -Unique)
if (Compare-Object -ReferenceObject $expectedPlanTokens -DifferenceObject $planTokens) {
    throw 'Capture plan runtime-token set is incomplete or contains an unsupported token.'
}

$typedPfn = @($steps | Where-Object scene_id -eq 'typed_pfn_unlock' | ForEach-Object actions |
    Where-Object { $_.type -eq 'replace_text' -and $_.value -ceq '${session.probe_pfn_hex}' })
$physicalApply = @($steps | Where-Object scene_id -eq 'write_and_readback' | ForEach-Object actions |
    Where-Object {
        if ($_.type -ne 'click') { return $false }
        $pointProperty = $_.PSObject.Properties['point']
        if ($null -ne $pointProperty -and [string]$pointProperty.Value -ceq 'physical.apply') {
            return $true
        }
        $xProperty = $_.PSObject.Properties['x']; $yProperty = $_.PSObject.Properties['y']
        $null -ne $xProperty -and $null -ne $yProperty -and
            [double]$xProperty.Value -eq [double]$calibration.points.'physical.apply'.x -and
            [double]$yProperty.Value -eq [double]$calibration.points.'physical.apply'.y
    })
$rollback = @($steps | Where-Object scene_id -eq 'rollback_baseline' | ForEach-Object actions |
    Where-Object { $_.type -eq 'replace_text' -and $_.value -ceq '${session.probe_pfn_hex}' })
$typedPid = @($steps | Where-Object scene_id -eq 'address_list_verified_freeze' | ForEach-Object actions |
    Where-Object { $_.type -eq 'replace_text' -and $_.value -ceq '${session.fixture_pid}' })
$fixtureCrcChecks = @($steps | ForEach-Object actions | Where-Object type -eq 'wait_fixture_crc')
if ($typedPfn.Count -ne 1 -or $physicalApply.Count -ne 1 -or $rollback.Count -ne 1 -or
    $typedPid.Count -ne 1 -or $fixtureCrcChecks.Count -ne 2) {
    throw 'Write/rollback/PID/freeze confirmation contracts are incomplete.'
}
$smokeSteps = @($steps | Where-Object {
        $property = $_.PSObject.Properties['safe_for_uncalibrated_smoke']
        $null -ne $property -and $property.Value -eq $true
    })
if ($smokeSteps.Count -ne 1 -or [string]$smokeSteps[0].scene_id -cne 'driver_probe_ready') {
    throw 'Uncalibrated smoke mode must expose only the non-destructive overview frame.'
}

$orchestratorText = Get-Content -LiteralPath (Join-Path $root 'Invoke-HyperVWin11GuiOrchestrator.ps1') -Raw
$prepareText = Get-Content -LiteralPath (Join-Path $root 'Prepare-Win11GuiGuest.ps1') -Raw
$captureText = Get-Content -LiteralPath (Join-Path $root 'Invoke-Win11GuiGuestCapture.ps1') -Raw
$bootstrapText = Get-Content -LiteralPath (Join-Path $root 'interactive-bootstrap.ps1') -Raw
$uiActionText = Get-Content -LiteralPath (Join-Path $root 'ui-action.ps1') -Raw
$uiTaskText = Get-Content -LiteralPath (Join-Path $root 'ui-task.ps1') -Raw
$autoLogonCleanupText = Get-Content -LiteralPath (Join-Path $root 'Clear-Win11AutoLogonAfterExplorer.ps1') -Raw
$uiWriteJsonFunction = [regex]::Match(
    $uiActionText,
    '(?ms)^function Write-Json\(.*?(?=^function Get-Sha256\()')
if (-not $uiWriteJsonFunction.Success) {
    throw 'ui-action Write-Json function is missing.'
}
$uiWriteJsonText = $uiWriteJsonFunction.Value
$uiWriteJsonTemporary = $uiWriteJsonText.IndexOf(
    '$temporaryFull = Join-Path $parent (',
    [StringComparison]::Ordinal)
$uiWriteJsonWrite = $uiWriteJsonText.IndexOf(
    '[IO.File]::WriteAllText(',
    [StringComparison]::Ordinal)
$uiWriteJsonMove = $uiWriteJsonText.IndexOf(
    'Move-Item -LiteralPath $temporaryFull -Destination $targetFull -Force',
    [StringComparison]::Ordinal)
$uiWriteJsonCatchCleanup = $uiWriteJsonText.IndexOf(
    'Remove-Item -LiteralPath $temporaryFull -Force -ErrorAction SilentlyContinue',
    $uiWriteJsonMove,
    [StringComparison]::Ordinal)
$uiWriteJsonRethrow = $uiWriteJsonText.IndexOf(
    'throw',
    $uiWriteJsonCatchCleanup,
    [StringComparison]::Ordinal)
if ($uiWriteJsonTemporary -lt 0 -or $uiWriteJsonWrite -le $uiWriteJsonTemporary -or
    $uiWriteJsonMove -le $uiWriteJsonWrite -or
    $uiWriteJsonCatchCleanup -le $uiWriteJsonMove -or
    $uiWriteJsonRethrow -le $uiWriteJsonCatchCleanup -or
    -not $uiWriteJsonText.Contains("[guid]::NewGuid().ToString('N')") -or
    @([regex]::Matches(
            $uiWriteJsonText,
            'Remove-Item -LiteralPath \$temporaryFull -Force -ErrorAction SilentlyContinue')).Count -lt 2 -or
    $uiWriteJsonText.Contains('[IO.File]::Move(')) {
    throw 'ui-action result JSON must be fully written to a unique same-directory temporary file before atomic Move-Item publication, with fail-closed cleanup.'
}
$checkboxStripFunction = [regex]::Match(
    $uiActionText,
    '(?ms)^function Get-ReferenceCheckboxStripState\(.*?(?=^function Invoke-UncheckedReferenceCheckboxUntilChecked\()')
if (-not $checkboxStripFunction.Success) {
    throw 'Checkbox-strip locator function is missing.'
}
$checkboxStripText = $checkboxStripFunction.Value
$checkboxStripAway = $checkboxStripText.IndexOf(
    '$away = Get-ReferencePoint 100 350 $Geometry $CalibrationValue',
    [StringComparison]::Ordinal)
$checkboxStripFailClosed = $checkboxStripText.IndexOf(
    'if (-not [KdbgGuiNative]::SetCursorPos($away.X,$away.Y))',
    [StringComparison]::Ordinal)
$checkboxStripSettle = $checkboxStripText.IndexOf(
    'Start-Sleep -Milliseconds 120',
    [StringComparison]::Ordinal)
$checkboxStripCapture = $checkboxStripText.IndexOf(
    '$bitmap = [Drawing.Bitmap]::new(',
    [StringComparison]::Ordinal)
if ($checkboxStripAway -lt 0 -or $checkboxStripFailClosed -le $checkboxStripAway -or
    $checkboxStripSettle -le $checkboxStripFailClosed -or
    $checkboxStripCapture -le $checkboxStripSettle -or
    -not $checkboxStripText.Contains(
        "throw 'SetCursorPos failed while stabilizing a checkbox-strip assertion.'")) {
    throw 'Checkbox-strip capture must fail closed after moving to the neutral reference point and settling for 120 ms.'
}
foreach ($token in $planTokens) {
    $literal = '${' + $token + '}'
    if (-not $uiActionText.Contains("'$literal' =")) {
        throw "ui-action token resolver does not cover: $literal"
    }
}
if (-not $uiActionText.Contains("if (`$resolved -match '\$\{')") -or
    -not $uiActionText.Contains('function Get-Point') -or
    -not $uiActionText.Contains('function Get-Region')) {
    throw 'ui-action must fail closed on unresolved tokens and retain named calibration-key resolution.'
}
$orchestratorContracts = [ordered]@{
    exact_vm_name_guid = $orchestratorText.Contains('$vmMatches[0].Id -ne $VMId')
    initial_vm_off = $orchestratorText.Contains('$vm.State.ToString() -ne ''Off''')
    exact_checkpoint_name_guid = $orchestratorText.Contains('$_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId')
    exact_restore_final_off = $orchestratorText.Contains('Restore-VMSnapshot -VMSnapshot $checkpointNow[0]') -and
        $orchestratorText.Contains('$finalOff = $finalVm.State.ToString() -eq ''Off'' -and $finalVm.Id -eq $VMId')
    dpapi_credential = $orchestratorText.Contains('Import-Clixml -LiteralPath $credentialFull')
    no_plaintext_securestring_conversion = $orchestratorText -notmatch '(?i)ConvertTo-SecureString\s+.*-AsPlainText'
    transient_bstr_zeroed = $orchestratorText.Contains('ZeroFreeBSTR($pointer)')
    autologon_secret_immediate_clear = $orchestratorText.Contains('Interactive Explorer did not appear before timeout.') -and
        $orchestratorText.Contains('Remove-ItemProperty -LiteralPath $key -Name DefaultPassword') -and
        $orchestratorText.Contains("New-ScheduledTaskTrigger -AtStartup") -and
        $autoLogonCleanupText.Contains('Start-Sleep -Milliseconds 200')
    autologon_cleanup_repeated = @([regex]::Matches($orchestratorText,'Remove-ItemProperty -LiteralPath \$key -Name DefaultPassword')).Count -ge 2
    host_hashes_main_symbols_cert = $orchestratorText.Contains('$actualHashes.package -cne $ExpectedPackageSha256') -and
        $orchestratorText.Contains('$actualHashes.symbols -cne $ExpectedSymbolsSha256') -and
        $orchestratorText.Contains('$actualHashes.certificate -cne $ExpectedCertificateSha256')
    guest_hashes_main_symbols_cert = $prepareText.Contains('$observed.package -cne $ExpectedPackageSha256') -and
        $prepareText.Contains('$observed.symbols -cne $ExpectedSymbolsSha256') -and
        $prepareText.Contains('$observed.certificate -cne $ExpectedCertificateSha256')
    trusted_stores = $prepareText.Contains("@('Root','TrustedPublisher')")
    readonly_probe_discovery = $prepareText.Contains('$probePfn = [uint64]$report.probe_before.pfn')
    current_fixture_info = $bootstrapText.Contains("'kdbg.process-fixture.v1'") -and
        $captureText.Contains('$fixtureVa = Convert-HexUInt64 ([string]$fixture.virtual_address)') -and
        $bootstrapText.Contains("Join-Path `$evidenceRoot 'fixture-info.json'") -and
        $uiActionText.Contains("'`${session.fixture_info_path}' = [string]`$Session.fixture_info_path") -and
        $planText.Contains('"assertion": "analysis_fixture_info_path"')
    resolution_dpi_assertion = $bootstrapText.Contains('$observedWidth -ne $Width') -and
        $bootstrapText.Contains('GetSystemMetrics(0)') -and
        $bootstrapText.Contains('$observedDpi -ne $Dpi')
    postboot_demand_start_order = $orchestratorText.Contains("foreach (`$name in @('KDBG','KDBGProbe'))") -and
        $orchestratorText.Contains('[uint32]$serviceConfig.Start -ne 3') -and
        $orchestratorText.Contains('[uint32]$serviceConfig.Type -ne 1') -and
        $orchestratorText.Contains('[System.ServiceProcess.ServiceControllerStatus]::Running')
    postboot_exact_diagnose = $orchestratorText.Contains("'postboot-diagnose.stdout.log'") -and
        $orchestratorText.Contains("'-VerifyPackage','-RequireAdministrator','-RequireTrustedDriverSignatures'") -and
        $orchestratorText.Contains("'-RequireRunning','-PackageRootMode','DistributionSource'")
    postboot_synchronous_readonly_verifier = $orchestratorText.Contains("'postboot-readonly-probe.json'") -and
        $orchestratorText.Contains("'--read-samples','8') -Wait -PassThru") -and
        $orchestratorText.Contains('$verifyProcess.HasExited')
    postboot_exact_runtime_identity = $orchestratorText.Contains("[string]`$report.runtime_identity.verifier.sha256 -cne `$expectedVerifierSha") -and
        $orchestratorText.Contains("[string]`$report.runtime_identity.kdbg_service.binary.sha256 -cne `$expectedDriverSha") -and
        $orchestratorText.Contains("[string]`$report.runtime_identity.probe_service.binary.sha256 -cne `$expectedProbeSha") -and
        $orchestratorText.Contains('backend.connected -ne $true') -and
        $orchestratorText.Contains('backend.abi_version -ne 7') -and
        $orchestratorText.Contains('supports_physical_page_compare_write -ne $true') -and
        $orchestratorText.Contains('write_cleanup.final_gate_locked -ne $true')
    postboot_probe_refresh_before_gui = $orchestratorText.Contains('$prepared.probe_pfn = [uint64]$report.probe_before.pfn') -and
        $orchestratorText.Contains("`$prepared.probe_pfn_hex = '0x{0:X}'") -and
        $orchestratorText.Contains("phase='postboot-driver-readiness'") -and
        $orchestratorText.IndexOf("phase='postboot-driver-readiness'",[StringComparison]::Ordinal) -lt
            $orchestratorText.IndexOf("phase='interactive-resolution-dpi-fixture'",[StringComparison]::Ordinal)
    ui_action_pid_scoped_live_readiness = $uiActionText.Contains("'driver.connect_succeeded'") -and
        $uiActionText.Contains("'probe.device_open_succeeded'") -and
        $uiActionText.Contains("'probe.query_succeeded'") -and
        $uiActionText.Contains('$pidToken = "pid=$GuiProcessId "') -and
        $uiActionText.Contains('$processLines = @(Get-Content -LiteralPath $LogPath | Where-Object { $_.Contains($pidToken) })') -and
        $uiActionText.Contains("`$failurePattern = 'event=(driver\.connect_failed|probe\.device_open_failed|probe\.query_failed)'") -and
        $uiActionText.Contains('$readinessDiagnostics = Wait-GuiReadinessDiagnostics $process.Id $diagnosticLogSource') -and
        @([regex]::Matches($uiActionText,'live_readiness_diagnostics=\$readinessDiagnostics')).Count -ge 2
    runtime_json_reads_are_explicit_utf8 = $orchestratorText.Contains('-Raw -Encoding UTF8 | ConvertFrom-Json') -and
        $prepareText.Contains('-Raw -Encoding UTF8 | ConvertFrom-Json') -and
        $bootstrapText.Contains('-Raw -Encoding UTF8 | ConvertFrom-Json') -and
        $captureText.Contains('-Raw -Encoding UTF8 | ConvertFrom-Json') -and
        $uiActionText.Contains('-Raw -Encoding UTF8 | ConvertFrom-Json')
    ui_task_scheduler_race_is_bounded = $uiTaskText.Contains('$missingTaskPolls = 0') -and
        $uiTaskText.Contains("Get-ScheduledTask -TaskName `$TaskName -ErrorAction SilentlyContinue") -and
        $uiTaskText.Contains("Get-Process -Name 'KDBG' -ErrorAction SilentlyContinue") -and
        $uiTaskText.Contains('$missingTaskPolls -ge 10') -and
        $uiTaskText.Contains("Interactive capture task disappeared and no KDBG GUI process remains.")
    ui_click_has_settle_and_hold = $uiActionText.Contains("throw 'SetCursorPos failed at the click target.'") -and
        $uiActionText.Contains('Start-Sleep -Milliseconds 80') -and
        $uiActionText.Contains('[KdbgGuiNative]::mouse_event(0x0002,0,0,0,[UIntPtr]::Zero)') -and
        $uiActionText.Contains('Start-Sleep -Milliseconds 50') -and
        $uiActionText.Contains('[KdbgGuiNative]::mouse_event(0x0004,0,0,0,[UIntPtr]::Zero)')
    ui_result_json_atomic_publish = $uiWriteJsonTemporary -ge 0 -and
        $uiWriteJsonWrite -gt $uiWriteJsonTemporary -and
        $uiWriteJsonMove -gt $uiWriteJsonWrite -and
        $uiWriteJsonCatchCleanup -gt $uiWriteJsonMove -and
        $uiWriteJsonRethrow -gt $uiWriteJsonCatchCleanup
    guest_uninstall = $orchestratorText.Contains("'-ConfirmKdbgServices -PurgeUserData'") -or
        ($orchestratorText.Contains('-ConfirmKdbgServices') -and $orchestratorText.Contains('-PurgeUserData'))
    guest_script_execution_policy = @([regex]::Matches(
            $orchestratorText,
            'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force')).Count -ge 2
    canonical_guest_evidence_zip = $orchestratorText.Contains(".Replace('\','/')") -and
        $orchestratorText.Contains("[Array]::Sort(`$ordered,[StringComparer]::Ordinal)") -and
        -not $orchestratorText.Contains("Compress-Archive -Path (Join-Path `$Root 'evidence\\*')")
    no_credential_claim = $orchestratorText.Contains('credential_serialized=$false') -and
        $orchestratorText.Contains('plaintext_password_logged=$false')
}
foreach ($contract in $orchestratorContracts.GetEnumerator()) {
    if ($contract.Value -ne $true) { throw "Complete orchestrator static contract failed: $($contract.Key)" }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('kdbg-win11-gui-static-' + [guid]::NewGuid().ToString('N'))
try {
    & (Join-Path $root 'Invoke-HyperVWin11GuiCapture.ps1') -DryRun `
        -GuestPackageRoot 'C:\KDBG-Lab\dry-run\KDBG-1.1.0-win-x64' `
        -HostEvidenceRoot $testRoot -ProbePfn 1 -FixturePid 1 `
        -FixtureVirtualAddress 4096 -FixturePointerTarget 8192 -FixtureCodeAddress 12288 | Out-Null
    $dryResultPath = Join-Path $testRoot 'dry-run\capture-run.json'
    $dryResult = Get-Content -LiteralPath $dryResultPath -Raw | ConvertFrom-Json
    if ($dryResult.harness_valid -ne $true -or [string]$dryResult.live_capture_status -cne 'NOT_RUN' -or
        $dryResult.evidence_pass -ne $false -or [int]$dryResult.step_count -ne 24 -or
        [int]$dryResult.scene_count -ne 20) {
        throw 'Dry-run result falsely claimed evidence or failed the plan contract.'
    }
    $orchestratorDryRoot = Join-Path $testRoot 'orchestrator'
    $hash64 = 'a' * 64
    $hash40 = 'b' * 40
    & (Join-Path $root 'Invoke-HyperVWin11GuiOrchestrator.ps1') -DryRun `
        -VMName 'KDBG-Static-Test' -VMId ([Guid]'11111111-1111-1111-1111-111111111111') `
        -CheckpointName 'KDBG-Static-Checkpoint' `
        -CheckpointId ([Guid]'22222222-2222-2222-2222-222222222222') `
        -PackageZipPath 'C:\dry-run\package.zip' -SymbolsZipPath 'C:\dry-run\symbols.zip' `
        -CertificatePath 'C:\dry-run\test.cer' -ExpectedPackageSha256 $hash64 `
        -ExpectedSymbolsSha256 $hash64 -ExpectedCertificateSha256 $hash64 `
        -ExpectedSourceSnapshotSha256 $hash64 -ExpectedSignerThumbprint $hash40 `
        -CredentialPath 'C:\dry-run\credential.clixml' -HostEvidenceRoot $orchestratorDryRoot | Out-Null
    $orchestratorDry = Get-Content -LiteralPath (Join-Path $orchestratorDryRoot 'orchestrator-dry-run.json') -Raw | ConvertFrom-Json
    if ($orchestratorDry.success -ne $true -or [string]$orchestratorDry.execution_status -cne 'NOT_RUN' -or
        $orchestratorDry.vm_executed -ne $false -or $orchestratorDry.credential_serialized -ne $false -or
        @($orchestratorDry.required_sequence).Count -ne 11 -or
        @($orchestratorDry.required_sequence | Where-Object { $_ -ceq 'postboot-driver-readiness' }).Count -ne 1) {
        throw 'Complete host orchestrator dry-run contract failed.'
    }
} finally {
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    if ($resolvedTestRoot.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedTestRoot).StartsWith('kdbg-win11-gui-static-')) {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$result = [ordered]@{
    schema='kdbg.win11-extended-gui-harness-static-test.v1'
    success=$true
    vm_executed=$false
    ast_files=$parseResults.Count
    ast_parse_errors=0
    plan_frames=$steps.Count
    plan_scenes=$scenes.Count
    calibration_status=[string]$calibration.calibration_status
    dry_run_status='NOT_RUN'
    orchestrator_dry_run_status='NOT_RUN'
    safety=[ordered]@{
        typed_pfn_confirmation=$true; one_shot_apply=$true; rollback_confirmation=$true
        typed_pid_confirmation=$true; freeze_crc_checks=2; smoke_is_non_destructive=$true
        evidence_pass_requires_human_review=$true
        complete_orchestrator_contracts=$orchestratorContracts.Count
        proven_action_types=$provenActionTypes.Count
        readiness_actions=@($allActions | Where-Object type -eq 'wait_window_responsive').Count
        capture_actions=@($allActions | Where-Object type -eq 'capture').Count
        source_bound_readability_contracts=$readabilityContracts.Count
        checkbox_strip_hover_stabilization=$true
        token_count=$planTokens.Count
        planned_duration_ms=$plannedDuration
        client_height=[int]$calibration.client.height
        maximum_plan_y=$maxPlanY
    }
    completed_utc=[DateTime]::UtcNow.ToString('o')
}
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { Write-Json $OutputPath $result }
$result | ConvertTo-Json -Depth 20

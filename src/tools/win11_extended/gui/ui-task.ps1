[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageRoot,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [Parameter(Mandatory = $true)][string]$SessionPath,
    [Parameter(Mandatory = $true)][string]$InteractiveUser,
    [string]$PlanPath = (Join-Path $PSScriptRoot 'capture-plan.json'),
    [string]$CalibrationPath = (Join-Path $PSScriptRoot 'calibration.win11-1024x768-v1.json'),
    [string]$TaskName = 'KDBG-Win11-Extended-GUI',
    [int]$TimeoutSeconds = 3600,
    [switch]$DryRun,
    [switch]$CalibrationSmoke
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Quote-Argument([string]$Value) {
    '"' + $Value.Replace('"','""') + '"'
}

if ($TimeoutSeconds -lt 60 -or $TimeoutSeconds -gt 7200) {
    throw 'TimeoutSeconds must be between 60 and 7200.'
}
$worker = Join-Path $PSScriptRoot 'ui-action.ps1'
$resultPath = Join-Path $EvidenceRoot 'capture-run.json'
$errorPath = Join-Path $EvidenceRoot 'capture-run-error.txt'
foreach ($required in @($worker,$PlanPath,$CalibrationPath,$SessionPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing UI task input: $required" }
}

if ($DryRun) {
    & $worker -PackageRoot $PackageRoot -EvidenceRoot $EvidenceRoot -SessionPath $SessionPath `
        -PlanPath $PlanPath -CalibrationPath $CalibrationPath -ResultPath $resultPath `
        -ErrorPath $errorPath -DryRun
    return
}

$arguments = [Collections.Generic.List[string]]::new()
foreach ($value in @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-Sta','-File')) { $arguments.Add($value) }
$arguments.Add((Quote-Argument $worker))
$workerArguments = [ordered]@{
    '-PackageRoot'=$PackageRoot; '-EvidenceRoot'=$EvidenceRoot; '-SessionPath'=$SessionPath
    '-PlanPath'=$PlanPath; '-CalibrationPath'=$CalibrationPath
    '-ResultPath'=$resultPath; '-ErrorPath'=$errorPath
}
foreach ($pair in $workerArguments.GetEnumerator()) {
    $arguments.Add([string]$pair.Key)
    $arguments.Add((Quote-Argument ([string]$pair.Value)))
}
if ($CalibrationSmoke) { $arguments.Add('-CalibrationSmoke') }

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $resultPath,$errorPath -Force -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($arguments -join ' ') `
    -WorkingDirectory $PSScriptRoot
$principal = New-ScheduledTaskPrincipal -UserId $InteractiveUser -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds $TimeoutSeconds) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal `
        -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $missingTaskPolls = 0
    do {
        Start-Sleep -Milliseconds 500
        if (Test-Path -LiteralPath $resultPath -PathType Leaf) { break }
        if (Test-Path -LiteralPath $errorPath -PathType Leaf) {
            throw (Get-Content -LiteralPath $errorPath -Raw -Encoding UTF8)
        }
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        $info = if ($null -ne $task) {
            Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        } else { $null }
        if ($null -eq $task -or $null -eq $info) {
            $missingTaskPolls++
            $guiProcesses = @(Get-Process -Name 'KDBG' -ErrorAction SilentlyContinue)
            if ($guiProcesses.Count -eq 0 -and $missingTaskPolls -ge 10) {
                throw 'Interactive capture task disappeared and no KDBG GUI process remains.'
            }
            continue
        }
        $missingTaskPolls = 0
        if ($task.State -ne 'Running' -and $info.LastTaskResult -notin @(267009,0) -and
            -not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            throw "Interactive capture task exited without a result: $($info.LastTaskResult)"
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw "Interactive capture timed out after $TimeoutSeconds seconds."
    }
    $result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $expectedStatus = if ($CalibrationSmoke) { 'CALIBRATION_SMOKE_NOT_EVIDENCE' } else { 'CAPTURED_UNREVIEWED' }
    if ($result.harness_valid -ne $true -or [string]$result.live_capture_status -cne $expectedStatus) {
        throw "Unexpected capture result status: $($result.live_capture_status)"
    }
    $result | ConvertTo-Json -Depth 30
} finally {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

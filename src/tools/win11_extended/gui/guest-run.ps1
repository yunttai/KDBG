[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageRoot,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [Parameter(Mandatory = $true)][uint64]$ProbePfn,
    [Parameter(Mandatory = $true)][uint32]$FixturePid,
    [Parameter(Mandatory = $true)][uint64]$FixtureVirtualAddress,
    [Parameter(Mandatory = $true)][uint64]$FixturePointerTarget,
    [Parameter(Mandatory = $true)][uint64]$FixtureCodeAddress,
    [string]$FixtureScanValue = '610839776',
    [string]$FixturePipeName = '\\.\pipe\KDBGProcessFixture',
    [string]$FixtureScanOffset = 'freeze_value',
    [string]$FixtureSnapshotOffset = 'aob',
    [string]$FixtureBaselineCrc32 = '00000000',
    [string]$FixtureFreezeExpectedCrc32 = '00000000',
    [string]$KernelPdbPath = 'C:\KDBG-Lab\symbols\drivers\KDbgDriver.pdb',
    [string]$InteractiveUser = 'kdbgtest',
    [string]$PlanPath = (Join-Path $PSScriptRoot 'capture-plan.json'),
    [string]$CalibrationPath = (Join-Path $PSScriptRoot 'calibration.win11-1024x768-v1.json'),
    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot,
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
        ($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

function Find-InteractiveSession([string]$UserName, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        foreach ($candidate in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)) {
            try {
                $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwner -ErrorAction Stop
                if ([uint32]$owner.ReturnValue -eq 0 -and [uint32]$candidate.SessionId -gt 0 -and
                    [string]$owner.User -ieq $UserName) {
                    return [ordered]@{
                        user=[string]$owner.User; domain=[string]$owner.Domain
                        account="$($owner.Domain)\$($owner.User)"
                        session_id=[uint32]$candidate.SessionId; explorer_pid=[uint32]$candidate.ProcessId
                    }
                }
            } catch {}
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Interactive Explorer session was not available for $UserName within ${TimeoutSeconds}s."
}

function Grant-HarnessAccess([string]$Path, [string]$Account, [string]$Rights) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Harness ACL target must not be a reparse point: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $Account,
        [enum]::Parse([Security.AccessControl.FileSystemRights],$Rights),
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
    $after = Get-Acl -LiteralPath $Path
    $effective = @(& icacls.exe $Path 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) { throw "Could not capture effective ACL evidence: $Path" }
    [ordered]@{ path=[IO.Path]::GetFullPath($Path); account=$Account; rights=$Rights; sddl=[string]$after.Sddl; icacls=$effective }
}

$packageFull = [IO.Path]::GetFullPath($PackageRoot)
$evidenceFull = [IO.Path]::GetFullPath($EvidenceRoot)
$sessionPath = Join-Path $evidenceFull 'session-start.json'
New-Item -ItemType Directory -Path $evidenceFull -Force | Out-Null

$testSigning = $false
$interactive = $null
$osRecord = [ordered]@{ caption='DRY_RUN'; build='0'; architecture='DRY_RUN' }
if (-not $DryRun) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Guest GUI capture requires Administrator.'
    }
    if (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot) {
        throw 'Guest GUI capture requires -ConfirmDedicatedVm and -ConfirmSnapshot.'
    }
    $computer = Get-CimInstance Win32_ComputerSystem
    if ([string]$computer.Model -notmatch 'Virtual|Hyper-V' -and [string]$computer.Manufacturer -notmatch 'Microsoft') {
        throw 'Guest preflight did not identify a Hyper-V virtual machine.'
    }
    $os = Get-CimInstance Win32_OperatingSystem
    if ($env:PROCESSOR_ARCHITECTURE -cne 'AMD64' -or [uint32]$os.BuildNumber -lt 22000) {
        throw 'Guest GUI capture requires Windows 11 x64.'
    }
    $osRecord = [ordered]@{ caption=[string]$os.Caption; build=[string]$os.BuildNumber; architecture=[string]$os.OSArchitecture }
    $testSigning = ((& bcdedit.exe /enum '{current}' 2>&1 | Out-String) -match 'testsigning\s+Yes')
    if (-not $testSigning) { throw 'Guest GUI capture requires test-signing mode.' }
    if (-not (Test-Path -LiteralPath (Join-Path $packageFull 'KDBG.exe') -PathType Leaf)) {
        throw "Package KDBG.exe is missing: $packageFull"
    }
    if ($ProbePfn -eq 0) { throw 'ProbePfn must identify the dedicated KDbgProbe page.' }
    if ($null -eq (Get-Process -Id $FixturePid -ErrorAction SilentlyContinue)) {
        throw "Fixture PID is not running: $FixturePid"
    }
    if (-not $CalibrationSmoke) {
        if ($FixtureBaselineCrc32 -notmatch '^(?:0x)?[0-9A-Fa-f]{8}$' -or $FixtureBaselineCrc32 -in @('00000000','0x00000000') -or
            $FixtureFreezeExpectedCrc32 -notmatch '^(?:0x)?[0-9A-Fa-f]{8}$' -or $FixtureFreezeExpectedCrc32 -in @('00000000','0x00000000')) {
            throw 'Full capture requires current nonzero fixture baseline and freeze CRC32 values.'
        }
        if (-not (Test-Path -LiteralPath $KernelPdbPath -PathType Leaf)) {
            throw "Exact kernel PDB is missing: $KernelPdbPath"
        }
    }
    $interactive = Find-InteractiveSession $InteractiveUser 90
    $aclEvidence = [ordered]@{
        schema='kdbg.win11-extended-gui-filesystem-acl.v1'
        scope='filesystem harness paths only; driver and device ACLs unchanged'
        captured_utc=[DateTime]::UtcNow.ToString('o')
        entries=@(
            Grant-HarnessAccess $PSScriptRoot ([string]$interactive.account) 'ReadAndExecute'
            Grant-HarnessAccess $packageFull ([string]$interactive.account) 'ReadAndExecute'
            Grant-HarnessAccess $evidenceFull ([string]$interactive.account) 'Modify'
        )
    }
    Write-Json (Join-Path $evidenceFull 'filesystem-acl.json') $aclEvidence
} else {
    $interactive = [ordered]@{ user=$InteractiveUser; domain='DRY_RUN'; account="DRY_RUN\$InteractiveUser"; session_id=1; explorer_pid=1 }
}

$session = [ordered]@{
    schema='kdbg.win11-extended-gui-session.v1'
    created_utc=[DateTime]::UtcNow.ToString('o')
    dry_run=[bool]$DryRun
    calibration_smoke=[bool]$CalibrationSmoke
    dedicated_vm=if ($DryRun) { $true } else { [bool]$ConfirmDedicatedVm }
    snapshot_confirmed=if ($DryRun) { $true } else { [bool]$ConfirmSnapshot }
    test_signing=if ($DryRun) { $true } else { $testSigning }
    os=$osRecord
    interactive_session=$interactive
    package_root=$packageFull
    evidence_root=$evidenceFull
    fixture_info_path=(Join-Path $evidenceFull 'fixture-info.json')
    probe_pfn=[uint64]$ProbePfn
    probe_pfn_hex=('0x{0:X}' -f $ProbePfn)
    fixture_pid=[uint32]$FixturePid
    fixture_virtual_address=[uint64]$FixtureVirtualAddress
    fixture_virtual_address_hex=('0x{0:X}' -f $FixtureVirtualAddress)
    fixture_pointer_target=[uint64]$FixturePointerTarget
    fixture_pointer_target_hex=('0x{0:X}' -f $FixturePointerTarget)
    fixture_code_address=[uint64]$FixtureCodeAddress
    fixture_code_address_hex=('0x{0:X}' -f $FixtureCodeAddress)
    fixture_scan_value=$FixtureScanValue
    fixture_pipe_name=$FixturePipeName
    fixture_scan_offset=$FixtureScanOffset
    fixture_snapshot_offset=$FixtureSnapshotOffset
    fixture_baseline_crc32=$FixtureBaselineCrc32
    fixture_freeze_expected_crc32=$FixtureFreezeExpectedCrc32
    kernel_pdb_path=$KernelPdbPath
}
Write-Json $sessionPath $session

$taskScript = Join-Path $PSScriptRoot 'ui-task.ps1'
$taskParameters = @{
    PackageRoot=$packageFull; EvidenceRoot=$evidenceFull; SessionPath=$sessionPath
    InteractiveUser=[string]$interactive.account; PlanPath=$PlanPath; CalibrationPath=$CalibrationPath
}
if ($DryRun) { $taskParameters.DryRun = $true }
if ($CalibrationSmoke) { $taskParameters.CalibrationSmoke = $true }
& $taskScript @taskParameters

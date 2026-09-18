[CmdletBinding()]
param(
    [string]$VMName = 'KDBG-Win11-25H2',
    [string]$CredentialPath = (Join-Path $env:LOCALAPPDATA 'KDBG\secrets\KDBG-Win11-25H2.credential.clixml'),
    [Parameter(Mandatory = $true)][string]$GuestPackageRoot,
    [Parameter(Mandatory = $true)][string]$HostEvidenceRoot,
    [uint64]$ProbePfn = 1,
    [uint32]$FixturePid = 1,
    [uint64]$FixtureVirtualAddress = 4096,
    [uint64]$FixturePointerTarget = 8192,
    [uint64]$FixtureCodeAddress = 12288,
    [string]$FixtureScanValue = '610839776',
    [string]$FixturePipeName = '\\.\pipe\KDBGProcessFixture',
    [string]$FixtureScanOffset = 'freeze_value',
    [string]$FixtureSnapshotOffset = 'aob',
    [string]$FixtureBaselineCrc32 = '00000000',
    [string]$FixtureFreezeExpectedCrc32 = '00000000',
    [string]$KernelPdbPath = 'C:\KDBG-Lab\symbols\drivers\KDbgDriver.pdb',
    [string]$InteractiveUser = 'kdbgtest',
    [string]$GuestHarnessRoot = 'C:\KDBG-Lab\win11-extended-gui',
    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot,
    [switch]$DryRun,
    [switch]$CalibrationSmoke
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$evidenceFull = [IO.Path]::GetFullPath($HostEvidenceRoot)
New-Item -ItemType Directory -Path $evidenceFull -Force | Out-Null
if ($DryRun) {
    $dryRoot = Join-Path $evidenceFull 'dry-run'
    & (Join-Path $PSScriptRoot 'guest-run.ps1') -PackageRoot $GuestPackageRoot `
        -EvidenceRoot $dryRoot -ProbePfn $ProbePfn -FixturePid $FixturePid `
        -FixtureVirtualAddress $FixtureVirtualAddress -FixturePointerTarget $FixturePointerTarget `
        -FixtureCodeAddress $FixtureCodeAddress -FixtureScanValue $FixtureScanValue `
        -FixturePipeName $FixturePipeName -FixtureScanOffset $FixtureScanOffset `
        -FixtureSnapshotOffset $FixtureSnapshotOffset -FixtureBaselineCrc32 $FixtureBaselineCrc32 `
        -FixtureFreezeExpectedCrc32 $FixtureFreezeExpectedCrc32 `
        -KernelPdbPath $KernelPdbPath `
        -InteractiveUser $InteractiveUser -DryRun
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Hyper-V host runner requires Administrator.'
}
if (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot) {
    throw 'Hyper-V host runner requires -ConfirmDedicatedVm and -ConfirmSnapshot.'
}
if (-not (Test-Path -LiteralPath $CredentialPath -PathType Leaf)) {
    throw "DPAPI credential file is missing: $CredentialPath"
}
$vm = Get-VM -Name $VMName -ErrorAction Stop
if ([string]$vm.State -cne 'Running') { throw "VM must already be running: $VMName ($($vm.State))" }
$credential = Import-Clixml -LiteralPath $CredentialPath
$session = $null
$guestEvidenceRoot = Join-Path $guestHarnessRoot 'evidence'
try {
    $session = New-PSSession -VMName $VMName -Credential $credential -ErrorAction Stop
    Invoke-Command -Session $session -ScriptBlock {
        param($HarnessRoot,$EvidenceRoot)
        New-Item -ItemType Directory -Path $HarnessRoot,$EvidenceRoot -Force | Out-Null
        Get-ChildItem -LiteralPath $HarnessRoot -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
    } -ArgumentList $guestHarnessRoot,$guestEvidenceRoot
    foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -File)) {
        Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $guestHarnessRoot $file.Name) `
            -ToSession $session -Force
    }
    $remote = Invoke-Command -Session $session -ScriptBlock {
        param($HarnessRoot,$PackageRoot,$EvidenceRoot,$Pfn,$Pid,$FixtureVa,$PointerTarget,$CodeAddress,
            $ScanValue,$PipeName,$ScanOffset,$SnapshotOffset,$BaselineCrc,$FreezeCrc,$PdbPath,
            $UserName,$Dedicated,$Snapshot,$Smoke)
        $parameters = @{
            PackageRoot=$PackageRoot; EvidenceRoot=$EvidenceRoot; ProbePfn=[uint64]$Pfn
            FixturePid=[uint32]$Pid; FixtureVirtualAddress=[uint64]$FixtureVa
            FixturePointerTarget=[uint64]$PointerTarget; FixtureCodeAddress=[uint64]$CodeAddress
            FixtureScanValue=$ScanValue; InteractiveUser=$UserName
            FixturePipeName=$PipeName; FixtureScanOffset=$ScanOffset
            FixtureSnapshotOffset=$SnapshotOffset; FixtureBaselineCrc32=$BaselineCrc
            FixtureFreezeExpectedCrc32=$FreezeCrc
            KernelPdbPath=$PdbPath
            ConfirmDedicatedVm=[bool]$Dedicated; ConfirmSnapshot=[bool]$Snapshot
        }
        if ($Smoke) { $parameters.CalibrationSmoke = $true }
        & (Join-Path $HarnessRoot 'guest-run.ps1') @parameters
    } -ArgumentList $guestHarnessRoot,$GuestPackageRoot,$guestEvidenceRoot,$ProbePfn,$FixturePid,
        $FixtureVirtualAddress,$FixturePointerTarget,$FixtureCodeAddress,$FixtureScanValue,
        $FixturePipeName,$FixtureScanOffset,$FixtureSnapshotOffset,$FixtureBaselineCrc32,$FixtureFreezeExpectedCrc32,$KernelPdbPath,
        $InteractiveUser,$ConfirmDedicatedVm,$ConfirmSnapshot,$CalibrationSmoke
    $remote | Out-String | Write-Output
    Copy-Item -Path (Join-Path $guestEvidenceRoot '*') -Destination $evidenceFull `
        -FromSession $session -Recurse -Force
} finally {
    if ($null -ne $session) { Remove-PSSession $session }
}

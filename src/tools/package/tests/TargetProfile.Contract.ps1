[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$ToolsRoot = [IO.Path]::GetFullPath((Join-Path $PackageRoot '..'))
$ModulePath = Join-Path $PackageRoot 'TargetProfile.psm1'
$Checks = 0

function Assert-True([bool]$Condition, [string]$Message) {
    $script:Checks++
    if (-not $Condition) { throw "CHECK FAILED: $Message" }
}

function Assert-Throws([scriptblock]$Operation, [string]$Message) {
    $script:Checks++
    try { & $Operation } catch { return }
    throw "CHECK FAILED: $Message"
}

function Assert-Parses([string]$Path) {
    $Tokens = $null
    $Errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$Tokens, [ref]$Errors)
    Assert-True ($Errors.Count -eq 0) "PowerShell syntax: $Path"
}

Import-Module $ModulePath -Force
$MachineBinding = Get-KdbgMachineBindingSha256 `
    -MachineGuid '00112233-4455-6677-8899-AABBCCDDEEFF' `
    -ComputerName 'kdbg-host'
Assert-True ($MachineBinding -ceq `
    '70ec97278955506f87a6e80f3cdb75ce345d896ebefc8f9537018974cc748540') `
    'machine binding must be a deterministic canonical SHA-256 digest'
Assert-True ($MachineBinding -cmatch '^[0-9a-f]{64}$') `
    'machine binding must expose only a lowercase SHA-256 digest'
$NormalizedMachineBinding = Get-KdbgMachineBindingSha256 `
    -MachineGuid ' 00112233-4455-6677-8899-aabbccddeeff ' `
    -ComputerName ' KDBG-HOST '
Assert-True ($NormalizedMachineBinding -ceq $MachineBinding) `
    'machine binding must normalize case and surrounding whitespace'
Assert-Throws {
    Get-KdbgMachineBindingSha256 -MachineGuid '' -ComputerName 'kdbg-host'
} 'machine binding must reject an unavailable identity input'

$Default = Assert-KdbgTargetProfile
Assert-True ($Default.TargetProfile -eq 'LocalHost') `
    'ordinary target profile must default to LocalHost'
$LocalHost = Assert-KdbgTargetProfile -TargetProfile LocalHost
Assert-True ($LocalHost.TargetProfile -eq 'LocalHost') `
    'LocalHost must be accepted without VM confirmations'
Assert-Throws {
    Assert-KdbgTargetProfile -TargetProfile LocalHost -ConfirmDedicatedVm
} 'LocalHost must reject VM confirmation mixing'
Assert-Throws {
    Assert-KdbgTargetProfile -TargetProfile DisposableVm
} 'DisposableVm must still require both legacy confirmations'
$Vm = Assert-KdbgTargetProfile -TargetProfile DisposableVm `
    -ConfirmDedicatedVm -ConfirmSnapshot
Assert-True ($Vm.TargetProfile -eq 'DisposableVm') `
    'DisposableVm must preserve the two-confirmation path'

$Scripts = @(
    (Join-Path $PackageRoot 'install.ps1'),
    (Join-Path $PackageRoot 'start.ps1'),
    (Join-Path $PackageRoot 'run.ps1'),
    (Join-Path $ToolsRoot 'run.ps1'),
    (Join-Path $ToolsRoot 'manage_drivers.ps1'))
foreach ($Script in $Scripts) {
    Assert-Parses $Script
    $Text = Get-Content -LiteralPath $Script -Raw
    Assert-True ($Text.Contains('TargetProfile')) `
        "$Script must expose or enforce the target profile"
    Assert-True ($Text.Contains('LocalHost')) `
        "$Script must admit the LocalHost profile"
}

$InstallText = Get-Content -LiteralPath (Join-Path $PackageRoot 'install.ps1') -Raw
$PackageRunText = Get-Content -LiteralPath (Join-Path $PackageRoot 'run.ps1') -Raw
$StartText = Get-Content -LiteralPath (Join-Path $PackageRoot 'start.ps1') -Raw
Assert-True ($InstallText.Contains('-TargetProfile $ResolvedTargetProfile')) `
    'package install must forward TargetProfile to package start'
Assert-True ($PackageRunText.Contains('-TargetProfile $ResolvedTargetProfile')) `
    'package run must forward TargetProfile to package start'
Assert-True ($StartText.Contains('$Readiness.backend.abi_version -ne 7') -and
    $StartText.Contains('supports_physical_page_compare_write -ne $true') -and
    -not $StartText.Contains('ABI 6')) `
    'package readiness must pin the current ABI 7 contract'

Write-Host "Target profile contract tests: PASS ($Checks checks)"

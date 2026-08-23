[CmdletBinding()]
param(
    [ValidateSet("Install", "Start", "Stop", "Restart", "Remove", "Status")]
    [string]$Action = "Status",

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [string]$DriverDirectory,

    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") { throw "Driver management is Windows-only." }
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}
if ($Action -in @("Install", "Start", "Restart") -and
    (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot)) {
    throw "Install/start/restart requires -ConfirmDedicatedVm and -ConfirmSnapshot."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($DriverDirectory)) {
    $DriverDirectory = Join-Path $RepoRoot "out\drivers\$Configuration"
}
$DriverDirectory = [System.IO.Path]::GetFullPath($DriverDirectory)

$Drivers = @(
    @{ Service = "KDBG";      Display = "KDBG Physical Memory Driver"; File = "KDbgDriver.sys" },
    @{ Service = "KDBGProbe"; Display = "KDBG Probe Fixture Driver";  File = "KDbgProbe.sys"  }
)

function Invoke-Sc([string[]]$Arguments, [switch]$AllowFailure) {
    $Output = & sc.exe @Arguments 2>&1
    $Code = $LASTEXITCODE
    if ($null -ne $Output) {
        $Output | ForEach-Object { Write-Host $_ }
    }
    if ($Code -ne 0 -and -not $AllowFailure) {
        throw "sc.exe $($Arguments -join ' ') failed with exit code $Code."
    }
    return [int]$Code
}

$ReverseDrivers = @($Drivers)
[Array]::Reverse($ReverseDrivers)

function Install-Driver($Driver) {
    $Path = Join-Path $DriverDirectory $Driver.File
    if (-not (Test-Path $Path)) { throw "Driver binary not found: $Path" }
    $Path = (Resolve-Path -LiteralPath $Path).Path
    $QuotedPath = '"' + $Path + '"'
    $Existing = Invoke-Sc -Arguments @("query", $Driver.Service) -AllowFailure
    if ($Existing -eq 0) {
        Invoke-Sc -Arguments @("config", $Driver.Service, "type=", "kernel", "start=", "demand", "binPath=", $QuotedPath, "DisplayName=", $Driver.Display) | Out-Null
    } else {
        Invoke-Sc -Arguments @("create", $Driver.Service, "type=", "kernel", "start=", "demand", "binPath=", $QuotedPath, "DisplayName=", $Driver.Display) | Out-Null
    }
}

switch ($Action) {
    "Install" {
        foreach ($Driver in $Drivers) { Install-Driver $Driver }
    }
    "Start" {
        foreach ($Driver in $Drivers) { Invoke-Sc -Arguments @("start", $Driver.Service) | Out-Null }
    }
    "Stop" {
        foreach ($Driver in $ReverseDrivers) {
            Invoke-Sc -Arguments @("stop", $Driver.Service) -AllowFailure | Out-Null
        }
    }
    "Restart" {
        foreach ($Driver in $ReverseDrivers) {
            Invoke-Sc -Arguments @("stop", $Driver.Service) -AllowFailure | Out-Null
        }
        Start-Sleep -Milliseconds 500
        foreach ($Driver in $Drivers) { Invoke-Sc -Arguments @("start", $Driver.Service) | Out-Null }
    }
    "Remove" {
        foreach ($Driver in $ReverseDrivers) {
            Invoke-Sc -Arguments @("stop", $Driver.Service) -AllowFailure | Out-Null
            Invoke-Sc -Arguments @("delete", $Driver.Service) -AllowFailure | Out-Null
        }
    }
    "Status" {
        foreach ($Driver in $Drivers) {
            Write-Host "--- $($Driver.Service) ---"
            Invoke-Sc -Arguments @("query", $Driver.Service) -AllowFailure | Out-Null
        }
    }
}

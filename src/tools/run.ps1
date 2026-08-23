[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [switch]$NoBuild,
    [switch]$ConfirmDisposableVm,
    [switch]$ConfirmSnapshot
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "KDBG GUI runs on Windows only." }
if (-not $ConfirmDisposableVm -or -not $ConfirmSnapshot) {
    throw "KDBG live mode requires -ConfirmDisposableVm and -ConfirmSnapshot."
}
$Preset = if ($Configuration -eq "Release") { "windows-release" } else { "windows-debug" }
if (-not $NoBuild) {
    & (Join-Path $PSScriptRoot "build.ps1") -Preset $Preset
}
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Executable = Get-ChildItem (Join-Path $RepositoryRoot "out\build\$Preset") -Recurse -Filter KDBG.exe |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $Executable) { throw "KDBG.exe was not found for preset $Preset." }
Start-Process -FilePath $Executable.FullName -Verb RunAs -Wait

[CmdletBinding()]
param(
    [ValidateSet("core-debug", "core-release", "core-sanitized", "core-clang-tidy", "windows-debug", "windows-release", "windows-analyze")]
    [string]$Preset = "core-debug",

    [switch]$SkipTests,
    [switch]$BuildDrivers,
    [switch]$Package,
    [switch]$Fresh
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Import-MsvcEnvironment {
    if ($env:OS -ne "Windows_NT") {
        throw "Windows GUI presets require Windows and MSVC."
    }
    if ((Get-Command cl.exe -ErrorAction SilentlyContinue) -and $env:VSCMD_VER) {
        return
    }

    $VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $VsWhere)) {
        throw "vswhere.exe was not found. Install Visual Studio with Desktop C++."
    }
    $InstallPath = & $VsWhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($InstallPath)) {
        throw "Visual Studio with the x64 C++ toolset was not found."
    }
    $DevCmd = Join-Path $InstallPath "Common7\Tools\VsDevCmd.bat"
    if (-not (Test-Path -LiteralPath $DevCmd)) {
        throw "VsDevCmd.bat was not found: $DevCmd"
    }

    $CommandLine = '"' + $DevCmd + '" -arch=x64 -host_arch=x64 >nul && set'
    $Variables = & $env:ComSpec /d /s /c $CommandLine
    if ($LASTEXITCODE -ne 0) {
        throw "Visual Studio developer environment initialization failed."
    }
    foreach ($Entry in $Variables) {
        $Separator = $Entry.IndexOf('=')
        if ($Separator -gt 0) {
            [Environment]::SetEnvironmentVariable(
                $Entry.Substring(0, $Separator),
                $Entry.Substring($Separator + 1),
                'Process')
        }
    }
    $env:CC = "cl.exe"
    $env:CXX = "cl.exe"
    $env:VSLANG = "1033"
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        throw "MSVC cl.exe is unavailable after developer environment initialization."
    }
}

$WindowsPreset = $Preset -in @("windows-debug", "windows-release", "windows-analyze")
if ($WindowsPreset) {
    Import-MsvcEnvironment
}

$BuildDirectory = [System.IO.Path]::GetFullPath(
    (Join-Path $SourceRoot "..\out\build\$Preset"))
$UseFreshConfigure = [bool]$Fresh
if ($WindowsPreset) {
    $CachePath = Join-Path $BuildDirectory "CMakeCache.txt"
    if (Test-Path -LiteralPath $CachePath) {
        $CompilerLine = Select-String -LiteralPath $CachePath `
            -Pattern '^CMAKE_CXX_COMPILER:FILEPATH=' | Select-Object -First 1
        if ($null -eq $CompilerLine -or
            $CompilerLine.Line -notmatch '[\\/]cl\.exe$') {
            $UseFreshConfigure = $true
        }
    }
}

Push-Location $SourceRoot
try {
    $ConfigureArguments = @("--preset", $Preset)
    if ($UseFreshConfigure) { $ConfigureArguments += "--fresh" }
    & cmake @ConfigureArguments
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed." }

    & cmake --build --preset $Preset --parallel
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed." }

    if (-not $SkipTests) {
        & ctest --preset $Preset --output-on-failure
        if ($LASTEXITCODE -ne 0) { throw "Tests failed." }
    }
}
finally {
    Pop-Location
}

if ($BuildDrivers -or $Package) {
    if ($Preset -notin @("windows-debug", "windows-release")) {
        throw "Driver builds require the windows-debug or windows-release preset."
    }
    $Configuration = if ($Preset -eq "windows-release") { "Release" } else { "Debug" }
    $DriverArguments = @{ Configuration = $Configuration }
    if ($Fresh) { $DriverArguments.Clean = $true }
    & (Join-Path $PSScriptRoot "build_drivers.ps1") @DriverArguments
    if ($LASTEXITCODE -ne 0) { throw "Driver build failed." }
}

if ($Package) {
    if ($Preset -ne "windows-release") {
        throw "Release packaging requires the windows-release preset."
    }
    & (Join-Path $PSScriptRoot "package_windows.ps1") -Configuration Release -Zip
    if ($LASTEXITCODE -ne 0) { throw "Windows packaging failed." }
}

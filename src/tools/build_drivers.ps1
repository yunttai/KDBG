[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [switch]$Clean,

    [string]$OutputDirectory,

    [string]$WindowsTargetPlatformVersion,

    [switch]$KeepIntermediateOutput
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "KDBG driver builds require Windows with Visual Studio 2022 and the WDK."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Solution = Join-Path $RepoRoot "src\driver\KDBGDrivers.sln"
if (-not (Test-Path $Solution)) { throw "Driver solution not found: $Solution" }

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepoRoot "out\drivers\$Configuration"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $VsWhere)) {
    throw "vswhere.exe was not found. Install Visual Studio 2022 with Desktop C++ and the WDK."
}
$InstallPath = & $VsWhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($InstallPath)) {
    throw "Visual Studio with MSBuild was not found."
}
$MsBuild = Join-Path $InstallPath "MSBuild\Current\Bin\amd64\MSBuild.exe"
if (-not (Test-Path -LiteralPath $MsBuild)) {
    $MsBuild = Join-Path $InstallPath "MSBuild\Current\Bin\MSBuild.exe"
}
if (-not (Test-Path -LiteralPath $MsBuild)) {
    throw "MSBuild was not found under: $InstallPath"
}

if ([string]::IsNullOrWhiteSpace($WindowsTargetPlatformVersion)) {
    $KitIncludeRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Include"
    $KitBuildRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\build"
    $InstalledKits = @(Get-ChildItem -Path $KitIncludeRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-Path (Join-Path $_.FullName "km\ntifs.h")) -and
            (Test-Path (Join-Path $_.FullName "km\ntddk.h")) -and
            (Test-Path (Join-Path $KitBuildRoot "$($_.Name)\bin\x64\InfVerif.dll"))
        } |
        Sort-Object { [Version]$_.Name } -Descending)
    if ($InstalledKits.Count -eq 0) {
        throw "No installed Windows Driver Kit with ntifs.h and ntddk.h was found."
    }
    $WindowsTargetPlatformVersion = $InstalledKits[0].Name
}

$Target = if ($Clean) { "Rebuild" } else { "Build" }
$BuildOutput = @(& $MsBuild $Solution "/t:$Target" "/m" "/p:Configuration=$Configuration" "/p:Platform=x64" "/p:WindowsTargetPlatformVersion=$WindowsTargetPlatformVersion" "/v:minimal" 2>&1)
$BuildExitCode = $LASTEXITCODE
$BuildOutput | ForEach-Object { Write-Host $_ }
$ReportedBuildErrors = @($BuildOutput | Where-Object {
    $_.ToString() -match '(?i)(?:^|\)|\])\s*:\s*error(?:\s|:)'
})
if ($BuildExitCode -ne 0 -or $ReportedBuildErrors.Count -ne 0) {
    throw "WDK driver build failed (exit $BuildExitCode, reported errors $($ReportedBuildErrors.Count))."
}

$Projects = @(
    @{ Name = "KDbgDriver"; Folder = Join-Path $RepoRoot "src\driver\KDbgDriver" },
    @{ Name = "KDbgProbe";  Folder = Join-Path $RepoRoot "src\driver\KDbgProbe"  }
)
$DriverBuildRoot = Join-Path $RepoRoot "src\driver"
$ConfigurationPattern = "\\x64\\$([Regex]::Escape($Configuration))\\|\\$([Regex]::Escape($Configuration))\\"
foreach ($Project in $Projects) {
    $Sys = Get-ChildItem -Path $DriverBuildRoot -Recurse -File -Filter "$($Project.Name).sys" |
        Where-Object { $_.FullName -match $ConfigurationPattern } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $Sys) {
        throw "$($Project.Name).sys was not found after a successful MSBuild invocation."
    }
    Copy-Item -Force $Sys.FullName (Join-Path $OutputDirectory $Sys.Name)

    $Inf = Get-ChildItem -Path $DriverBuildRoot -Recurse -File -Filter "$($Project.Name).inf" |
        Where-Object { $_.FullName -match $ConfigurationPattern } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $Inf) {
        throw "$($Project.Name).inf was not found in the stamped build output."
    }
    Copy-Item -Force $Inf.FullName (Join-Path $OutputDirectory "$($Project.Name).inf")

    $Pdb = Get-ChildItem -Path $DriverBuildRoot -Recurse -File -Filter "$($Project.Name).pdb" |
        Where-Object { $_.FullName -match $ConfigurationPattern } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -ne $Pdb) {
        Copy-Item -Force $Pdb.FullName (Join-Path $OutputDirectory $Pdb.Name)
    }

    $Cat = Get-ChildItem -Path $DriverBuildRoot -Recurse -File -Filter "$($Project.Name).cat" |
        Where-Object { $_.FullName -match $ConfigurationPattern } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -ne $Cat) {
        Copy-Item -Force $Cat.FullName (Join-Path $OutputDirectory $Cat.Name)
    }
}

if (-not $KeepIntermediateOutput) {
    $GeneratedDirectories = @(
        (Join-Path $DriverBuildRoot "x64"),
        (Join-Path $DriverBuildRoot "KDbgDriver\x64"),
        (Join-Path $DriverBuildRoot "KDbgProbe\x64")
    )
    $Allowed = @($GeneratedDirectories | ForEach-Object {
        [IO.Path]::GetFullPath($_).TrimEnd([IO.Path]::DirectorySeparatorChar)
    })
    foreach ($Directory in $GeneratedDirectories) {
        $Full = [IO.Path]::GetFullPath($Directory).TrimEnd(
            [IO.Path]::DirectorySeparatorChar)
        if ($Full -notin $Allowed) {
            throw "Refusing to remove an unexpected driver build directory: $Full"
        }
        if (Test-Path -LiteralPath $Full -PathType Container) {
            Remove-Item -LiteralPath $Full -Recurse -Force
        }
    }
}

Write-Host "KDBG driver build artifacts: $OutputDirectory"
Get-ChildItem -Path $OutputDirectory -File | Select-Object Name, Length, LastWriteTimeUtc
Write-Warning "The script does not bypass driver signing. Sign the drivers with a test certificate in a disposable test-signing VM or with an appropriate production certificate."

[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [switch]$Clean,

    [string]$OutputDirectory,

    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,47}$')]
    [string]$EpochName,

    [string]$VisualStudioInstallPath,

    [string]$NuGetPackageCache,

    [string]$NuGetSource = "https://api.nuget.org/v3/index.json",

    [switch]$Offline,

    [ValidatePattern('^[D-Zd-z]:$')]
    [string]$PathMapDrive = "K:",

    [switch]$KeepIntermediateOutput
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "The pinned NuGet WDK driver build requires Windows x64."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ProfileRoot = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::UserProfile)
$RepoPathRoot = [IO.Path]::GetPathRoot($RepoRoot)
$RepoAtDriveRoot = $RepoRoot.TrimEnd('\') -ceq $RepoPathRoot.TrimEnd('\')
$PhysicalRepoRoot = $RepoRoot
if ($RepoAtDriveRoot) {
    $RepoDrive = $RepoPathRoot.Substring(0, 2)
    $Mapping = @(& subst.exe) |
        Where-Object {
            [string]$_ -match "^$([regex]::Escape($RepoDrive))\\: => "
        } |
        Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace($Mapping)) {
        $PhysicalRepoRoot = [IO.Path]::GetFullPath(
            ([string]$Mapping).Substring(([string]$Mapping).IndexOf('=>') + 2).Trim())
    }
}
$WdkPackageVersion = "10.0.26100.2454"
$WdkKitVersion = "10.0.26100.0"
$NuGetPackageHashes = [ordered]@{
    "microsoft.windows.wdk.x64" =
        "zzOYh91xa827HWByuF5KEXpb92/oJSa9l8bRkRnq9Da6ljwFDGHDFU/JTfPlc/UyIT7ZOiohC3mLBTIuIYMTQA=="
    "microsoft.windows.sdk.cpp" =
        "iy+x7OJ9txS6maNM5kbez0Sptha93eeZt9ayQxrvUU8QWphzK/J121HbQoEf1zbQk0rRbetVTZxewNLIhtfNsw=="
    "microsoft.windows.sdk.cpp.x64" =
        "3ptfAxPbuCq8HqMOWaoa9/nBJ0HyyJiitg/53i+RzsBtOA+Ot9ovm457F0TfCIw/i+N+7j2xUjf62vcumMILmQ=="
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = if ([string]::IsNullOrWhiteSpace($EpochName)) {
        Join-Path $RepoRoot "out\drivers\$Configuration"
    } else {
        Join-Path $RepoRoot `
            "out\release-epochs\$EpochName\drivers\$Configuration"
    }
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

if ([string]::IsNullOrWhiteSpace($NuGetPackageCache)) {
    $NuGetPackageCache = Join-Path $RepoRoot "out\wdk-nuget"
}
$NuGetPackageCache = [IO.Path]::GetFullPath($NuGetPackageCache)
New-Item -ItemType Directory -Force -Path $NuGetPackageCache | Out-Null

function Get-PackageDirectory([string]$PackageId) {
    return Join-Path $NuGetPackageCache "$PackageId\$WdkPackageVersion"
}

function Test-PackageCacheComplete {
    foreach ($PackageId in $NuGetPackageHashes.Keys) {
        $PackageDirectory = Get-PackageDirectory $PackageId
        $PackageFile = Join-Path $PackageDirectory "$PackageId.$WdkPackageVersion.nupkg"
        if (-not (Test-Path -LiteralPath $PackageFile -PathType Leaf)) {
            return $false
        }
    }
    return $true
}

function Assert-PackageHash(
    [string]$PackageId,
    [string]$ExpectedHash) {
    $PackageDirectory = Get-PackageDirectory $PackageId
    $PackageFile = Join-Path $PackageDirectory "$PackageId.$WdkPackageVersion.nupkg"
    $SignatureFile = Join-Path $PackageDirectory ".signature.p7s"
    if (-not (Test-Path -LiteralPath $PackageFile -PathType Leaf)) {
        throw "Pinned NuGet package is missing: $PackageFile"
    }
    if (-not (Test-Path -LiteralPath $SignatureFile -PathType Leaf)) {
        throw "NuGet package signature is missing: $SignatureFile"
    }

    $Stream = [IO.File]::OpenRead($PackageFile)
    try {
        $Algorithm = [Security.Cryptography.SHA512]::Create()
        try {
            $ActualHash = [Convert]::ToBase64String(
                $Algorithm.ComputeHash($Stream))
        } finally {
            $Algorithm.Dispose()
        }
    } finally {
        $Stream.Dispose()
    }
    if ($ActualHash -cne $ExpectedHash) {
        throw "Pinned NuGet package hash mismatch: $PackageId"
    }
}

if (-not (Test-PackageCacheComplete)) {
    if ($Offline) {
        throw "The pinned WDK cache is incomplete and -Offline forbids restore: $NuGetPackageCache"
    }
    $DotNet = Get-Command dotnet.exe -ErrorAction SilentlyContinue
    if ($null -eq $DotNet) {
        throw ".NET 8 SDK is required to restore the pinned WDK package cache."
    }
    $BootstrapProject = Join-Path $RepoRoot `
        "src\driver\WdkBootstrap\KDBG.WdkBootstrap.csproj"
    $BootstrapIntermediate = Join-Path $NuGetPackageCache "bootstrap-obj\"
    $PreviousTelemetrySetting = $env:DOTNET_CLI_TELEMETRY_OPTOUT
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
    try {
        $RestoreArguments = @(
            "restore",
            $BootstrapProject,
            "--packages", $NuGetPackageCache,
            "--source", $NuGetSource,
            "--locked-mode",
            "--property:BaseIntermediateOutputPath=$BootstrapIntermediate",
            "--verbosity", "minimal"
        )
        $RestoreOutput = @(& $DotNet.Source @RestoreArguments 2>&1)
        $RestoreExitCode = $LASTEXITCODE
        $RestoreOutput | ForEach-Object { Write-Host $_ }
        if ($RestoreExitCode -ne 0) {
            throw "Pinned WDK NuGet restore failed (exit $RestoreExitCode)."
        }
    } finally {
        $env:DOTNET_CLI_TELEMETRY_OPTOUT = $PreviousTelemetrySetting
    }
}

foreach ($PackageId in $NuGetPackageHashes.Keys) {
    Assert-PackageHash $PackageId $NuGetPackageHashes[$PackageId]
}

if ([string]::IsNullOrWhiteSpace($VisualStudioInstallPath)) {
    $VsWhere = Join-Path ${env:ProgramFiles(x86)} `
        "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $VsWhere -PathType Leaf)) {
        throw "vswhere.exe was not found. Install Visual Studio 2022 C++ tools."
    }
    $VsWhereArguments = @(
        "-latest", "-products", "*", "-requires",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "-property", "installationPath"
    )
    $VisualStudioInstallPath = & $VsWhere @VsWhereArguments
    if ($LASTEXITCODE -ne 0 -or
        [string]::IsNullOrWhiteSpace($VisualStudioInstallPath)) {
        throw "Visual Studio 2022 x64 C++ tools were not found."
    }
}
$VisualStudioInstallPath = [IO.Path]::GetFullPath($VisualStudioInstallPath)
$MsvcRoot = Join-Path $VisualStudioInstallPath "VC\Tools\MSVC"
$MsvcVersionDirectory = Get-ChildItem -LiteralPath $MsvcRoot -Directory |
    Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName `
            "bin\Hostx64\x64\cl.exe")
    } |
    Sort-Object { [Version]$_.Name } -Descending |
    Select-Object -First 1
if ($null -eq $MsvcVersionDirectory) {
    throw "An x64 MSVC compiler was not found under: $MsvcRoot"
}
$MsvcRoot = $MsvcVersionDirectory.FullName
$Compiler = Join-Path $MsvcRoot "bin\Hostx64\x64\cl.exe"
$Linker = Join-Path $MsvcRoot "bin\Hostx64\x64\link.exe"

$WdkPackageRoot = Get-PackageDirectory "microsoft.windows.wdk.x64"
$SdkPackageRoot = Get-PackageDirectory "microsoft.windows.sdk.cpp"
$WdkRoot = Join-Path $WdkPackageRoot "c"
$SdkRoot = Join-Path $SdkPackageRoot "c"
$WdkInclude = Join-Path $WdkRoot "Include\$WdkKitVersion"
$SdkInclude = Join-Path $SdkRoot "Include\$WdkKitVersion"
$KernelLibraryRoot = Join-Path $WdkRoot "Lib\$WdkKitVersion\km\x64"
$Inf2Cat = Join-Path $WdkRoot "bin\$WdkKitVersion\x86\Inf2Cat.exe"
$ResourceCompiler = Join-Path $SdkRoot "bin\$WdkKitVersion\x64\rc.exe"
$RequiredToolchainFiles = @(
    $Compiler,
    $Linker,
    $Inf2Cat,
    $ResourceCompiler,
    (Join-Path $WdkInclude "km\ntddk.h"),
    (Join-Path $SdkInclude "shared\ntdef.h"),
    (Join-Path $KernelLibraryRoot "ntoskrnl.lib"),
    (Join-Path $KernelLibraryRoot "wdmsec.lib"),
    (Join-Path $KernelLibraryRoot "BufferOverflowFastFailK.lib")
)
foreach ($RequiredFile in $RequiredToolchainFiles) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Pinned WDK toolchain file is missing: $RequiredFile"
    }
}

function Invoke-CheckedTool(
    [string]$Tool,
    [string[]]$Arguments,
    [string]$Operation) {
    $ToolOutput = @(& $Tool @Arguments 2>&1)
    $ToolExitCode = $LASTEXITCODE
    $ToolOutput | ForEach-Object { Write-Host $_ }
    if ($ToolExitCode -ne 0) {
        throw "$Operation failed (exit $ToolExitCode)."
    }
}

function Get-RepoRelativePath([string]$Path) {
    $FullPath = [IO.Path]::GetFullPath($Path)
    $RootPrefix = $BuildRepoRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $FullPath.StartsWith(
            $RootPrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the repository and cannot be made reproducible: $FullPath"
    }
    return $FullPath.Substring($RootPrefix.Length)
}

function Convert-ToBuildPath([string]$Path) {
    $FullPath = [IO.Path]::GetFullPath($Path)
    $PhysicalPrefix = $RepoRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $FullPath.StartsWith(
            $PhysicalPrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Pinned WDK cache must be inside the repository for a reproducible symbol build: $FullPath"
    }
    return Join-Path $BuildRepoRoot $FullPath.Substring(
        $PhysicalPrefix.Length)
}

$PhysicalBuildRoot = if ([string]::IsNullOrWhiteSpace($EpochName)) {
    [IO.Path]::GetFullPath((Join-Path $RepoRoot "out\driver-build"))
} else {
    [IO.Path]::GetFullPath((Join-Path $RepoRoot `
        "out\release-epochs\$EpochName\driver-build"))
}
$PrivateSymbolsDirectory = if ([string]::IsNullOrWhiteSpace($EpochName)) {
    [IO.Path]::GetFullPath((Join-Path $RepoRoot `
        "out\private-symbols\drivers\$Configuration"))
} else {
    [IO.Path]::GetFullPath((Join-Path $RepoRoot `
        "out\release-epochs\$EpochName\private-symbols\drivers\$Configuration"))
}
New-Item -ItemType Directory -Force -Path $PhysicalBuildRoot | Out-Null
New-Item -ItemType Directory -Force -Path $PrivateSymbolsDirectory | Out-Null
$BuildId = "kdbg-nuget-$Configuration-$WdkPackageVersion"
$BuildLockPath = Join-Path $PhysicalBuildRoot ".$BuildId.lock"
try {
    $BuildLock = [IO.File]::Open(
        $BuildLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
} catch {
    throw "Another $Configuration NuGet WDK driver build is already active."
}
$IntermediateRoot = $null
$BuildPrefix = $null
$SubstCreated = $false
$PreviousTemp = $env:TEMP
$PreviousTmp = $env:TMP
try {
    if ($RepoAtDriveRoot) {
        $BuildRepoRoot = $RepoPathRoot
    } else {
        $BuildRepoRoot = "$PathMapDrive\"
        if (Test-Path -LiteralPath $BuildRepoRoot) {
            throw "Deterministic build drive is already in use: $PathMapDrive"
        }
        $Subst = Join-Path $env:SystemRoot "System32\subst.exe"
        & $Subst $PathMapDrive $RepoRoot
        if ($LASTEXITCODE -ne 0 -or
            -not (Test-Path -LiteralPath $BuildRepoRoot)) {
            throw "Unable to create deterministic build drive $PathMapDrive."
        }
        $SubstCreated = $true
    }

    $WdkInclude = Convert-ToBuildPath $WdkInclude
    $SdkInclude = Convert-ToBuildPath $SdkInclude
    $KernelLibraryRoot = Convert-ToBuildPath $KernelLibraryRoot
    $BuildRoot = if ([string]::IsNullOrWhiteSpace($EpochName)) {
        Join-Path $BuildRepoRoot "out\driver-build"
    } else {
        Join-Path $BuildRepoRoot "out\release-epochs\$EpochName\driver-build"
    }
    $IntermediateRoot = Join-Path $BuildRoot $BuildId
    $BuildPrefix = $BuildRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $IntermediateRoot.StartsWith(
            $BuildPrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to use an unexpected driver build directory: $IntermediateRoot"
    }
    if (Test-Path -LiteralPath $IntermediateRoot -PathType Container) {
        Remove-Item -LiteralPath $IntermediateRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $IntermediateRoot | Out-Null
    $BuildTemp = Join-Path $BuildRoot "temp"
    New-Item -ItemType Directory -Force -Path $BuildTemp | Out-Null
    $env:TEMP = $BuildTemp
    $env:TMP = $BuildTemp

    $Projects = @(
        @{
            Name = "KDbgDriver"
            Source = Join-Path $BuildRepoRoot "src\driver\KDbgDriver\Driver.cpp"
            Resource = Join-Path $BuildRepoRoot "src\driver\KDbgDriver\KDbgDriver.rc"
            Inf = Join-Path $BuildRepoRoot "src\driver\KDbgDriver\KDbgDriver.inf"
        },
        @{
            Name = "KDbgProbe"
            Source = Join-Path $BuildRepoRoot "src\driver\KDbgProbe\Driver.cpp"
            Resource = Join-Path $BuildRepoRoot "src\driver\KDbgProbe\KDbgProbe.rc"
            Inf = Join-Path $BuildRepoRoot "src\driver\KDbgProbe\KDbgProbe.inf"
        }
    )

    foreach ($Project in $Projects) {
        $Name = $Project.Name
        $ProjectRoot = Join-Path $IntermediateRoot $Name
        $ObjectRoot = Join-Path $ProjectRoot "obj"
        $PackageRoot = Join-Path $ProjectRoot "package"
        New-Item -ItemType Directory -Force -Path $ObjectRoot | Out-Null
        New-Item -ItemType Directory -Force -Path $PackageRoot | Out-Null

        $ObjectFile = Join-Path $ObjectRoot "Driver.obj"
        $ResourceFile = Join-Path $ObjectRoot "$Name.res"
        $DriverFile = Join-Path $PackageRoot "$Name.sys"
        $DriverPdb = Join-Path $PackageRoot "$Name.pdb"
        $PublicDriverPdb = Join-Path $PackageRoot "$Name.public.pdb"
        $WarningHeader = Join-Path $SdkInclude "shared\warning.h"
        $CompileArguments = @(
            "/nologo", "/c", "/kernel", "/std:c++20", "/W4", "/WX",
            "/GS", "/guard:cf", "/Z7", "/Zl", "/EHs-c-", "/GR-",
            "/permissive-", "/Zc:wchar_t-", "/Zc:inline",
            "/Zc:__cplusplus", "/diagnostics:caret", "/d1nodatetime",
            "/experimental:deterministic",
            ("/pathmap:" + $BuildRepoRoot + "=KDBG_ROOT"),
            "/D_AMD64_", "/DAMD64", "/D_WIN64", "/DWINNT=1",
            "/DUNICODE", "/D_UNICODE", "/DDEPRECATE_DDK_FUNCTIONS=1",
            "/DWINVER=0x0A00", "/D_WIN32_WINNT=0x0A00",
            "/DNTDDI_VERSION=0x0A000008",
            ("/I" + (Join-Path $MsvcRoot "include")),
            ("/I" + (Join-Path $WdkInclude "km")),
            ("/I" + (Join-Path $SdkInclude "shared")),
            ("/I" + (Join-Path $WdkInclude "shared")),
            ("/I" + (Join-Path $SdkInclude "ucrt")),
            ("/FI" + $WarningHeader),
            ("/Fo" + $ObjectFile)
        )
        if ($Configuration -eq "Release") {
            $CompileArguments += @("/O2", "/Oi", "/Gy", "/Gw", "/GF", "/Zo")
        } else {
            $CompileArguments += @("/Od", "/Ob0", "/DDBG=1", "/DMSC_NOOPT")
        }
        $CompileArguments += $Project.Source
        Invoke-CheckedTool $Compiler $CompileArguments "Compile $Name"

        Invoke-CheckedTool $ResourceCompiler @(
            "/nologo",
            ("/fo" + $ResourceFile),
            ("/i" + (Join-Path $SdkInclude "shared")),
            ("/i" + (Join-Path $SdkInclude "um")),
            $Project.Resource
        ) "Compile resources for $Name"

        $LinkArguments = @(
            "/nologo", "/WX", ("/OUT:" + (Get-RepoRelativePath $DriverFile)), "/DRIVER",
            "/SUBSYSTEM:NATIVE,10.00", "/MACHINE:X64", "/ENTRY:DriverEntry",
            "/NODEFAULTLIB", "/DEBUG:FULL",
            ("/PDB:" + (Get-RepoRelativePath $DriverPdb)),
            ("/PDBSTRIPPED:" + (Get-RepoRelativePath $PublicDriverPdb)),
            "/PDBALTPATH:%_PDB%", "/GUARD:CF", "/DYNAMICBASE", "/NXCOMPAT",
            "/INCREMENTAL:NO", "/OPT:REF", "/OPT:ICF", "/MERGE:_TEXT=.text",
            "/MERGE:_PAGE=PAGE", "/SECTION:INIT,d", "/VERSION:10.0",
            "/OSVERSION:10.0", "/RELEASE", "/KERNEL", "/BREPRO", "/MANIFEST:NO",
            "/experimental:deterministic",
            ("/pathmap:" + $BuildRepoRoot + "=KDBG_ROOT"),
            (Get-RepoRelativePath $ObjectFile),
            (Get-RepoRelativePath $ResourceFile),
            (Get-RepoRelativePath (Join-Path $KernelLibraryRoot "ntoskrnl.lib")),
            (Get-RepoRelativePath (Join-Path $KernelLibraryRoot "hal.lib")),
            (Get-RepoRelativePath (Join-Path $KernelLibraryRoot "wmilib.lib")),
            (Get-RepoRelativePath (Join-Path $KernelLibraryRoot "wdmsec.lib")),
            (Get-RepoRelativePath (Join-Path $KernelLibraryRoot "BufferOverflowFastFailK.lib"))
        )
        Push-Location $BuildRepoRoot
        try {
            Invoke-CheckedTool $Linker $LinkArguments "Link $Name"
        } finally {
            Pop-Location
        }
        if (-not (Test-Path -LiteralPath $PublicDriverPdb -PathType Leaf) -or
            (Get-Item -LiteralPath $PublicDriverPdb).Length -eq 0) {
            throw "$Name public stripped PDB was not produced."
        }
        Copy-Item -LiteralPath $DriverPdb `
            -Destination (Join-Path $PrivateSymbolsDirectory "$Name.pdb") `
            -Force
        Copy-Item -LiteralPath $PublicDriverPdb -Destination $DriverPdb -Force
        [IO.File]::Delete($PublicDriverPdb)

        Copy-Item -LiteralPath $Project.Inf -Destination `
            (Join-Path $PackageRoot "$Name.inf") -Force
        Invoke-CheckedTool $Inf2Cat @(
            "/driver:$PackageRoot",
            "/os:10_VB_X64,10_CO_X64,10_NI_X64,10_GE_X64",
            "/verbose"
        ) "Inf2Cat $Name"

        foreach ($Extension in @("sys", "inf", "pdb", "cat")) {
            $Artifact = Join-Path $PackageRoot "$Name.$Extension"
            if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf) -or
                (Get-Item -LiteralPath $Artifact).Length -eq 0) {
                throw "$Name.$Extension was not produced."
            }
        }
    }

    foreach ($Project in $Projects) {
        $Name = $Project.Name
        $PackageRoot = Join-Path (Join-Path $IntermediateRoot $Name) "package"
        foreach ($Extension in @("sys", "inf", "pdb", "cat")) {
            Copy-Item -LiteralPath (Join-Path $PackageRoot "$Name.$Extension") `
                -Destination (Join-Path $OutputDirectory "$Name.$Extension") `
                -Force
        }
    }

    $DriverContractVerifier = Join-Path $RepoRoot `
        "src\driver\tests\verify_driver_contract.ps1"
    & $DriverContractVerifier -ArtifactsDirectory $OutputDirectory
    $DriverSymbolVerifier = Join-Path $RepoRoot `
        "src\driver\tests\verify_driver_symbols.ps1"
    & $DriverSymbolVerifier `
        -ArtifactsDirectory $OutputDirectory `
        -PrivatePdbDirectory $PrivateSymbolsDirectory `
        -StableBuildAlias $BuildRepoRoot `
        -PrivatePath @($PhysicalRepoRoot, $ProfileRoot)
} finally {
    $env:TEMP = $PreviousTemp
    $env:TMP = $PreviousTmp
    try {
        if ($KeepIntermediateOutput -and $null -ne $IntermediateRoot) {
            Write-Host "KDBG driver intermediate output: $IntermediateRoot"
        } elseif ($null -ne $IntermediateRoot -and
            (Test-Path -LiteralPath $IntermediateRoot -PathType Container)) {
            $ResolvedIntermediate = [IO.Path]::GetFullPath($IntermediateRoot)
            if (-not $ResolvedIntermediate.StartsWith(
                    $BuildPrefix,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to remove an unexpected driver build directory: $ResolvedIntermediate"
            }
            Remove-Item -LiteralPath $ResolvedIntermediate -Recurse -Force
        }
    } finally {
        try {
            if ($SubstCreated) {
                & $Subst $PathMapDrive /D | Out-Null
                if ($LASTEXITCODE -ne 0 -or
                    (Test-Path -LiteralPath "$PathMapDrive\")) {
                    throw "Unable to remove deterministic build drive $PathMapDrive."
                }
            }
        } finally {
            $BuildLock.Dispose()
        }
    }
}

Write-Host "KDBG driver build mode: pinned NuGet WDK $WdkPackageVersion"
Write-Host "KDBG WDK cache: $NuGetPackageCache"
Write-Host "KDBG driver build artifacts: $OutputDirectory"
Get-ChildItem -LiteralPath $OutputDirectory -File |
    Where-Object { $_.Name -match '^KDbg(?:Driver|Probe)\.(?:sys|inf|pdb|cat)$' } |
    Sort-Object Name |
    Select-Object Name, Length, LastWriteTimeUtc
Write-Warning "The script does not bypass driver signing. Sign the drivers with a test certificate in a disposable test-signing VM or with an appropriate production certificate."

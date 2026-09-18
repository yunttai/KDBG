[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,47}$')]
    [string]$EpochName,

    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,47}$')]
    [string]$BuildId,

    [ValidatePattern('^[A-Z]$')]
    [string]$VirtualDrive = 'R',

    [switch]$SkipTests,
    [switch]$BuildDrivers,
    [switch]$Package,
    [switch]$PrepareProductionSigning,
    [string]$ProductionSigningOutputDirectory,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($BuildId)) {
    $BuildId = $EpochName
}
if ($PrepareProductionSigning -and -not $Package) {
    throw '-PrepareProductionSigning requires -Package.'
}
if ($PrepareProductionSigning -and
    [string]::IsNullOrWhiteSpace($ProductionSigningOutputDirectory)) {
    throw '-PrepareProductionSigning requires -ProductionSigningOutputDirectory.'
}

$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$EpochRoot = [IO.Path]::GetFullPath(
    (Join-Path $RepoRoot "out\release-epochs\$EpochName"))
$AllowedRoot = [IO.Path]::GetFullPath(
    (Join-Path $RepoRoot 'out\release-epochs')).TrimEnd('\') + '\'
$SourceSnapshotTool = Join-Path $RepoRoot `
    'src\tools\source_snapshot\source_snapshot.py'
$SourceSnapshotScope = Join-Path $RepoRoot `
    'src\tools\source_snapshot\scope.kdbg.json'
$SourceProvenanceRoot = Join-Path $EpochRoot 'source-provenance'
if (-not $EpochRoot.StartsWith($AllowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Epoch output must remain below ${AllowedRoot}: $EpochRoot"
}

function Import-MsvcEnvironment {
    if ((Get-Command cl.exe -ErrorAction SilentlyContinue) -and $env:VSCMD_VER) {
        return
    }
    $VsWhere = Join-Path ${env:ProgramFiles(x86)} `
        'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $VsWhere -PathType Leaf)) {
        throw 'vswhere.exe was not found. Install Visual Studio with Desktop C++.'
    }
    $InstallPath = & $VsWhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($InstallPath)) {
        throw 'Visual Studio with the x64 C++ toolset was not found.'
    }
    $DevCmd = Join-Path $InstallPath 'Common7\Tools\VsDevCmd.bat'
    $CommandLine = '"' + $DevCmd + '" -arch=x64 -host_arch=x64 >nul && set'
    $Variables = & $env:ComSpec /d /s /c $CommandLine
    if ($LASTEXITCODE -ne 0) {
        throw 'Visual Studio developer environment initialization failed.'
    }
    foreach ($Entry in $Variables) {
        $Separator = $Entry.IndexOf('=')
        if ($Separator -gt 0) {
            [Environment]::SetEnvironmentVariable(
                $Entry.Substring(0, $Separator),
                $Entry.Substring($Separator + 1), 'Process')
        }
    }
    $env:CC = 'cl.exe'
    $env:CXX = 'cl.exe'
    $env:VSLANG = '1033'
}

function Remove-OwnedEpochDirectory([string]$Path) {
    $Full = [IO.Path]::GetFullPath($Path)
    if (-not $Full.StartsWith($AllowedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not $Full.StartsWith(
            $EpochRoot.TrimEnd('\') + '\',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a directory outside this epoch: $Full"
    }
    if (Test-Path -LiteralPath $Full) {
        Remove-Item -LiteralPath $Full -Recurse -Force
    }
}

function Read-KdbgSourceSnapshotMetadata(
    [string]$Path,
    [string]$ManifestPath) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Source snapshot artifacts are missing: $Path / $ManifestPath"
    }
    $Metadata = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($Metadata.schema -ne 'kdbg.source-manifest-metadata.v1' -or
        [string]$Metadata.scope_version -ne 'kdbg.product-source.v1' -or
        [string]$Metadata.digest -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Metadata.scope_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (-not ($Metadata.count -is [int] -or
                $Metadata.count -is [long])) -or
        $Metadata.count -le 0 -or
        [string]$Metadata.path_order -ne 'ordinal-posix-relative-path') {
        throw "Source snapshot metadata is invalid: $Path"
    }
    $ManifestDigest = (Get-FileHash -LiteralPath $ManifestPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ManifestDigest -cne [string]$Metadata.digest) {
        throw "Source snapshot manifest digest does not match metadata: $ManifestPath"
    }
    return [pscustomobject]@{
        Digest = [string]$Metadata.digest
        Count = [int]$Metadata.count
        ScopeVersion = [string]$Metadata.scope_version
        ScopeSha256 = [string]$Metadata.scope_sha256
        ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
        MetadataPath = [IO.Path]::GetFullPath($Path)
    }
}

function New-KdbgSourceSnapshotArtifacts(
    [string]$ToolPath,
    [string]$RootPath,
    [string]$ScopePath,
    [string]$OutputRoot,
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,47}$')]
    [string]$Phase) {
    foreach ($Required in @($ToolPath, $ScopePath)) {
        if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
            throw "Source snapshot input is missing: $Required"
        }
    }
    $PhaseRoot = Join-Path $OutputRoot $Phase
    New-Item -ItemType Directory -Path $PhaseRoot -Force | Out-Null
    $ManifestPath = Join-Path $PhaseRoot 'SOURCE-SNAPSHOT-SHA256SUMS.txt'
    $MetadataPath = Join-Path $PhaseRoot 'SOURCE-SNAPSHOT-METADATA.json'
    & python $ToolPath generate `
        --root $RootPath `
        --scope $ScopePath `
        --manifest $ManifestPath `
        --metadata $MetadataPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Source snapshot capture failed during ${Phase}."
    }
    return Read-KdbgSourceSnapshotMetadata $MetadataPath $ManifestPath
}

function Assert-KdbgSourceSnapshotEqual(
    [object]$Baseline,
    [object]$Candidate,
    [string]$Phase) {
    if ([string]$Candidate.Digest -cne [string]$Baseline.Digest -or
        [int]$Candidate.Count -ne [int]$Baseline.Count -or
        [string]$Candidate.ScopeVersion -cne [string]$Baseline.ScopeVersion -or
        [string]$Candidate.ScopeSha256 -cne [string]$Baseline.ScopeSha256) {
        throw "Product source drift detected during ${Phase}: baseline $($Baseline.Digest)/$($Baseline.Count), candidate $($Candidate.Digest)/$($Candidate.Count)."
    }
}

function Assert-KdbgSourceSnapshotTree(
    [string]$ToolPath,
    [string]$RootPath,
    [string]$ScopePath,
    [object]$Baseline,
    [string]$Phase) {
    & python $ToolPath verify `
        --root $RootPath `
        --scope $ScopePath `
        --manifest $Baseline.ManifestPath `
        --metadata $Baseline.MetadataPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Product source differs from the before-configure snapshot during ${Phase}."
    }
}

Import-MsvcEnvironment

$Drive = "${VirtualDrive}:"
$ExistingMapping = @(& subst.exe) |
    Where-Object { [string]$_ -match "^$([regex]::Escape($Drive))\\: => " } |
    Select-Object -First 1
$CreatedMapping = $false
if ([string]::IsNullOrWhiteSpace($ExistingMapping)) {
    & subst.exe $Drive $RepoRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to map $Drive to the repository root."
    }
    $CreatedMapping = $true
} elseif ($ExistingMapping -notmatch [regex]::Escape($RepoRoot) + '\\?$') {
    throw "$Drive is already mapped to a different directory: $ExistingMapping"
}

$SavedTemp = $env:TEMP
$SavedTmp = $env:TMP
try {
    $VirtualEpochRoot = "$Drive\out\release-epochs\$EpochName"
    $BuildDirectory = "$VirtualEpochRoot\build\windows-release"
    $TempDirectory = "$VirtualEpochRoot\temp"
    if ($Clean) {
        Remove-OwnedEpochDirectory (Join-Path $EpochRoot 'build')
        Remove-OwnedEpochDirectory (Join-Path $EpochRoot 'temp')
        Remove-OwnedEpochDirectory $SourceProvenanceRoot
    } elseif (Test-Path -LiteralPath $SourceProvenanceRoot) {
        throw "Source provenance already exists for this epoch; use -Clean or a new EpochName: $SourceProvenanceRoot"
    }
    New-Item -ItemType Directory -Path $BuildDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $TempDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $SourceProvenanceRoot -Force | Out-Null
    $env:TEMP = $TempDirectory
    $env:TMP = $TempDirectory

    $BeforeConfigureSnapshot = New-KdbgSourceSnapshotArtifacts `
        $SourceSnapshotTool `
        $RepoRoot `
        $SourceSnapshotScope `
        $SourceProvenanceRoot `
        'before-configure'

    $DependencyRoot = "$Drive\out\build\windows-release\_deps"
    $DependencyArguments = @(
        "-DFETCHCONTENT_SOURCE_DIR_DEAR_IMGUI=$DependencyRoot\dear_imgui-src",
        "-DFETCHCONTENT_SOURCE_DIR_IMGUI_CLUB=$DependencyRoot\imgui_club-src",
        "-DFETCHCONTENT_SOURCE_DIR_ZYDIS=$DependencyRoot\zydis-src"
    )
    foreach ($Argument in $DependencyArguments) {
        $Value = $Argument.Substring($Argument.IndexOf('=') + 1)
        if (-not (Test-Path -LiteralPath $Value -PathType Container)) {
            throw "Pinned local dependency checkout was not found: $Value"
        }
    }

    $ConfigureArguments = @(
        '-S', "$Drive\src",
        '-B', $BuildDirectory,
        '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DKDBG_BUILD_TESTS=ON',
        '-DKDBG_BUILD_GUI=ON',
        '-DKDBG_BUILD_MEMPROCFS_BRIDGE=ON',
        '-DKDBG_BUILD_BENCHMARKS=ON',
        '-DKDBG_BUILD_LIVE_VERIFY=ON',
        '-DKDBG_BUILD_PROCESS_FIXTURE=ON',
        '-DKDBG_REPRODUCIBLE_RELEASE_SYMBOLS=ON',
        "-DKDBG_BUILD_ID=$BuildId",
        "-DKDBG_TEST_SOURCE_ROOT=$(Join-Path $RepoRoot 'src')",
        "-DKDBG_TEST_BINARY_ROOT=$(Join-Path $EpochRoot 'build\windows-release')"
    ) + $DependencyArguments
    if ($Clean) { $ConfigureArguments += '--fresh' }
    & cmake @ConfigureArguments
    if ($LASTEXITCODE -ne 0) { throw 'Public Release configure failed.' }
    & cmake --build $BuildDirectory --parallel
    if ($LASTEXITCODE -ne 0) { throw 'Public Release build failed.' }
    if (-not $SkipTests) {
        & ctest --test-dir $BuildDirectory --output-on-failure
        if ($LASTEXITCODE -ne 0) { throw 'Public Release tests failed.' }
    }

    if ($BuildDrivers -or $Package) {
        & (Join-Path $PSScriptRoot 'build_drivers_nuget.ps1') `
            -Configuration Release -EpochName $EpochName -Clean:$Clean
        if ($LASTEXITCODE -ne 0) { throw 'Public Release driver build failed.' }
    }
    if ($Package) {
        $BeforePackageSnapshot = New-KdbgSourceSnapshotArtifacts `
            $SourceSnapshotTool `
            $RepoRoot `
            $SourceSnapshotScope `
            $SourceProvenanceRoot `
            'before-package-publication'
        Assert-KdbgSourceSnapshotEqual `
            $BeforeConfigureSnapshot `
            $BeforePackageSnapshot `
            'before package publication'
        Assert-KdbgSourceSnapshotTree `
            $SourceSnapshotTool `
            $RepoRoot `
            $SourceSnapshotScope `
            $BeforeConfigureSnapshot `
            'before package publication'
        $ForbiddenRoots = @(
            $RepoRoot,
            $SavedTemp,
            $SavedTmp
        ) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Select-Object -Unique
        & "$Drive\src\tools\package_windows.ps1" `
            -Configuration Release `
            -EpochName $EpochName `
            -ForbiddenSymbolPath ([string[]]$ForbiddenRoots) `
            -ExpectedSourceSnapshotSha256 $BeforeConfigureSnapshot.Digest `
            -Zip
        if ($LASTEXITCODE -ne 0) { throw 'Public Release packaging failed.' }
        $AfterPackageSnapshot = New-KdbgSourceSnapshotArtifacts `
            $SourceSnapshotTool `
            $RepoRoot `
            $SourceSnapshotScope `
            $SourceProvenanceRoot `
            'after-packaging'
        Assert-KdbgSourceSnapshotEqual `
            $BeforeConfigureSnapshot `
            $AfterPackageSnapshot `
            'after packaging'
        Assert-KdbgSourceSnapshotTree `
            $SourceSnapshotTool `
            $RepoRoot `
            $SourceSnapshotScope `
            $BeforeConfigureSnapshot `
            'after packaging'
    }
    if ($PrepareProductionSigning) {
        $MainZip = Join-Path $EpochRoot 'package\KDBG-1.1.0-win-x64.zip'
        $SymbolsZip = Join-Path $EpochRoot 'package\KDBG-1.1.0-win-x64-symbols.zip'
        $MainHash = (Get-FileHash -LiteralPath $MainZip -Algorithm SHA256).Hash
        $SymbolsHash = (Get-FileHash -LiteralPath $SymbolsZip -Algorithm SHA256).Hash
        & (Join-Path $PSScriptRoot 'stage_production_signing.ps1') `
            -Mode Prepare `
            -PackagePath $MainZip `
            -ExpectedMainSha256 $MainHash `
            -SymbolsPath $SymbolsZip `
            -ExpectedSymbolsSha256 $SymbolsHash `
            -OutputDirectory $ProductionSigningOutputDirectory
        if ($LASTEXITCODE -ne 0) {
            throw 'Production-signing input staging failed.'
        }
    }
}
finally {
    $env:TEMP = $SavedTemp
    $env:TMP = $SavedTmp
    if ($CreatedMapping) {
        $Mapping = @(& subst.exe) |
            Where-Object { [string]$_ -match "^$([regex]::Escape($Drive))\\: => " } |
            Select-Object -First 1
        if ($Mapping -match [regex]::Escape($RepoRoot) + '\\?$') {
            & subst.exe $Drive /D
        }
    }
}

[CmdletBinding()]
param(
    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [string]$OutputDirectory,

    [switch]$Zip
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "Windows package assembly must run on Windows."
}

$Version = "1.0.0"
$PackageName = "KDBG-$Version-win-x64"
$SymbolsName = "$PackageName-symbols"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$PackageRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot "out\package"))
$BuildDirectory = Join-Path $RepoRoot "out\build\windows-release"
$DriverDirectory = Join-Path $RepoRoot "out\drivers\Release"
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PackageRoot $PackageName
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$SymbolsDirectory = Join-Path $PackageRoot $SymbolsName

function Get-KdbgRelativePath([string]$BasePath, [string]$TargetPath) {
    $BaseFull = [IO.Path]::GetFullPath($BasePath).TrimEnd([char[]]@('\', '/'))
    $TargetFull = [IO.Path]::GetFullPath($TargetPath)
    $Prefix = $BaseFull + [IO.Path]::DirectorySeparatorChar
    if (-not $TargetFull.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the expected root ${BaseFull}: $TargetFull"
    }
    return $TargetFull.Substring($Prefix.Length).Replace('\', '/')
}

function Assert-PackagePath([string]$Path, [string]$ExpectedLeaf) {
    $Full = [IO.Path]::GetFullPath($Path)
    $Prefix = $PackageRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $Full.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Package output must remain below ${PackageRoot}: $Full"
    }
    if ([IO.Path]::GetFileName($Full) -ne $ExpectedLeaf) {
        throw "Package output leaf must be ${ExpectedLeaf}: $Full"
    }
}

function Clear-PackageDirectory([string]$Path, [string]$ExpectedLeaf) {
    Assert-PackagePath $Path $ExpectedLeaf
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Reset-PackageDirectory([string]$Path, [string]$ExpectedLeaf) {
    Clear-PackageDirectory $Path $ExpectedLeaf
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Copy-RequiredFile([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required release input is missing: $Source"
    }
    if ((Get-Item -LiteralPath $Source).Length -eq 0) {
        throw "Required release input is empty: $Source"
    }
    $Parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Write-HashManifest([string]$Directory) {
    $Manifest = Join-Path $Directory "SHA256SUMS.txt"
    $Lines = Get-ChildItem -LiteralPath $Directory -Recurse -File |
        Where-Object { $_.FullName -ne $Manifest } |
        ForEach-Object {
            $Relative = Get-KdbgRelativePath $Directory $_.FullName
            [pscustomobject]@{ Relative = $Relative; FullName = $_.FullName }
        } |
        Sort-Object Relative |
        ForEach-Object {
            $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            "$Hash  $($_.Relative)"
        }
    Set-Content -LiteralPath $Manifest -Value $Lines -Encoding ascii
}

function New-DeterministicZip([string]$Directory, [string]$ZipPath) {
    Assert-PackagePath $Directory ([IO.Path]::GetFileName($Directory))
    $ZipFull = [IO.Path]::GetFullPath($ZipPath)
    $Prefix = $PackageRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $ZipFull.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "ZIP output must remain below ${PackageRoot}: $ZipFull"
    }
    if (Test-Path -LiteralPath $ZipFull) {
        Remove-Item -LiteralPath $ZipFull -Force
    }
    Add-Type -AssemblyName System.IO.Compression
    $Stream = [IO.File]::Open($ZipFull, [IO.FileMode]::CreateNew)
    try {
        $Archive = [IO.Compression.ZipArchive]::new(
            $Stream,
            [IO.Compression.ZipArchiveMode]::Create,
            $false)
        try {
            $Files = Get-ChildItem -LiteralPath $Directory -Recurse -File |
                ForEach-Object {
                    [pscustomobject]@{
                        Relative = Get-KdbgRelativePath $Directory $_.FullName
                        FullName = $_.FullName
                    }
                } | Sort-Object Relative
            foreach ($File in $Files) {
                $Entry = $Archive.CreateEntry(
                    "$([IO.Path]::GetFileName($Directory))/$($File.Relative)",
                    [IO.Compression.CompressionLevel]::Optimal)
                $Entry.LastWriteTime = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $Input = [IO.File]::OpenRead($File.FullName)
                $Output = $Entry.Open()
                try { $Input.CopyTo($Output) }
                finally { $Output.Dispose(); $Input.Dispose() }
            }
        }
        finally { $Archive.Dispose() }
    }
    finally { $Stream.Dispose() }
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ZipFull).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$ZipFull.sha256" -Value "$Hash  $([IO.Path]::GetFileName($ZipFull))" -Encoding ascii
}

function Add-LockedPackagesToSbom([string]$SbomPath) {
    $Sbom = Get-Content -LiteralPath $SbomPath -Raw | ConvertFrom-Json
    if ($Sbom.spdxVersion -ne "SPDX-2.3") {
        throw "Syft did not emit SPDX-2.3 JSON."
    }
    $Lock = Get-Content -LiteralPath (Join-Path $RepoRoot "THIRD_PARTY.lock.json") -Raw |
        ConvertFrom-Json
    $LockHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $RepoRoot "THIRD_PARTY.lock.json")).Hash.ToLowerInvariant()
    $Sbom.documentNamespace = "https://kdbg.invalid/spdx/$PackageName/$LockHash"
    if ($null -ne $Sbom.creationInfo) {
        $Sbom.creationInfo.created = if ([string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) {
            "2000-01-01T00:00:00Z"
        } else {
            [DateTimeOffset]::FromUnixTimeSeconds([Int64]$env:SOURCE_DATE_EPOCH).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    }
    $Packages = [Collections.Generic.List[object]]::new()
    foreach ($Existing in @($Sbom.packages)) { $Packages.Add($Existing) }
    $ExistingNames = @{} 
    foreach ($Existing in $Packages) { $ExistingNames[[string]$Existing.name] = $true }
    if (-not $ExistingNames.ContainsKey("KDBG")) {
        $Packages.Add([ordered]@{
            SPDXID = "SPDXRef-Package-KDBG"
            name = "KDBG"
            versionInfo = $Version
            downloadLocation = "NOASSERTION"
            filesAnalyzed = $false
            licenseConcluded = "NOASSERTION"
            licenseDeclared = "MIT"
            copyrightText = "Copyright (c) 2026 KDBG contributors"
        })
    }
    foreach ($Dependency in $Lock.dependencies) {
        if ($ExistingNames.ContainsKey([string]$Dependency.name)) { continue }
        $Id = "SPDXRef-Package-" + ([string]$Dependency.name -replace '[^A-Za-z0-9.-]', '-')
        $License = switch ([string]$Dependency.license) {
            "MIT" { "MIT" }
            "AGPL-3.0" { "AGPL-3.0-only" }
            "GPL-3.0" { "GPL-3.0-only" }
            default { "NOASSERTION" }
        }
        $Packages.Add([ordered]@{
            SPDXID = $Id
            name = [string]$Dependency.name
            versionInfo = [string]$Dependency.revision
            downloadLocation = [string]$Dependency.url
            filesAnalyzed = $false
            licenseConcluded = "NOASSERTION"
            licenseDeclared = $License
            copyrightText = "NOASSERTION"
            comment = "Integration: $($Dependency.integration)"
        })
    }
    $Sbom.packages = $Packages
    $Sbom.name = $PackageName
    $Sbom | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $SbomPath -Encoding utf8
}

function Get-SourceSnapshot {
    $RootFiles = @(
        ".editorconfig", ".env.example", ".gitignore", "AGENTS.md",
        "ARTIFACT_MANIFEST.md", "CHANGELOG.md", "LICENSE", "README.md",
        "THIRD_PARTY.lock.json"
    )
    $ScanRoots = @(
        ".agents", ".codex", ".github", "docs", "licenses",
        "src\app", "src\benchmarks", "src\cmake", "src\config",
        "src\core", "src\driver", "src\fixtures", "src\plugins",
        "src\shared", "src\tests", "src\tools"
    )
    $Files = @{}
    foreach ($RelativeRootFile in $RootFiles) {
        $RootFile = Join-Path $RepoRoot $RelativeRootFile
        if (Test-Path -LiteralPath $RootFile -PathType Leaf) {
            $Files[[IO.Path]::GetFullPath($RootFile)] = $true
        }
    }
    foreach ($SourceFile in Get-ChildItem -LiteralPath (Join-Path $RepoRoot "src") -Force -File) {
        if ($SourceFile.Extension -notin @(".obj", ".pdb", ".ilk")) {
            $Files[$SourceFile.FullName] = $true
        }
    }
    foreach ($RelativeRoot in $ScanRoots) {
        $Root = Join-Path $RepoRoot $RelativeRoot
        if (-not (Test-Path -LiteralPath $Root -PathType Container)) { continue }
        foreach ($File in Get-ChildItem -LiteralPath $Root -Recurse -Force -File) {
            $Relative = Get-KdbgRelativePath $RepoRoot $File.FullName
            if ($Relative -match '(^|/)(x64|Debug|Release|out|CMakeFiles|__pycache__)(/|$)' -or
                $File.Extension -in @(".obj", ".pdb", ".ilk", ".sys", ".cat")) {
                continue
            }
            $Files[$File.FullName] = $true
        }
    }

    $Records = [Collections.Generic.List[string]]::new()
    foreach ($FullName in $Files.Keys) {
        $Relative = Get-KdbgRelativePath $RepoRoot $FullName
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $FullName).Hash.ToLowerInvariant()
        $Records.Add("$Hash  $Relative")
    }
    $RecordArray = [string[]]$Records.ToArray()
    [Array]::Sort($RecordArray, [StringComparer]::Ordinal)
    $Manifest = ($RecordArray -join "`n") + "`n"
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $DigestBytes = $Hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Manifest))
    }
    finally {
        $Hasher.Dispose()
    }
    $Digest = ([BitConverter]::ToString($DigestBytes)).Replace("-", "").ToLowerInvariant()
    return [pscustomobject]@{
        Digest = $Digest
        FileCount = $RecordArray.Count
    }
}

$KdbgExe = Join-Path $BuildDirectory "KDBG.exe"
$BridgeExe = Join-Path $BuildDirectory "kdbg_memprocfs_bridge.exe"
$Inputs = @(
    $KdbgExe,
    $BridgeExe,
    (Join-Path $DriverDirectory "KDbgDriver.sys"),
    (Join-Path $DriverDirectory "KDbgProbe.sys"),
    (Join-Path $DriverDirectory "KDbgDriver.inf"),
    (Join-Path $DriverDirectory "KDbgProbe.inf")
)
Clear-PackageDirectory $OutputDirectory $PackageName
Clear-PackageDirectory $SymbolsDirectory $SymbolsName
$MainZipPath = Join-Path $PackageRoot "$PackageName.zip"
$MainZipHashPath = "$MainZipPath.sha256"
$SymbolsZipPath = Join-Path $PackageRoot "$SymbolsName.zip"
$SymbolsZipHashPath = "$SymbolsZipPath.sha256"
Assert-PackagePath $MainZipPath "$PackageName.zip"
Assert-PackagePath $MainZipHashPath "$PackageName.zip.sha256"
Assert-PackagePath $SymbolsZipPath "$SymbolsName.zip"
Assert-PackagePath $SymbolsZipHashPath "$SymbolsName.zip.sha256"
foreach ($StalePackageArtifact in @(
        $MainZipPath, $MainZipHashPath,
        $SymbolsZipPath, $SymbolsZipHashPath)) {
    if (Test-Path -LiteralPath $StalePackageArtifact) {
        Remove-Item -LiteralPath $StalePackageArtifact -Force
    }
}
foreach ($InputPath in $Inputs) {
    if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
        throw "Release input is missing; no package was produced: $InputPath"
    }
}

Reset-PackageDirectory $OutputDirectory $PackageName
foreach ($Directory in @("drivers", "plugins\memprocfs_bridge", "config", "tools", "docs", "licenses")) {
    New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $Directory) -Force | Out-Null
}

Copy-RequiredFile $KdbgExe (Join-Path $OutputDirectory "KDBG.exe")
Copy-RequiredFile $BridgeExe (Join-Path $OutputDirectory "plugins\memprocfs_bridge\kdbg_memprocfs_bridge.exe")
foreach ($Name in @("KDbgDriver.sys", "KDbgProbe.sys", "KDbgDriver.inf", "KDbgProbe.inf")) {
    Copy-RequiredFile (Join-Path $DriverDirectory $Name) (Join-Path $OutputDirectory "drivers\$Name")
}
$Catalogs = @()
foreach ($Name in @("KDbgDriver.cat", "KDbgProbe.cat")) {
    $Source = Join-Path $DriverDirectory $Name
    if (Test-Path -LiteralPath $Source -PathType Leaf) {
        Copy-RequiredFile $Source (Join-Path $OutputDirectory "drivers\$Name")
        $Catalogs += "drivers/$Name"
    }
}
foreach ($Name in @("app.example.json", "safety_policy.example.json")) {
    Copy-RequiredFile (Join-Path $RepoRoot "src\config\$Name") (Join-Path $OutputDirectory "config\$Name")
}
foreach ($Name in @("install.ps1", "uninstall.ps1", "diagnose.ps1")) {
    Copy-RequiredFile (Join-Path $RepoRoot "src\tools\package\$Name") (Join-Path $OutputDirectory "tools\$Name")
}
foreach ($Name in @("QUICKSTART.md", "OPERATOR_GUIDE.md", "TROUBLESHOOTING.md")) {
    Copy-RequiredFile (Join-Path $RepoRoot "docs\$Name") (Join-Path $OutputDirectory "docs\$Name")
}
foreach ($Name in @(
    "LICENSE-PROJECT.txt", "MIT-kn-live-dbg.txt", "MIT-PTView.txt",
    "MIT-Dear-ImGui.txt", "MIT-imgui-memory-editor.txt", "MIT-Zydis.txt",
    "MIT-Zycore.txt", "THIRD-PARTY-NOTICES.txt")) {
    Copy-RequiredFile (Join-Path $RepoRoot "licenses\$Name") (Join-Path $OutputDirectory "licenses\$Name")
}
Copy-RequiredFile (Join-Path $RepoRoot "THIRD_PARTY.lock.json") (Join-Path $OutputDirectory "licenses\THIRD_PARTY.lock.json")

$SourceSnapshot = Get-SourceSnapshot
$SourceRevision = if ([string]::IsNullOrWhiteSpace($env:KDBG_SOURCE_REVISION)) {
    "snapshot-sha256:$($SourceSnapshot.Digest)"
} else { $env:KDBG_SOURCE_REVISION }
$Metadata = [ordered]@{
    schema = "kdbg.build-metadata.v1"
    product = "KDBG"
    version = $Version
    configuration = "Release"
    architecture = "x64"
    package_name = $PackageName
    source_revision = $SourceRevision
    source_snapshot_scope = "kdbg.source-snapshot.v1"
    source_snapshot_sha256 = $SourceSnapshot.Digest
    source_file_count = $SourceSnapshot.FileCount
    source_date_epoch = if ([string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) { $null } else { $env:SOURCE_DATE_EPOCH }
    catalogs = @($Catalogs | Sort-Object)
    signature_claim = "not asserted; inspect with tools/diagnose.ps1"
    symbols_package = $SymbolsName
    reproducible_commands = @(
        ".\src\tools\build.ps1 -Preset windows-release",
        ".\src\tools\build_drivers.ps1 -Configuration Release -Clean",
        ".\src\tools\package_windows.ps1 -Configuration Release -Zip"
    )
}
$Metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory "BUILD-METADATA.json") -Encoding utf8

$Syft = Get-Command syft -ErrorAction SilentlyContinue
if ($null -eq $Syft) {
    throw "Syft is required to create SBOM.spdx.json; install Syft and rerun packaging."
}
$SbomPath = Join-Path $OutputDirectory "SBOM.spdx.json"
& $Syft.Source scan "dir:$OutputDirectory" --source-name $PackageName -o "spdx-json=$SbomPath"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $SbomPath)) {
    throw "Syft SBOM generation failed."
}
Add-LockedPackagesToSbom $SbomPath
Write-HashManifest $OutputDirectory

& python (Join-Path $PSScriptRoot "validate_release.py") --windows-package $OutputDirectory
if ($LASTEXITCODE -ne 0) { throw "Windows package validation failed." }

$PdbInputs = @(
    @{ Source = Join-Path $BuildDirectory "KDBG.pdb"; Destination = "KDBG.pdb" },
    @{ Source = Join-Path $BuildDirectory "kdbg_memprocfs_bridge.pdb"; Destination = "plugins\memprocfs_bridge\kdbg_memprocfs_bridge.pdb" },
    @{ Source = Join-Path $DriverDirectory "KDbgDriver.pdb"; Destination = "drivers\KDbgDriver.pdb" },
    @{ Source = Join-Path $DriverDirectory "KDbgProbe.pdb"; Destination = "drivers\KDbgProbe.pdb" }
)
$AvailablePdbs = @($PdbInputs | Where-Object { Test-Path -LiteralPath $_.Source -PathType Leaf })
if ($AvailablePdbs.Count -gt 0) {
    Reset-PackageDirectory $SymbolsDirectory $SymbolsName
    foreach ($Pdb in $AvailablePdbs) {
        Copy-RequiredFile $Pdb.Source (Join-Path $SymbolsDirectory $Pdb.Destination)
    }
    [ordered]@{
        schema = "kdbg.symbols-metadata.v1"
        product = "KDBG"
        version = $Version
        configuration = "Release"
        architecture = "x64"
        package_name = $SymbolsName
        source_revision = $SourceRevision
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $SymbolsDirectory "BUILD-METADATA.json") -Encoding utf8
    Write-HashManifest $SymbolsDirectory
    & python (Join-Path $PSScriptRoot "validate_release.py") --symbols-package $SymbolsDirectory
    if ($LASTEXITCODE -ne 0) { throw "Symbols package validation failed." }
} else {
    Remove-Item -LiteralPath $SymbolsDirectory -Recurse -Force
    Write-Warning "No Release PDBs were found; a symbols package was not produced."
}

if ($Zip) {
    New-DeterministicZip $OutputDirectory $MainZipPath
    if (Test-Path -LiteralPath $SymbolsDirectory -PathType Container) {
        New-DeterministicZip $SymbolsDirectory $SymbolsZipPath
    }
}

Write-Host "Validated main package: $OutputDirectory"
if (Test-Path -LiteralPath $SymbolsDirectory -PathType Container) {
    Write-Host "Validated symbols package: $SymbolsDirectory"
}

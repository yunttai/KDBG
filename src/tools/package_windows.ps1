[CmdletBinding()]
param(
    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [string]$OutputDirectory,

    [string]$DriverDirectory,

    [string]$EpochName,

    [string[]]$ForbiddenSymbolPath = @(),

    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedSourceSnapshotSha256,

    [switch]$Zip
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "Windows package assembly must run on Windows."
}

$Version = "1.1.0"
$PackageName = "KDBG-$Version-win-x64"
$SymbolsName = "$PackageName-symbols"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

function Resolve-KdbgEpochLayout(
    [string]$Name,
    [bool]$WasSpecified = $false) {
    if ([string]::IsNullOrWhiteSpace($Name)) {
        if ($WasSpecified) {
            throw "EpochName cannot be empty or whitespace when explicitly supplied."
        }
        return [pscustomobject]@{
            IsEpoch = $false
            EpochRoot = $null
            PackageRoot = [IO.Path]::GetFullPath(
                (Join-Path $RepoRoot "out\package"))
            BuildDirectory = [IO.Path]::GetFullPath(
                (Join-Path $RepoRoot "out\build\windows-release"))
            DefaultDriverDirectory = [IO.Path]::GetFullPath(
                (Join-Path $RepoRoot "out\drivers\Release"))
            AllowedDriverParents = @(
                [IO.Path]::GetFullPath((Join-Path $RepoRoot "out\drivers")),
                [IO.Path]::GetFullPath((Join-Path $RepoRoot "out\signed-drivers")))
        }
    }

    if ($Name.Length -gt 64 -or
        $Name -cnotmatch '^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$' -or
        $Name -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$') {
        throw "EpochName must be a lowercase 1-64 character filesystem slug with alphanumeric endpoints: $Name"
    }

    $ReleaseEpochsRoot = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot "out\release-epochs"))
    $EpochRoot = [IO.Path]::GetFullPath(
        (Join-Path $ReleaseEpochsRoot $Name))
    if (-not ([IO.Path]::GetDirectoryName($EpochRoot)).Equals(
            $ReleaseEpochsRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($EpochRoot) -cne $Name) {
        throw "Epoch output must be one exact child below ${ReleaseEpochsRoot}: $EpochRoot"
    }

    $RepoBoundary = [IO.Path]::GetFullPath($RepoRoot)
    $RepoPathRoot = [IO.Path]::GetPathRoot($RepoBoundary)
    if (-not $RepoBoundary.Equals(
            $RepoPathRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $RepoBoundary = $RepoBoundary.TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
    }
    $RepoPrefix = if ($RepoBoundary.EndsWith(
            [IO.Path]::DirectorySeparatorChar)) {
        $RepoBoundary
    } else {
        $RepoBoundary + [IO.Path]::DirectorySeparatorChar
    }
    $Cursor = $EpochRoot
    while ($true) {
        if (-not ($Cursor.Equals(
                    $RepoBoundary,
                    [StringComparison]::OrdinalIgnoreCase) -or
                $Cursor.StartsWith(
                    $RepoPrefix,
                    [StringComparison]::OrdinalIgnoreCase))) {
            throw "Epoch output escaped the repository boundary: $Cursor"
        }
        if (Test-Path -LiteralPath $Cursor) {
            $Entry = Get-Item -LiteralPath $Cursor -Force
            if (-not $Entry.PSIsContainer) {
                throw "Epoch path component is not a directory: $Cursor"
            }
            if (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Epoch output path must not contain reparse points: $Cursor"
            }
        }
        if ($Cursor.Equals(
                $RepoBoundary,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $Cursor = [IO.Path]::GetDirectoryName($Cursor)
        if ([string]::IsNullOrWhiteSpace($Cursor)) {
            throw "Epoch output has no repository ancestor: $EpochRoot"
        }
    }

    return [pscustomobject]@{
        IsEpoch = $true
        EpochRoot = $EpochRoot
        PackageRoot = Join-Path $EpochRoot "package"
        BuildDirectory = Join-Path $EpochRoot "build\windows-release"
        DefaultDriverDirectory = Join-Path $EpochRoot "drivers\Release"
        AllowedDriverParents = @(
            (Join-Path $EpochRoot "drivers"),
            (Join-Path $EpochRoot "signed-drivers"))
    }
}

$EpochLayout = Resolve-KdbgEpochLayout `
    $EpochName `
    $PSBoundParameters.ContainsKey("EpochName")
$PackageRoot = [IO.Path]::GetFullPath($EpochLayout.PackageRoot)
$BuildDirectory = [IO.Path]::GetFullPath($EpochLayout.BuildDirectory)

function Resolve-DriverInputDirectory([string]$Path) {
    $Candidate = if ([string]::IsNullOrWhiteSpace($Path)) {
        $EpochLayout.DefaultDriverDirectory
    } else {
        $Path
    }
    $Full = [IO.Path]::GetFullPath($Candidate)
    $AllowedParents = @($EpochLayout.AllowedDriverParents | ForEach-Object {
        [IO.Path]::GetFullPath([string]$_)
    })
    $Parent = [IO.Path]::GetDirectoryName($Full)
    if ([IO.Path]::GetFileName($Full) -cne "Release" -or
        -not ($AllowedParents | Where-Object {
            $Parent.Equals($_, [StringComparison]::OrdinalIgnoreCase)
        })) {
        $Expected = @($AllowedParents | ForEach-Object {
            Join-Path $_ "Release"
        }) -join " or "
        throw "DriverDirectory must be an exact allowed Release directory ($Expected): $Full"
    }
    if (Test-Path -LiteralPath $Full) {
        $Entries = @((Get-Item -LiteralPath $Full -Force)) +
            @(Get-ChildItem -LiteralPath $Full -Recurse -Force)
        foreach ($Entry in $Entries) {
            if (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "DriverDirectory must not contain reparse points: $($Entry.FullName)"
            }
        }
    }
    return $Full
}

$DriverDirectory = Resolve-DriverInputDirectory $DriverDirectory
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PackageRoot $PackageName
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$SymbolsDirectory = Join-Path $PackageRoot $SymbolsName
$PublishTransactionId = [Guid]::NewGuid().ToString("N")
$StagingRoot = Join-Path $PackageRoot ".staging-$PublishTransactionId"
$StagingOutputDirectory = Join-Path $StagingRoot $PackageName
$StagingSymbolsDirectory = Join-Path $StagingRoot $SymbolsName
$StagingMainZipPath = Join-Path $StagingRoot "$PackageName.zip"
$StagingSymbolsZipPath = Join-Path $StagingRoot "$SymbolsName.zip"
$BackupRoot = Join-Path $PackageRoot ".backup-$PublishTransactionId"
$PublishJournalPath = Join-Path $PackageRoot ".publish-transaction.json"

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

function Assert-PublishTransactionPath(
    [string]$Path,
    [string]$ExpectedPrefix) {
    $Full = [IO.Path]::GetFullPath($Path)
    $Root = $PackageRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $Full.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetDirectoryName($Full) -ne $PackageRoot -or
        -not [IO.Path]::GetFileName($Full).StartsWith(
            $ExpectedPrefix, [StringComparison]::Ordinal)) {
        throw "Invalid package transaction path: $Full"
    }
    return $Full
}

function Test-IsAllowedPublishTarget([string]$Path) {
    $Full = [IO.Path]::GetFullPath($Path)
    foreach ($Allowed in $PublishAllowedTargets) {
        if ($Full.Equals(
                [IO.Path]::GetFullPath([string]$Allowed),
                [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Remove-PackageArtifact([string]$Path) {
    $Full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-IsAllowedPublishTarget $Full)) {
        throw "Refusing to remove a path outside the package artifact set: $Full"
    }
    if (Test-Path -LiteralPath $Full -PathType Container) {
        Remove-Item -LiteralPath $Full -Recurse -Force
    } elseif (Test-Path -LiteralPath $Full) {
        Remove-Item -LiteralPath $Full -Force
    }
}

function Write-PublishJournal([object]$Journal) {
    New-Item -ItemType Directory -Path $PackageRoot -Force | Out-Null
    $Temporary = "$PublishJournalPath.tmp"
    $Json = $Journal | ConvertTo-Json -Depth 8
    $Encoding = [Text.UTF8Encoding]::new($false)
    $Stream = [IO.FileStream]::new(
        $Temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $Bytes = $Encoding.GetBytes($Json)
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    } finally {
        $Stream.Dispose()
    }
    if (Test-Path -LiteralPath $PublishJournalPath -PathType Leaf) {
        $Previous = "$PublishJournalPath.previous"
        if (Test-Path -LiteralPath $Previous) {
            Remove-Item -LiteralPath $Previous -Force
        }
        [IO.File]::Replace($Temporary, $PublishJournalPath, $Previous, $true)
        Remove-Item -LiteralPath $Previous -Force -ErrorAction SilentlyContinue
    } else {
        [IO.File]::Move($Temporary, $PublishJournalPath)
    }
}

function Read-PublishJournal {
    if (-not (Test-Path -LiteralPath $PublishJournalPath -PathType Leaf)) {
        return $null
    }
    try {
        return Get-Content -LiteralPath $PublishJournalPath -Raw | ConvertFrom-Json
    } catch {
        throw "Package publish journal is unreadable; preserve it for recovery: $PublishJournalPath ($_)"
    }
}

function Test-PublishJournal([object]$Journal) {
    if ($Journal.schema -ne "kdbg.package-publish.v1" -or
        $Journal.phase -notin @("prepared", "committed")) {
        throw "Package publish journal has an unsupported schema or phase."
    }
    if (-not ([IO.Path]::GetFullPath([string]$Journal.package_root)).Equals(
            $PackageRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Package publish journal belongs to a different package root."
    }
    $Backup = Assert-PublishTransactionPath ([string]$Journal.backup_directory) ".backup-"
    $Staging = Assert-PublishTransactionPath ([string]$Journal.staging_directory) ".staging-"
    $SeenTargets = @{}
    foreach ($Artifact in @($Journal.artifacts)) {
        $Target = [IO.Path]::GetFullPath([string]$Artifact.target)
        if (-not (Test-IsAllowedPublishTarget $Target) -or
            $SeenTargets.ContainsKey($Target)) {
            throw "Package publish journal contains an invalid target: $Target"
        }
        $SeenTargets[$Target] = $true
        $ExpectedBackup = Join-Path $Backup ([IO.Path]::GetFileName($Target))
        if (-not ([IO.Path]::GetFullPath([string]$Artifact.backup)).Equals(
                $ExpectedBackup, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Package publish journal contains an invalid backup path."
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$Artifact.staged)) {
            $StagedFull = [IO.Path]::GetFullPath([string]$Artifact.staged)
            $StagingPrefix = $Staging.TrimEnd([IO.Path]::DirectorySeparatorChar) +
                [IO.Path]::DirectorySeparatorChar
            if (-not $StagedFull.StartsWith(
                    $StagingPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Package publish journal contains an invalid staging path."
            }
        }
    }
}

function Recover-PackagePublish {
    $Journal = Read-PublishJournal
    if ($null -eq $Journal) {
        foreach ($Debris in @(
                "$PublishJournalPath.tmp", "$PublishJournalPath.previous")) {
            if (Test-Path -LiteralPath $Debris) {
                Remove-Item -LiteralPath $Debris -Force
            }
        }
        return
    }
    Test-PublishJournal $Journal
    $BackupDirectory = [IO.Path]::GetFullPath([string]$Journal.backup_directory)
    $StagingDirectory = [IO.Path]::GetFullPath([string]$Journal.staging_directory)

    if ($Journal.phase -eq "committed") {
        foreach ($Artifact in @($Journal.artifacts)) {
            $TargetExists = Test-Path -LiteralPath ([string]$Artifact.target)
            $ShouldExist = -not [string]::IsNullOrWhiteSpace([string]$Artifact.staged)
            if ($TargetExists -ne $ShouldExist) {
                throw "Committed package transaction has an incomplete artifact set; backups were preserved."
            }
        }
    } else {
        $Artifacts = @($Journal.artifacts)
        [Array]::Reverse($Artifacts)
        foreach ($Artifact in $Artifacts) {
            $Target = [string]$Artifact.target
            $Backup = [string]$Artifact.backup
            if (Test-Path -LiteralPath $Backup) {
                Remove-PackageArtifact $Target
                Move-Item -LiteralPath $Backup -Destination $Target
            } elseif (-not [bool]$Artifact.had_target) {
                Remove-PackageArtifact $Target
            } elseif (-not (Test-Path -LiteralPath $Target)) {
                throw "Cannot restore pre-publish artifact because target and backup are both missing: $Target"
            }
        }
    }

    foreach ($Directory in @($BackupDirectory, $StagingDirectory)) {
        if (Test-Path -LiteralPath $Directory) {
            Remove-Item -LiteralPath $Directory -Recurse -Force
        }
    }
    Remove-Item -LiteralPath $PublishJournalPath -Force
    if (Test-Path -LiteralPath "$PublishJournalPath.tmp") {
        Remove-Item -LiteralPath "$PublishJournalPath.tmp" -Force
    }
    if (Test-Path -LiteralPath "$PublishJournalPath.previous") {
        Remove-Item -LiteralPath "$PublishJournalPath.previous" -Force
    }
}

function Publish-PackageArtifacts(
    [object[]]$Artifacts,
    [string]$BackupDirectory,
    [scriptblock]$FaultInjector = $null) {
    $BackupFull = Assert-PublishTransactionPath $BackupDirectory ".backup-"
    $Records = @(
        foreach ($Artifact in $Artifacts) {
            $Target = [IO.Path]::GetFullPath([string]$Artifact.Target)
            [pscustomobject]@{
                target = $Target
                staged = if ([string]::IsNullOrWhiteSpace([string]$Artifact.Staged)) {
                    $null
                } else { [IO.Path]::GetFullPath([string]$Artifact.Staged) }
                backup = Join-Path $BackupFull ([IO.Path]::GetFileName($Target))
                had_target = [bool](Test-Path -LiteralPath $Target)
            }
        })
    $Journal = [ordered]@{
        schema = "kdbg.package-publish.v1"
        phase = "prepared"
        transaction_id = $PublishTransactionId
        package_root = $PackageRoot
        staging_directory = $StagingRoot
        backup_directory = $BackupFull
        artifacts = $Records
    }
    Test-PublishJournal $Journal
    Write-PublishJournal $Journal
    try {
        New-Item -ItemType Directory -Path $BackupFull -Force | Out-Null
        foreach ($Artifact in $Records) {
            if (-not $Artifact.had_target) { continue }
            Move-Item -LiteralPath $Artifact.target -Destination $Artifact.backup
            if ($null -ne $FaultInjector) { & $FaultInjector "after-backup" $Artifact }
        }
        foreach ($Artifact in $Records) {
            if ([string]::IsNullOrWhiteSpace([string]$Artifact.staged)) { continue }
            if (-not (Test-Path -LiteralPath $Artifact.staged)) {
                throw "Validated staging artifact is missing: $($Artifact.staged)"
            }
            Move-Item -LiteralPath $Artifact.staged -Destination $Artifact.target
            if ($null -ne $FaultInjector) { & $FaultInjector "after-publish" $Artifact }
        }
        $Journal.phase = "committed"
        Write-PublishJournal $Journal
        Recover-PackagePublish
    } catch {
        $PublishFailure = $_
        try {
            Recover-PackagePublish
        } catch {
            throw "Package publish failed: $PublishFailure; durable recovery also failed: $($_.Exception.Message)"
        }
        throw $PublishFailure
    }
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

function Get-KdbgToolchainVersions {
    $CompilerCommand = Get-Command cl.exe -ErrorAction SilentlyContinue
    if ($null -eq $CompilerCommand -or
        -not (Test-Path -LiteralPath $CompilerCommand.Source -PathType Leaf)) {
        throw "MSVC cl.exe is required to record Release package provenance."
    }
    $CompilerVersion = (Get-Item -LiteralPath $CompilerCommand.Source).VersionInfo.FileVersion
    $MsvcToolsetVersion = ([string]$env:VCToolsVersion).Trim().TrimEnd('\', '/')
    if ([string]::IsNullOrWhiteSpace($CompilerVersion) -or
        [string]::IsNullOrWhiteSpace($MsvcToolsetVersion)) {
        throw "The MSVC compiler or VCToolsVersion could not be recorded."
    }

    $WindowsSdkVersion = ([string]$env:WindowsSDKVersion).Trim().TrimEnd('\', '/')
    $WindowsSdkRoot = ([string]$env:WindowsSdkDir).Trim().TrimEnd('\', '/')
    if ([string]::IsNullOrWhiteSpace($WindowsSdkRoot)) {
        $WindowsSdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
    }
    if ([string]::IsNullOrWhiteSpace($WindowsSdkVersion) -or
        -not (Test-Path -LiteralPath (
            Join-Path $WindowsSdkRoot "Include\$WindowsSdkVersion\um\Windows.h") -PathType Leaf)) {
        throw "The selected Windows SDK version could not be verified. Run packaging from the same initialized MSVC environment as the Release build."
    }

    $WdkVersions = @(Get-ChildItem -LiteralPath (
            Join-Path $WindowsSdkRoot "Include") -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-Path -LiteralPath (Join-Path $_.FullName "km\ntddk.h") -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName "km\ntifs.h") -PathType Leaf) -and
            (Test-Path -LiteralPath (
                Join-Path $WindowsSdkRoot "build\$($_.Name)\WindowsDriver.Common.targets") -PathType Leaf)
        } |
        Sort-Object { [Version]$_.Name } -Descending)
    if ($WdkVersions.Count -eq 0) {
        $PinnedWdkPackageVersion = "10.0.26100.2454"
        $PinnedWdkKitVersion = "10.0.26100.0"
        $PinnedWdkExpectedHash =
            "zzOYh91xa827HWByuF5KEXpb92/oJSa9l8bRkRnq9Da6ljwFDGHDFU/JTfPlc/UyIT7ZOiohC3mLBTIuIYMTQA=="
        $PinnedWdkDirectory = Join-Path $RepoRoot `
            "out\wdk-nuget\microsoft.windows.wdk.x64\$PinnedWdkPackageVersion"
        $PinnedWdkArchive = Join-Path $PinnedWdkDirectory `
            "microsoft.windows.wdk.x64.$PinnedWdkPackageVersion.nupkg"
        $PinnedWdkHeader = Join-Path $PinnedWdkDirectory `
            "c\Include\$PinnedWdkKitVersion\km\ntddk.h"
        $PinnedWdkTargets = Join-Path $PinnedWdkDirectory `
            "c\build\$PinnedWdkKitVersion\WindowsDriver.Common.targets"
        foreach ($PinnedFile in @(
                $PinnedWdkArchive, $PinnedWdkHeader, $PinnedWdkTargets)) {
            if (-not (Test-Path -LiteralPath $PinnedFile -PathType Leaf)) {
                throw "No complete installed or pinned NuGet WDK was found for Release package provenance."
            }
        }
        $PinnedStream = [IO.File]::OpenRead($PinnedWdkArchive)
        try {
            $PinnedAlgorithm = [Security.Cryptography.SHA512]::Create()
            try {
                $PinnedWdkActualHash = [Convert]::ToBase64String(
                    $PinnedAlgorithm.ComputeHash($PinnedStream))
            } finally {
                $PinnedAlgorithm.Dispose()
            }
        } finally {
            $PinnedStream.Dispose()
        }
        if ($PinnedWdkActualHash -cne $PinnedWdkExpectedHash) {
            throw "Pinned Microsoft.Windows.WDK.x64 package hash mismatch."
        }
        $WdkVersion =
            "$PinnedWdkKitVersion (NuGet $PinnedWdkPackageVersion)"
    } else {
        $WdkVersion = $WdkVersions[0].Name
    }

    return [ordered]@{
        msvc_compiler = ([string]$CompilerVersion).Trim()
        msvc_toolset = $MsvcToolsetVersion
        windows_sdk = $WindowsSdkVersion
        wdk = $WdkVersion
    }
}

function Assert-DriverCatalogContract([string]$DriverName) {
    $InfPath = Join-Path $DriverDirectory "$DriverName.inf"
    $ExpectedCatalog = "$DriverName.cat"
    $CatalogPath = Join-Path $DriverDirectory $ExpectedCatalog
    if (-not (Test-Path -LiteralPath $InfPath -PathType Leaf)) {
        throw "Required Release INF is missing: $InfPath"
    }
    $CatalogDeclarations = @(Get-Content -LiteralPath $InfPath |
        Where-Object { $_ -match '^\s*CatalogFile\s*=\s*(\S+)\s*$' } |
        ForEach-Object { ([regex]::Match($_, '^\s*CatalogFile\s*=\s*(\S+)\s*$')).Groups[1].Value })
    if ($CatalogDeclarations.Count -ne 1 -or
        -not $CatalogDeclarations[0].Equals(
            $ExpectedCatalog, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$DriverName.inf must declare exactly CatalogFile=$ExpectedCatalog."
    }
    if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf) -or
        (Get-Item -LiteralPath $CatalogPath).Length -eq 0) {
        throw "Required Release catalog is missing or empty: $CatalogPath"
    }
}

function Test-ProductIdentityValues {
    param(
        [Parameter(Mandatory)]$VersionInfo,
        [Parameter(Mandatory)][string]$ExpectedOriginalFilename)
    $versionPattern = '^1\.1\.0(?:\.0)?$'
    return ([string]$VersionInfo.CompanyName).Trim() -ceq 'KDBG Project' -and
        ([string]$VersionInfo.ProductName).Trim() -ceq 'KDBG' -and
        ([string]$VersionInfo.FileVersion).Trim() -match $versionPattern -and
        ([string]$VersionInfo.ProductVersion).Trim() -match $versionPattern -and
        ([string]$VersionInfo.OriginalFilename).Trim() -ceq $ExpectedOriginalFilename
}

function Test-InfProviderIdentityValues {
    param([Parameter(Mandatory)][AllowEmptyString()][string[]]$Lines)
    $providers = @($Lines |
        Where-Object { $_ -match '^\s*ProviderName\s*=\s*"([^"]+)"\s*$' } |
        ForEach-Object {
            ([regex]::Match(
                $_, '^\s*ProviderName\s*=\s*"([^"]+)"\s*$')).Groups[1].Value
        })
    return $providers.Count -eq 1 -and $providers[0] -ceq 'KDBG Project'
}

function Assert-ProductIdentityContract {
    param(
        [Parameter(Mandatory)][object[]]$Binaries,
        [Parameter(Mandatory)][string[]]$InfPaths)
    foreach ($binary in $Binaries) {
        $path = [string]$binary.Path
        $expectedOriginalFilename = [string]$binary.OriginalFilename
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Product identity input is missing: $path"
        }
        $versionInfo = (Get-Item -LiteralPath $path).VersionInfo
        if (-not (Test-ProductIdentityValues `
                $versionInfo $expectedOriginalFilename)) {
            throw (
                "Product identity mismatch for $expectedOriginalFilename; require " +
                "CompanyName='KDBG Project', ProductName='KDBG', " +
                "FileVersion/ProductVersion=1.1.0 or 1.1.0.0, and exact OriginalFilename.")
        }
    }
    foreach ($infPath in $InfPaths) {
        if (-not (Test-Path -LiteralPath $infPath -PathType Leaf)) {
            throw "Product identity INF is missing: $infPath"
        }
        if (-not (Test-InfProviderIdentityValues (
                Get-Content -LiteralPath $infPath))) {
            throw "INF ProviderName must be exactly KDBG Project: $infPath"
        }
    }
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
            copyrightText = "Copyright (c) 2026 KDBG Project"
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

function Get-KdbgSourceSnapshotPolicy {
    # Product identity deliberately excludes mutable release-run ledgers. Keep
    # this an allowlist: adding a planning or evidence file must not change the
    # digest unless it is deliberately promoted into the product scope.
    return [pscustomobject]@{
        Schema = "kdbg.product-source.v1"
        RootFiles = @(
            ".env.example", "CHANGELOG.md", "LICENSE", "README.md",
            "THIRD_PARTY.lock.json"
        )
        DocumentationFiles = @(
            "docs/BUILD_ENVIRONMENT.md",
            "docs/DEVELOPER_GUIDE.md",
            "docs/LICENSE_AND_ATTRIBUTION.md",
            "docs/LICENSE_AND_EULA.md",
            "docs/OPERATOR_GUIDE.md",
            "docs/PRIVACY.md",
            "docs/QUICKSTART.md",
            "docs/SECURITY.md",
            "docs/SUPPORT.md",
            "docs/TROUBLESHOOTING.md",
            "docs/UPDATE_AND_ROLLBACK.md",
            "docs/VULNERABILITY_DISCLOSURE.md"
        )
        ScanRoots = @(".github/workflows", "licenses", "src")
        ExcludedPaths = @(
            "ARTIFACT_MANIFEST.md",
            "docs/exec-plans/**",
            "docs/IMPLEMENTATION_STATUS.md",
            "docs/TRACEABILITY_MATRIX.md",
            "docs/VALIDATION_REPORT.md",
            "docs/TEST_MATRIX.md",
            "docs/RELEASE_CHECKLIST.md",
            "docs/DEMO_AND_SUBMISSION_CHECKLIST.md",
            "docs/DEFCON_SUBMISSION.md",
            "out/**",
            "all paths not selected by this allowlist"
        )
        IgnoredDirectoryNames = @(
            "x64", "Debug", "Release", "out", "CMakeFiles", "__pycache__"
        )
        IgnoredExtensions = @(".obj", ".pdb", ".ilk", ".sys", ".cat")
    }
}

function Get-SourceSnapshot([string]$RootPath = $RepoRoot) {
    $RootPath = [IO.Path]::GetFullPath($RootPath)
    $Policy = Get-KdbgSourceSnapshotPolicy
    $Files = @{}
    foreach ($RelativeRootFile in @($Policy.RootFiles) + @($Policy.DocumentationFiles)) {
        $RootFile = Join-Path $RootPath ([string]$RelativeRootFile)
        if (Test-Path -LiteralPath $RootFile -PathType Leaf) {
            $Files[[IO.Path]::GetFullPath($RootFile)] = $true
        }
    }
    foreach ($RelativeRoot in $Policy.ScanRoots) {
        $Root = Join-Path $RootPath ([string]$RelativeRoot)
        if (-not (Test-Path -LiteralPath $Root -PathType Container)) { continue }
        foreach ($File in Get-ChildItem -LiteralPath $Root -Recurse -Force -File) {
            $Relative = Get-KdbgRelativePath $RootPath $File.FullName
            $Segments = @($Relative -split '/')
            if (@($Segments | Where-Object {
                        $_ -in @($Policy.IgnoredDirectoryNames)
                    }).Count -ne 0 -or
                $File.Extension -in @($Policy.IgnoredExtensions)) {
                continue
            }
            $Files[$File.FullName] = $true
        }
    }

    $RelativePaths = [Collections.Generic.List[string]]::new()
    $PathToFullName = @{}
    foreach ($FullName in $Files.Keys) {
        $Relative = Get-KdbgRelativePath $RootPath $FullName
        $RelativePaths.Add($Relative)
        $PathToFullName[$Relative] = $FullName
    }
    $PathArray = [string[]]$RelativePaths.ToArray()
    [Array]::Sort($PathArray, [StringComparer]::Ordinal)
    $Records = [Collections.Generic.List[string]]::new()
    foreach ($Relative in $PathArray) {
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (
            $PathToFullName[$Relative])).Hash.ToLowerInvariant()
        $Records.Add("$Hash  $Relative")
    }
    $RecordArray = [string[]]$Records.ToArray()
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
        Manifest = $Manifest
        Policy = $Policy
    }
}

function Assert-SourceSnapshotDigest(
    [object]$Snapshot,
    [string]$ExpectedDigest,
    [string]$Phase) {
    if ([string]::IsNullOrWhiteSpace($ExpectedDigest)) { return }
    $Expected = $ExpectedDigest.ToLowerInvariant()
    if ([string]$Snapshot.Digest -cne $Expected) {
        throw "Product source changed during ${Phase}: expected $Expected, got $($Snapshot.Digest)."
    }
}

$KdbgExe = Join-Path $BuildDirectory "KDBG.exe"
$SetupExe = Join-Path $BuildDirectory "KDBGSetup.exe"
$BridgeExe = Join-Path $BuildDirectory "kdbg_memprocfs_bridge.exe"
$LiveVerifyExe = Join-Path $BuildDirectory "kdbg_live_verify.exe"
$ProcessFixtureExe = Join-Path $BuildDirectory "kdbg_process_fixture.exe"
$Inputs = @(
    $KdbgExe,
    $SetupExe,
    $BridgeExe,
    $LiveVerifyExe,
    $ProcessFixtureExe,
    (Join-Path $DriverDirectory "KDbgDriver.sys"),
    (Join-Path $DriverDirectory "KDbgProbe.sys"),
    (Join-Path $DriverDirectory "KDbgDriver.inf"),
    (Join-Path $DriverDirectory "KDbgProbe.inf"),
    (Join-Path $DriverDirectory "KDbgDriver.cat"),
    (Join-Path $DriverDirectory "KDbgProbe.cat")
)
$PdbInputs = @(
    @{ Source = Join-Path $BuildDirectory "KDBG.pdb"; Destination = "KDBG.pdb" },
    @{ Source = Join-Path $BuildDirectory "KDBGSetup.pdb"; Destination = "KDBGSetup.pdb" },
    @{ Source = Join-Path $BuildDirectory "kdbg_memprocfs_bridge.pdb"; Destination = "plugins\memprocfs_bridge\kdbg_memprocfs_bridge.pdb" },
    @{ Source = Join-Path $BuildDirectory "kdbg_live_verify.pdb"; Destination = "tools\kdbg_live_verify.pdb" },
    @{ Source = Join-Path $BuildDirectory "kdbg_process_fixture.pdb"; Destination = "tools\kdbg_process_fixture.pdb" },
    @{ Source = Join-Path $DriverDirectory "KDbgDriver.pdb"; Destination = "drivers\KDbgDriver.pdb" },
    @{ Source = Join-Path $DriverDirectory "KDbgProbe.pdb"; Destination = "drivers\KDbgProbe.pdb" }
)
Assert-PackagePath $OutputDirectory $PackageName
Assert-PackagePath $SymbolsDirectory $SymbolsName
$MainZipPath = Join-Path $PackageRoot "$PackageName.zip"
$MainZipHashPath = "$MainZipPath.sha256"
$SymbolsZipPath = Join-Path $PackageRoot "$SymbolsName.zip"
$SymbolsZipHashPath = "$SymbolsZipPath.sha256"
Assert-PackagePath $MainZipPath "$PackageName.zip"
Assert-PackagePath $MainZipHashPath "$PackageName.zip.sha256"
Assert-PackagePath $SymbolsZipPath "$SymbolsName.zip"
Assert-PackagePath $SymbolsZipHashPath "$SymbolsName.zip.sha256"
$PublishAllowedTargets = @(
    $OutputDirectory, $SymbolsDirectory,
    $MainZipPath, $MainZipHashPath,
    $SymbolsZipPath, $SymbolsZipHashPath)
Recover-PackagePublish
foreach ($InputPath in @($Inputs) + @($PdbInputs | ForEach-Object { $_.Source })) {
    if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
        throw "Release input is missing; no package was produced: $InputPath"
    }
    if ((Get-Item -LiteralPath $InputPath).Length -eq 0) {
        throw "Release input is empty; no package was produced: $InputPath"
    }
}
Assert-ProductIdentityContract @(
    @{ Path = $KdbgExe; OriginalFilename = 'KDBG.exe' },
    @{ Path = $SetupExe; OriginalFilename = 'KDBGSetup.exe' },
    @{ Path = $BridgeExe; OriginalFilename = 'kdbg_memprocfs_bridge.exe' },
    @{ Path = $LiveVerifyExe; OriginalFilename = 'kdbg_live_verify.exe' },
    @{ Path = $ProcessFixtureExe; OriginalFilename = 'kdbg_process_fixture.exe' },
    @{ Path = (Join-Path $DriverDirectory 'KDbgDriver.sys'); OriginalFilename = 'KDbgDriver.sys' },
    @{ Path = (Join-Path $DriverDirectory 'KDbgProbe.sys'); OriginalFilename = 'KDbgProbe.sys' }
) @(
    (Join-Path $DriverDirectory 'KDbgDriver.inf'),
    (Join-Path $DriverDirectory 'KDbgProbe.inf'))
Assert-DriverCatalogContract "KDbgDriver"
Assert-DriverCatalogContract "KDbgProbe"

if (Test-Path -LiteralPath $StagingRoot) {
    Remove-Item -LiteralPath $StagingRoot -Recurse -Force
}
if (Test-Path -LiteralPath $BackupRoot) {
    throw "Unexpected package backup directory already exists: $BackupRoot"
}
New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
try {
Reset-PackageDirectory $StagingOutputDirectory $PackageName
foreach ($Directory in @("drivers", "plugins\memprocfs_bridge", "config", "tools", "docs", "licenses")) {
    New-Item -ItemType Directory -Path (Join-Path $StagingOutputDirectory $Directory) -Force | Out-Null
}

Copy-RequiredFile $KdbgExe (Join-Path $StagingOutputDirectory "KDBG.exe")
Copy-RequiredFile $SetupExe (Join-Path $StagingOutputDirectory "KDBGSetup.exe")
Copy-RequiredFile $BridgeExe (Join-Path $StagingOutputDirectory "plugins\memprocfs_bridge\kdbg_memprocfs_bridge.exe")
Copy-RequiredFile $LiveVerifyExe (Join-Path $StagingOutputDirectory "tools\kdbg_live_verify.exe")
Copy-RequiredFile $ProcessFixtureExe (Join-Path $StagingOutputDirectory "tools\kdbg_process_fixture.exe")
Copy-RequiredFile (Join-Path $RepoRoot "src\fixtures\process_fixture\README.md") (Join-Path $StagingOutputDirectory "docs\PROCESS_FIXTURE.md")
Copy-RequiredFile (Join-Path $RepoRoot "src\tools\live_verify\README.md") (Join-Path $StagingOutputDirectory "docs\LIVE_VERIFY.md")
foreach ($Name in @(
    "KDbgDriver.sys", "KDbgProbe.sys", "KDbgDriver.inf", "KDbgProbe.inf",
    "KDbgDriver.cat", "KDbgProbe.cat")) {
    Copy-RequiredFile (Join-Path $DriverDirectory $Name) (Join-Path $StagingOutputDirectory "drivers\$Name")
}
$Catalogs = @("drivers/KDbgDriver.cat", "drivers/KDbgProbe.cat")
foreach ($Name in @("app.example.json", "safety_policy.example.json")) {
    Copy-RequiredFile (Join-Path $RepoRoot "src\config\$Name") (Join-Path $StagingOutputDirectory "config\$Name")
}
foreach ($Name in @(
    "install.ps1", "start.ps1", "run.ps1", "stop.ps1", "uninstall.ps1",
    "diagnose.ps1", "TargetProfile.psm1")) {
    Copy-RequiredFile (Join-Path $RepoRoot "src\tools\package\$Name") (Join-Path $StagingOutputDirectory "tools\$Name")
}
Copy-RequiredFile (Join-Path $RepoRoot "src\tools\setup\setup.ps1") (Join-Path $StagingOutputDirectory "tools\setup.ps1")
Copy-RequiredFile (Join-Path $RepoRoot "src\tools\setup\setup_contract.psm1") (Join-Path $StagingOutputDirectory "tools\setup_contract.psm1")
foreach ($Name in @(
    "new_live_evidence.ps1", "capture_demo.ps1", "live-evidence.example.json",
    "validate_release.py")) {
    Copy-RequiredFile (Join-Path $RepoRoot "src\tools\$Name") (Join-Path $StagingOutputDirectory "tools\$Name")
}
foreach ($Name in @(
    "QUICKSTART.md", "OPERATOR_GUIDE.md", "TROUBLESHOOTING.md",
    "SECURITY.md", "SUPPORT.md", "PRIVACY.md", "LICENSE_AND_EULA.md",
    "UPDATE_AND_ROLLBACK.md", "VULNERABILITY_DISCLOSURE.md")) {
    Copy-RequiredFile (Join-Path $RepoRoot "docs\$Name") (Join-Path $StagingOutputDirectory "docs\$Name")
}
Copy-RequiredFile (Join-Path $RepoRoot "CHANGELOG.md") (Join-Path $StagingOutputDirectory "docs\RELEASE_NOTES.md")
foreach ($Name in @(
    "LICENSE-PROJECT.txt", "MIT-kn-live-dbg.txt", "MIT-PTView.txt",
    "MIT-Dear-ImGui.txt", "MIT-imgui-memory-editor.txt", "MIT-Zydis.txt",
    "MIT-Zycore.txt", "THIRD-PARTY-NOTICES.txt")) {
    Copy-RequiredFile (Join-Path $RepoRoot "licenses\$Name") (Join-Path $StagingOutputDirectory "licenses\$Name")
}
Copy-RequiredFile (Join-Path $RepoRoot "THIRD_PARTY.lock.json") (Join-Path $StagingOutputDirectory "licenses\THIRD_PARTY.lock.json")

$SourceSnapshot = Get-SourceSnapshot
Assert-SourceSnapshotDigest `
    $SourceSnapshot $ExpectedSourceSnapshotSha256 "package staging"
$SourceRevision = if ([string]::IsNullOrWhiteSpace($env:KDBG_SOURCE_REVISION)) {
    "snapshot-sha256:$($SourceSnapshot.Digest)"
} else { $env:KDBG_SOURCE_REVISION }
$Syft = Get-Command syft -ErrorAction SilentlyContinue
if ($null -eq $Syft) {
    throw "Syft is required to create SBOM.spdx.json; install Syft and rerun packaging."
}
$CmakeVersion = (& cmake --version | Select-Object -First 1).Trim()
$PythonVersion = (& python --version 2>&1 | Select-Object -First 1).Trim()
$SyftVersionLine = & $Syft.Source version 2>&1 |
    Where-Object { [string]$_ -match '^Version:\s*\S+' } |
    Select-Object -First 1
if ($null -eq $SyftVersionLine) {
    throw "Unable to capture the Syft version."
}
$SyftVersion = ([string]$SyftVersionLine -replace '^Version:\s*', '').Trim()
$ToolVersions = Get-KdbgToolchainVersions
$ToolVersions.powershell = $PSVersionTable.PSVersion.ToString()
$ToolVersions.cmake = $CmakeVersion
$ToolVersions.python = $PythonVersion
$ToolVersions.syft = $SyftVersion
$ReproducibleCommands = if ($EpochLayout.IsEpoch) {
    $EpochRelative = ".\out\release-epochs\$EpochName"
    @(
        ".\src\tools\build_public_release.ps1 -EpochName $EpochName -Clean -Package",
        "python .\src\tools\validate_release.py --windows-package $EpochRelative\package\KDBG-1.1.0-win-x64 --symbols-package $EpochRelative\package\KDBG-1.1.0-win-x64-symbols"
    )
} else {
    @(
        ".\src\tools\build.ps1 -Preset windows-release -Fresh -Package",
        "python .\src\tools\validate_release.py --windows-package .\out\package\KDBG-1.1.0-win-x64 --symbols-package .\out\package\KDBG-1.1.0-win-x64-symbols"
    )
}
$Metadata = [ordered]@{
    schema = "kdbg.build-metadata.v1"
    product = "KDBG"
    version = $Version
    configuration = "Release"
    architecture = "x64"
    minimum_windows_build = 19041
    package_name = $PackageName
    source_revision = $SourceRevision
    source_snapshot_scope = $SourceSnapshot.Policy.Schema
    source_snapshot_sha256 = $SourceSnapshot.Digest
    source_file_count = $SourceSnapshot.FileCount
    source_snapshot_manifest = "SOURCE-SNAPSHOT-SHA256SUMS.txt"
    source_snapshot_policy = [ordered]@{
        root_files = @($SourceSnapshot.Policy.RootFiles)
        documentation_files = @($SourceSnapshot.Policy.DocumentationFiles)
        scan_roots = @($SourceSnapshot.Policy.ScanRoots)
        excluded_paths = @($SourceSnapshot.Policy.ExcludedPaths)
        ignored_directory_names = @($SourceSnapshot.Policy.IgnoredDirectoryNames)
        ignored_extensions = @($SourceSnapshot.Policy.IgnoredExtensions)
    }
    source_date_epoch = if ([string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) { $null } else { $env:SOURCE_DATE_EPOCH }
    catalogs = @($Catalogs | Sort-Object)
    signature_claim = "not asserted; inspect with tools/diagnose.ps1"
    symbols_package = $SymbolsName
    tool_versions = $ToolVersions
    reproducible_commands = $ReproducibleCommands
}
if ($EpochLayout.IsEpoch) {
    $Metadata.release_epoch = $EpochName
}
$Metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $StagingOutputDirectory "BUILD-METADATA.json") -Encoding utf8
[IO.File]::WriteAllText(
    (Join-Path $StagingOutputDirectory "SOURCE-SNAPSHOT-SHA256SUMS.txt"),
    $SourceSnapshot.Manifest,
    [Text.UTF8Encoding]::new($false))

$SbomPath = Join-Path $StagingOutputDirectory "SBOM.spdx.json"
& $Syft.Source scan "dir:$StagingOutputDirectory" --source-name $PackageName -o "spdx-json=$SbomPath"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $SbomPath)) {
    throw "Syft SBOM generation failed."
}
Add-LockedPackagesToSbom $SbomPath
Write-HashManifest $StagingOutputDirectory

Reset-PackageDirectory $StagingSymbolsDirectory $SymbolsName
foreach ($Pdb in $PdbInputs) {
    Copy-RequiredFile $Pdb.Source (Join-Path $StagingSymbolsDirectory $Pdb.Destination)
}
$SymbolsMetadata = [ordered]@{
    schema = "kdbg.symbols-metadata.v1"
    product = "KDBG"
    version = $Version
    configuration = "Release"
    architecture = "x64"
    minimum_windows_build = 19041
    package_name = $SymbolsName
    source_revision = $SourceRevision
    source_snapshot_scope = $SourceSnapshot.Policy.Schema
    source_snapshot_sha256 = $SourceSnapshot.Digest
    source_file_count = $SourceSnapshot.FileCount
    source_snapshot_manifest = "SOURCE-SNAPSHOT-SHA256SUMS.txt"
    source_snapshot_policy = [ordered]@{
        root_files = @($SourceSnapshot.Policy.RootFiles)
        documentation_files = @($SourceSnapshot.Policy.DocumentationFiles)
        scan_roots = @($SourceSnapshot.Policy.ScanRoots)
        excluded_paths = @($SourceSnapshot.Policy.ExcludedPaths)
        ignored_directory_names = @($SourceSnapshot.Policy.IgnoredDirectoryNames)
        ignored_extensions = @($SourceSnapshot.Policy.IgnoredExtensions)
    }
    tool_versions = $ToolVersions
    path_policy = [ordered]@{
        schema = "kdbg.symbol-path-policy.v1"
        logical_root = "KDBG_ROOT"
        scan_scope = @("raw", "logical-streams")
        encodings = @("ascii", "utf-16le")
        permitted_stable_aliases = @("R:\", "K:\")
        stable_aliases_are_private = $false
        private_paths_present = $false
    }
}
if ($EpochLayout.IsEpoch) {
    $SymbolsMetadata.release_epoch = $EpochName
}
$SymbolsMetadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $StagingSymbolsDirectory "BUILD-METADATA.json") -Encoding utf8
[IO.File]::WriteAllText(
    (Join-Path $StagingSymbolsDirectory "SOURCE-SNAPSHOT-SHA256SUMS.txt"),
    $SourceSnapshot.Manifest,
    [Text.UTF8Encoding]::new($false))
Write-HashManifest $StagingSymbolsDirectory
$ValidationArguments = @(
    (Join-Path $PSScriptRoot "validate_release.py"),
    "--windows-package", $StagingOutputDirectory,
    "--symbols-package", $StagingSymbolsDirectory)
foreach ($ForbiddenPath in $ForbiddenSymbolPath) {
    if ([string]::IsNullOrWhiteSpace($ForbiddenPath)) { continue }
    $ValidationArguments += "--forbid-symbol-path"
    $ValidationArguments += [IO.Path]::GetFullPath($ForbiddenPath)
}
& python @ValidationArguments
if ($LASTEXITCODE -ne 0) { throw "Paired Windows and symbols package validation failed." }

if ($Zip) {
    New-DeterministicZip $StagingOutputDirectory $StagingMainZipPath
    if (Test-Path -LiteralPath $StagingSymbolsDirectory -PathType Container) {
        New-DeterministicZip $StagingSymbolsDirectory $StagingSymbolsZipPath
    }
}

$Artifacts = @(
    [pscustomobject]@{ Staged = $StagingOutputDirectory; Target = $OutputDirectory },
    [pscustomobject]@{ Staged = $StagingSymbolsDirectory; Target = $SymbolsDirectory },
    [pscustomobject]@{ Staged = if ($Zip) { $StagingMainZipPath } else { $null }; Target = $MainZipPath },
    [pscustomobject]@{ Staged = if ($Zip) { "$StagingMainZipPath.sha256" } else { $null }; Target = $MainZipHashPath },
    [pscustomobject]@{ Staged = if ($Zip) { $StagingSymbolsZipPath } else { $null }; Target = $SymbolsZipPath },
    [pscustomobject]@{ Staged = if ($Zip) { "$StagingSymbolsZipPath.sha256" } else { $null }; Target = $SymbolsZipHashPath }
)
$PrePublishSourceSnapshot = Get-SourceSnapshot
Assert-SourceSnapshotDigest `
    $PrePublishSourceSnapshot $SourceSnapshot.Digest "package publication"
Assert-SourceSnapshotDigest `
    $PrePublishSourceSnapshot $ExpectedSourceSnapshotSha256 "package publication"
Publish-PackageArtifacts $Artifacts $BackupRoot

Write-Host "Validated main package: $OutputDirectory"
if (Test-Path -LiteralPath $SymbolsDirectory -PathType Container) {
    Write-Host "Validated symbols package: $SymbolsDirectory"
}
} finally {
    if (Test-Path -LiteralPath $StagingRoot) {
        Remove-Item -LiteralPath $StagingRoot -Recurse -Force
    }
}

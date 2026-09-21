[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$PackagerPath = Join-Path $RepoRoot "src\tools\package_windows.ps1"
$PublicReleasePath = Join-Path $RepoRoot "src\tools\build_public_release.ps1"
$SourceSnapshotToolPath = Join-Path $RepoRoot `
    "src\tools\source_snapshot\source_snapshot.py"
$SourceSnapshotScopePath = Join-Path $RepoRoot `
    "src\tools\source_snapshot\scope.kdbg.json"
$DriverNugetPath = Join-Path $RepoRoot "src\tools\build_drivers_nuget.ps1"
$InstallPath = Join-Path $RepoRoot "src\tools\package\install.ps1"
$RunPath = Join-Path $RepoRoot "src\tools\package\run.ps1"
$StartPath = Join-Path $RepoRoot "src\tools\package\start.ps1"
$DiagnosePath = Join-Path $RepoRoot "src\tools\package\diagnose.ps1"
$StopPath = Join-Path $RepoRoot "src\tools\package\stop.ps1"
$UninstallPath = Join-Path $RepoRoot "src\tools\package\uninstall.ps1"
$Checks = 0

function Assert-True([bool]$Condition, [string]$Message) {
    $script:Checks++
    if (-not $Condition) { throw "CHECK FAILED: $Message" }
}

function Assert-Throws([scriptblock]$Operation, [string]$Message) {
    $script:Checks++
    try {
        & $Operation
    } catch {
        return
    }
    throw "CHECK FAILED: $Message"
}

function Get-ScriptAst([string]$Path) {
    $Tokens = $null
    $Errors = $null
    $Ast = [Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$Tokens, [ref]$Errors)
    if ($Errors.Count -ne 0) {
        throw "PowerShell parse failed for ${Path}: $($Errors[0].Message)"
    }
    return $Ast
}

function Get-FunctionDefinitions([string]$Path, [string[]]$Names) {
    $Ast = Get-ScriptAst $Path
    $Definitions = [Collections.Generic.List[string]]::new()
    foreach ($Name in $Names) {
        $Definition = $Ast.Find(
            {
                param($Node)
                $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $Node.Name -eq $Name
            },
            $true)
        if ($null -eq $Definition) {
            throw "Function $Name was not found in $Path"
        }
        $Definitions.Add($Definition.Extent.Text)
    }
    return $Definitions -join "`n`n"
}

$Definitions = Get-FunctionDefinitions $PackagerPath @(
    "Get-KdbgRelativePath",
    "Get-KdbgSourceSnapshotPolicy",
    "Get-SourceSnapshot",
    "Assert-SourceSnapshotDigest",
    "Resolve-KdbgEpochLayout",
    "Resolve-DriverInputDirectory",
    "Assert-PublishTransactionPath",
    "Test-IsAllowedPublishTarget",
    "Remove-PackageArtifact",
    "Write-PublishJournal",
    "Read-PublishJournal",
    "Test-PublishJournal",
    "Recover-PackagePublish",
    "Publish-PackageArtifacts",
    "Test-ProductIdentityValues",
    "Test-InfProviderIdentityValues")
$Definitions += "`n`n" + (Get-FunctionDefinitions $PublicReleasePath @(
    "Read-KdbgSourceSnapshotMetadata",
    "New-KdbgSourceSnapshotArtifacts",
    "Assert-KdbgSourceSnapshotEqual",
    "Assert-KdbgSourceSnapshotTree"))
$Definitions += "`n`n" + (Get-FunctionDefinitions $UninstallPath @(
    "Assert-NoReparsePoints",
    "Remove-ValidatedChildDirectory"))
$Definitions += "`n`n" + (Get-FunctionDefinitions $InstallPath @(
    "Get-ScStartMode",
    "New-PairLifecyclePlan"))
$Definitions += "`n`n" + (Get-FunctionDefinitions $DiagnosePath @(
    "Get-NormalizedServicePath",
    "Test-IsTrustedDriverSignature",
    "Test-IsProductionDriverSignature"))
Invoke-Expression $Definitions
$EpochLayout = Resolve-KdbgEpochLayout ""

$UninstallScript = Get-Content -LiteralPath $UninstallPath -Raw
Assert-True ($UninstallScript.Contains("CreateProcessW") -and
    $UninstallScript.Contains("inheritHandles") -and
    $UninstallScript.Contains("IntPtr.Zero, IntPtr.Zero, false")) `
    "self-purge helper must launch without inheriting captured parent handles"
Assert-True (-not $UninstallScript.Contains("RedirectStandardOutput") -and
    -not $UninstallScript.Contains("RedirectStandardError")) `
    "self-purge helper must not keep managed redirect pumps alive"

function Set-PublishFixture([string]$Root, [string]$Transaction) {
    $script:PackageRoot = [IO.Path]::GetFullPath($Root)
    $script:PackageName = "KDBG-1.1.0-win-x64"
    $script:SymbolsName = "$PackageName-symbols"
    $script:PublishTransactionId = $Transaction
    $script:StagingRoot = Join-Path $PackageRoot ".staging-$Transaction"
    $script:PublishJournalPath = Join-Path $PackageRoot ".publish-transaction.json"
    $script:PublishAllowedTargets = @(
        (Join-Path $PackageRoot $PackageName),
        (Join-Path $PackageRoot $SymbolsName),
        (Join-Path $PackageRoot "$PackageName.zip"),
        (Join-Path $PackageRoot "$PackageName.zip.sha256"),
        (Join-Path $PackageRoot "$SymbolsName.zip"),
        (Join-Path $PackageRoot "$SymbolsName.zip.sha256"))
    New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
}

$TestRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "kdbg-package-lifecycle-$([Guid]::NewGuid().ToString('N'))")
New-Item -ItemType Directory -Path $TestRoot -Force | Out-Null
try {
    $SnapshotFixture = Join-Path $TestRoot "source-snapshot"
    foreach ($Directory in @(
            "src\core", "src\out", "licenses", ".github\workflows",
            "docs\exec-plans")) {
        New-Item -ItemType Directory -Path (Join-Path $SnapshotFixture $Directory) `
            -Force | Out-Null
    }
    $SnapshotFiles = [ordered]@{
        "README.md" = "product overview"
        "LICENSE" = "project license"
        "THIRD_PARTY.lock.json" = '{"dependencies":[]}'
        "src\CMakeLists.txt" = "project(KDBG)"
        "src\core\product.cpp" = "int product = 1;"
        "licenses\LICENSE-PROJECT.txt" = "license notice"
        ".github\workflows\validate.yml" = "name: validate"
        "docs\QUICKSTART.md" = "operator quickstart"
        "docs\VALIDATION_REPORT.md" = "run one"
        "docs\TRACEABILITY_MATRIX.md" = "matrix one"
        "docs\exec-plans\STATUS.md" = "status one"
        "ARTIFACT_MANIFEST.md" = "artifact one"
        "src\out\generated.txt" = "generated one"
    }
    foreach ($Entry in $SnapshotFiles.GetEnumerator()) {
        $Path = Join-Path $SnapshotFixture $Entry.Key
        New-Item -ItemType Directory -Path (Split-Path -Parent $Path) `
            -Force | Out-Null
        Set-Content -LiteralPath $Path -Value $Entry.Value -Encoding utf8
    }
    $InitialSnapshot = Get-SourceSnapshot $SnapshotFixture
    Assert-True ($InitialSnapshot.Policy.Schema -eq "kdbg.product-source.v1") `
        "source snapshot must advertise the stable product-source scope"
    Assert-True ($InitialSnapshot.FileCount -eq 8 -and
        $InitialSnapshot.Manifest.Contains("  src/core/product.cpp`n") -and
        $InitialSnapshot.Manifest.Contains("  docs/QUICKSTART.md`n")) `
        "source snapshot must include product code, build inputs, licenses, and operator docs"
    $ManifestPaths = [string[]]@(
        $InitialSnapshot.Manifest.TrimEnd("`n").Split("`n") |
            ForEach-Object { $_.Substring(66) })
    $OrdinalPaths = [string[]]$ManifestPaths.Clone()
    [Array]::Sort($OrdinalPaths, [StringComparer]::Ordinal)
    Assert-True (($ManifestPaths -join "`n") -ceq ($OrdinalPaths -join "`n")) `
        "canonical source records must use ordinal relative-path order"
    $PythonManifestPath = Join-Path $TestRoot "python-source-manifest.txt"
    $PythonMetadataPath = Join-Path $TestRoot "python-source-metadata.json"
    & python $SourceSnapshotToolPath generate `
        --root $SnapshotFixture `
        --scope $SourceSnapshotScopePath `
        --manifest $PythonManifestPath `
        --metadata $PythonMetadataPath | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) `
        "canonical Python source-snapshot generator must accept the package fixture"
    $PythonManifest = [IO.File]::ReadAllText($PythonManifestPath)
    $PythonMetadata = Get-Content -LiteralPath $PythonMetadataPath -Raw |
        ConvertFrom-Json
    Assert-True ($PythonManifest -ceq $InitialSnapshot.Manifest -and
        $PythonMetadata.scope_version -eq $InitialSnapshot.Policy.Schema -and
        $PythonMetadata.digest -eq $InitialSnapshot.Digest -and
        $PythonMetadata.count -eq $InitialSnapshot.FileCount) `
        "Python and package source snapshots must have identical records, digest, scope, and count"
    Assert-True ($InitialSnapshot.Policy.ExcludedPaths -contains "docs/exec-plans/**" -and
        $InitialSnapshot.Policy.ExcludedPaths -contains "docs/VALIDATION_REPORT.md" -and
        $InitialSnapshot.Policy.ExcludedPaths -contains "docs/TRACEABILITY_MATRIX.md") `
        "source snapshot policy must disclose mutable run/evidence ledger exclusions"
    foreach ($ExcludedMutation in @(
            "docs\VALIDATION_REPORT.md", "docs\TRACEABILITY_MATRIX.md",
            "docs\exec-plans\STATUS.md", "ARTIFACT_MANIFEST.md",
            "src\out\generated.txt")) {
        Add-Content -LiteralPath (Join-Path $SnapshotFixture $ExcludedMutation) `
            -Value "post-run ledger update"
    }
    $AfterLedgerUpdates = Get-SourceSnapshot $SnapshotFixture
    Assert-True ($AfterLedgerUpdates.Digest -ceq $InitialSnapshot.Digest -and
        $AfterLedgerUpdates.FileCount -eq $InitialSnapshot.FileCount) `
        "mutable evidence ledgers and generated output must not change product identity"
    $ReleaseProvenance = Join-Path $TestRoot "release-provenance"
    $ReleaseBefore = New-KdbgSourceSnapshotArtifacts `
        $SourceSnapshotToolPath `
        $SnapshotFixture `
        $SourceSnapshotScopePath `
        $ReleaseProvenance `
        "before-configure"
    $ReleaseStable = New-KdbgSourceSnapshotArtifacts `
        $SourceSnapshotToolPath `
        $SnapshotFixture `
        $SourceSnapshotScopePath `
        $ReleaseProvenance `
        "before-package-publication"
    Assert-KdbgSourceSnapshotEqual `
        $ReleaseBefore $ReleaseStable "stable fixture"
    Assert-KdbgSourceSnapshotTree `
        $SourceSnapshotToolPath `
        $SnapshotFixture `
        $SourceSnapshotScopePath `
        $ReleaseBefore `
        "stable fixture"
    Assert-True ($ReleaseBefore.Digest -ceq $InitialSnapshot.Digest -and
        $ReleaseBefore.Count -eq $InitialSnapshot.FileCount -and
        (Test-Path -LiteralPath $ReleaseBefore.ManifestPath -PathType Leaf) -and
        (Test-Path -LiteralPath $ReleaseStable.MetadataPath -PathType Leaf)) `
        "release capture must preserve canonical before-configure and pre-publication artifacts"
    Add-Content -LiteralPath (Join-Path $SnapshotFixture "src\core\product.cpp") `
        -Value "int included_change = 2;"
    $AfterProductUpdate = Get-SourceSnapshot $SnapshotFixture
    Assert-True ($AfterProductUpdate.Digest -cne $InitialSnapshot.Digest -and
        $AfterProductUpdate.FileCount -eq $InitialSnapshot.FileCount) `
        "an included product-source edit must change the product identity digest"
    $ReleaseDrift = New-KdbgSourceSnapshotArtifacts `
        $SourceSnapshotToolPath `
        $SnapshotFixture `
        $SourceSnapshotScopePath `
        $ReleaseProvenance `
        "after-packaging"
    Assert-Throws {
        Assert-KdbgSourceSnapshotEqual `
            $ReleaseBefore $ReleaseDrift "synthetic drift"
    } "release metadata comparison must fail closed on included source drift"
    Assert-Throws {
        Assert-KdbgSourceSnapshotTree `
            $SourceSnapshotToolPath `
            $SnapshotFixture `
            $SourceSnapshotScopePath `
            $ReleaseBefore `
            "synthetic drift"
    } "release tree verification must fail closed on included source drift"
    Assert-Throws {
        Assert-SourceSnapshotDigest `
            $AfterProductUpdate $InitialSnapshot.Digest "synthetic packaging"
    } "packager expected digest must fail closed on included source drift"

    $DefaultLayout = Resolve-KdbgEpochLayout ""
    Assert-True (-not $DefaultLayout.IsEpoch -and
        ([IO.Path]::GetFullPath($DefaultLayout.PackageRoot)).Equals(
            [IO.Path]::GetFullPath((Join-Path $RepoRoot "out\package")),
            [StringComparison]::OrdinalIgnoreCase) -and
        ([IO.Path]::GetFullPath($DefaultLayout.BuildDirectory)).Equals(
            [IO.Path]::GetFullPath((Join-Path $RepoRoot "out\build\windows-release")),
            [StringComparison]::OrdinalIgnoreCase)) `
        "default packaging layout must remain byte-for-byte compatible with out/package"
    Assert-Throws { Resolve-KdbgEpochLayout "" $true } `
        "an explicitly supplied empty epoch must not fall back to frozen default output"
    Assert-Throws { Resolve-KdbgEpochLayout "   " $true } `
        "an explicitly supplied whitespace epoch must not fall back to frozen default output"

    $EpochSlug = "public-symbols-r1"
    $IsolatedLayout = Resolve-KdbgEpochLayout $EpochSlug
    $ExpectedEpochRoot = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot "out\release-epochs\$EpochSlug"))
    Assert-True ($IsolatedLayout.IsEpoch -and
        ([IO.Path]::GetFullPath($IsolatedLayout.EpochRoot)).Equals(
            $ExpectedEpochRoot, [StringComparison]::OrdinalIgnoreCase) -and
        ([IO.Path]::GetFullPath($IsolatedLayout.PackageRoot)).Equals(
            (Join-Path $ExpectedEpochRoot "package"),
            [StringComparison]::OrdinalIgnoreCase) -and
        ([IO.Path]::GetFullPath($IsolatedLayout.BuildDirectory)).Equals(
            (Join-Path $ExpectedEpochRoot "build\windows-release"),
            [StringComparison]::OrdinalIgnoreCase)) `
        "epoch mode must isolate package and build output below one exact epoch root"
    Assert-True (-not ([IO.Path]::GetFullPath(
            $IsolatedLayout.PackageRoot)).StartsWith(
                [IO.Path]::GetFullPath((Join-Path $RepoRoot "out\package")) +
                    [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase)) `
        "epoch package output must not be nested below the frozen default package root"
    foreach ($InvalidEpoch in @(
            "../escape", "UPPERCASE", "trailing-", "trailing.", "con",
            ("a" * 65))) {
        Assert-Throws { Resolve-KdbgEpochLayout $InvalidEpoch } `
            "epoch slug must reject unsafe value: $InvalidEpoch"
    }

    $EpochLayoutRepo = Join-Path $TestRoot "epoch-layout-repo"
    $EpochLayoutExternal = Join-Path $TestRoot "epoch-layout-external"
    $EpochLayoutLink = Join-Path $EpochLayoutRepo `
        "out\release-epochs\linked-epoch"
    New-Item -ItemType Directory -Path (Split-Path -Parent $EpochLayoutLink) `
        -Force | Out-Null
    New-Item -ItemType Directory -Path $EpochLayoutExternal -Force | Out-Null
    New-Item -ItemType Junction -Path $EpochLayoutLink `
        -Target $EpochLayoutExternal | Out-Null
    $SavedRepoRoot = $RepoRoot
    try {
        $RepoRoot = $EpochLayoutRepo
        Assert-Throws { Resolve-KdbgEpochLayout "linked-epoch" } `
            "epoch layout must reject a reparse-point output root"
    } finally {
        $RepoRoot = $SavedRepoRoot
        if (Test-Path -LiteralPath $EpochLayoutLink) {
            [IO.Directory]::Delete($EpochLayoutLink, $false)
        }
    }

    $ExpectedUnsignedDrivers = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot "out\drivers\Release"))
    $ExpectedSignedDrivers = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot "out\signed-drivers\Release"))
    Assert-True ((Resolve-DriverInputDirectory "").Equals(
            $ExpectedUnsignedDrivers, [StringComparison]::OrdinalIgnoreCase)) `
        "packaging must retain out/drivers/Release as the default driver input"
    Assert-True ((Resolve-DriverInputDirectory $ExpectedSignedDrivers).Equals(
            $ExpectedSignedDrivers, [StringComparison]::OrdinalIgnoreCase)) `
        "packaging must accept the exact isolated signed-driver Release directory"
    Assert-Throws {
        Resolve-DriverInputDirectory (Join-Path $RepoRoot "out\signed-drivers\Debug")
    } "packaging must reject a non-Release signed-driver directory"
    Assert-Throws {
        Resolve-DriverInputDirectory (Join-Path $TestRoot "outside\Release")
    } "packaging must reject a driver directory outside the two owned roots"

    $EpochLayout = $IsolatedLayout
    $ExpectedEpochDrivers = [IO.Path]::GetFullPath(
        (Join-Path $ExpectedEpochRoot "drivers\Release"))
    $ExpectedEpochSignedDrivers = [IO.Path]::GetFullPath(
        (Join-Path $ExpectedEpochRoot "signed-drivers\Release"))
    Assert-True ((Resolve-DriverInputDirectory "").Equals(
            $ExpectedEpochDrivers, [StringComparison]::OrdinalIgnoreCase)) `
        "epoch packaging must derive its isolated Release driver input"
    Assert-True ((Resolve-DriverInputDirectory $ExpectedEpochSignedDrivers).Equals(
            $ExpectedEpochSignedDrivers, [StringComparison]::OrdinalIgnoreCase)) `
        "epoch packaging must accept its exact isolated signed-driver directory"
    Assert-Throws {
        Resolve-DriverInputDirectory $ExpectedUnsignedDrivers
    } "epoch packaging must reject the frozen default driver input"
    Assert-Throws {
        Resolve-DriverInputDirectory (Join-Path $ExpectedEpochRoot "drivers\Debug")
    } "epoch packaging must reject a non-Release epoch driver input"
    $EpochLayout = $DefaultLayout

    $OriginalRepoRoot = $RepoRoot
    $DriverRootFixture = Join-Path $TestRoot "driver-root-fixture"
    $DriverExternalFixture = Join-Path $TestRoot "driver-external-fixture"
    $DriverReleaseLink = Join-Path $DriverRootFixture "out\signed-drivers\Release"
    try {
        New-Item -ItemType Directory -Path (
            Split-Path -Parent $DriverReleaseLink) -Force | Out-Null
        New-Item -ItemType Directory -Path $DriverExternalFixture -Force | Out-Null
        New-Item -ItemType Junction -Path $DriverReleaseLink `
            -Target $DriverExternalFixture | Out-Null
        $RepoRoot = $DriverRootFixture
        $EpochLayout = Resolve-KdbgEpochLayout ""
        Assert-Throws {
            Resolve-DriverInputDirectory $DriverReleaseLink
        } "packaging must reject a reparse-point driver input directory"
    } finally {
        $RepoRoot = $OriginalRepoRoot
        $EpochLayout = $DefaultLayout
        if (Test-Path -LiteralPath $DriverReleaseLink) {
            Remove-Item -LiteralPath $DriverReleaseLink -Force
        }
    }

    $ExpectedDriverPath = [IO.Path]::GetFullPath(
        (Join-Path $TestRoot "package\drivers\KDbgDriver.sys"))
    Assert-True ((Get-NormalizedServicePath ("\??\" + $ExpectedDriverPath)).Equals(
            $ExpectedDriverPath, [StringComparison]::OrdinalIgnoreCase)) `
        "SCM NT path prefixes must normalize to the owning package path"
    Assert-True ((Get-NormalizedServicePath ("\\?\" + $ExpectedDriverPath)).Equals(
            $ExpectedDriverPath, [StringComparison]::OrdinalIgnoreCase)) `
        "Win32 extended path prefixes must normalize to the owning package path"
    $TrustedSignature = [pscustomobject]@{
        Status = [Management.Automation.SignatureStatus]::Valid
        SignerCertificate = [pscustomobject]@{ Thumbprint = "fixture" }
    }
    $UntrustedSignature = [pscustomobject]@{
        Status = [Management.Automation.SignatureStatus]::UnknownError
        SignerCertificate = [pscustomobject]@{ Thumbprint = "fixture" }
    }
    $MissingSigner = [pscustomobject]@{
        Status = [Management.Automation.SignatureStatus]::Valid
        SignerCertificate = $null
    }
    Assert-True (Test-IsTrustedDriverSignature $TrustedSignature) `
        "trusted driver signature gate must accept Valid status with a signer certificate"
    Assert-True (-not (Test-IsTrustedDriverSignature $UntrustedSignature)) `
        "trusted driver signature gate must reject an untrusted chain"
    Assert-True (-not (Test-IsTrustedDriverSignature $MissingSigner)) `
        "trusted driver signature gate must reject Valid-like metadata without a signer"
    $ProductionSignature = [pscustomobject]@{
        Status = [Management.Automation.SignatureStatus]::Valid
        SignerCertificate = [pscustomobject]@{
            Subject = "CN=KDBG Production Fixture"
            Issuer = "CN=Fixture Public CA"
        }
        TimeStamperCertificate = [pscustomobject]@{ Subject = "CN=Fixture TSA" }
    }
    Assert-True (Test-IsProductionDriverSignature `
            $ProductionSignature "CN=KDBG Production Fixture") `
        "production signature gate must accept trusted exact-publisher timestamped chain metadata"
    Assert-True (-not (Test-IsProductionDriverSignature `
            $ProductionSignature "CN=Wrong Publisher")) `
        "production signature gate must reject a different publisher subject"
    $ProductionSignature.SignerCertificate.Issuer =
        $ProductionSignature.SignerCertificate.Subject
    Assert-True (-not (Test-IsProductionDriverSignature `
            $ProductionSignature "CN=KDBG Production Fixture")) `
        "production signature gate must reject self-signed test/private certificates"
    $ProductionSignature.SignerCertificate.Issuer = "CN=Fixture Public CA"
    $ProductionSignature.TimeStamperCertificate = $null
    Assert-True (-not (Test-IsProductionDriverSignature `
            $ProductionSignature "CN=KDBG Production Fixture")) `
        "production signature gate must reject untimestamped signatures"
    $ProductIdentity = [pscustomobject]@{
        CompanyName = "KDBG Project"
        ProductName = "KDBG"
        FileVersion = "1.1.0.0"
        ProductVersion = "1.1.0"
        OriginalFilename = "KDBG.exe"
    }
    Assert-True (Test-ProductIdentityValues $ProductIdentity "KDBG.exe") `
        "product identity gate must accept the documented 1.1.0/1.1.0.0 version forms"
    $ProductIdentity.CompanyName = "KDBG contributors"
    Assert-True (-not (Test-ProductIdentityValues $ProductIdentity "KDBG.exe")) `
        "product identity gate must reject CompanyName drift"
    $ProductIdentity.CompanyName = "KDBG Project"
    $ProductIdentity.ProductName = "KDBG Research"
    Assert-True (-not (Test-ProductIdentityValues $ProductIdentity "KDBG.exe")) `
        "product identity gate must reject ProductName drift"
    $ProductIdentity.ProductName = "KDBG"
    $ProductIdentity.FileVersion = "1.1.1.0"
    Assert-True (-not (Test-ProductIdentityValues $ProductIdentity "KDBG.exe")) `
        "product identity gate must reject release version drift"
    $ProductIdentity.FileVersion = "1.1.0.0"
    $ProductIdentity.OriginalFilename = "renamed.exe"
    Assert-True (-not (Test-ProductIdentityValues $ProductIdentity "KDBG.exe")) `
        "product identity gate must reject OriginalFilename drift"
    Assert-True (Test-InfProviderIdentityValues @(
            '[Strings]', 'ProviderName="KDBG Project"')) `
        "product identity gate must accept exact INF ProviderName"
    Assert-True (-not (Test-InfProviderIdentityValues @(
            '[Strings]', 'ProviderName="KDBG contributors"'))) `
        "product identity gate must reject INF ProviderName drift"
    foreach ($DriverInf in @(
        (Join-Path $RepoRoot "src\driver\KDbgDriver\KDbgDriver.inf"),
        (Join-Path $RepoRoot "src\driver\KDbgProbe\KDbgProbe.inf"))) {
        Assert-True (Test-InfProviderIdentityValues (
                Get-Content -LiteralPath $DriverInf)) `
            "product identity gate must accept the real INF including blank lines"
    }
    $PackagerText = Get-Content -LiteralPath $PackagerPath -Raw
    $PublicReleaseText = Get-Content -LiteralPath $PublicReleasePath -Raw
    Assert-True ($PackagerText.Contains("Assert-ProductIdentityContract @(")) `
        "packaging must invoke the complete product identity contract"
    Assert-True ($PackagerText.Contains(
            'copyrightText = "Copyright (c) 2026 KDBG Project"')) `
        "packaged SBOM project identity must be normalized"
    foreach ($Path in @($InstallPath, $DiagnosePath, $StopPath, $UninstallPath)) {
        $PathText = Get-Content -LiteralPath $Path -Raw
        Assert-True ($PathText.Contains("StartsWith('\??\'") -and
            $PathText.Contains("StartsWith('\\?\'")) `
            "all package lifecycle commands must normalize SCM and extended path prefixes: $Path"
    }

    # A normal exception after the new directory is published must restore the old set.
    $Case = Join-Path $TestRoot "fault-after-publish"
    Set-PublishFixture $Case "fault"
    $Target = Join-Path $PackageRoot $PackageName
    $Staged = Join-Path $StagingRoot $PackageName
    $Backup = Join-Path $PackageRoot ".backup-fault"
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    New-Item -ItemType Directory -Path $Staged -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Target "version.txt") -Value "old"
    Set-Content -LiteralPath (Join-Path $Staged "version.txt") -Value "new"
    Assert-Throws {
        Publish-PackageArtifacts @(
            [pscustomobject]@{ Staged = $Staged; Target = $Target }) $Backup {
                param($Stage, $Artifact)
                if ($Stage -eq "after-publish") { throw "injected publish failure" }
            }
    } "fault injection must fail the publish"
    Assert-True ((Get-Content -LiteralPath (Join-Path $Target "version.txt") -Raw).Trim() -eq "old") `
        "exception rollback must restore the old directory"
    Assert-True (-not (Test-Path -LiteralPath $PublishJournalPath)) `
        "successful rollback must remove the journal"

    # A successful publish must durably commit before cleaning the old set.
    $Case = Join-Path $TestRoot "successful-commit"
    Set-PublishFixture $Case "success"
    $Target = Join-Path $PackageRoot $PackageName
    $Staged = Join-Path $StagingRoot $PackageName
    $Backup = Join-Path $PackageRoot ".backup-success"
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    New-Item -ItemType Directory -Path $Staged -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Target "version.txt") -Value "old"
    Set-Content -LiteralPath (Join-Path $Staged "version.txt") -Value "new"
    Publish-PackageArtifacts @(
        [pscustomobject]@{ Staged = $Staged; Target = $Target }) $Backup
    Assert-True ((Get-Content -LiteralPath (Join-Path $Target "version.txt") -Raw).Trim() -eq "new") `
        "successful publish must expose the new directory"
    Assert-True (-not (Test-Path -LiteralPath $PublishJournalPath)) `
        "successful publish must remove the completed journal"
    Assert-True (-not (Test-Path -LiteralPath $Backup)) `
        "successful publish must remove the obsolete backup"

    # Simulate process termination after backup and publish but before commit.
    $Case = Join-Path $TestRoot "crash-before-commit"
    Set-PublishFixture $Case "crash"
    $Target = Join-Path $PackageRoot $PackageName
    $Staged = Join-Path $StagingRoot $PackageName
    $BackupRoot = Join-Path $PackageRoot ".backup-crash"
    $Backup = Join-Path $BackupRoot $PackageName
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    New-Item -ItemType Directory -Path $Staged -Force | Out-Null
    New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Target "version.txt") -Value "old"
    Set-Content -LiteralPath (Join-Path $Staged "version.txt") -Value "new"
    $Journal = [ordered]@{
        schema = "kdbg.package-publish.v1"
        phase = "prepared"
        transaction_id = "crash"
        package_root = $PackageRoot
        staging_directory = $StagingRoot
        backup_directory = $BackupRoot
        artifacts = @([pscustomobject]@{
            target = $Target
            staged = $Staged
            backup = $Backup
            had_target = $true
        })
    }
    Write-PublishJournal $Journal
    Move-Item -LiteralPath $Target -Destination $Backup
    Move-Item -LiteralPath $Staged -Destination $Target
    Recover-PackagePublish
    Assert-True ((Get-Content -LiteralPath (Join-Path $Target "version.txt") -Raw).Trim() -eq "old") `
        "next-run recovery must restore the pre-commit directory"
    Assert-True (-not (Test-Path -LiteralPath $BackupRoot)) `
        "next-run recovery must remove its backup directory"

    # A durable committed journal preserves the complete new set and only cleans debris.
    $Case = Join-Path $TestRoot "crash-after-commit"
    Set-PublishFixture $Case "committed"
    $Target = Join-Path $PackageRoot $PackageName
    $Staged = Join-Path $StagingRoot $PackageName
    $BackupRoot = Join-Path $PackageRoot ".backup-committed"
    $Backup = Join-Path $BackupRoot $PackageName
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    New-Item -ItemType Directory -Path $Backup -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Target "version.txt") -Value "new"
    Set-Content -LiteralPath (Join-Path $Backup "version.txt") -Value "old"
    $Journal = [ordered]@{
        schema = "kdbg.package-publish.v1"
        phase = "committed"
        transaction_id = "committed"
        package_root = $PackageRoot
        staging_directory = $StagingRoot
        backup_directory = $BackupRoot
        artifacts = @([pscustomobject]@{
            target = $Target
            staged = $Staged
            backup = $Backup
            had_target = $true
        })
    }
    Write-PublishJournal $Journal
    Recover-PackagePublish
    Assert-True ((Get-Content -LiteralPath (Join-Path $Target "version.txt") -Raw).Trim() -eq "new") `
        "committed recovery must preserve the new directory"
    Assert-True (-not (Test-Path -LiteralPath $BackupRoot)) `
        "committed recovery must remove the obsolete backup"

    # A forged crash journal must be rejected before touching the published
    # target. This is the fail-closed half of next-run recovery.
    $Case = Join-Path $TestRoot "forged-crash-journal"
    Set-PublishFixture $Case "forged"
    $Target = Join-Path $PackageRoot $PackageName
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Target "version.txt") -Value "trusted"
    $ForgedJournal = [ordered]@{
        schema = "kdbg.package-publish.v1"
        phase = "prepared"
        transaction_id = "forged"
        package_root = $PackageRoot
        staging_directory = $StagingRoot
        backup_directory = (Join-Path $TestRoot "outside-backup")
        artifacts = @([pscustomobject]@{
            target = $Target
            staged = $null
            backup = (Join-Path $TestRoot "outside-backup\$PackageName")
            had_target = $true
        })
    }
    Write-PublishJournal $ForgedJournal
    Assert-Throws { Recover-PackagePublish } `
        "recovery must reject a journal whose backup escapes the package root"
    Assert-True ((Get-Content -LiteralPath (Join-Path $Target "version.txt") -Raw).Trim() -eq "trusted") `
        "invalid-journal recovery must not mutate the published target"
    Assert-True (Test-Path -LiteralPath $PublishJournalPath -PathType Leaf) `
        "invalid recovery journal must be preserved for operator inspection"

    # Recursive deletion is exercised only against this disposable temp fixture.
    $PurgeParent = Join-Path $TestRoot "purge-parent"
    $PurgeTarget = Join-Path $PurgeParent "KDBG"
    New-Item -ItemType Directory -Path $PurgeTarget -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $PurgeTarget "settings.json") -Value "{}"
    Assert-Throws {
        Remove-ValidatedChildDirectory $PurgeParent $TestRoot "KDBG"
    } "purge helper must reject a path other than the exact child"
    Remove-ValidatedChildDirectory $PurgeParent $PurgeTarget "KDBG"
    Assert-True (-not (Test-Path -LiteralPath $PurgeTarget)) `
        "purge helper must remove only the validated temp child"

    # Recursive purge must refuse junction traversal and preserve both the
    # package fixture and the external target.
    $PurgeTarget = Join-Path $PurgeParent "KDBG"
    $PurgeExternal = Join-Path $TestRoot "purge-external"
    $PurgeLink = Join-Path $PurgeTarget "external-link"
    New-Item -ItemType Directory -Path $PurgeTarget -Force | Out-Null
    New-Item -ItemType Directory -Path $PurgeExternal -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $PurgeExternal "sentinel.txt") -Value "keep"
    New-Item -ItemType Junction -Path $PurgeLink -Target $PurgeExternal | Out-Null
    Assert-Throws {
        Remove-ValidatedChildDirectory $PurgeParent $PurgeTarget "KDBG"
    } "purge helper must reject a reparse point below the exact child"
    Assert-True (Test-Path -LiteralPath $PurgeTarget -PathType Container) `
        "reparse-point rejection must preserve the package fixture"
    Assert-True ((Get-Content -LiteralPath (Join-Path $PurgeExternal "sentinel.txt") -Raw).Trim() -eq "keep") `
        "reparse-point rejection must preserve the external target"
    # Windows PowerShell 5.1 can throw an internal NullReferenceException when
    # Remove-Item targets a junction. Directory.Delete removes the link itself
    # without traversing or touching the external target.
    [IO.Directory]::Delete($PurgeLink, $false)

    # Exercise the asynchronous self-purge only against a disposable temp package.
    $SelfPurgeParent = Join-Path $TestRoot "self-purge-parent"
    $SelfPurgePackage = Join-Path $SelfPurgeParent "KDBG-1.1.0-win-x64"
    $SelfPurgeTools = Join-Path $SelfPurgePackage "tools"
    New-Item -ItemType Directory -Path $SelfPurgeTools -Force | Out-Null
    [ordered]@{
        schema = "kdbg.build-metadata.v1"
        product = "KDBG"
        package_name = "KDBG-1.1.0-win-x64"
    } | ConvertTo-Json | Set-Content -LiteralPath (
        Join-Path $SelfPurgePackage "BUILD-METADATA.json") -Encoding utf8
    Set-Content -LiteralPath (Join-Path $SelfPurgePackage "SHA256SUMS.txt") `
        -Value "temp fixture"
    $SelfPurgeRunner = Join-Path $TestRoot "invoke-self-purge.ps1"
    $SelfPurgeDefinition = Get-FunctionDefinitions $UninstallPath @(
        "Start-KdbgDetachedPowerShell",
        "Start-PackageSelfPurge")
    $RunnerText = @"
`$ErrorActionPreference = "Stop"
`$ExpectedPackageName = "KDBG-1.1.0-win-x64"
`$ExpectedRootLeaf = "KDBG-1.1.0-win-x64"
$SelfPurgeDefinition
Start-PackageSelfPurge '$($SelfPurgePackage.Replace("'", "''"))' -StatusDirectory '$((Join-Path $TestRoot "self-purge-status").Replace("'", "''"))'
"@
    Set-Content -LiteralPath $SelfPurgeRunner -Value $RunnerText -Encoding utf8
    $PowerShellPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    $RunnerProcess = Start-Process -FilePath $PowerShellPath -ArgumentList @(
        "-NoProfile", "-NonInteractive", "-File", "`"$SelfPurgeRunner`"") `
        -Wait -PassThru -WindowStyle Hidden
    Assert-True ($RunnerProcess.ExitCode -eq 0) `
        "temp self-purge launcher must exit successfully"
    $PurgeDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while ((Test-Path -LiteralPath $SelfPurgePackage) -and
        [DateTime]::UtcNow -lt $PurgeDeadline) {
        Start-Sleep -Milliseconds 100
    }
    Assert-True (-not (Test-Path -LiteralPath $SelfPurgePackage)) `
        "temp self-purge helper must remove the verified package after launcher exit"
    $SelfPurgeStatuses = @(Get-ChildItem -LiteralPath (
        Join-Path $TestRoot "self-purge-status") -Filter "purge-*.json")
    Assert-True ($SelfPurgeStatuses.Count -eq 1) `
        "temp self-purge must persist exactly one status document"
    $SelfPurgeStatus = Get-Content -LiteralPath $SelfPurgeStatuses[0].FullName `
        -Raw | ConvertFrom-Json
    Assert-True ($SelfPurgeStatus.schema -eq "kdbg.setup-purge.v1" -and
        $SelfPurgeStatus.state -eq "succeeded" -and
        (Test-Path -LiteralPath $SelfPurgeStatus.log_file -PathType Leaf)) `
        "temp self-purge must persist succeeded state and its log"

    # Execute the exact run.ps1 try/finally fragment with a mocked GUI process.
    # This proves a forced/non-zero GUI exit still invokes optional driver
    # cleanup, without requiring Administrator or loading a driver.
    $RunAst = Get-ScriptAst $RunPath
    $RunTransaction = $RunAst.Find(
        {
            param($Node)
            $Node -is [Management.Automation.Language.TryStatementAst] -and
                $Node.Extent.Text.Contains("KDBG exited with code")
        },
        $true)
    Assert-True ($null -ne $RunTransaction) `
        "GUI launch must remain inside a try/finally cleanup transaction"
    $RunFragment = $RunTransaction.Extent.Text.Replace(
        '& (Join-Path $PSScriptRoot "stop.ps1")',
        '& $StopHook')
    $script:RunStopCalls = 0
    function Invoke-MockedGuiRun([int]$ExitCode, [bool]$StopOnExit) {
        $Executable = "mock-KDBG.exe"
        $StopDriversOnExit = $StopOnExit
        $StopHook = { $script:RunStopCalls++ }
        function Start-Process {
            [CmdletBinding()]
            param(
                [string]$FilePath,
                [switch]$PassThru,
                [switch]$Wait)
            return [pscustomobject]@{ ExitCode = $ExitCode }
        }
        Invoke-Expression $RunFragment
    }
    Assert-Throws { Invoke-MockedGuiRun 23 $true } `
        "forced GUI exit must remain an observable run failure"
    Assert-True ($script:RunStopCalls -eq 1) `
        "forced GUI exit must invoke stop.ps1 when StopDriversOnExit is selected"
    Invoke-MockedGuiRun 0 $true
    Assert-True ($script:RunStopCalls -eq 2) `
        "normal GUI exit must also invoke selected driver cleanup exactly once"
    Invoke-MockedGuiRun 0 $false
    Assert-True ($script:RunStopCalls -eq 2) `
        "run.ps1 must leave drivers running when cleanup was not selected"

    $StartText = Get-Content -LiteralPath $StartPath -Raw
    $StartCall = $StartText.IndexOf("Start-Service -Name `$Name", [StringComparison]::Ordinal)
    $JournalCall = $StartText.IndexOf("`$Started.Add(`$Name)", $StartCall, [StringComparison]::Ordinal)
    $WaitCall = $StartText.IndexOf("`$Service.WaitForStatus(", $StartCall, [StringComparison]::Ordinal)
    Assert-True (0 -le $StartCall -and $StartCall -lt $JournalCall -and $JournalCall -lt $WaitCall) `
        "start rollback journal must be updated before waiting for Running"
    $VerifierCall = $StartText.IndexOf("& `$Verifier --output", [StringComparison]::Ordinal)
    $StartCatch = $StartText.IndexOf("} catch {", [StringComparison]::Ordinal)
    Assert-True ($VerifierCall -gt $WaitCall -and $VerifierCall -lt $StartCatch) `
        "packaged read-only live verifier must run inside the startup rollback transaction"
    Assert-True ($StartText.Contains('schema -ne "kdbg.live-verify.v1"') -and
        $StartText.Contains("probe_before.byte_count -ne 4096") -and
        $StartText.Contains("write_cleanup.final_gate_locked -ne `$true")) `
        "startup readiness must verify schema, exact Probe read, and final gate lock"
    Assert-True ($StartText.Contains("runtime_identity.verified -ne `$true") -and
        $StartText.Contains('kdbg_service.service_type -ne 1') -and
        $StartText.Contains('probe_service.current_state -ne 4')) `
        "startup readiness must verify packaged running-driver identity"
    Assert-True ($StartText.Contains("-RequireTrustedDriverSignatures")) `
        "startup must reject driver SYS/CAT files that are not trusted on the guest"

    # A same-path repair of a running pair must not hash new files while old
    # images remain loaded. Exercise the exact lifecycle plan as a small SCM
    # state model: both old images must unload before the first rebind and both
    # starts must load the post-rebind generation.
    $RunningPairPlan = @(
        [pscustomobject]@{
            Driver = [pscustomobject]@{ Service = "KDBG" }
            Existing = $true
            WasRunning = $true
        },
        [pscustomobject]@{
            Driver = [pscustomobject]@{ Service = "KDBGProbe" }
            Existing = $true
            WasRunning = $true
        })
    $PairActions = @(New-PairLifecyclePlan $RunningPairPlan $true)
    $PairSequence = @($PairActions | ForEach-Object {
        "$($_.Action):$($_.Service)"
    })
    Assert-True (($PairSequence -join ",") -eq (
        "StopOrConfirmAbsent:KDBGProbe,StopOrConfirmAbsent:KDBG," +
        "Configure:KDBG,Configure:KDBGProbe,ReloadPair:KDBG+KDBGProbe")) `
        "running same-path repair must stop the whole pair before rebind/reload"

    $LoadedGeneration = @{ KDBG = "old"; KDBGProbe = "old" }
    $DiskGeneration = @{ KDBG = "old"; KDBGProbe = "old" }
    foreach ($Action in $PairActions) {
        switch ($Action.Action) {
            "StopOrConfirmAbsent" {
                $LoadedGeneration[$Action.Service] = $null
            }
            "Configure" {
                Assert-True (
                    $null -eq $LoadedGeneration.KDBG -and
                    $null -eq $LoadedGeneration.KDBGProbe) `
                    "no service may be rebound while either old image is loaded"
                $DiskGeneration[$Action.Service] = "new"
            }
            "ReloadPair" {
                Assert-True (
                    $null -eq $LoadedGeneration.KDBG -and
                    $null -eq $LoadedGeneration.KDBGProbe) `
                    "pair reload must begin from a fully stopped pair"
                $LoadedGeneration.KDBG = $DiskGeneration.KDBG
                $LoadedGeneration.KDBGProbe = $DiskGeneration.KDBGProbe
            }
            default { throw "unexpected mock lifecycle action" }
        }
    }
    Assert-True (
        $LoadedGeneration.KDBG -eq "new" -and
        $LoadedGeneration.KDBGProbe -eq "new") `
        "successful repair must run both newly rebound on-disk images"

    $StoppedPairActions = @(New-PairLifecyclePlan $RunningPairPlan $false)
    Assert-True (-not ($StoppedPairActions.Action -contains "ReloadPair")) `
        "a stopped install without -Start must remain stopped after rebind"

    $MixedPairPlan = @(
        [pscustomobject]@{
            Driver = [pscustomobject]@{ Service = "KDBG" }
            Existing = $true
            WasRunning = $true
        },
        [pscustomobject]@{
            Driver = [pscustomobject]@{ Service = "KDBGProbe" }
            Existing = $false
            WasRunning = $false
        })
    $MixedPairActions = @(New-PairLifecyclePlan $MixedPairPlan $true)
    Assert-True ((@($MixedPairActions | ForEach-Object {
                "$($_.Action):$($_.Service)"
            }) -join ",") -eq (
            "StopOrConfirmAbsent:KDBGProbe,StopOrConfirmAbsent:KDBG," +
            "Configure:KDBG,Configure:KDBGProbe,ReloadPair:KDBG+KDBGProbe")) `
        "partial prior installation must still stop, repair, and reload the pair atomically"

    Assert-True ((Get-ScStartMode 0) -eq "boot") `
        "rollback must preserve an original boot start mode"
    Assert-True ((Get-ScStartMode 1) -eq "system") `
        "rollback must preserve an original system start mode"
    Assert-True ((Get-ScStartMode 2) -eq "auto") `
        "rollback must preserve an original automatic start mode"
    Assert-True ((Get-ScStartMode 3) -eq "demand") `
        "rollback must preserve an original demand start mode"
    Assert-True ((Get-ScStartMode 4) -eq "disabled") `
        "rollback must preserve an original disabled start mode"
    Assert-Throws { Get-ScStartMode 5 } `
        "rollback must reject an unsupported original SCM start value"

    $InstallAst = Get-ScriptAst $InstallPath
    $InstallTransaction = $InstallAst.Find(
        {
            param($Node)
            $Node -is [Management.Automation.Language.TryStatementAst] -and
                $Node.Extent.Text.Contains("Installed service readiness check failed")
        },
        $true)
    Assert-True ($null -ne $InstallTransaction) "install SCM transaction must exist"
    Assert-True ($InstallTransaction.Extent.Text.Contains('Join-Path $PSScriptRoot "start.ps1"')) `
        "install -Start must be inside the SCM transaction"
    Assert-True ($InstallTransaction.Extent.Text.Contains(
            "Final reloaded-pair readiness check failed")) `
        "final reloaded-pair readiness must be inside the SCM transaction"
    $InstallText = Get-Content -LiteralPath $InstallPath -Raw
    Assert-True ($InstallText.Contains("-RequireTrustedDriverSignatures")) `
        "install and repair must reject driver SYS/CAT files that are not trusted on the guest"
    $DiagnoseText = Get-Content -LiteralPath $DiagnosePath -Raw
    Assert-True ($DiagnoseText.Contains("[switch]`$RequireTrustedDriverSignatures") -and
        $DiagnoseText.Contains("Test-IsTrustedDriverSignature") -and
        $DiagnoseText.Contains('drivers/$($Driver.Catalog) does not have a trusted')) `
        "diagnostics must provide an opt-in exact Valid-status gate for both SYS and CAT"
    Assert-True ($DiagnoseText.Contains("[switch]`$RequireProductionDriverSignatures") -and
        $DiagnoseText.Contains("ExpectedDriverPublisherSubject") -and
        $DiagnoseText.Contains("Test-IsProductionDriverSignature")) `
        "diagnostics must distinguish test/private trust from exact-publisher production signing"
    Assert-True ($InstallTransaction.Extent.Text.Contains("Stop-ServiceAndWait") -and
        $InstallText.Contains("`$Lifecycle = New-PairLifecyclePlan")) `
        "install transaction must execute the stop-before-rebind pair plan"
    Assert-True ($InstallText.Contains("Restore-OriginalService") -and
        $InstallText.Contains("restart original") -and
        $InstallText.Contains('Where-Object { $_.WasRunning }')) `
        "install rollback must restore original SCM config and running state"
    $RollbackText = $InstallTransaction.CatchClauses[0].Body.Extent.Text
    $StopBoth = $RollbackText.IndexOf(
        'foreach ($Name in @("KDBGProbe", "KDBG"))',
        [StringComparison]::Ordinal)
    $RestoreBoth = $RollbackText.IndexOf(
        'foreach ($Item in $Plan)',
        [StringComparison]::Ordinal)
    $RestartOriginal = $RollbackText.IndexOf(
        'foreach ($Name in @("KDBG", "KDBGProbe"))',
        [StringComparison]::Ordinal)
    Assert-True (0 -le $StopBoth -and $StopBoth -lt $RestoreBoth -and
        $RestoreBoth -lt $RestartOriginal) `
        "failed update must stop the new pair before restoring and restarting the old pair"
    Assert-True ($RollbackText.Contains('if (-not $SafeToRestore[$Name]) { continue }') -and
        $RollbackText.Contains('-not $SafeToRestore[$Name]')) `
        "failed update must not restore or restart a service that could not be stopped safely"

    $PackagerText = Get-Content -LiteralPath $PackagerPath -Raw
    $DriverNugetText = Get-Content -LiteralPath $DriverNugetPath -Raw
    Assert-True ($DriverNugetText.Contains(
            'Join-Path $BuildRepoRoot "out\release-epochs\$EpochName\driver-build"') -and
        $DriverNugetText.Contains(
            '"out\release-epochs\$EpochName\driver-build"')) `
        "concurrent release epochs must use matching virtual and physical driver-build roots"
    $ConcurrentEpochA = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot "out\release-epochs\concurrency-a\driver-build"))
    $ConcurrentEpochB = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot "out\release-epochs\concurrency-b\driver-build"))
    Assert-True (-not $ConcurrentEpochA.Equals(
            $ConcurrentEpochB, [StringComparison]::OrdinalIgnoreCase) -and
        -not $ConcurrentEpochA.StartsWith(
            $ConcurrentEpochB + '\', [StringComparison]::OrdinalIgnoreCase) -and
        -not $ConcurrentEpochB.StartsWith(
            $ConcurrentEpochA + '\', [StringComparison]::OrdinalIgnoreCase)) `
        "two concurrent release epochs must not share or nest driver intermediates"
    Assert-True ($PackagerText.Contains(
            '$EpochLayout = Resolve-KdbgEpochLayout') -and
        $PackagerText.Contains(
            '$PackageRoot = [IO.Path]::GetFullPath($EpochLayout.PackageRoot)') -and
        $PackagerText.Contains(
            '$BuildDirectory = [IO.Path]::GetFullPath($EpochLayout.BuildDirectory)')) `
        "packaging must bind every mutable build/package path to the selected layout"
    Assert-True ($PackagerText.Contains(
            '.\out\release-epochs\$EpochName') -and
        $PackagerText.Contains(
            '.\src\tools\build_public_release.ps1 -EpochName $EpochName -Clean -Package') -and
        $PackagerText.Contains('$Metadata.release_epoch = $EpochName') -and
        $PackagerText.Contains('$SymbolsMetadata.release_epoch = $EpochName')) `
        "epoch package metadata must retain isolated reproducible commands and epoch identity"
    Assert-True ($PackagerText.Contains(
            'Schema = "kdbg.product-source.v1"') -and
        $PackagerText.Contains('"docs/exec-plans/**"') -and
        $PackagerText.Contains('"docs/VALIDATION_REPORT.md"') -and
        $PackagerText.Contains('"docs/TRACEABILITY_MATRIX.md"') -and
        $PackagerText.Contains(
            'source_snapshot_manifest = "SOURCE-SNAPSHOT-SHA256SUMS.txt"')) `
        "package metadata must disclose stable product-source scope and ledger exclusions"
    Assert-True (([regex]::Matches(
            $PackagerText, 'SOURCE-SNAPSHOT-SHA256SUMS\.txt')).Count -ge 4 -and
        $PackagerText.Contains('$SourceSnapshot.Manifest')) `
        "main and symbols packages must retain the canonical source record manifest"
    $BeforeConfigureCapture = $PublicReleaseText.IndexOf(
        "'before-configure'", [StringComparison]::Ordinal)
    $ConfigureStart = $PublicReleaseText.IndexOf(
        '$ConfigureArguments = @(', [StringComparison]::Ordinal)
    $BeforePublicationCapture = $PublicReleaseText.IndexOf(
        "'before-package-publication'", [StringComparison]::Ordinal)
    $PackageInvocation = $PublicReleaseText.IndexOf(
        '& "$Drive\src\tools\package_windows.ps1"',
        [StringComparison]::Ordinal)
    $AfterPackageCapture = $PublicReleaseText.IndexOf(
        "'after-packaging'", [StringComparison]::Ordinal)
    Assert-True (0 -le $BeforeConfigureCapture -and
        $BeforeConfigureCapture -lt $ConfigureStart -and
        $ConfigureStart -lt $BeforePublicationCapture -and
        $BeforePublicationCapture -lt $PackageInvocation -and
        $PackageInvocation -lt $AfterPackageCapture) `
        "public release must preserve before-configure, pre-publication, and post-package source captures in order"
    Assert-True ($PublicReleaseText.Contains(
            '-ExpectedSourceSnapshotSha256 $BeforeConfigureSnapshot.Digest') -and
        ([regex]::Matches(
            $PublicReleaseText, 'Assert-KdbgSourceSnapshotTree')).Count -ge 3 -and
        ([regex]::Matches(
            $PublicReleaseText, 'Assert-KdbgSourceSnapshotEqual')).Count -ge 3) `
        "public release must pass the frozen digest and verify source equality around publication"
    $ExpectedDigestChecks = [regex]::Matches(
        $PackagerText, 'Assert-SourceSnapshotDigest').Count
    Assert-True ($PackagerText.Contains(
            '[string]$ExpectedSourceSnapshotSha256') -and
        $ExpectedDigestChecks -ge 4 -and
        $PackagerText.IndexOf(
            '$PrePublishSourceSnapshot = Get-SourceSnapshot',
            [StringComparison]::Ordinal) -lt
            $PackagerText.IndexOf(
                'Publish-PackageArtifacts $Artifacts $BackupRoot',
                [StringComparison]::Ordinal)) `
        "packager must enforce the expected digest during staging and immediately before publication"
    Assert-True ($PackagerText.Contains('@($Inputs) + @($PdbInputs')) `
        "all shipped PDB inputs must be release prerequisites"
    Assert-True (-not $PackagerText.Contains("No Release PDBs were found")) `
        "release packaging must not silently omit the symbols package"
    $RequiredPdbNames = @(
        "KDBG.pdb", "kdbg_memprocfs_bridge.pdb", "kdbg_live_verify.pdb",
        "KDbgDriver.pdb", "KDbgProbe.pdb")
    Assert-True (-not ($RequiredPdbNames | Where-Object {
        -not $PackagerText.Contains($_)
    })) "symbols package must require GUI, bridge, live verifier, and both driver PDBs"
    $PairedValidation = $PackagerText.IndexOf(
        '$ValidationArguments = @(', [StringComparison]::Ordinal)
    $SymbolsHash = $PackagerText.IndexOf(
        "Write-HashManifest `$StagingSymbolsDirectory", [StringComparison]::Ordinal)
    Assert-True ($SymbolsHash -ge 0 -and $SymbolsHash -lt $PairedValidation -and
        $PackagerText.Contains('"--windows-package", $StagingOutputDirectory') -and
        $PackagerText.Contains('"--symbols-package", $StagingSymbolsDirectory') -and
        $PackagerText.Contains('$ValidationArguments += "--forbid-symbol-path"') -and
        $PackagerText.Contains('& python @ValidationArguments')) `
        "main and symbols staging directories must be validated as one release pair"

    $UninstallText = Get-Content -LiteralPath $UninstallPath -Raw
    Assert-True ($UninstallText.Contains("[switch]`$PurgePackage") -and
        $UninstallText.Contains("[switch]`$PurgeUserData")) `
        "clean uninstall must require explicit package and user-data purge switches"
    foreach ($Path in @($InstallPath, $StartPath, $RunPath, $UninstallPath)) {
        $Text = Get-Content -LiteralPath $Path -Raw
        Assert-True ($Text.Contains(
                '[ValidateSet("DistributionSource", "InstalledProduct")]') -and
            $Text.Contains("PackageRootMode")) `
            "package lifecycle entry point must expose the explicit narrow root mode: $Path"
    }
    Assert-True ($InstallText.Contains(
            '-PackageRootMode $PackageRootMode') -and
        (Get-Content -LiteralPath $StartPath -Raw).Contains(
            '-PackageRootMode $PackageRootMode') -and
        (Get-Content -LiteralPath $RunPath -Raw).Contains(
            '-PackageRootMode $PackageRootMode')) `
        "root mode must propagate through install/start/run diagnostics"
    Assert-True ($DiagnoseText.Contains(
            '[ValidateSet("DistributionSource", "SetupStaging", "InstalledProduct")]') -and
        $DiagnoseText.Contains("^\.staging-[0-9a-f]{32}`$") -and
        $DiagnoseText.Contains('Join-Path $ProgramFiles "KDBG"')) `
        "diagnostics must separate exact distribution, setup staging, and installed Product roots"

    Write-Host "Package lifecycle tests PASS: $Checks checks"
} finally {
    $FullTestRoot = [IO.Path]::GetFullPath($TestRoot)
    $TempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if ($FullTestRoot.StartsWith($TempPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($FullTestRoot).StartsWith(
            "kdbg-package-lifecycle-", [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $FullTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

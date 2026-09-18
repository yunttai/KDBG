[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..'))
$toolRoot = Join-Path $repoRoot 'src\tools\win11_validation'
$entrypoint = Join-Path $toolRoot 'New-Win11ValidationWorkspace.ps1'
$outputParent = Join-Path $repoRoot 'out\win11-validation'
$checks = 0

function Assert-True([bool]$Condition, [string]$Message) {
    $script:checks++
    if (-not $Condition) { throw "CHECK FAILED: $Message" }
}

function Assert-Equal([object]$Expected, [object]$Actual, [string]$Message) {
    $script:checks++
    if ([string]$Expected -cne [string]$Actual) {
        throw "CHECK FAILED: $Message (expected '$Expected', actual '$Actual')"
    }
}

function Assert-Throws([scriptblock]$Operation, [string]$Pattern, [string]$Message) {
    $script:checks++
    try { & $Operation | Out-Null }
    catch {
        if ($_.Exception.Message -like $Pattern) { return }
        throw "CHECK FAILED: $Message (unexpected error: $($_.Exception.Message))"
    }
    throw "CHECK FAILED: $Message (operation succeeded)"
}

function Remove-ExactTestPath([string]$Path, [string]$AllowedRoot) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $allowed = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\')
    if (-not $full.StartsWith(($allowed + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing test cleanup outside exact root: $full"
    }
    Remove-Item -LiteralPath $full -Recurse -Force
}

$tokens = $null
$parseErrors = $null
[Management.Automation.Language.Parser]::ParseFile(
    $entrypoint, [ref]$tokens, [ref]$parseErrors) | Out-Null
Assert-Equal 0 @($parseErrors).Count 'workspace entrypoint parser errors'
$entryText = Get-Content -LiteralPath $entrypoint -Raw
foreach ($parameter in @(
        'CertificatePath', 'ExpectedCertificateSha256', 'ExpectedSignerThumbprint')) {
    Assert-True $entryText.Contains("`$$parameter") "entrypoint lacks mandatory $parameter"
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'kdbg-win11-workspace-certificate-' + [Guid]::NewGuid().ToString('N'))
$fixturePackageRoot = Join-Path $fixtureRoot 'KDBG-1.1.0-win-x64'
$fixtureZip = Join-Path $fixtureRoot 'KDBG-1.1.0-win-x64.zip'
$fixtureCertificate = Join-Path $fixtureRoot 'fixture.cer'
$fixturePrivateContainer = Join-Path $fixtureRoot 'fixture-private.cer'
$sourceSha = ('1' * 64)
$epoch = 'test-cert-binding-' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
$wrongHashEpoch = 'test-cert-hash-' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
$wrongSignerEpoch = 'test-cert-signer-' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
$privateEpoch = 'test-cert-private-' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
$workspace = Join-Path $outputParent $epoch

try {
    foreach ($directory in @(
            $fixturePackageRoot,
            (Join-Path $fixturePackageRoot 'drivers'),
            (Join-Path $fixturePackageRoot 'tools'))) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    $metadata = [ordered]@{
        schema = 'kdbg.build-metadata.v1'
        package_name = 'KDBG-1.1.0-win-x64'
        source_snapshot_sha256 = $sourceSha
        source_file_count = 7
        minimum_windows_build = 19041
    }
    [IO.File]::WriteAllText(
        (Join-Path $fixturePackageRoot 'BUILD-METADATA.json'),
        (($metadata | ConvertTo-Json) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    foreach ($relative in @(
            'drivers\KDbgDriver.sys', 'drivers\KDbgDriver.cat',
            'drivers\KDbgProbe.sys', 'drivers\KDbgProbe.cat',
            'tools\install.ps1', 'tools\uninstall.ps1',
            'tools\kdbg_live_verify.exe')) {
        [IO.File]::WriteAllText(
            (Join-Path $fixturePackageRoot $relative),
            "fixture:$relative",
            [Text.UTF8Encoding]::new($false))
    }
    [IO.File]::WriteAllText(
        (Join-Path $fixturePackageRoot 'SHA256SUMS.txt'),
        "fixture manifest`n",
        [Text.UTF8Encoding]::new($false))
    Compress-Archive -LiteralPath $fixturePackageRoot -DestinationPath $fixtureZip
    $packageSha = (Get-FileHash -LiteralPath $fixtureZip -Algorithm SHA256).Hash.ToLowerInvariant()

    $rsa = [Security.Cryptography.RSA]::Create(2048)
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=KDBG Workspace Contract Test', $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $ekuOids = [Security.Cryptography.OidCollection]::new()
        [void]$ekuOids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        $request.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
                $ekuOids, $false))
        $certificateWithKey = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(1))
        try {
            [IO.File]::WriteAllBytes(
                $fixtureCertificate,
                $certificateWithKey.Export(
                    [Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            [IO.File]::WriteAllBytes(
                $fixturePrivateContainer,
                $certificateWithKey.Export(
                    [Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
                    'contract-only'))
            $signerThumbprint = $certificateWithKey.Thumbprint.ToLowerInvariant()
        }
        finally { $certificateWithKey.Dispose() }
    }
    finally { $rsa.Dispose() }
    $certificateSha = (Get-FileHash -LiteralPath $fixtureCertificate -Algorithm SHA256).Hash.ToLowerInvariant()
    $privateSha = (Get-FileHash -LiteralPath $fixturePrivateContainer -Algorithm SHA256).Hash.ToLowerInvariant()

    $created = & $entrypoint `
        -PackageZipPath $fixtureZip `
        -ExpectedPackageSha256 $packageSha `
        -ExpectedSourceSnapshotSha256 $sourceSha `
        -CertificatePath $fixtureCertificate `
        -ExpectedCertificateSha256 $certificateSha `
        -ExpectedSignerThumbprint $signerThumbprint `
        -VMName 'Windows-VM' `
        -EpochName $epoch
    Assert-True $created.success 'valid certificate-bound workspace creation failed'
    Assert-Equal $certificateSha $created.certificate_sha256 'creation result certificate hash mismatch'
    Assert-Equal $signerThumbprint $created.signer_thumbprint 'creation result signer mismatch'

    $bindingPath = Join-Path $workspace 'binding.json'
    $bindingText = Get-Content -LiteralPath $bindingPath -Raw
    $binding = $bindingText | ConvertFrom-Json
    Assert-Equal 'certificate/KDBG-TestSigning.cer' `
        $binding.test_signing_certificate.relative_path 'certificate relative path is not canonical'
    Assert-Equal $certificateSha $binding.test_signing_certificate.sha256 `
        'binding certificate hash mismatch'
    Assert-Equal $signerThumbprint $binding.test_signing_certificate.signer_thumbprint `
        'binding signer thumbprint mismatch'
    Assert-Equal $false $binding.test_signing_certificate.production_trust `
        'test certificate must be explicitly VM-only'
    Assert-True ($bindingText -notmatch '(?i)[A-Z]:\\|/Users/|\\Users\\') `
        'binding leaked an absolute path'
    $workspaceCertificate = Join-Path $workspace 'certificate\KDBG-TestSigning.cer'
    Assert-Equal $certificateSha `
        (Get-FileHash -LiteralPath $workspaceCertificate -Algorithm SHA256).Hash.ToLowerInvariant() `
        'workspace certificate copy hash mismatch'

    $static = & (Join-Path $workspace 'Test-Win11ValidationWorkspace.ps1')
    Assert-True $static.success 'certificate-bound workspace static validation failed'
    Assert-True $static.invariants.certificate_hash_matches 'static certificate hash invariant failed'
    Assert-True $static.invariants.certificate_thumbprint_matches 'static signer invariant failed'
    Assert-True $static.invariants.certificate_is_public_vm_only 'static VM-only certificate invariant failed'

    Assert-Throws {
        & $entrypoint -PackageZipPath $fixtureZip -ExpectedPackageSha256 $packageSha `
            -ExpectedSourceSnapshotSha256 $sourceSha -CertificatePath $fixtureCertificate `
            -ExpectedCertificateSha256 ('0' * 64) -ExpectedSignerThumbprint $signerThumbprint `
            -VMName 'Windows-VM' -EpochName $wrongHashEpoch
    } '*certificate SHA-256 mismatch*' 'wrong certificate hash was accepted'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $outputParent $wrongHashEpoch))) `
        'wrong-certificate-hash workspace artifact was left behind'

    Assert-Throws {
        & $entrypoint -PackageZipPath $fixtureZip -ExpectedPackageSha256 $packageSha `
            -ExpectedSourceSnapshotSha256 $sourceSha -CertificatePath $fixtureCertificate `
            -ExpectedCertificateSha256 $certificateSha -ExpectedSignerThumbprint ('0' * 40) `
            -VMName 'Windows-VM' -EpochName $wrongSignerEpoch
    } '*signer thumbprint mismatch*' 'wrong certificate signer was accepted'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $outputParent $wrongSignerEpoch))) `
        'wrong-certificate-signer workspace artifact was left behind'

    Assert-Throws {
        & $entrypoint -PackageZipPath $fixtureZip -ExpectedPackageSha256 $packageSha `
            -ExpectedSourceSnapshotSha256 $sourceSha -CertificatePath $fixturePrivateContainer `
            -ExpectedCertificateSha256 $privateSha -ExpectedSignerThumbprint $signerThumbprint `
            -VMName 'Windows-VM' -EpochName $privateEpoch
    } '*exactly one public X.509 certificate*' 'private-key container was accepted as a public certificate'

    [IO.File]::WriteAllBytes($workspaceCertificate, [byte[]](0, 1, 2, 3))
    Assert-Throws {
        & (Join-Path $workspace 'Test-Win11ValidationWorkspace.ps1')
    } '*certificate SHA-256 mismatch*' 'workspace certificate tamper was accepted'
}
finally {
    Remove-ExactTestPath $workspace $outputParent
    foreach ($name in @($wrongHashEpoch, $wrongSignerEpoch, $privateEpoch)) {
        Remove-ExactTestPath (Join-Path $outputParent $name) $outputParent
    }
    Remove-ExactTestPath $fixtureRoot ([IO.Path]::GetTempPath())
}

Write-Host "Win11 workspace certificate contract PASS ($checks checks; no VM commands executed)"

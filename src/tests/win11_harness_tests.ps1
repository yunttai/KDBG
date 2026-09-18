[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$toolRoot = Join-Path $repoRoot 'src\tools\win11_validation'
$entrypoint = Join-Path $toolRoot 'New-Win11ValidationWorkspace.ps1'
$modulePath = Join-Path $toolRoot 'Win11ValidationHarness.psm1'
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

function Get-ScriptAst([string]$Path) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count "PowerShell parser errors in $Path"
    return $ast
}

function Remove-ExactTestPath([string]$Path, [string]$AllowedRoot) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $allowed = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\')
    if (-not $full.StartsWith(($allowed + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing test cleanup outside exact root: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        [IO.Directory]::Delete($full, $false)
    } else {
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

foreach ($path in @(
        $entrypoint,
        $modulePath,
        (Join-Path $toolRoot 'workspace\Check-Win11Readiness.ps1'),
        (Join-Path $toolRoot 'workspace\Invoke-Win11GuestValidation.ps1'),
        (Join-Path $toolRoot 'workspace\Invoke-Win11Validation.ps1'),
        (Join-Path $toolRoot 'workspace\Test-Win11ValidationWorkspace.ps1'))) {
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "missing harness source: $path"
    Get-ScriptAst $path | Out-Null
}

$moduleAst = Get-ScriptAst $modulePath
$moduleText = Get-Content -LiteralPath $modulePath -Raw
$entryText = Get-Content -LiteralPath $entrypoint -Raw
$readinessFunction = $moduleAst.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-KdbgWin11Readiness'
}, $true)
Assert-True ($null -ne $readinessFunction) 'readiness function is missing'
$readinessCommands = @($readinessFunction.FindAll({
        param($node) $node -is [Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
foreach ($mutator in @('Start-VM', 'Stop-VM', 'Restore-VMSnapshot', 'New-PSSession', 'Invoke-Command', 'Copy-Item')) {
    Assert-True ($mutator -notin $readinessCommands) "readiness contains VM mutator: $mutator"
}
foreach ($parameter in @(
        'PackageZipPath', 'ExpectedPackageSha256', 'ExpectedSourceSnapshotSha256',
        'CertificatePath', 'ExpectedCertificateSha256', 'ExpectedSignerThumbprint',
        'VMName', 'EpochName')) {
    Assert-True ($entryText.Contains("`$$parameter")) "entrypoint lacks explicit $parameter parameter"
}
Assert-True ($moduleText.Contains("initial_state -ne 'Off'")) 'host runner does not require initial Off'
Assert-True ($moduleText.Contains('$_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId')) `
    'host runner does not bind exact checkpoint Name/GUID'
Assert-True ($moduleText.Contains('-not $ConfirmDisposableVm.IsPresent -or -not $ConfirmCheckpointRestore.IsPresent')) `
    'host runner lacks both explicit confirmations'
Assert-True ($moduleText.Contains('Restore-VMSnapshot -VMSnapshot $checkpointNow[0]')) `
    'host runner lacks exact finally restore'
Assert-True ($moduleText.Contains('$finalVmOff = $finalVm.State.ToString() -eq ''Off''')) `
    'host runner lacks final Off proof'
Assert-True ($moduleText.Contains('$probePfn = [uint64]$readOnlyReport.probe_before.pfn')) `
    'guest runner does not discover Probe PFN from read-only report'
Assert-True ($moduleText.Contains("'--confirm-probe-pfn', ([string]`$probePfn)")) `
    'guest runner does not type-confirm discovered Probe PFN'
Assert-True ($moduleText.Contains('$writeReport.write_cleanup.rollback_requested_bytes -ne 4096')) `
    'guest runner lacks full-page rollback proof'
Assert-True ($moduleText.Contains('$writeReport.write_cleanup.final_gate_locked -ne $true')) `
    'guest runner lacks final gate lock proof'
Assert-True ($moduleText.Contains("'-ConfirmKdbgServices', '-PurgeUserData'")) `
    'guest runner lacks service/user-data cleanup'
Assert-True ($moduleText.Contains("Get-KdbgDeviceQuery") -and
    $moduleText.Contains("device_queries = `$deviceQueries")) `
    'guest runner lacks DOS-device cleanup proof'
Assert-True ($moduleText.Contains("foreach (`$storeName in @('Root', 'TrustedPublisher'))") -and
    $moduleText.Contains('certificateAddedStores.Add($storeName)') -and
    $moduleText.Contains("certificate-remove-`$storeName")) `
    'guest runner does not import and remove only run-added test trust'
Assert-True ($moduleText.Contains('$guestCertificatePath') -and
    $moduleText.Contains('-CertificatePath $Certificate')) `
    'host runner does not stage the exact bound certificate into the guest harness'
Assert-True ($moduleText.Contains('[string]$_.signer_thumbprint -cne $certificateThumbprint')) `
    'guest signature validation does not bind the expected signer thumbprint'
Assert-True ($moduleText.Contains('$signature.SignerCertificate.Thumbprint.ToLowerInvariant()')) `
    'guest signature evidence does not normalize the signer thumbprint'
Assert-True ($moduleText.Contains('function Test-KdbgMachineCertificatePresent') -and
    $moduleText.Contains('[Security.Cryptography.X509Certificates.X509Store]::new(')) `
    'guest certificate verification does not reopen the machine store after mutation'
Assert-True ($moduleText.Contains('elapsed_ms = $stopwatch.ElapsedMilliseconds') -and
    $moduleText.Contains("phase = 'guest-required-core'") -and
    $moduleText.Contains("phase = 'session-cleanup-checkpoint-restore-final-off'")) `
    'required execution phases lack elapsed_ms accounting'
Assert-True ($moduleText.Contains('credential_serialized = $false')) `
    'credential serialization boundary is missing'
Assert-True ($moduleText.Contains('-ExecutionPolicy Bypass -File $Harness')) `
    'guest harness subprocess does not bypass a guest Restricted execution policy'
Assert-True ($moduleText.Contains('public static class NativeMethods') -and
    $moduleText.Contains('public static extern uint QueryDosDevice')) `
    'guest cleanup QueryDosDevice interop is not publicly callable from PowerShell'
Assert-True ($moduleText.Contains("'S-1-5-32-578'") -and
    $moduleText.Contains('Test-KdbgCanManageHyperV')) `
    'host runner does not accept a scoped Hyper-V Administrators token'
Assert-True ($moduleText -notmatch (('(?i)ConvertFrom-' + 'SecureString') + '|' +
        ('ConvertTo-' + 'SecureString\s+-AsPlainText'))) `
    'credential secret conversion is present'
Assert-Equal 0 @([regex]::Matches(
        ($moduleText + $entryText), '(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')).Count `
    'source harness must not pin a release-specific SHA-256'

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'kdbg-win11-harness-' + [Guid]::NewGuid().ToString('N'))
$fixturePackageRoot = Join-Path $fixtureRoot 'KDBG-1.1.0-win-x64'
$fixtureZip = Join-Path $fixtureRoot 'KDBG-1.1.0-win-x64.zip'
$fixtureCertificate = Join-Path $fixtureRoot 'fixture.cer'
$sourceSha = ('1' * 64)
$epoch = 'test-harness-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$wrongHashEpoch = 'test-wrong-hash-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$wrongSourceEpoch = 'test-wrong-source-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$reparseEpoch = 'test-reparse-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$workspace = Join-Path $outputParent $epoch
$reparseWorkspace = Join-Path $outputParent $reparseEpoch
$externalReparseTarget = Join-Path $fixtureRoot 'external-output'

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
            'CN=KDBG Harness Contract Test', $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificateWithKey = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(1))
        try {
            [IO.File]::WriteAllBytes(
                $fixtureCertificate,
                $certificateWithKey.Export(
                    [Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            $signerThumbprint = $certificateWithKey.Thumbprint.ToLowerInvariant()
        }
        finally { $certificateWithKey.Dispose() }
    }
    finally { $rsa.Dispose() }
    $certificateSha = (Get-FileHash -LiteralPath $fixtureCertificate -Algorithm SHA256).Hash.ToLowerInvariant()

    $created = & $entrypoint `
        -PackageZipPath $fixtureZip `
        -ExpectedPackageSha256 $packageSha `
        -ExpectedSourceSnapshotSha256 $sourceSha `
        -CertificatePath $fixtureCertificate `
        -ExpectedCertificateSha256 $certificateSha `
        -ExpectedSignerThumbprint $signerThumbprint `
        -VMName 'Windows-VM' `
        -EpochName $epoch
    Assert-True $created.success 'valid workspace creation failed'
    Assert-Equal $epoch $created.epoch 'created epoch mismatch'
    Assert-Equal $false $created.live_execution_performed 'workspace creation claimed live execution'
    Assert-True (Test-Path -LiteralPath $workspace -PathType Container) 'workspace directory missing'

    $bindingText = Get-Content -LiteralPath (Join-Path $workspace 'binding.json') -Raw
    $binding = $bindingText | ConvertFrom-Json
    Assert-Equal 'kdbg.win11-validation-binding.v1' $binding.schema 'binding schema mismatch'
    Assert-Equal $packageSha $binding.package.sha256 'binding package hash mismatch'
    Assert-Equal $sourceSha $binding.package.source_snapshot_sha256 'binding source hash mismatch'
    Assert-Equal 'package/KDBG-1.1.0-win-x64.zip' $binding.package.relative_path `
        'binding package path must be workspace-relative'
    Assert-Equal 'certificate/KDBG-TestSigning.cer' `
        $binding.test_signing_certificate.relative_path `
        'binding certificate path must be workspace-relative and canonical'
    Assert-Equal $certificateSha $binding.test_signing_certificate.sha256 `
        'binding certificate hash mismatch'
    Assert-Equal $signerThumbprint $binding.test_signing_certificate.signer_thumbprint `
        'binding signer thumbprint mismatch'
    Assert-Equal $false $binding.test_signing_certificate.production_trust `
        'binding certificate must be explicitly VM-only'
    Assert-Equal 7 @($binding.required_gate_scope).Count 'required core gate count mismatch'
    Assert-Equal 'NOT RUN' $binding.optional_extended_gate.status `
        'optional Extended gate must default to NOT RUN'
    Assert-Equal $false $binding.optional_extended_gate.blocks_required_core `
        'optional Extended gate must not block required core'
    Assert-True (-not $bindingText.Contains($fixtureRoot)) 'binding leaked fixture absolute path'
    Assert-True ($bindingText -notmatch '(?i)[A-Z]:\\|/Users/|\\Users\\') `
        'binding contains a private absolute path'

    $static = & (Join-Path $workspace 'Test-Win11ValidationWorkspace.ps1')
    Assert-True $static.success 'generated workspace static validation failed'
    Assert-Equal $false $static.live_execution_performed 'static validation claimed live execution'
    Assert-Equal 0 @($static.failed).Count 'generated workspace has failed invariants'

    Assert-Throws {
        & $entrypoint -PackageZipPath $fixtureZip -ExpectedPackageSha256 ('0' * 64) `
            -ExpectedSourceSnapshotSha256 $sourceSha -CertificatePath $fixtureCertificate `
            -ExpectedCertificateSha256 $certificateSha -ExpectedSignerThumbprint $signerThumbprint `
            -VMName 'Windows-VM' `
            -EpochName $wrongHashEpoch
    } '*package SHA-256 mismatch*' 'wrong package hash was accepted'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $outputParent $wrongHashEpoch))) `
        'wrong-hash workspace artifact was left behind'

    Assert-Throws {
        & $entrypoint -PackageZipPath $fixtureZip -ExpectedPackageSha256 $packageSha `
            -ExpectedSourceSnapshotSha256 ('2' * 64) -CertificatePath $fixtureCertificate `
            -ExpectedCertificateSha256 $certificateSha -ExpectedSignerThumbprint $signerThumbprint `
            -VMName 'Windows-VM' `
            -EpochName $wrongSourceEpoch
    } '*metadata does not match*' 'wrong source snapshot hash was accepted'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $outputParent $wrongSourceEpoch))) `
        'wrong-source workspace artifact was left behind'

    Assert-Throws {
        & $entrypoint -PackageZipPath $fixtureZip -ExpectedPackageSha256 $packageSha `
            -ExpectedSourceSnapshotSha256 $sourceSha -CertificatePath $fixtureCertificate `
            -ExpectedCertificateSha256 $certificateSha -ExpectedSignerThumbprint $signerThumbprint `
            -VMName 'Windows-VM' `
            -EpochName '..\escape'
    } '*safe slug*' 'unsafe epoch was accepted'

    Assert-Throws {
        & $entrypoint -PackageZipPath $fixtureZip -ExpectedPackageSha256 $packageSha `
            -ExpectedSourceSnapshotSha256 $sourceSha -CertificatePath $fixtureCertificate `
            -ExpectedCertificateSha256 $certificateSha -ExpectedSignerThumbprint $signerThumbprint `
            -VMName 'Windows-VM' `
            -EpochName $epoch
    } '*overwrite*' 'existing workspace overwrite was accepted'

    [IO.Directory]::CreateDirectory($externalReparseTarget) | Out-Null
    New-Item -ItemType Junction -Path $reparseWorkspace -Target $externalReparseTarget | Out-Null
    Assert-Throws {
        & $entrypoint -PackageZipPath $fixtureZip -ExpectedPackageSha256 $packageSha `
            -ExpectedSourceSnapshotSha256 $sourceSha -CertificatePath $fixtureCertificate `
            -ExpectedCertificateSha256 $certificateSha -ExpectedSignerThumbprint $signerThumbprint `
            -VMName 'Windows-VM' `
            -EpochName $reparseEpoch
    } '*Reparse points are not allowed*' 'reparse workspace was accepted'
}
finally {
    Remove-ExactTestPath $workspace $outputParent
    Remove-ExactTestPath $reparseWorkspace $outputParent
    Remove-ExactTestPath $fixtureRoot ([IO.Path]::GetTempPath())
}

Write-Host "Win11 harness tests PASS ($checks checks; no VM commands executed)"

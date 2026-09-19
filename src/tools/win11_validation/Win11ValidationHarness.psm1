Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ModuleSourcePath = $PSCommandPath
$script:ModuleRoot = Split-Path -Parent $PSCommandPath
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:BindingSchema = 'kdbg.win11-validation-binding.v1'
$script:PackageLeaf = 'KDBG-1.1.0-win-x64.zip'
$script:PackageRootLeaf = 'KDBG-1.1.0-win-x64'
$script:CertificateLeaf = 'KDBG-TestSigning.cer'

function Get-KdbgSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-KdbgSha256 {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Name)
    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Name must be exactly 64 lowercase hexadecimal characters."
    }
}

function Assert-KdbgSignerThumbprint {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Name)
    if ($Value -cnotmatch '^[0-9a-f]{40}$') {
        throw "$Name must be exactly 40 lowercase hexadecimal characters."
    }
}

function Test-KdbgMachineCertificatePresent {
    param(
        [Parameter(Mandatory)][ValidateSet('Root', 'TrustedPublisher')][string]$StoreName,
        [Parameter(Mandatory)][string]$Thumbprint
    )
    Assert-KdbgSignerThumbprint $Thumbprint 'certificate store thumbprint'
    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        $StoreName,
        [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        return @($store.Certificates | Where-Object {
                $_.Thumbprint.ToLowerInvariant() -ceq $Thumbprint
            }).Count -ne 0
    }
    finally { $store.Close() }
}

function Assert-KdbgSafeEpoch {
    param([Parameter(Mandatory)][string]$EpochName)
    if ($EpochName -cnotmatch '^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$' -or
        $EpochName -in @('con', 'prn', 'aux', 'nul', 'clock$', 'com1', 'lpt1')) {
        throw 'EpochName must be a 1-64 character lowercase safe slug.'
    }
}

function Assert-KdbgSafeVmName {
    param([Parameter(Mandatory)][string]$VMName)
    if ($VMName.Length -lt 1 -or $VMName.Length -gt 128 -or
        $VMName -match '[\x00-\x1f\\/:]' -or $VMName.Trim() -cne $VMName) {
        throw 'VMName contains an unsafe character or length.'
    }
}

function Test-KdbgPathUnder {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $fullPath.StartsWith(($fullRoot + '\'), [StringComparison]::OrdinalIgnoreCase)
}

function Assert-KdbgNoReparsePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter()][switch]$LeafMayBeMissing
    )
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $LeafMayBeMissing.IsPresent -and -not (Test-Path -LiteralPath $full)) {
        throw "Required path is missing: $full"
    }
    $cursor = $full
    while (-not [string]::IsNullOrEmpty($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse points are not allowed in validation paths: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Write-KdbgJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    [IO.File]::WriteAllText(
        $Path,
        (($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine),
        $script:Utf8NoBom)
}

function Get-KdbgPackageIdentity {
    param(
        [Parameter(Mandatory)][string]$PackageZipPath,
        [Parameter(Mandatory)][string]$ExpectedPackageSha256,
        [Parameter(Mandatory)][string]$ExpectedSourceSnapshotSha256
    )
    Assert-KdbgSha256 $ExpectedPackageSha256 'ExpectedPackageSha256'
    Assert-KdbgSha256 $ExpectedSourceSnapshotSha256 'ExpectedSourceSnapshotSha256'
    $resolved = [IO.Path]::GetFullPath($PackageZipPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw 'Exact package ZIP is missing.'
    }
    Assert-KdbgNoReparsePath $resolved
    if ([IO.Path]::GetFileName($resolved) -cne $script:PackageLeaf) {
        throw "PackageZipPath leaf must be $($script:PackageLeaf)."
    }
    $observed = Get-KdbgSha256 $resolved
    if ($observed -cne $ExpectedPackageSha256) {
        throw "Exact package SHA-256 mismatch: $observed"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($resolved)
    try {
        $fileEntries = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })
        $names = @($fileEntries | ForEach-Object FullName)
        if ($names.Count -eq 0 -or @($names | Where-Object {
                $_ -match '\\' -or $_ -match '^/' -or $_ -match '^[A-Za-z]:' -or
                $_ -match '(^|/)\.\.(/|$)'
            }).Count -ne 0 -or
            @($names | ForEach-Object { $_.ToLowerInvariant() } | Group-Object |
                Where-Object Count -gt 1).Count -ne 0) {
            throw 'Package ZIP contains an empty, unsafe, or duplicate entry set.'
        }
        $metadataName = "$($script:PackageRootLeaf)/BUILD-METADATA.json"
        $metadataEntries = @($fileEntries | Where-Object FullName -ceq $metadataName)
        if ($metadataEntries.Count -ne 1) {
            throw 'Package ZIP must contain exactly one expected BUILD-METADATA.json.'
        }
        $reader = [IO.StreamReader]::new($metadataEntries[0].Open(), [Text.Encoding]::UTF8, $true)
        try { $metadata = $reader.ReadToEnd() | ConvertFrom-Json }
        finally { $reader.Dispose() }
        if ($metadata.package_name -cne $script:PackageRootLeaf -or
            $metadata.source_snapshot_sha256 -cne $ExpectedSourceSnapshotSha256 -or
            [int]$metadata.minimum_windows_build -ne 19041) {
            throw 'Package metadata does not match the expected product/source identity.'
        }
        foreach ($required in @(
                'SHA256SUMS.txt',
                'drivers/KDbgDriver.sys', 'drivers/KDbgDriver.cat',
                'drivers/KDbgProbe.sys', 'drivers/KDbgProbe.cat',
                'tools/install.ps1', 'tools/uninstall.ps1',
                'tools/kdbg_live_verify.exe')) {
            $entryName = "$($script:PackageRootLeaf)/$required"
            if (@($fileEntries | Where-Object FullName -ceq $entryName).Count -ne 1) {
                throw "Package ZIP is missing required entry: $required"
            }
        }
        return [pscustomobject]@{
            Path = $resolved
            PackageSha256 = $observed
            SourceSnapshotSha256 = $metadata.source_snapshot_sha256
            SourceFileCount = [int]$metadata.source_file_count
            EntryCount = $fileEntries.Count
        }
    }
    finally { $archive.Dispose() }
}

function Get-KdbgTestSigningCertificateIdentity {
    param(
        [Parameter(Mandatory)][string]$CertificatePath,
        [Parameter(Mandatory)][string]$ExpectedCertificateSha256,
        [Parameter(Mandatory)][string]$ExpectedSignerThumbprint
    )
    Assert-KdbgSha256 $ExpectedCertificateSha256 'ExpectedCertificateSha256'
    Assert-KdbgSignerThumbprint $ExpectedSignerThumbprint 'ExpectedSignerThumbprint'
    $resolved = [IO.Path]::GetFullPath($CertificatePath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw 'Exact public test-signing certificate is missing.'
    }
    Assert-KdbgNoReparsePath $resolved
    if ([IO.Path]::GetExtension($resolved) -cne '.cer') {
        throw 'CertificatePath must identify a public .cer certificate.'
    }
    $observed = Get-KdbgSha256 $resolved
    if ($observed -cne $ExpectedCertificateSha256) {
        throw "Exact certificate SHA-256 mismatch: $observed"
    }
    $contentType = [Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($resolved)
    if ($contentType -ne [Security.Cryptography.X509Certificates.X509ContentType]::Cert) {
        throw 'CertificatePath must contain exactly one public X.509 certificate, not a private-key container.'
    }
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved)
    try {
        if ($certificate.HasPrivateKey) {
            throw 'CertificatePath must not contain a private key.'
        }
        $thumbprint = $certificate.Thumbprint.ToLowerInvariant()
        if ($thumbprint -cne $ExpectedSignerThumbprint) {
            throw "Exact certificate signer thumbprint mismatch: $thumbprint"
        }
        return [pscustomobject]@{
            Path = $resolved
            Sha256 = $observed
            SignerThumbprint = $thumbprint
        }
    }
    finally { $certificate.Dispose() }
}

function Get-KdbgRepositoryRoot {
    $root = [IO.Path]::GetFullPath((Join-Path $script:ModuleRoot '..\..\..'))
    if (-not (Test-Path -LiteralPath (Join-Path $root 'src\tools') -PathType Container)) {
        throw 'Unable to resolve the KDBG repository root from the harness source.'
    }
    return $root
}

function New-KdbgWin11ValidationWorkspace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PackageZipPath,
        [Parameter(Mandatory)][string]$ExpectedPackageSha256,
        [Parameter(Mandatory)][string]$ExpectedSourceSnapshotSha256,
        [Parameter(Mandatory)][string]$CertificatePath,
        [Parameter(Mandatory)][string]$ExpectedCertificateSha256,
        [Parameter(Mandatory)][string]$ExpectedSignerThumbprint,
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][string]$EpochName
    )
    Assert-KdbgSafeEpoch $EpochName
    Assert-KdbgSafeVmName $VMName
    $identity = Get-KdbgPackageIdentity $PackageZipPath $ExpectedPackageSha256 $ExpectedSourceSnapshotSha256
    $certificateIdentity = Get-KdbgTestSigningCertificateIdentity `
        $CertificatePath $ExpectedCertificateSha256 $ExpectedSignerThumbprint
    $repoRoot = Get-KdbgRepositoryRoot
    $outputParent = [IO.Path]::GetFullPath((Join-Path $repoRoot 'out\win11-validation'))
    $workspaceRoot = [IO.Path]::GetFullPath((Join-Path $outputParent $EpochName))
    if (-not (Test-KdbgPathUnder $workspaceRoot $outputParent)) {
        throw 'Resolved workspace escaped out/win11-validation.'
    }
    Assert-KdbgNoReparsePath $outputParent -LeafMayBeMissing
    Assert-KdbgNoReparsePath $workspaceRoot -LeafMayBeMissing
    if (Test-Path -LiteralPath $workspaceRoot) {
        throw 'Refusing to overwrite an existing Win11 validation workspace.'
    }

    $sourceFiles = @(
        [pscustomobject]@{ Source = $script:ModuleSourcePath; Destination = 'Win11ValidationHarness.psm1' },
        [pscustomobject]@{ Source = (Join-Path $script:ModuleRoot 'workspace\Check-Win11Readiness.ps1'); Destination = 'Check-Win11Readiness.ps1' },
        [pscustomobject]@{ Source = (Join-Path $script:ModuleRoot 'workspace\Invoke-Win11GuestValidation.ps1'); Destination = 'Invoke-Win11GuestValidation.ps1' },
        [pscustomobject]@{ Source = (Join-Path $script:ModuleRoot 'workspace\Invoke-Win11Validation.ps1'); Destination = 'Invoke-Win11Validation.ps1' },
        [pscustomobject]@{ Source = (Join-Path $script:ModuleRoot 'workspace\Test-Win11ValidationWorkspace.ps1'); Destination = 'Test-Win11ValidationWorkspace.ps1' }
    )
    foreach ($source in $sourceFiles) {
        if (-not (Test-Path -LiteralPath $source.Source -PathType Leaf)) {
            throw "Harness source is missing: $($source.Destination)"
        }
        Assert-KdbgNoReparsePath $source.Source
    }

    [IO.Directory]::CreateDirectory($outputParent) | Out-Null
    [IO.Directory]::CreateDirectory($workspaceRoot) | Out-Null
    try {
        Assert-KdbgNoReparsePath $workspaceRoot
        $packageDirectory = Join-Path $workspaceRoot 'package'
        [IO.Directory]::CreateDirectory($packageDirectory) | Out-Null
        $workspacePackage = Join-Path $packageDirectory $script:PackageLeaf
        Copy-Item -LiteralPath $identity.Path -Destination $workspacePackage
        if ((Get-KdbgSha256 $workspacePackage) -cne $ExpectedPackageSha256) {
            throw 'Workspace package copy failed exact hash verification.'
        }

        $certificateDirectory = Join-Path $workspaceRoot 'certificate'
        [IO.Directory]::CreateDirectory($certificateDirectory) | Out-Null
        $workspaceCertificate = Join-Path $certificateDirectory $script:CertificateLeaf
        Copy-Item -LiteralPath $certificateIdentity.Path -Destination $workspaceCertificate
        $copiedCertificate = Get-KdbgTestSigningCertificateIdentity `
            $workspaceCertificate $ExpectedCertificateSha256 $ExpectedSignerThumbprint

        $harnessHashes = [ordered]@{}
        foreach ($source in $sourceFiles) {
            $destination = Join-Path $workspaceRoot $source.Destination
            Copy-Item -LiteralPath $source.Source -Destination $destination
            $harnessHashes[$source.Destination] = Get-KdbgSha256 $destination
        }
        $binding = [ordered]@{
            schema = $script:BindingSchema
            epoch = $EpochName
            vm_name = $VMName
            package = [ordered]@{
                relative_path = "package/$($script:PackageLeaf)"
                sha256 = $ExpectedPackageSha256
                source_snapshot_sha256 = $ExpectedSourceSnapshotSha256
                source_file_count = $identity.SourceFileCount
                zip_entry_count = $identity.EntryCount
            }
            test_signing_certificate = [ordered]@{
                relative_path = "certificate/$($script:CertificateLeaf)"
                sha256 = $copiedCertificate.Sha256
                signer_thumbprint = $copiedCertificate.SignerThumbprint
                production_trust = $false
            }
            harness_files = $harnessHashes
            required_gate_scope = @(
                'exact-package-and-source-hash',
                'win11-x64-build-and-security-inventory',
                'package-trust-install-start-and-abi7',
                'readonly-probe-discovery',
                'single-probe-apply-readback-reload-rollback-relock',
                'service-and-device-cleanup',
                'exact-checkpoint-restore-and-final-off'
            )
            optional_extended_gate = [ordered]@{
                status = 'NOT RUN'
                blocks_required_core = $false
                scope = 'Interactive GUI/media, repeated reboot/lifecycle, full feature matrix, and long-run performance.'
            }
            output_policy = 'All generated reports and run evidence remain below this workspace.'
            claim_boundary = 'Hash-bound harness source only; Windows 11 is not passed until a live report proves every gate.'
        }
        Write-KdbgJson (Join-Path $workspaceRoot 'binding.json') $binding
        $validation = Test-KdbgWin11ValidationWorkspace -WorkspaceRoot $workspaceRoot
        if (-not $validation.success) {
            throw "Generated workspace failed its independent static validation: $(@($validation.failed) -join ', ')"
        }
        return [pscustomobject]@{
            schema = 'kdbg.win11-validation-workspace-create.v1'
            success = $true
            epoch = $EpochName
            workspace_relative_path = "out/win11-validation/$EpochName"
            package_sha256 = $ExpectedPackageSha256
            source_snapshot_sha256 = $ExpectedSourceSnapshotSha256
            certificate_sha256 = $ExpectedCertificateSha256
            signer_thumbprint = $ExpectedSignerThumbprint
            static_invariant_count = $validation.invariant_count
            live_execution_performed = $false
        }
    }
    catch {
        if (Test-Path -LiteralPath $workspaceRoot) {
            $resolvedWorkspace = [IO.Path]::GetFullPath($workspaceRoot)
            if (-not (Test-KdbgPathUnder $resolvedWorkspace $outputParent) -or
                [IO.Path]::GetFileName($resolvedWorkspace) -cne $EpochName) {
                throw 'Workspace cleanup target identity changed; refusing cleanup.'
            }
            Assert-KdbgNoReparsePath $resolvedWorkspace
            Remove-Item -LiteralPath $resolvedWorkspace -Recurse -Force
        }
        throw
    }
}

function Get-KdbgWin11Binding {
    param([Parameter(Mandatory)][string]$WorkspaceRoot)
    $root = [IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\')
    $outputParent = Split-Path -Parent $root
    $outRoot = Split-Path -Parent $outputParent
    if ([IO.Path]::GetFileName($outputParent) -cne 'win11-validation' -or
        [IO.Path]::GetFileName($outRoot) -cne 'out') {
        throw 'Workspace must remain at out/win11-validation/<safe epoch>.'
    }
    Assert-KdbgNoReparsePath $root
    $bindingPath = Join-Path $root 'binding.json'
    if (-not (Test-Path -LiteralPath $bindingPath -PathType Leaf)) {
        throw 'Workspace binding.json is missing.'
    }
    $binding = Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json
    if ($binding.schema -cne $script:BindingSchema) { throw 'Workspace binding schema mismatch.' }
    Assert-KdbgSafeEpoch $binding.epoch
    Assert-KdbgSafeVmName $binding.vm_name
    if ([IO.Path]::GetFileName($root) -cne $binding.epoch) { throw 'Workspace epoch/path identity mismatch.' }
    Assert-KdbgSha256 $binding.package.sha256 'binding package sha256'
    Assert-KdbgSha256 $binding.package.source_snapshot_sha256 'binding source sha256'
    Assert-KdbgSha256 $binding.test_signing_certificate.sha256 'binding certificate sha256'
    Assert-KdbgSignerThumbprint $binding.test_signing_certificate.signer_thumbprint `
        'binding certificate signer thumbprint'
    if ($binding.package.relative_path -cne "package/$($script:PackageLeaf)") {
        throw 'Workspace package relative path is not canonical.'
    }
    if ($binding.test_signing_certificate.relative_path -cne "certificate/$($script:CertificateLeaf)" -or
        $binding.test_signing_certificate.production_trust -ne $false) {
        throw 'Workspace test-signing certificate binding is not canonical and VM-only.'
    }
    $serialized = $binding | ConvertTo-Json -Depth 20 -Compress
    if ($serialized -match '(?i)[A-Z]:\\|/Users/|\\Users\\') {
        throw 'Workspace binding contains a private absolute path.'
    }
    return [pscustomobject]@{ Root = $root; Binding = $binding; Path = $bindingPath }
}

function Test-KdbgWin11ValidationWorkspace {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$WorkspaceRoot)
    $resolved = Get-KdbgWin11Binding $WorkspaceRoot
    $binding = $resolved.Binding
    $packagePath = Join-Path $resolved.Root ($binding.package.relative_path -replace '/', '\')
    $identity = Get-KdbgPackageIdentity $packagePath $binding.package.sha256 $binding.package.source_snapshot_sha256
    $certificatePath = Join-Path $resolved.Root `
        ($binding.test_signing_certificate.relative_path -replace '/', '\')
    $certificateIdentity = Get-KdbgTestSigningCertificateIdentity `
        $certificatePath $binding.test_signing_certificate.sha256 `
        $binding.test_signing_certificate.signer_thumbprint
    $failed = [Collections.Generic.List[string]]::new()
    $scriptRecords = [Collections.Generic.List[object]]::new()
    $expectedHarnessNames = @(
        'Win11ValidationHarness.psm1',
        'Check-Win11Readiness.ps1',
        'Invoke-Win11GuestValidation.ps1',
        'Invoke-Win11Validation.ps1',
        'Test-Win11ValidationWorkspace.ps1')
    $actualHarnessNames = @($binding.harness_files.PSObject.Properties.Name | Sort-Object)
    $exactHarnessSet = ($actualHarnessNames -join "`n") -ceq (($expectedHarnessNames | Sort-Object) -join "`n")
    foreach ($property in $binding.harness_files.PSObject.Properties) {
        $path = Join-Path $resolved.Root $property.Name
        $tokens = $null
        $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
        $hash = if (Test-Path -LiteralPath $path -PathType Leaf) { Get-KdbgSha256 $path } else { $null }
        if (@($parseErrors).Count -ne 0) { $failed.Add("parse:$($property.Name)") }
        if ($hash -cne $property.Value) { $failed.Add("hash:$($property.Name)") }
        $scriptRecords.Add([ordered]@{
            file = $property.Name
            sha256 = $hash
            expected_sha256 = $property.Value
            parse_error_count = @($parseErrors).Count
        })
    }
    $moduleText = Get-Content -LiteralPath (Join-Path $resolved.Root 'Win11ValidationHarness.psm1') -Raw
    $moduleTokens = $null
    $moduleErrors = $null
    $moduleAst = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $resolved.Root 'Win11ValidationHarness.psm1'),
        [ref]$moduleTokens, [ref]$moduleErrors)
    $readinessFunction = $moduleAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Test-KdbgWin11Readiness'
    }, $true)
    $readinessCommands = if ($readinessFunction) {
        @($readinessFunction.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
    } else { @() }
    $mutators = @('Start-VM', 'Stop-VM', 'Restore-VMSnapshot', 'New-PSSession', 'Invoke-Command', 'Copy-Item')
    $invariants = [ordered]@{
        package_hash_matches = $identity.PackageSha256 -ceq $binding.package.sha256
        source_hash_matches = $identity.SourceSnapshotSha256 -ceq $binding.package.source_snapshot_sha256
        certificate_hash_matches = $certificateIdentity.Sha256 -ceq $binding.test_signing_certificate.sha256
        certificate_thumbprint_matches = $certificateIdentity.SignerThumbprint -ceq `
            $binding.test_signing_certificate.signer_thumbprint
        certificate_is_public_vm_only = -not $binding.test_signing_certificate.production_trust
        exact_harness_file_set = $exactHarnessSet
        harness_files_parse_and_match = $failed.Count -eq 0
        readiness_function_exists = $null -ne $readinessFunction
        readiness_has_no_vm_mutator = @($readinessCommands | Where-Object { $_ -in $mutators }).Count -eq 0
        host_requires_initial_off = $moduleText.Contains("initial_state -ne 'Off'")
        host_requires_unique_checkpoint_name_and_id = $moduleText.Contains('$_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId')
        host_requires_two_confirmations = $moduleText.Contains('-not $ConfirmDisposableVm.IsPresent -or -not $ConfirmCheckpointRestore.IsPresent')
        host_restores_exact_checkpoint_in_finally = $moduleText.Contains('Restore-VMSnapshot -VMSnapshot $checkpointNow[0]')
        host_requires_final_off = $moduleText.Contains('$finalVmOff = $finalVm.State.ToString() -eq ''Off''')
        guest_derives_probe_pfn = $moduleText.Contains('$probePfn = [uint64]$readOnlyReport.probe_before.pfn')
        guest_types_discovered_probe_pfn = $moduleText.Contains("'--confirm-probe-pfn', ([string]`$probePfn)")
        guest_requires_full_rollback = $moduleText.Contains('$writeReport.write_cleanup.rollback_requested_bytes -ne 4096')
        guest_requires_final_lock = $moduleText.Contains('$writeReport.write_cleanup.final_gate_locked -ne $true')
        guest_requires_cleanup = $moduleText.Contains("'-ConfirmKdbgServices', '-PurgeUserData'")
        guest_requires_device_cleanup = $moduleText.Contains('Get-KdbgDeviceQuery') -and
            $moduleText.Contains('device_queries = $deviceQueries')
        required_phases_record_elapsed_ms = $moduleText.Contains('elapsed_ms = $stopwatch.ElapsedMilliseconds') -and
            $moduleText.Contains("phase = 'guest-required-core'") -and
            $moduleText.Contains("phase = 'session-cleanup-checkpoint-restore-final-off'")
        credential_not_serialized = $moduleText.Contains('credential_serialized = $false') -and
            $moduleText -notmatch (('(?i)ConvertFrom-' + 'SecureString') + '|' +
                ('ConvertTo-' + 'SecureString\s+-AsPlainText'))
        no_fixed_release_hash_in_harness = @([regex]::Matches($moduleText, '(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')).Count -eq 0
    }
    foreach ($entry in $invariants.GetEnumerator()) {
        if ($entry.Value -ne $true) { $failed.Add("invariant:$($entry.Key)") }
    }
    return [pscustomobject]@{
        schema = 'kdbg.win11-validation-workspace-static.v1'
        success = $failed.Count -eq 0
        epoch = $binding.epoch
        vm_name = $binding.vm_name
        package_sha256 = $binding.package.sha256
        source_snapshot_sha256 = $binding.package.source_snapshot_sha256
        certificate_sha256 = $binding.test_signing_certificate.sha256
        signer_thumbprint = $binding.test_signing_certificate.signer_thumbprint
        optional_extended_gate = $binding.optional_extended_gate
        invariant_count = $invariants.Count
        invariants = $invariants
        scripts = @($scriptRecords)
        failed = @($failed)
        live_execution_performed = $false
        claim_boundary = 'Static workspace, AST, package identity, and fail-closed contract validation only.'
    }
}

function Protect-KdbgHostText {
    param(
        [AllowNull()][string]$Text,
        [AllowNull()][string]$WorkspaceRoot,
        [AllowNull()][string]$CredentialUserName
    )
    if ($null -eq $Text) { return $null }
    $protected = $Text
    foreach ($value in @(
            [Environment]::MachineName,
            [Environment]::UserName,
            $WorkspaceRoot,
            $CredentialUserName)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $protected = $protected -replace [regex]::Escape($value), '<REDACTED-HOST-IDENTIFIER>'
        }
    }
    return $protected
}

function Write-KdbgWorkspaceReport {
    param(
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Value
    )
    $root = [IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\')
    $path = [IO.Path]::GetFullPath($OutputPath)
    if (-not (Test-KdbgPathUnder $path $root)) {
        throw 'Report output must remain below the hash-bound workspace.'
    }
    Assert-KdbgNoReparsePath (Split-Path -Parent $path) -LeafMayBeMissing
    $parent = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    Assert-KdbgNoReparsePath $parent
    Write-KdbgJson $path $Value
}

function Test-KdbgIsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-KdbgIsHyperVAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return @($identity.Groups | ForEach-Object Value) -contains 'S-1-5-32-578'
}

function Test-KdbgCanManageHyperV {
    return (Test-KdbgIsElevated) -or (Test-KdbgIsHyperVAdministrator)
}

function Test-KdbgWin11Readiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter()][switch]$GuestCredentialAvailable,
        [Parameter()][string]$OutputPath,
        [Parameter()][switch]$FailIfNotReady
    )
    $resolved = Get-KdbgWin11Binding $WorkspaceRoot
    $binding = $resolved.Binding
    $static = Test-KdbgWin11ValidationWorkspace $resolved.Root
    $blockers = [Collections.Generic.List[string]]::new()
    $isElevated = Test-KdbgIsElevated
    $isHyperVAdministrator = Test-KdbgIsHyperVAdministrator
    $hostAuthorized = $isElevated -or $isHyperVAdministrator
    if (-not $hostAuthorized) { $blockers.Add('Current host token is neither elevated nor a Hyper-V Administrators token.') }

    $capabilities = @('Get-VM', 'Get-VMSnapshot', 'New-PSSession', 'Invoke-Command') | ForEach-Object {
        $command = Get-Command -Name $_ -ErrorAction SilentlyContinue | Select-Object -First 1
        [ordered]@{ name = $_; available = $null -ne $command }
    }
    $commandsReady = @($capabilities | Where-Object available -eq $false).Count -eq 0
    if (-not $commandsReady) { $blockers.Add('Required Hyper-V or PowerShell Direct commands are unavailable.') }

    $vmms = Get-Service -Name 'vmms' -ErrorAction SilentlyContinue
    $vmmsState = if ($vmms) { $vmms.Status.ToString() } else { $null }
    if (-not $vmms -or $vmms.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        $blockers.Add('Hyper-V Virtual Machine Management is unavailable or stopped.')
    }

    $vmRecord = $null
    $checkpointRecords = @()
    $vmQueryError = $null
    $checkpointQueryError = $null
    if ($commandsReady) {
        try {
            $matches = @(Get-VM -Name $binding.vm_name -ErrorAction Stop)
            if ($matches.Count -ne 1) { throw 'The bound VM name did not resolve exactly once.' }
            $vm = $matches[0]
            $vmRecord = [ordered]@{
                name = $vm.Name
                id = $vm.Id.ToString()
                initial_state = $vm.State.ToString()
                generation = [int]$vm.Generation
                version = $vm.Version.ToString()
            }
            if ($vmRecord.initial_state -ne 'Off') { $blockers.Add('The bound VM must initially be Off.') }
            try {
                $checkpointRecords = @(Get-VMSnapshot -VM $vm -ErrorAction Stop |
                    Sort-Object CreationTime, Name | ForEach-Object {
                        [ordered]@{
                            name = $_.Name
                            id = $_.Id.ToString()
                            checkpoint_type = $_.CheckpointType.ToString()
                            creation_time_utc = $_.CreationTime.ToUniversalTime().ToString('o')
                        }
                    })
                if ($checkpointRecords.Count -eq 0) { $blockers.Add('No checkpoint is visible for the bound VM.') }
            }
            catch {
                $checkpointQueryError = Protect-KdbgHostText $_.Exception.Message $resolved.Root $null
                $blockers.Add('Checkpoint enumeration failed.')
            }
        }
        catch {
            $vmQueryError = Protect-KdbgHostText $_.Exception.Message $resolved.Root $null
            $blockers.Add('The bound VM could not be queried with the current token.')
        }
    }
    if (-not $GuestCredentialAvailable.IsPresent) {
        $blockers.Add('A guest Administrator credential has not been intentionally declared available.')
    }
    if (-not $static.success) { $blockers.Add('The hash-bound workspace failed static validation.') }
    $ready = $hostAuthorized -and $commandsReady -and $vmms -and
        $vmms.Status -eq [ServiceProcess.ServiceControllerStatus]::Running -and
        $null -ne $vmRecord -and $vmRecord.initial_state -eq 'Off' -and
        $checkpointRecords.Count -gt 0 -and $GuestCredentialAvailable.IsPresent -and $static.success
    $result = [ordered]@{
        schema = 'kdbg.win11-validation-readiness.v1'
        captured_utc = [DateTime]::UtcNow.ToString('o')
        mode = 'read-only-host-control-plane-preflight'
        mutation_performed = $false
        epoch = $binding.epoch
        vm_name = $binding.vm_name
        package_sha256 = $binding.package.sha256
        source_snapshot_sha256 = $binding.package.source_snapshot_sha256
        elevated = $isElevated
        hyper_v_administrator = $isHyperVAdministrator
        host_authorized = $hostAuthorized
        vmms_state = $vmmsState
        capabilities = $capabilities
        vm = $vmRecord
        vm_query_error = $vmQueryError
        checkpoints = $checkpointRecords
        checkpoint_query_error = $checkpointQueryError
        guest_credential_available = $GuestCredentialAvailable.IsPresent
        static_workspace_passed = $static.success
        optional_extended_gate = $binding.optional_extended_gate
        blockers = @($blockers)
        ready_for_controlled_win11_validation = [bool]$ready
        credential_serialized = $false
        claim_boundary = 'Read-only readiness only; this result never starts, stops, restores, connects to, or modifies a VM.'
    }
    if ($OutputPath) { Write-KdbgWorkspaceReport $resolved.Root $OutputPath $result }
    if ($FailIfNotReady.IsPresent -and -not $ready) { throw 'Win11 validation readiness did not pass.' }
    return [pscustomobject]$result
}

function Invoke-KdbgCapturedProcess {
    param(
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )
    $stdout = Join-Path $EvidenceRoot "$Name.stdout.log"
    $stderr = Join-Path $EvidenceRoot "$Name.stderr.log"
    $started = [DateTime]::UtcNow
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList `
        -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $stopwatch.Stop()
    return [pscustomobject]@{
        name = $Name
        started_utc = $started.ToString('o')
        completed_utc = [DateTime]::UtcNow.ToString('o')
        elapsed_ms = $stopwatch.ElapsedMilliseconds
        exit_code = $process.ExitCode
        stdout_file = [IO.Path]::GetFileName($stdout)
        stderr_file = [IO.Path]::GetFileName($stderr)
    }
}

function Get-KdbgServiceQuery {
    param([Parameter(Mandatory)][string]$ServiceName)
    $output = (& sc.exe query $ServiceName 2>&1 | Out-String)
    return [ordered]@{
        service = $ServiceName
        absent = $LASTEXITCODE -eq 1060 -or $output -match 'FAILED\s+1060'
        exit_code = $LASTEXITCODE
    }
}

function Get-KdbgDeviceQuery {
    param([Parameter(Mandatory)][string]$DeviceName)
    if (-not ('Kdbg.Win11.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace Kdbg.Win11 {
    public static class NativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint QueryDosDevice(
            string deviceName, StringBuilder targetPath, int maxLength);
    }
}
'@
    }
    $buffer = [Text.StringBuilder]::new(1024)
    $result = [Kdbg.Win11.NativeMethods]::QueryDosDevice($DeviceName, $buffer, $buffer.Capacity)
    $nativeError = if ($result -eq 0) { [Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }
    return [ordered]@{
        device = $DeviceName
        absent = $result -eq 0 -and $nativeError -in @(2, 3)
        native_error = $nativeError
    }
}

function Assert-KdbgReadOnlyReport {
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$Label)
    if ($Report.schema -ne 'kdbg.live-verify.v1' -or $Report.success -ne $true -or
        $Report.mode -ne 'read-only' -or $Report.runtime_identity.verified -ne $true -or
        $Report.backend.abi_version -ne 7 -or
        $Report.backend.supports_physical_page_compare_write -ne $true -or
        $Report.backend.is_mock -ne $false -or
        @($Report.operations | Where-Object passed -ne $true).Count -ne 0 -or
        @($Report.comparisons | Where-Object { $_.match -ne $true -or $_.byte_count -ne 4096 }).Count -ne 0 -or
        $Report.write_cleanup.final_gate_locked -ne $true -or
        $Report.session_final.write_enabled -ne $false) {
        throw "$Label did not prove a real ABI 7 exact read and locked final gate."
    }
}

function Invoke-KdbgWin11GuestValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunRoot,
        [Parameter(Mandatory)][string]$PackageZipPath,
        [Parameter(Mandatory)][string]$CertificatePath,
        [Parameter(Mandatory)][string]$BindingPath,
        [Parameter(Mandatory)][string]$CheckpointId
    )
    $allowedGuestRoot = [IO.Path]::GetFullPath('C:\KDBG-Win11-Live')
    $resolvedRunRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    $resolvedPackageZip = [IO.Path]::GetFullPath($PackageZipPath)
    $resolvedCertificatePath = [IO.Path]::GetFullPath($CertificatePath)
    $resolvedBindingPath = [IO.Path]::GetFullPath($BindingPath)
    if (-not (Test-KdbgPathUnder $resolvedRunRoot $allowedGuestRoot) -or
        -not (Test-KdbgPathUnder $resolvedPackageZip $resolvedRunRoot) -or
        -not (Test-KdbgPathUnder $resolvedCertificatePath $resolvedRunRoot) -or
        -not (Test-KdbgPathUnder $resolvedBindingPath $resolvedRunRoot)) {
        throw 'Guest run, package, certificate, and binding paths must stay below the controlled guest root.'
    }
    Assert-KdbgNoReparsePath $resolvedRunRoot
    Assert-KdbgNoReparsePath $resolvedPackageZip
    Assert-KdbgNoReparsePath $resolvedCertificatePath
    Assert-KdbgNoReparsePath $resolvedBindingPath
    if (-not (Test-KdbgIsElevated)) { throw 'Guest validation requires an Administrator token.' }
    if ([string]::IsNullOrWhiteSpace($CheckpointId)) { throw 'CheckpointId is required.' }

    $binding = Get-Content -LiteralPath $resolvedBindingPath -Raw | ConvertFrom-Json
    if ($binding.schema -cne $script:BindingSchema -or
        $binding.package.relative_path -cne "package/$($script:PackageLeaf)") {
        throw 'Guest received an invalid workspace binding.'
    }
    Assert-KdbgSafeEpoch $binding.epoch
    Assert-KdbgSafeVmName $binding.vm_name
    Assert-KdbgSha256 $binding.package.sha256 'binding package sha256'
    Assert-KdbgSha256 $binding.package.source_snapshot_sha256 'binding source sha256'
    $certificateIdentity = Get-KdbgTestSigningCertificateIdentity `
        $resolvedCertificatePath `
        ([string]$binding.test_signing_certificate.sha256) `
        ([string]$binding.test_signing_certificate.signer_thumbprint)
    $identity = Get-KdbgPackageIdentity $resolvedPackageZip `
        $binding.package.sha256 $binding.package.source_snapshot_sha256

    $evidenceRoot = Join-Path $resolvedRunRoot 'evidence'
    $expandedRoot = Join-Path $resolvedRunRoot 'expanded'
    [IO.Directory]::CreateDirectory($evidenceRoot) | Out-Null
    $phaseRecords = [Collections.Generic.List[object]]::new()
    $packageRoot = $null
    $packageRecord = $null
    $inventory = $null
    $transaction = $null
    $transactionPassed = $false
    $cleanupPassed = $false
    $cleanupRecord = $null
    $certificateRecord = $null
    $certificateAddedStores = [Collections.Generic.List[string]]::new()
    $primaryError = $null
    $powershellExe = (Get-Process -Id $PID).Path
    try {
        $inventoryStopwatch = [Diagnostics.Stopwatch]::StartNew()
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        $bcdText = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
        $secureBoot = $null
        try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $secureBoot = $null }
        $inventoryStopwatch.Stop()
        $inventory = [ordered]@{
            schema = 'kdbg.win11-guest-inventory.v1'
            captured_utc = [DateTime]::UtcNow.ToString('o')
            caption = $os.Caption
            version = $os.Version
            build_number = [int]$os.BuildNumber
            architecture = $architecture
            secure_boot_enabled = $secureBoot
            test_signing_visible = [bool]($bcdText -match '(?im)^testsigning\s+Yes\s*$')
            checkpoint_id = $CheckpointId
            elapsed_ms = $inventoryStopwatch.ElapsedMilliseconds
            credential_serialized = $false
        }
        Write-KdbgJson (Join-Path $evidenceRoot 'guest-inventory.json') $inventory
        [IO.File]::WriteAllText(
            (Join-Path $evidenceRoot 'bcd-current.txt'),
            ($bcdText -replace [regex]::Escape($resolvedRunRoot), '<GUEST_RUN_ROOT>'),
            $script:Utf8NoBom)
        if ([int]$os.BuildNumber -lt 22000 -or $architecture -ne 'X64') {
            throw 'The controlled guest is not Windows 11 x64.'
        }
        if (-not $inventory.test_signing_visible) {
            throw 'The controlled guest does not report test-signing enabled.'
        }

        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $certificateIdentity.Path)
        try {
            if ($certificate.Subject -cne $certificate.Issuer) {
                throw 'The disposable-VM test-signing certificate must be self-signed.'
            }
            $certificateThumbprint = $certificate.Thumbprint.ToLowerInvariant()
        }
        finally { $certificate.Dispose() }
        $certificateStores = [Collections.Generic.List[object]]::new()
        $certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
        foreach ($storeName in @('Root', 'TrustedPublisher')) {
            $presentBefore = Test-KdbgMachineCertificatePresent `
                $storeName $certificateThumbprint
            if (-not $presentBefore) {
                $import = Invoke-KdbgCapturedProcess $evidenceRoot "certificate-import-$storeName" `
                    $certutil @('-f', '-addstore', $storeName, $resolvedCertificatePath)
                $phaseRecords.Add($import)
                if ($import.exit_code -ne 0) {
                    throw "Test-signing certificate import failed for $storeName."
                }
                $certificateAddedStores.Add($storeName)
            }
            $presentAfter = Test-KdbgMachineCertificatePresent `
                $storeName $certificateThumbprint
            if (-not $presentAfter) {
                throw "Test-signing certificate is absent from $storeName after import."
            }
            $certificateStores.Add([ordered]@{
                    name = $storeName
                    present_before = $presentBefore
                    imported_by_run = -not $presentBefore
                    present_after = $presentAfter
                })
        }
        $certificateRecord = [ordered]@{
            sha256 = $certificateIdentity.Sha256
            thumbprint = $certificateThumbprint
            stores = @($certificateStores)
            added_stores = @($certificateAddedStores)
        }

        $packageStopwatch = [Diagnostics.Stopwatch]::StartNew()
        Expand-Archive -LiteralPath $resolvedPackageZip -DestinationPath $expandedRoot
        $packageRoot = Join-Path $expandedRoot $script:PackageRootLeaf
        if (-not (Test-Path -LiteralPath $packageRoot -PathType Container)) {
            throw 'Expanded package root is missing.'
        }
        Assert-KdbgNoReparsePath $packageRoot
        $manifestPath = Join-Path $packageRoot 'SHA256SUMS.txt'
        $manifestRecords = [Collections.Generic.List[object]]::new()
        foreach ($line in Get-Content -LiteralPath $manifestPath) {
            if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9_.\-/]+)$') {
                throw "Malformed package checksum line: $line"
            }
            $relative = $Matches[2]
            $candidate = [IO.Path]::GetFullPath((Join-Path $packageRoot ($relative -replace '/', '\')))
            if (-not (Test-KdbgPathUnder $candidate $packageRoot) -or
                -not (Test-Path -LiteralPath $candidate -PathType Leaf) -or
                (Get-KdbgSha256 $candidate) -cne $Matches[1]) {
                throw "Package checksum verification failed: $relative"
            }
            $manifestRecords.Add([ordered]@{ path = $relative; sha256 = $Matches[1] })
        }
        $signatures = @('KDbgDriver.sys', 'KDbgDriver.cat', 'KDbgProbe.sys', 'KDbgProbe.cat') | ForEach-Object {
            $path = Join-Path $packageRoot "drivers\$_"
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            [ordered]@{
                file = $_
                sha256 = Get-KdbgSha256 $path
                status = $signature.Status.ToString()
                signer_subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
                signer_thumbprint = if ($signature.SignerCertificate) {
                    $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
                } else { $null }
            }
        }
        if (@($signatures | Where-Object {
                    $_.status -ne 'Valid' -or
                    [string]$_.signer_thumbprint -cne $certificateThumbprint
                }).Count -ne 0) {
            throw 'The packaged SYS/CAT pairs are not trusted as Valid in this guest.'
        }
        $packageStopwatch.Stop()
        $packageRecord = [ordered]@{
            schema = 'kdbg.win11-package-preflight.v1'
            package_sha256 = $identity.PackageSha256
            source_snapshot_sha256 = $identity.SourceSnapshotSha256
            manifest_file_count = $manifestRecords.Count
            signatures = $signatures
            elapsed_ms = $packageStopwatch.ElapsedMilliseconds
            success = $true
        }
        Write-KdbgJson (Join-Path $evidenceRoot 'package-preflight.json') $packageRecord

        $install = Invoke-KdbgCapturedProcess $evidenceRoot 'install-start' $powershellExe @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $packageRoot 'tools\install.ps1'), '-Start', '-ConfirmDedicatedVm', '-ConfirmSnapshot')
        $phaseRecords.Add($install)
        if ($install.exit_code -ne 0) { throw 'Packaged install/start failed.' }

        $verifier = Join-Path $packageRoot 'tools\kdbg_live_verify.exe'
        $readOnlyPath = Join-Path $evidenceRoot 'readonly-before.json'
        $readOnly = Invoke-KdbgCapturedProcess $evidenceRoot 'readonly-before' $verifier @(
            '--output', $readOnlyPath, '--build-id', "$($binding.epoch)-win11-before", '--read-samples', '8')
        $phaseRecords.Add($readOnly)
        if ($readOnly.exit_code -ne 0) { throw 'Initial read-only verifier failed.' }
        $readOnlyReport = Get-Content -LiteralPath $readOnlyPath -Raw | ConvertFrom-Json
        Assert-KdbgReadOnlyReport $readOnlyReport 'Initial read-only verifier'
        if ([int]$readOnlyReport.system.os_build -ne [int]$os.BuildNumber) {
            throw 'Verifier OS build does not match guest inventory.'
        }
        $probePfn = [uint64]$readOnlyReport.probe_before.pfn

        $writePath = Join-Path $evidenceRoot 'probe-write-readback-rollback.json'
        $write = Invoke-KdbgCapturedProcess $evidenceRoot 'probe-write-readback-rollback' $verifier @(
            '--output', $writePath, '--build-id', "$($binding.epoch)-win11-write", '--read-samples', '16',
            '--write', '--confirm-disposable-vm', '--snapshot-id', $CheckpointId,
            '--confirm-probe-pfn', ([string]$probePfn))
        $phaseRecords.Add($write)
        if ($write.exit_code -ne 0) { throw 'Controlled Probe transaction failed.' }
        $writeReport = Get-Content -LiteralPath $writePath -Raw | ConvertFrom-Json
        $successfulWriteDelta = [uint64]$writeReport.session_final.successful_writes -
            [uint64]$writeReport.session_before.successful_writes
        if ($writeReport.schema -ne 'kdbg.live-verify.v1' -or
            $writeReport.mode -ne 'probe-write-rollback' -or $writeReport.success -ne $true -or
            $writeReport.operator_confirmed_disposable_vm -ne $true -or
            $writeReport.snapshot_id -ne $CheckpointId -or
            $writeReport.runtime_identity.verified -ne $true -or
            $writeReport.backend.abi_version -ne 7 -or
            $writeReport.backend.supports_physical_page_compare_write -ne $true -or
            $writeReport.backend.is_mock -ne $false -or
            [uint64]$writeReport.probe_before.pfn -ne $probePfn -or
            [uint64]$writeReport.probe_after_write.pfn -ne $probePfn -or
            [uint64]$writeReport.probe_after_rollback.pfn -ne $probePfn -or
            $writeReport.write_cleanup.edit_offset -ne 256 -or
            $writeReport.write_cleanup.edit_length -ne 8 -or
            $writeReport.write_cleanup.apply_requested_bytes -ne 8 -or
            $writeReport.write_cleanup.rollback_requested_bytes -ne 4096 -or
            $writeReport.write_cleanup.rollback_verified -ne $true -or
            $writeReport.write_cleanup.final_gate_locked -ne $true -or
            $writeReport.session_final.write_enabled -ne $false -or
            $successfulWriteDelta -ne 2 -or
            @($writeReport.operations | Where-Object passed -ne $true).Count -ne 0 -or
            @($writeReport.comparisons | Where-Object { $_.match -ne $true -or $_.mismatch_count -ne 0 }).Count -ne 0) {
            throw 'Controlled Probe report did not prove apply, read-back, reload, rollback, and relock.'
        }

        $afterPath = Join-Path $evidenceRoot 'readonly-after.json'
        $after = Invoke-KdbgCapturedProcess $evidenceRoot 'readonly-after' $verifier @(
            '--output', $afterPath, '--build-id', "$($binding.epoch)-win11-after", '--read-samples', '8')
        $phaseRecords.Add($after)
        if ($after.exit_code -ne 0) { throw 'Post-transaction read-only verifier failed.' }
        $afterReport = Get-Content -LiteralPath $afterPath -Raw | ConvertFrom-Json
        Assert-KdbgReadOnlyReport $afterReport 'Post-transaction read-only verifier'
        if ([uint64]$afterReport.probe_before.pfn -ne $probePfn -or
            [uint64]$afterReport.probe_before.crc32 -ne [uint64]$writeReport.probe_before.crc32 -or
            [uint64]$afterReport.session_final.successful_writes -ne [uint64]$writeReport.session_final.successful_writes) {
            throw 'Post-transaction verifier did not preserve the Probe baseline and zero-additional-write invariant.'
        }
        $transaction = [ordered]@{
            probe_pfn = $probePfn
            baseline_crc32 = [uint64]$writeReport.probe_before.crc32
            changed_crc32 = [uint64]$writeReport.probe_after_write.crc32
            rollback_crc32 = [uint64]$writeReport.probe_after_rollback.crc32
            edit_offset = 256
            edit_length = 8
            apply_requested_bytes = 8
            rollback_requested_bytes = 4096
            successful_write_delta = $successfulWriteDelta
            post_verifier_additional_writes = 0
            rollback_verified = $true
            final_gate_locked = $true
        }
        $transactionPassed = $true
    }
    catch {
        $primaryError = $_.Exception.Message -replace [regex]::Escape($resolvedRunRoot), '<GUEST_RUN_ROOT>'
    }
    finally {
        $cleanupErrors = [Collections.Generic.List[string]]::new()
        $uninstall = $null
        if ($packageRoot -and (Test-Path -LiteralPath (Join-Path $packageRoot 'tools\uninstall.ps1') -PathType Leaf)) {
            try {
                $uninstall = Invoke-KdbgCapturedProcess $evidenceRoot 'uninstall-purge-user-data' $powershellExe @(
                    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
                    (Join-Path $packageRoot 'tools\uninstall.ps1'), '-ConfirmKdbgServices', '-PurgeUserData')
                $phaseRecords.Add($uninstall)
                if ($uninstall.exit_code -ne 0) { $cleanupErrors.Add('Uninstall returned a nonzero exit code.') }
            }
            catch { $cleanupErrors.Add($_.Exception.Message) }
        }
        $cleanupStopwatch = [Diagnostics.Stopwatch]::StartNew()
        $serviceQueries = @('KDBGProbe', 'KDBG') | ForEach-Object { Get-KdbgServiceQuery $_ }
        if (@($serviceQueries | Where-Object absent -ne $true).Count -ne 0) {
            $cleanupErrors.Add('One or more KDBG services remain registered after cleanup.')
        }
        $deviceQueries = @('KDBGProbe', 'KDBG') | ForEach-Object { Get-KdbgDeviceQuery $_ }
        if (@($deviceQueries | Where-Object absent -ne $true).Count -ne 0) {
            $cleanupErrors.Add('One or more KDBG DOS device links remain after cleanup.')
        }
        $certificateRemovals = [Collections.Generic.List[object]]::new()
        foreach ($storeName in @($certificateAddedStores)) {
            try {
                $remove = Invoke-KdbgCapturedProcess $evidenceRoot "certificate-remove-$storeName" `
                    $certutil @('-delstore', $storeName, $certificateThumbprint)
                $phaseRecords.Add($remove)
                $presentAfterRemoval = Test-KdbgMachineCertificatePresent `
                    $storeName $certificateThumbprint
                $certificateRemovals.Add([ordered]@{
                        name = $storeName
                        exit_code = $remove.exit_code
                        present_after_removal = $presentAfterRemoval
                    })
                if ($remove.exit_code -ne 0 -or $presentAfterRemoval) {
                    $cleanupErrors.Add("Run-added test certificate remains in $storeName.")
                }
            }
            catch { $cleanupErrors.Add("Test certificate cleanup failed for ${storeName}: $($_.Exception.Message)") }
        }
        $cleanupStopwatch.Stop()
        $cleanupPassed = $cleanupErrors.Count -eq 0
        $cleanupRecord = [ordered]@{
            schema = 'kdbg.win11-guest-cleanup.v1'
            uninstall = $uninstall
            service_queries = $serviceQueries
            device_queries = $deviceQueries
            certificate_import = $certificateRecord
            certificate_removals = @($certificateRemovals)
            elapsed_ms = $cleanupStopwatch.ElapsedMilliseconds
            errors = @($cleanupErrors)
            success = $cleanupPassed
        }
        Write-KdbgJson (Join-Path $evidenceRoot 'guest-cleanup.json') $cleanupRecord
    }
    $success = $transactionPassed -and $cleanupPassed
    $summary = [ordered]@{
        schema = 'kdbg.win11-guest-validation.v1'
        completed_utc = [DateTime]::UtcNow.ToString('o')
        success = $success
        epoch = $binding.epoch
        checkpoint_id = $CheckpointId
        package_sha256 = $binding.package.sha256
        source_snapshot_sha256 = $binding.package.source_snapshot_sha256
        guest = $inventory
        package = $packageRecord
        transaction = $transaction
        cleanup = $cleanupRecord
        phases = @($phaseRecords)
        primary_error = $primaryError
        credential_serialized = $false
        claim_boundary = if ($success) {
            'Guest transaction passed; host result remains incomplete until exact checkpoint restore and final Off are proven.'
        } else { 'Windows 11 guest validation failed or remained incomplete.' }
    }
    Write-KdbgJson (Join-Path $evidenceRoot 'guest-validation-summary.json') $summary
    if (-not $success) { throw 'Windows 11 guest validation failed.' }
    return [pscustomobject]$summary
}

function Assert-KdbgSafeArchive {
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $names = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) } | ForEach-Object FullName)
        if ($names.Count -eq 0 -or
            @($names | Where-Object {
                $_ -match '\\' -or $_ -match '^/' -or $_ -match '^[A-Za-z]:' -or $_ -match '(^|/)\.\.(/|$)'
            }).Count -ne 0 -or
            @($names | ForEach-Object { $_.ToLowerInvariant() } | Group-Object | Where-Object Count -gt 1).Count -ne 0) {
            throw 'Guest evidence archive has unsafe, duplicate, or empty entries.'
        }
        return $names.Count
    }
    finally { $archive.Dispose() }
}

function Invoke-KdbgWin11Validation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter(Mandatory)][string]$CheckpointName,
        [Parameter(Mandatory)][Guid]$CheckpointId,
        [Parameter(Mandatory)][PSCredential]$GuestCredential,
        [Parameter(Mandatory)][switch]$ConfirmDisposableVm,
        [Parameter(Mandatory)][switch]$ConfirmCheckpointRestore,
        [Parameter()][ValidateRange(30, 600)][int]$ConnectionTimeoutSeconds = 240
    )
    $hostOverallStopwatch = [Diagnostics.Stopwatch]::StartNew()
    if (-not $ConfirmDisposableVm.IsPresent -or -not $ConfirmCheckpointRestore.IsPresent) {
        throw 'Both explicit VM and checkpoint-restore confirmations are required.'
    }
    if ($CheckpointId -eq [Guid]::Empty -or [string]::IsNullOrWhiteSpace($CheckpointName)) {
        throw 'An exact non-empty checkpoint Name/GUID pair is required.'
    }
    if ($null -eq $GuestCredential) { throw 'GuestCredential is required and is never serialized.' }
    if (-not (Test-KdbgCanManageHyperV)) { throw 'Run the Win11 host runner with an elevated or Hyper-V Administrators token.' }
    $resolved = Get-KdbgWin11Binding $WorkspaceRoot
    $binding = $resolved.Binding
    $static = Test-KdbgWin11ValidationWorkspace $resolved.Root
    if (-not $static.success) { throw 'Hash-bound workspace static validation failed.' }
    $workspacePackage = Join-Path $resolved.Root ($binding.package.relative_path -replace '/', '\')
    Get-KdbgPackageIdentity $workspacePackage $binding.package.sha256 $binding.package.source_snapshot_sha256 | Out-Null
    foreach ($commandName in @(
            'Get-VM', 'Get-VMSnapshot', 'Restore-VMSnapshot', 'Start-VM', 'Stop-VM',
            'New-PSSession', 'Invoke-Command', 'Copy-Item', 'Remove-PSSession')) {
        if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
            throw "Required Hyper-V/PowerShell Direct command is unavailable: $commandName"
        }
    }
    $vmMatches = @(Get-VM -Name $binding.vm_name -ErrorAction Stop)
    if ($vmMatches.Count -ne 1) { throw 'The hash-bound VM name did not resolve exactly once.' }
    $vm = $vmMatches[0]
    $initial_state = $vm.State.ToString()
    if ($initial_state -ne 'Off') { throw 'The hash-bound VM must initially be Off.' }
    $checkpointMatches = @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
        $_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId
    })
    if ($checkpointMatches.Count -ne 1) {
        throw 'The exact checkpoint Name/GUID pair was not found exactly once.'
    }
    $checkpoint = $checkpointMatches[0]

    $runsRoot = Join-Path $resolved.Root 'runs'
    [IO.Directory]::CreateDirectory($runsRoot) | Out-Null
    Assert-KdbgNoReparsePath $runsRoot
    $runId = 'run-{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    $hostRunRoot = [IO.Path]::GetFullPath((Join-Path $runsRoot $runId))
    if (-not (Test-KdbgPathUnder $hostRunRoot $runsRoot) -or
        (Test-Path -LiteralPath $hostRunRoot)) {
        throw 'Refusing an unsafe or existing host run directory.'
    }
    [IO.Directory]::CreateDirectory($hostRunRoot) | Out-Null
    $checkpointIdText = $CheckpointId.ToString('D')
    $guestRunRoot = "C:\KDBG-Win11-Live\$runId"
    $guestPackageZip = "$guestRunRoot\$($script:PackageLeaf)"
    $guestCertificatePath = "$guestRunRoot\$($script:CertificateLeaf)"
    $guestBindingPath = "$guestRunRoot\binding.json"
    $guestModulePath = "$guestRunRoot\Win11ValidationHarness.psm1"
    $guestHarnessPath = "$guestRunRoot\Invoke-Win11GuestValidation.ps1"
    $guestEvidenceZip = "$guestRunRoot\guest-evidence.zip"
    $hostEvidenceZip = Join-Path $hostRunRoot 'guest-evidence.zip'
    $hostEvidenceRoot = Join-Path $hostRunRoot 'guest-evidence'
    $summaryPath = Join-Path $hostRunRoot 'host-validation-summary.json'
    $preflight = [ordered]@{
        schema = 'kdbg.win11-host-preflight.v1'
        captured_utc = [DateTime]::UtcNow.ToString('o')
        epoch = $binding.epoch
        vm = [ordered]@{
            name = $vm.Name
            id = $vm.Id.ToString()
            initial_state = $initial_state
            generation = [int]$vm.Generation
            version = $vm.Version.ToString()
        }
        checkpoint = [ordered]@{
            name = $checkpoint.Name
            id = $checkpoint.Id.ToString()
            creation_time_utc = $checkpoint.CreationTime.ToUniversalTime().ToString('o')
        }
        package = [ordered]@{
            relative_path = $binding.package.relative_path
            sha256 = $binding.package.sha256
            source_snapshot_sha256 = $binding.package.source_snapshot_sha256
        }
        confirmations = [ordered]@{
            disposable_vm = $ConfirmDisposableVm.IsPresent
            checkpoint_restore = $ConfirmCheckpointRestore.IsPresent
        }
        credential_supplied = $true
        credential_serialized = $false
        mutation_scope = 'Exact bound guest and discovered KDbgProbe PFN only; no host physical-memory operation.'
    }
    Write-KdbgJson (Join-Path $hostRunRoot 'host-preflight.json') $preflight

    $session = $null
    $mutationBegan = $false
    $guestValidationPassed = $false
    $guestEvidenceCopied = $false
    $guestEvidenceEntryCount = 0
    $guestError = $null
    $restoreErrors = [Collections.Generic.List[string]]::new()
    $hostPhases = [Collections.Generic.List[object]]::new()
    $restored = $false
    $finalVmOff = $false
    try {
        $mutationBegan = $true
        $phaseStopwatch = [Diagnostics.Stopwatch]::StartNew()
        Restore-VMSnapshot -VMSnapshot $checkpoint -Confirm:$false -ErrorAction Stop
        $vm = Get-VM -Name $binding.vm_name -ErrorAction Stop
        if ($vm.State.ToString() -ne 'Off') { throw 'Exact checkpoint did not restore the VM to Off.' }
        Start-VM -VM $vm -ErrorAction Stop | Out-Null
        $phaseStopwatch.Stop()
        $hostPhases.Add([ordered]@{ phase = 'checkpoint-restore-and-start'; elapsed_ms = $phaseStopwatch.ElapsedMilliseconds })
        $phaseStopwatch = [Diagnostics.Stopwatch]::StartNew()
        $deadline = [DateTime]::UtcNow.AddSeconds($ConnectionTimeoutSeconds)
        do {
            try { $session = New-PSSession -VMName $binding.vm_name -Credential $GuestCredential -ErrorAction Stop }
            catch {
                $guestError = Protect-KdbgHostText $_.Exception.Message $resolved.Root $GuestCredential.UserName
                Start-Sleep -Seconds 5
            }
        } while ($null -eq $session -and [DateTime]::UtcNow -lt $deadline)
        $phaseStopwatch.Stop()
        $hostPhases.Add([ordered]@{ phase = 'powershell-direct-connect'; elapsed_ms = $phaseStopwatch.ElapsedMilliseconds })
        if ($null -eq $session) { throw 'PowerShell Direct did not become available before timeout.' }
        $guestError = $null
        $phaseStopwatch = [Diagnostics.Stopwatch]::StartNew()
        Invoke-Command -Session $session -ScriptBlock {
            param($Root)
            if (Test-Path -LiteralPath $Root) { throw 'Guest run root already exists.' }
            [IO.Directory]::CreateDirectory($Root) | Out-Null
        } -ArgumentList $guestRunRoot -ErrorAction Stop
        Copy-Item -LiteralPath $workspacePackage -Destination $guestPackageZip -ToSession $session -ErrorAction Stop
        $workspaceCertificate = Join-Path $resolved.Root `
            ($binding.test_signing_certificate.relative_path -replace '/', '\')
        Get-KdbgTestSigningCertificateIdentity `
            $workspaceCertificate `
            ([string]$binding.test_signing_certificate.sha256) `
            ([string]$binding.test_signing_certificate.signer_thumbprint) | Out-Null
        Copy-Item -LiteralPath $workspaceCertificate -Destination $guestCertificatePath `
            -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath $resolved.Path -Destination $guestBindingPath -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath (Join-Path $resolved.Root 'Win11ValidationHarness.psm1') -Destination $guestModulePath -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath (Join-Path $resolved.Root 'Invoke-Win11GuestValidation.ps1') -Destination $guestHarnessPath -ToSession $session -ErrorAction Stop
        $phaseStopwatch.Stop()
        $hostPhases.Add([ordered]@{ phase = 'guest-stage'; elapsed_ms = $phaseStopwatch.ElapsedMilliseconds })
        $phaseStopwatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            Invoke-Command -Session $session -ScriptBlock {
                param($Harness, $Root, $Package, $Certificate, $Binding, $Checkpoint)
                $output = @(& powershell.exe -NoLogo -NoProfile -NonInteractive `
                    -ExecutionPolicy Bypass -File $Harness `
                    -RunRoot $Root -PackageZipPath $Package -CertificatePath $Certificate `
                    -BindingPath $Binding -CheckpointId $Checkpoint 2>&1 |
                    ForEach-Object { $_.ToString() })
                if ($LASTEXITCODE -ne 0) {
                    throw "Guest validation subprocess failed with exit code $LASTEXITCODE`: $($output -join [Environment]::NewLine)"
                }
            } -ArgumentList $guestHarnessPath, $guestRunRoot, $guestPackageZip, `
                $guestCertificatePath, $guestBindingPath, $checkpointIdText `
                -ErrorAction Stop | Out-Null
        }
        catch { $guestError = Protect-KdbgHostText $_.Exception.Message $resolved.Root $GuestCredential.UserName }
        $phaseStopwatch.Stop()
        $hostPhases.Add([ordered]@{ phase = 'guest-required-core'; elapsed_ms = $phaseStopwatch.ElapsedMilliseconds })
        $phaseStopwatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            Invoke-Command -Session $session -ScriptBlock {
                param($EvidenceRoot, $ArchivePath)
                if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) { throw 'Guest evidence is missing.' }
                if (Test-Path -LiteralPath $ArchivePath) { throw 'Refusing to overwrite guest evidence archive.' }
                Compress-Archive -Path (Join-Path $EvidenceRoot '*') -DestinationPath $ArchivePath -CompressionLevel Optimal
            } -ArgumentList "$guestRunRoot\evidence", $guestEvidenceZip -ErrorAction Stop
            Copy-Item -LiteralPath $guestEvidenceZip -Destination $hostEvidenceZip -FromSession $session -ErrorAction Stop
            $guestEvidenceEntryCount = Assert-KdbgSafeArchive $hostEvidenceZip
            [IO.Directory]::CreateDirectory($hostEvidenceRoot) | Out-Null
            Expand-Archive -LiteralPath $hostEvidenceZip -DestinationPath $hostEvidenceRoot
            $guestEvidenceCopied = $true
            $guestSummaryPath = Join-Path $hostEvidenceRoot 'guest-validation-summary.json'
            if (Test-Path -LiteralPath $guestSummaryPath -PathType Leaf) {
                $guestSummary = Get-Content -LiteralPath $guestSummaryPath -Raw | ConvertFrom-Json
                $guestValidationPassed = $guestSummary.success -eq $true -and
                    $guestSummary.package_sha256 -ceq $binding.package.sha256 -and
                    $guestSummary.source_snapshot_sha256 -ceq $binding.package.source_snapshot_sha256 -and
                    $guestSummary.checkpoint_id -ceq $checkpointIdText -and
                    $guestSummary.credential_serialized -eq $false
            }
        }
        catch {
            $copyError = Protect-KdbgHostText $_.Exception.Message $resolved.Root $GuestCredential.UserName
            $guestError = if ($guestError) { "$guestError; evidence: $copyError" } else { $copyError }
        }
        $phaseStopwatch.Stop()
        $hostPhases.Add([ordered]@{ phase = 'evidence-copy-and-verify'; elapsed_ms = $phaseStopwatch.ElapsedMilliseconds })
        if (-not $guestValidationPassed -and -not $guestError) { $guestError = 'Guest evidence did not report exact success.' }
    }
    catch {
        $outerError = Protect-KdbgHostText $_.Exception.Message $resolved.Root $GuestCredential.UserName
        $guestError = if ($guestError) { "$guestError; host: $outerError" } else { $outerError }
    }
    finally {
        $cleanupStopwatch = [Diagnostics.Stopwatch]::StartNew()
        if ($session) {
            try { Remove-PSSession -Session $session -ErrorAction Stop }
            catch { $restoreErrors.Add((Protect-KdbgHostText $_.Exception.Message $resolved.Root $GuestCredential.UserName)) }
        }
        if ($mutationBegan) {
            try {
                $vmNow = Get-VM -Name $binding.vm_name -ErrorAction Stop
                if ($vmNow.State.ToString() -ne 'Off') {
                    Stop-VM -VM $vmNow -TurnOff -Force -Confirm:$false -ErrorAction Stop
                }
            }
            catch { $restoreErrors.Add((Protect-KdbgHostText $_.Exception.Message $resolved.Root $GuestCredential.UserName)) }
            try {
                $checkpointNow = @(Get-VMSnapshot -VMName $binding.vm_name -ErrorAction Stop | Where-Object {
                    $_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId
                })
                if ($checkpointNow.Count -ne 1) { throw 'Exact checkpoint identity is no longer unique.' }
                Restore-VMSnapshot -VMSnapshot $checkpointNow[0] -Confirm:$false -ErrorAction Stop
                $restored = $true
            }
            catch { $restoreErrors.Add((Protect-KdbgHostText $_.Exception.Message $resolved.Root $GuestCredential.UserName)) }
            try {
                $finalVm = Get-VM -Name $binding.vm_name -ErrorAction Stop
                if ($finalVm.State.ToString() -ne 'Off') {
                    Stop-VM -VM $finalVm -TurnOff -Force -Confirm:$false -ErrorAction Stop
                    $finalVm = Get-VM -Name $binding.vm_name -ErrorAction Stop
                }
                $finalVmOff = $finalVm.State.ToString() -eq 'Off'
                if (-not $finalVmOff) { throw 'Final VM state is not Off.' }
            }
            catch { $restoreErrors.Add((Protect-KdbgHostText $_.Exception.Message $resolved.Root $GuestCredential.UserName)) }
        }
        $cleanupStopwatch.Stop()
        $hostPhases.Add([ordered]@{ phase = 'session-cleanup-checkpoint-restore-final-off'; elapsed_ms = $cleanupStopwatch.ElapsedMilliseconds })
    }
    $hostOverallStopwatch.Stop()
    $success = $guestValidationPassed -and $guestEvidenceCopied -and $restored -and $finalVmOff -and $restoreErrors.Count -eq 0
    $summary = [ordered]@{
        schema = 'kdbg.win11-host-validation.v1'
        completed_utc = [DateTime]::UtcNow.ToString('o')
        success = $success
        epoch = $binding.epoch
        vm_name = $binding.vm_name
        checkpoint = [ordered]@{ name = $CheckpointName; id = $checkpointIdText; restored = $restored }
        final_vm_off = $finalVmOff
        package_sha256 = $binding.package.sha256
        source_snapshot_sha256 = $binding.package.source_snapshot_sha256
        guest_validation_passed = $guestValidationPassed
        optional_extended_gate = $binding.optional_extended_gate
        guest_evidence = [ordered]@{
            copied = $guestEvidenceCopied
            archive_sha256 = if (Test-Path -LiteralPath $hostEvidenceZip) { Get-KdbgSha256 $hostEvidenceZip } else { $null }
            archive_entry_count = $guestEvidenceEntryCount
            relative_directory = if ($guestEvidenceCopied) { 'guest-evidence' } else { $null }
        }
        guest_error = $guestError
        restore_errors = @($restoreErrors)
        phases = @($hostPhases)
        elapsed_ms = $hostOverallStopwatch.ElapsedMilliseconds
        credential_serialized = $false
        claim_boundary = if ($success) {
            'The exact package driver transaction passed in the bound Win11 guest and the exact checkpoint was restored with final Off.'
        } else { 'Windows 11 validation failed or remained incomplete; no compatibility pass may be claimed.' }
    }
    Write-KdbgJson $summaryPath $summary
    if (-not $success) { throw 'Windows 11 Hyper-V validation did not pass; inspect the sanitized workspace summary.' }
    return [pscustomobject]$summary
}

Export-ModuleMember -Function @(
    'New-KdbgWin11ValidationWorkspace',
    'Test-KdbgWin11ValidationWorkspace',
    'Test-KdbgWin11Readiness',
    'Invoke-KdbgWin11GuestValidation',
    'Invoke-KdbgWin11Validation')

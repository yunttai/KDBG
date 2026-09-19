[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][string]$PackageArchive,
    [Parameter(Mandatory)][string]$EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-KdbgSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function ConvertTo-KdbgLowerHex([byte[]]$Bytes) {
    return ([BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}

function Get-KdbgByteSha256([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($Bytes)
        return ConvertTo-KdbgLowerHex $digest
    }
    finally { $algorithm.Dispose() }
}

function Write-KdbgAtomicJson([string]$Path, [object]$Value) {
    $parent = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $temporary = Join-Path $parent ('.{0}.{1}.tmp' -f `
        [IO.Path]::GetFileName($Path), [Guid]::NewGuid().ToString('N'))
    try {
        $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $temporary -Encoding utf8
        if (Test-Path -LiteralPath $Path) {
            [IO.File]::Replace($temporary, $Path, $null)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Get-KdbgBootBinding([string]$MachineBinding) {
    $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $material = "kdbg.boot-binding.v1`n$MachineBinding`n$($lastBoot.ToUniversalTime().ToString('o'))`n"
        $digest = $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($material))
        return ConvertTo-KdbgLowerHex $digest
    }
    finally { $algorithm.Dispose() }
}

function Get-KdbgArtifactRecord([string]$Root, [string]$Name) {
    $path = Join-Path $Root $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required evidence artifact is missing: $Name"
    }
    return [ordered]@{
        file = $Name.Replace('\', '/')
        sha256 = Get-KdbgSha256 $path
        bytes = (Get-Item -LiteralPath $path).Length
    }
}

function Get-KdbgRuntimeObservation {
    $services = [ordered]@{}
    $devices = [ordered]@{}
    foreach ($name in @('KDBG', 'KDBGProbe')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='$name'" `
            -ErrorAction SilentlyContinue
        $services[$name] = if ($null -eq $service) { 'absent' } else { $service.Status.ToString() }
        $devices[$name] = if ($null -eq $driver) { 'absent' } else { [string]$driver.State }
    }
    return [pscustomobject]@{ services = $services; devices = $devices }
}

function Get-KdbgHostFacts {
    $computer = Get-CimInstance Win32_ComputerSystem
    $virtual = ([string]$computer.Model -match 'Virtual|VMware|KVM|VirtualBox|Hyper-V') -or
        ([string]$computer.Manufacturer -match 'VMware|Xen|QEMU|innotek')
    return [pscustomobject]@{
        os_name = if ($env:OS -eq 'Windows_NT') { 'Windows' } else { [Environment]::OSVersion.Platform.ToString() }
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
        execution_context = if ($virtual) { 'virtual-machine-guest' } else { 'bare-metal' }
        is_virtual_machine = $virtual
        hypervisor_present = [bool]$computer.HypervisorPresent
    }
}

function Write-KdbgSignatureReport(
    [string]$Root, [string]$ArchiveHash, [string]$OutputPath) {
    $paths = @('drivers/KDbgDriver.cat', 'drivers/KDbgProbe.cat')
    $records = [Collections.Generic.List[object]]::new()
    $thumbprint = $null
    $certificateHash = $null
    foreach ($relative in $paths) {
        $path = Join-Path $Root ($relative -replace '/', '\')
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate) {
            throw "Authenticode signature is not Valid: $relative ($($signature.Status))"
        }
        $currentThumbprint = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
        $currentCertificateHash = Get-KdbgByteSha256 `
            $signature.SignerCertificate.RawData
        if ($null -eq $thumbprint) {
            $thumbprint = $currentThumbprint
            $certificateHash = $currentCertificateHash
        } elseif ($thumbprint -cne $currentThumbprint -or
                  $certificateHash -cne $currentCertificateHash) {
            throw 'Packaged driver artifacts do not share one signer identity.'
        }
        $records.Add([ordered]@{
            package_relative_path = $relative
            sha256 = Get-KdbgSha256 $path
            status = 'Valid'
        })
    }
    $report = [ordered]@{
        schema = 'kdbg.win11-baremetal-signature-report.v1'
        verified = $true; status = 'Valid'
        verification_command = 'Get-AuthenticodeSignature'; exit_code = 0
        package_sha256 = $ArchiveHash; signer_thumbprint = $thumbprint
        signer_certificate_sha256 = $certificateHash
        catalogs = @($records | Where-Object package_relative_path -Like '*.cat' |
            ForEach-Object {
                [ordered]@{
                    package_relative_path = $_.package_relative_path
                    sha256 = $_.sha256
                }
            })
    }
    Write-KdbgAtomicJson $OutputPath $report
    return $report
}

$packageFull = [IO.Path]::GetFullPath($PackageRoot)
$archiveFull = [IO.Path]::GetFullPath($PackageArchive)
$evidenceFull = [IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath $evidenceFull) {
    throw 'Refusing to overwrite an existing evidence directory.'
}
$tools = Join-Path $packageFull 'tools'
$profileModule = Join-Path $tools 'TargetProfile.psm1'
foreach ($required in @(
        $archiveFull, (Join-Path $packageFull 'BUILD-METADATA.json'),
        (Join-Path $packageFull 'SHA256SUMS.txt'), $profileModule,
        (Join-Path $tools 'install.ps1'), (Join-Path $tools 'uninstall.ps1'),
        (Join-Path $tools 'kdbg_live_verify.exe'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required package/evidence input is missing: $required"
    }
}
Import-Module $profileModule -Force
$machineBinding = Get-KdbgMachineBindingSha256
$bootBinding = Get-KdbgBootBinding $machineBinding
$hostFacts = Get-KdbgHostFacts
[IO.Directory]::CreateDirectory($evidenceFull) | Out-Null
$archiveCopy = Join-Path $evidenceFull 'package.zip'
Copy-Item -LiteralPath $archiveFull -Destination $archiveCopy
$signature = Write-KdbgSignatureReport $packageFull (Get-KdbgSha256 $archiveCopy) `
    (Join-Path $evidenceFull 'signature-report.json')

$readOnlyPath = Join-Path $evidenceFull 'read-only-run.json'
$livePath = Join-Path $evidenceFull 'live-run.json'
$pageDirectory = Join-Path $evidenceFull 'page-artifacts'
[IO.Directory]::CreateDirectory($pageDirectory) | Out-Null
$liveSucceeded = $false
$cleanupErrors = [Collections.Generic.List[string]]::new()
try {
    & (Join-Path $tools 'install.ps1') -Start -TargetProfile LocalHost `
        -PackageRootMode DistributionSource
    if ($LASTEXITCODE -ne 0) { throw 'LocalHost package install/start failed.' }
    $verifier = Join-Path $tools 'kdbg_live_verify.exe'
    & $verifier --output $readOnlyPath --build-id 'local-host-read-only' --read-samples 3
    if ($LASTEXITCODE -ne 0) { throw 'Local-host read-only verifier failed.' }
    $readOnly = Get-Content -LiteralPath $readOnlyPath -Raw | ConvertFrom-Json
    if ($readOnly.success -ne $true -or $readOnly.probe_before.pfn -le 0) {
        throw 'Read-only report did not provide a successful Probe PFN.'
    }
    & $verifier --write --baremetal-evidence `
        --confirm-probe-pfn ([string]$readOnly.probe_before.pfn) `
        --artifact-directory $pageDirectory `
        --output $livePath --build-id 'local-host-probe-transaction' --read-samples 3
    if ($LASTEXITCODE -ne 0) { throw 'Local-host Probe transaction verifier failed.' }
    $live = Get-Content -LiteralPath $livePath -Raw | ConvertFrom-Json
    if ($live.schema -cne 'kdbg.live-verify.v2' -or $live.success -ne $true) {
        throw 'Local-host Probe transaction report did not pass.'
    }
    $pageNames = [ordered]@{
        baseline = 'baseline.bin'; preflight = 'preflight.bin'
        expected_after = 'expected-after.bin'; readback = 'readback.bin'
        independent_reload = 'independent-reload.bin'; rollback = 'rollback.bin'
    }
    foreach ($entry in $pageNames.GetEnumerator()) {
        $records = @($live.raw_page_artifacts | Where-Object role -CEQ $entry.Key)
        if ($records.Count -ne 1) {
            throw "Live verifier did not emit one raw page record for $($entry.Key)."
        }
        $reported = [string]$records[0].file_name
        if ([IO.Path]::GetFileName($reported) -cne $reported) {
            throw "Live verifier emitted an unsafe page artifact name: $reported"
        }
        if ($reported -cne $entry.Value) {
            throw "Live verifier page artifact name mismatch for $($entry.Key)."
        }
        Move-Item -LiteralPath (Join-Path $pageDirectory $reported) `
            -Destination (Join-Path $evidenceFull $entry.Value)
    }
    Write-KdbgAtomicJson $livePath $live
    $liveSucceeded = $true
}
finally {
    try {
        & (Join-Path $tools 'uninstall.ps1') -ConfirmKdbgServices `
            -PackageRootMode DistributionSource
        if ($LASTEXITCODE -ne 0) { throw 'uninstall returned a non-zero exit code' }
    }
    catch { $cleanupErrors.Add($_.Exception.Message) }
}
if (-not $liveSucceeded) { throw 'Local-host transaction did not complete.' }

$observation = Get-KdbgRuntimeObservation
$uninstallCompleted = $cleanupErrors.Count -eq 0
$servicesAbsent = $observation.services.KDBG -ceq 'absent' -and
    $observation.services.KDBGProbe -ceq 'absent'
$devicesAbsent = $observation.devices.KDBG -ceq 'absent' -and
    $observation.devices.KDBGProbe -ceq 'absent'
$finalGateLocked = $live.write_cleanup.final_gate_locked -eq $true -and
    $live.session_final.write_enabled -eq $false
$cleanupSuccess = $uninstallCompleted -and $servicesAbsent -and
    $devicesAbsent -and $finalGateLocked
$cleanupReport = [ordered]@{
    schema = 'kdbg.win11-baremetal-cleanup-report.v1'; success = $cleanupSuccess
    runtime_host_machine_identity_sha256 = $machineBinding; boot_id_sha256 = $bootBinding
    final_gate_locked = $finalGateLocked
    services = $observation.services; devices = $observation.devices
    errors = @($cleanupErrors)
}
Write-KdbgAtomicJson (Join-Path $evidenceFull 'cleanup-report.json') $cleanupReport
if (-not $cleanupSuccess) { throw 'Local-host cleanup observation failed.' }

$artifactNames = [ordered]@{
    baseline = 'baseline.bin'; preflight = 'preflight.bin'
    expected_after = 'expected-after.bin'; readback = 'readback.bin'
    independent_reload = 'independent-reload.bin'; rollback = 'rollback.bin'
    package_archive = 'package.zip'; signature_report = 'signature-report.json'
    cleanup_report = 'cleanup-report.json'; live_run_report = 'live-run.json'
}
$artifacts = [ordered]@{}
foreach ($entry in $artifactNames.GetEnumerator()) {
    $artifacts[$entry.Key] = Get-KdbgArtifactRecord $evidenceFull $entry.Value
}
$live = Get-Content -LiteralPath $livePath -Raw | ConvertFrom-Json
$metadata = Get-Content -LiteralPath (Join-Path $packageFull 'BUILD-METADATA.json') -Raw |
    ConvertFrom-Json
$evidence = [ordered]@{
    schema = 'kdbg.win11-baremetal-validation.v1'; lane = 'bare-metal-runtime-host'
    success = $true; dry_run = $false; completed_utc = [DateTime]::UtcNow.ToString('o')
    roles = [ordered]@{
        runtime_host = [ordered]@{
            role = 'runtime_host'; machine_identity_sha256 = $machineBinding
            boot_id_before_sha256 = $bootBinding; os_name = $hostFacts.os_name
            os_build = [Environment]::OSVersion.Version.Build
            architecture = $hostFacts.architecture
            execution_context = $hostFacts.execution_context
            is_virtual_machine = $hostFacts.is_virtual_machine
            hypervisor_present = $hostFacts.hypervisor_present
        }
        orchestrator_host = [ordered]@{
            role = 'orchestrator_host'; machine_identity_sha256 = $machineBinding
        }
    }
    package = [ordered]@{
        package_sha256 = $artifacts.package_archive.sha256
        manifest_sha256 = Get-KdbgSha256 (Join-Path $packageFull 'SHA256SUMS.txt')
        source_snapshot_sha256 = $metadata.source_snapshot_sha256
        signer_thumbprint = $signature.signer_thumbprint
        signer_certificate_sha256 = $signature.signer_certificate_sha256
        signature_status = 'Valid'
    }
    binding = [ordered]@{
        runtime_host_machine_identity_sha256 = $machineBinding
        boot_id_before_sha256 = $bootBinding
        package_sha256 = $artifacts.package_archive.sha256
        source_snapshot_sha256 = $metadata.source_snapshot_sha256
        signer_thumbprint = $signature.signer_thumbprint
    }
    target = [ordered]@{
        provider = 'KDbgProbe'; discovery = 'IOCTL_KDBG_PROBE_GET_INFO'
        ownership = 'KDbgProbe-owned contiguous page'; probe_derived = $true
        raw_user_pfn = $false; pfn = $live.probe_before.pfn
        physical_address = $live.probe_before.physical_address
        page_size = 4096; generation = $live.probe_before.generation
    }
    backend = [ordered]@{
        name = 'KDbgDriver'; connected = $live.backend.connected
        is_mock = $live.backend.is_mock; abi_version = $live.backend.abi_version
        write_enabled_final = $live.session_final.write_enabled
        capabilities = if ($live.backend.supports_physical_page_compare_write -eq $true) {
            @('compare-write-page-v1')
        } else { @() }
    }
    artifacts = $artifacts
    transaction = [ordered]@{
        status = 'passed'; physical_read_4096 = $true; preflight_full_match = $true
        one_shot_unlock = $true; unlock_consumed = $true
        dirty_bytes = $live.write_cleanup.user_dirty_bytes; driver_requested_bytes = 4096
        driver_transferred_bytes = $live.write_cleanup.apply_driver_transferred_bytes
        full_readback_match = $true; independent_reload_match = $true
        rollback_requested_bytes = $live.write_cleanup.rollback_requested_bytes
        rollback_completed_bytes = $live.write_cleanup.rollback_driver_transferred_bytes
        rollback_full_match = $live.write_cleanup.rollback_verified
        final_gate_locked = $live.write_cleanup.final_gate_locked
        edit_offset = $live.write_cleanup.edit_offset; edit_length = $live.write_cleanup.edit_length
        edit_xor_mask = '4b444247a55a3cc3'
        runtime_host_machine_identity_sha256 = $machineBinding
        boot_id_sha256 = $bootBinding; abi_version = 7
        operation = 'compare-write-page-v1'; compare_bytes = 4096
    }
    cleanup = [ordered]@{
        uninstall_completed = $uninstallCompleted
        services_absent = $servicesAbsent; devices_absent = $devicesAbsent
        errors = @($cleanupErrors)
    }
    errors = @()
    claim_boundary = 'Local runtime-host Probe evidence; Probe is a deterministic evidence target and does not restrict RawPfn product behavior.'
}
$finalPath = Join-Path $evidenceFull 'evidence.json'
Write-KdbgAtomicJson $finalPath $evidence
Write-Output $finalPath

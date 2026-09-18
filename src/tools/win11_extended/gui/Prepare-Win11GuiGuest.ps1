[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunRoot,
    [Parameter(Mandatory = $true)][string]$PackageZipPath,
    [Parameter(Mandatory = $true)][string]$SymbolsZipPath,
    [Parameter(Mandatory = $true)][string]$CertificatePath,
    [Parameter(Mandatory = $true)][string]$ExpectedPackageSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSymbolsSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedCertificateSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSourceSnapshotSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory = $true)][string]$CheckpointId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}
function Invoke-Captured([string]$Name, [string]$FilePath, [string[]]$Arguments, [string]$EvidenceRoot) {
    $stdout = Join-Path $EvidenceRoot "$Name.stdout.log"
    $stderr = Join-Path $EvidenceRoot "$Name.stderr.log"
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [ordered]@{ name=$Name; exit_code=$process.ExitCode; stdout=$stdout; stderr=$stderr }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Guest preparation requires Administrator.'
}
$os = Get-CimInstance Win32_OperatingSystem
if ($env:PROCESSOR_ARCHITECTURE -cne 'AMD64' -or [uint32]$os.BuildNumber -lt 22000) {
    throw 'Guest preparation requires Windows 11 x64.'
}
if (((& bcdedit.exe /enum '{current}' 2>&1 | Out-String) -notmatch 'testsigning\s+Yes')) {
    throw 'Guest preparation requires test-signing mode.'
}
$resolvedRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$allowedRoot = [IO.Path]::GetFullPath('C:\KDBG-Win11-Extended').TrimEnd('\')
if (-not $resolvedRoot.StartsWith($allowedRoot + '\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'RunRoot must remain below C:\KDBG-Win11-Extended.'
}
foreach ($value in @($ExpectedPackageSha256,$ExpectedSymbolsSha256,$ExpectedCertificateSha256,$ExpectedSourceSnapshotSha256)) {
    if ($value -cnotmatch '^[0-9a-f]{64}$') { throw 'Expected SHA-256 values must be lowercase 64-hex.' }
}
if ($ExpectedSignerThumbprint -cnotmatch '^[0-9a-f]{40}$') { throw 'Expected signer thumbprint must be lowercase 40-hex.' }
foreach ($path in @($PackageZipPath,$SymbolsZipPath,$CertificatePath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing staged guest input: $path" }
}
$observed = [ordered]@{
    package=Get-Sha $PackageZipPath
    symbols=Get-Sha $SymbolsZipPath
    certificate=Get-Sha $CertificatePath
}
if ($observed.package -cne $ExpectedPackageSha256 -or $observed.symbols -cne $ExpectedSymbolsSha256 -or
    $observed.certificate -cne $ExpectedCertificateSha256) {
    throw 'Guest staged artifact hash mismatch.'
}

$evidenceRoot = Join-Path $resolvedRoot 'evidence'
$expandedRoot = Join-Path $resolvedRoot 'expanded'
$symbolsExpanded = Join-Path $resolvedRoot 'symbols-expanded'
New-Item -ItemType Directory -Path $evidenceRoot,$expandedRoot,$symbolsExpanded -Force | Out-Null
Expand-Archive -LiteralPath $PackageZipPath -DestinationPath $expandedRoot -Force
Expand-Archive -LiteralPath $SymbolsZipPath -DestinationPath $symbolsExpanded -Force
$packageRoot = Join-Path $expandedRoot 'KDBG-1.1.0-win-x64'
$symbolsRoot = Join-Path $symbolsExpanded 'KDBG-1.1.0-win-x64-symbols'
$metadataPath = Join-Path $packageRoot 'BUILD-METADATA.json'
$symbolsMetadataPath = Join-Path $symbolsRoot 'BUILD-METADATA.json'
foreach ($path in @($metadataPath,$symbolsMetadataPath,(Join-Path $packageRoot 'KDBG.exe'),
        (Join-Path $packageRoot 'drivers\KDbgDriver.sys'),(Join-Path $packageRoot 'drivers\KDbgProbe.sys'),
        (Join-Path $packageRoot 'tools\kdbg_live_verify.exe'),
        (Join-Path $packageRoot 'tools\kdbg_process_fixture.exe'),
        (Join-Path $symbolsRoot 'drivers\KDbgDriver.pdb'))) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Expanded artifact is incomplete: $path" }
}
$metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$symbolsMetadata = Get-Content -LiteralPath $symbolsMetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$metadata.source_snapshot_sha256 -cne $ExpectedSourceSnapshotSha256 -or
    [string]$symbolsMetadata.source_snapshot_sha256 -cne $ExpectedSourceSnapshotSha256) {
    throw 'Expanded package/symbol source snapshot mismatch.'
}

$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
if ($certificate.Thumbprint.ToLowerInvariant() -cne $ExpectedSignerThumbprint) {
    throw 'Certificate thumbprint mismatch.'
}
$certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
foreach ($store in @('Root','TrustedPublisher')) {
    $certRecord = Invoke-Captured "cert-import-$store" $certutil @('-f','-addstore',$store,$CertificatePath) $evidenceRoot
    if ($certRecord.exit_code -ne 0) { throw "Certificate import failed: $store" }
}
foreach ($relative in @('drivers\KDbgDriver.sys','drivers\KDbgProbe.sys','drivers\KDbgDriver.cat','drivers\KDbgProbe.cat')) {
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $packageRoot $relative)
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint.ToLowerInvariant() -cne $ExpectedSignerThumbprint) {
        throw "Expanded package signature mismatch: $relative"
    }
}

$pdbRoot = Join-Path $resolvedRoot 'symbols\drivers'
New-Item -ItemType Directory -Path $pdbRoot -Force | Out-Null
$pdbPath = Join-Path $pdbRoot 'KDbgDriver.pdb'
Copy-Item -LiteralPath (Join-Path $symbolsRoot 'drivers\KDbgDriver.pdb') -Destination $pdbPath -Force
$pdbSha = Get-Sha $pdbPath

$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$diagnose = Invoke-Captured 'diagnose' $powershell @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
    '-File',(Join-Path $packageRoot 'tools\diagnose.ps1'),'-VerifyPackage','-RequireAdministrator') $evidenceRoot
if ($diagnose.exit_code -ne 0) { throw 'Package diagnostic preflight failed.' }
$install = Invoke-Captured 'install-start' $powershell @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
    '-File',(Join-Path $packageRoot 'tools\install.ps1'),'-Start','-ConfirmDedicatedVm','-ConfirmSnapshot') $evidenceRoot
if ($install.exit_code -ne 0) { throw 'Package install/start failed.' }

$readOnlyPath = Join-Path $evidenceRoot 'readonly-probe-discovery.json'
$verifier = Join-Path $packageRoot 'tools\kdbg_live_verify.exe'
$verify = Invoke-Captured 'readonly-probe-discovery' $verifier @('--output',$readOnlyPath,
    '--build-id','win11-extended-gui-readonly','--read-samples','8') $evidenceRoot
if ($verify.exit_code -ne 0) { throw 'Read-only Probe discovery failed.' }
$report = Get-Content -LiteralPath $readOnlyPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($report.success -ne $true -or $report.runtime_identity.verified -ne $true -or
    [uint32]$report.backend.abi_version -ne 6 -or $report.backend.is_mock -ne $false -or
    [uint32]$report.probe_before.byte_count -ne 4096 -or
    $report.write_cleanup.final_gate_locked -ne $true) {
    throw 'Read-only Probe discovery report did not satisfy the live contract.'
}
$probePfn = [uint64]$report.probe_before.pfn
if ($probePfn -eq 0) { throw 'Read-only verifier returned an invalid Probe PFN.' }

$prepared = [ordered]@{
    schema='kdbg.win11-extended-gui-guest-prepared.v1'
    success=$true
    completed_utc=[DateTime]::UtcNow.ToString('o')
    checkpoint_id=$CheckpointId
    package_root=$packageRoot
    package_sha256=$observed.package
    symbols_sha256=$observed.symbols
    certificate_sha256=$observed.certificate
    source_snapshot_sha256=$ExpectedSourceSnapshotSha256
    signer_thumbprint=$ExpectedSignerThumbprint
    driver_pdb_path=$pdbPath
    driver_pdb_sha256=$pdbSha
    probe_pfn=$probePfn
    probe_pfn_hex=('0x{0:X}' -f $probePfn)
    os=[ordered]@{ caption=[string]$os.Caption; build=[string]$os.BuildNumber; architecture=[string]$os.OSArchitecture }
    credential_serialized=$false
}
Write-Json (Join-Path $resolvedRoot 'guest-prepared.json') $prepared
$prepared | ConvertTo-Json -Depth 20

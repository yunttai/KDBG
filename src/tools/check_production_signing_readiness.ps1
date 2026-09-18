[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PackagePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedMainSha256,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SymbolsPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedSymbolsSha256,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedAppPublisherSubject,

    [Parameter(Mandatory)]
    [ValidateSet('MicrosoftReturned', 'DirectPublisher')]
    [string]$DriverProfile,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedDriverPublisherSubject,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TimestampUrl,

    [ValidateSet('LocalCertificate', 'ExternalService')]
    [string]$AppSigningProvider = 'LocalCertificate',

    [string]$AppCertificateThumbprint,

    [switch]$AppSigningServiceAvailable,

    [switch]$DriverSigningServiceAvailable,

    [string]$SignToolPath,

    [string]$OutputPath,

    [switch]$FailOnNotReady
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$Utf8NoBom = [Text.UTF8Encoding]::new($false)

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-HttpsTimestampUrl {
    param([Parameter(Mandatory)][string]$Value)
    $uri = $null
    return [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -and
        $uri.Scheme -ceq 'https' -and
        [string]::IsNullOrWhiteSpace($uri.UserInfo) -and
        -not [string]::IsNullOrWhiteSpace($uri.Host)
}

function Test-CodeSigningEku {
    param([Parameter(Mandatory)]$Certificate)
    return @($Certificate.EnhancedKeyUsageList | Where-Object {
        [string]$_.ObjectId -eq '1.3.6.1.5.5.7.3.3'
    }).Count -gt 0
}

function Test-PathHasReparsePoint {
    param([Parameter(Mandatory)][string]$Path)
    $cursor = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $true
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $false
}

function Get-ZipEntryNames {
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::OpenRead($Path)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            return @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) } |
                ForEach-Object { $_.FullName.Replace('\', '/') } | Sort-Object -Unique)
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Resolve-X64SignTool {
    param([string]$ExplicitPath)
    $candidates = [Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $candidates.Add([IO.Path]::GetFullPath($ExplicitPath))
    }
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command) { $candidates.Add([IO.Path]::GetFullPath($command.Source)) }
    foreach ($root in @(
        'C:\Program Files (x86)\Windows Kits\10\bin',
        (Join-Path $RepoRoot 'out\wdk-nuget'))) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($candidate in Get-ChildItem -LiteralPath $root -Filter signtool.exe `
                -File -Recurse -ErrorAction SilentlyContinue) {
            if ($candidate.FullName -match '\\x64\\signtool\.exe$') {
                $candidates.Add([IO.Path]::GetFullPath($candidate.FullName))
            }
        }
    }
    return @($candidates | Where-Object {
        (Test-Path -LiteralPath $_ -PathType Leaf) -and
        $_ -match '\\x64\\signtool\.exe$'
    } | Sort-Object -Unique)
}

$blockers = [Collections.Generic.List[string]]::new()
$packageFull = [IO.Path]::GetFullPath($PackagePath)
$symbolsFull = [IO.Path]::GetFullPath($SymbolsPath)
$mainExpected = $ExpectedMainSha256.ToLowerInvariant()
$symbolsExpected = $ExpectedSymbolsSha256.ToLowerInvariant()

foreach ($binding in @(
    @{ Name = 'main'; Path = $packageFull; Expected = $mainExpected },
    @{ Name = 'symbols'; Path = $symbolsFull; Expected = $symbolsExpected })) {
    if (-not (Test-Path -LiteralPath $binding.Path -PathType Leaf)) {
        $blockers.Add("Exact $($binding.Name) ZIP is missing: $($binding.Path)")
        continue
    }
    if (Test-PathHasReparsePoint $binding.Path) {
        $blockers.Add("Exact $($binding.Name) ZIP path contains a reparse point.")
        continue
    }
    if ((Get-Sha256 $binding.Path) -cne $binding.Expected) {
        $blockers.Add("Exact $($binding.Name) ZIP SHA-256 mismatch.")
    }
}

$requiredMainEntries = @(
    'KDBG-1.1.0-win-x64/KDBG.exe',
    'KDBG-1.1.0-win-x64/KDBGSetup.exe',
    'KDBG-1.1.0-win-x64/plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe',
    'KDBG-1.1.0-win-x64/tools/kdbg_live_verify.exe',
    'KDBG-1.1.0-win-x64/tools/kdbg_process_fixture.exe',
    'KDBG-1.1.0-win-x64/drivers/KDbgDriver.sys',
    'KDBG-1.1.0-win-x64/drivers/KDbgDriver.inf',
    'KDBG-1.1.0-win-x64/drivers/KDbgDriver.cat',
    'KDBG-1.1.0-win-x64/drivers/KDbgProbe.sys',
    'KDBG-1.1.0-win-x64/drivers/KDbgProbe.inf',
    'KDBG-1.1.0-win-x64/drivers/KDbgProbe.cat')
$requiredSymbolEntries = @(
    'KDBG-1.1.0-win-x64-symbols/KDBG.pdb',
    'KDBG-1.1.0-win-x64-symbols/KDBGSetup.pdb',
    'KDBG-1.1.0-win-x64-symbols/drivers/KDbgDriver.pdb',
    'KDBG-1.1.0-win-x64-symbols/drivers/KDbgProbe.pdb')
if (Test-Path -LiteralPath $packageFull -PathType Leaf) {
    try {
        $entries = @(Get-ZipEntryNames $packageFull)
        foreach ($required in $requiredMainEntries) {
            if ($entries -cnotcontains $required) {
                $blockers.Add("Exact main ZIP is missing required entry: $required")
            }
        }
    }
    catch { $blockers.Add("Exact main ZIP is unreadable: $($_.Exception.Message)") }
}
if (Test-Path -LiteralPath $symbolsFull -PathType Leaf) {
    try {
        $entries = @(Get-ZipEntryNames $symbolsFull)
        foreach ($required in $requiredSymbolEntries) {
            if ($entries -cnotcontains $required) {
                $blockers.Add("Exact symbols ZIP is missing required entry: $required")
            }
        }
    }
    catch { $blockers.Add("Exact symbols ZIP is unreadable: $($_.Exception.Message)") }
}

$timestampValid = Test-HttpsTimestampUrl $TimestampUrl
if (-not $timestampValid) {
    $blockers.Add('TimestampUrl must be an absolute credential-free HTTPS URL.')
}
if (-not $DriverSigningServiceAvailable.IsPresent) {
    $blockers.Add('The selected production driver-signing service/path is not declared available.')
}
if ($AppSigningProvider -eq 'ExternalService' -and
    -not $AppSigningServiceAvailable.IsPresent) {
    $blockers.Add('The external application-signing service is not declared available.')
}

$signTools = @(Resolve-X64SignTool $SignToolPath)
if ($signTools.Count -eq 0) {
    $blockers.Add('An x64 Windows SDK SignTool was not found.')
}

$certificateRecords = [Collections.Generic.List[object]]::new()
$eligibleCertificates = [Collections.Generic.List[object]]::new()
if ($AppSigningProvider -eq 'LocalCertificate') {
    $normalizedThumbprint = if ([string]::IsNullOrWhiteSpace($AppCertificateThumbprint)) {
        ''
    } else {
        ($AppCertificateThumbprint -replace '\s', '').ToUpperInvariant()
    }
    if ($normalizedThumbprint -notmatch '^[0-9A-F]{40,64}$') {
        $blockers.Add('LocalCertificate requires an exact hexadecimal AppCertificateThumbprint.')
    }
    $now = [DateTime]::UtcNow
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        try {
            foreach ($certificate in Get-ChildItem -Path $store -ErrorAction Stop) {
                if (($certificate.Thumbprint -replace '\s', '').ToUpperInvariant() -cne
                    $normalizedThumbprint) { continue }
                $eku = Test-CodeSigningEku $certificate
                $selfSigned = $certificate.Subject -ceq $certificate.Issuer
                $timeValid = $certificate.NotBefore.ToUniversalTime() -le $now -and
                    $certificate.NotAfter.ToUniversalTime() -gt $now
                $eligible = $certificate.HasPrivateKey -and $eku -and
                    -not $selfSigned -and $timeValid -and
                    $certificate.Subject -ceq $ExpectedAppPublisherSubject
                $certificateRecords.Add([ordered]@{
                    store = $store
                    subject = $certificate.Subject
                    issuer = $certificate.Issuer
                    thumbprint = $certificate.Thumbprint
                    has_private_key = [bool]$certificate.HasPrivateKey
                    code_signing_eku = $eku
                    self_signed = $selfSigned
                    time_valid = $timeValid
                    exact_app_publisher_match =
                        $certificate.Subject -ceq $ExpectedAppPublisherSubject
                    eligible = $eligible
                    private_key_exported = $false
                })
                if ($eligible) { $eligibleCertificates.Add($certificate) }
            }
        }
        catch { $blockers.Add("Unable to inspect certificate store $store.") }
    }
    if ($eligibleCertificates.Count -ne 1) {
        $blockers.Add('Exactly one time-valid, non-self-signed local code-signing certificate must match the requested thumbprint and app publisher.')
    }
}

$mainObserved = if (Test-Path -LiteralPath $packageFull -PathType Leaf) {
    Get-Sha256 $packageFull
} else { $null }
$symbolsObserved = if (Test-Path -LiteralPath $symbolsFull -PathType Leaf) {
    Get-Sha256 $symbolsFull
} else { $null }
$ready = $blockers.Count -eq 0
$result = [ordered]@{
    schema = 'kdbg.production-signing-readiness.v2'
    captured_utc = [DateTime]::UtcNow.ToString('o')
    mode = 'read-only'
    mutation_performed = $false
    input = [ordered]@{
        main_zip_path = $packageFull
        main_zip_expected_sha256 = $mainExpected
        main_zip_observed_sha256 = $mainObserved
        main_zip_hash_matches = $mainObserved -ceq $mainExpected
        symbols_zip_path = $symbolsFull
        symbols_zip_expected_sha256 = $symbolsExpected
        symbols_zip_observed_sha256 = $symbolsObserved
        symbols_zip_hash_matches = $symbolsObserved -ceq $symbolsExpected
    }
    identity = [ordered]@{
        app_publisher_subject = $ExpectedAppPublisherSubject
        app_signing_provider = $AppSigningProvider
        driver_profile = $DriverProfile
        driver_publisher_subject = $ExpectedDriverPublisherSubject
        timestamp_url = if ($timestampValid) { ([Uri]$TimestampUrl).AbsoluteUri } else { $null }
    }
    x64_signtool_candidates = $signTools
    local_certificate_matches = @($certificateRecords)
    external_app_signing_service_declared_available =
        $AppSigningServiceAvailable.IsPresent
    driver_signing_service_declared_available =
        $DriverSigningServiceAvailable.IsPresent
    blockers = @($blockers)
    ready_for_signing_workflow = $ready
    production_signed_package_verified = $false
    private_key_material_read_or_exported = $false
    claim_boundary = 'Read-only prerequisite inventory. It does not sign, timestamp, submit, install, or load any artifact.'
}

$json = $result | ConvertTo-Json -Depth 12
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputFull = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $outputFull
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [IO.File]::WriteAllText($outputFull, $json + [Environment]::NewLine, $Utf8NoBom)
}
$json
if ($FailOnNotReady -and -not $ready) { exit 2 }

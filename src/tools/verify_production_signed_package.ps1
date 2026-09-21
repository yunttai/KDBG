[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PackageDirectory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SymbolsDirectory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$InputPackagePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedInputMainSha256,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$InputSymbolsPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedInputSymbolsSha256,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPackagePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputSymbolsPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ProvenancePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedAppPublisherSubject,
    [Parameter(Mandatory)][ValidateSet('MicrosoftReturned', 'DirectPublisher')][string]$DriverProfile,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedDriverPublisherSubject,
    [string]$SignToolPath,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$ExpectedPackageName = 'KDBG-1.1.0-win-x64'
$ExpectedSymbolsName = 'KDBG-1.1.0-win-x64-symbols'

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-KdbgRelativePath {
    param(
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$TargetPath)
    $base = [IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/')
    $target = [IO.Path]::GetFullPath($TargetPath)
    $prefix = $base + [IO.Path]::DirectorySeparatorChar
    if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Target path escapes the package root.'
    }
    return $target.Substring($prefix.Length).Replace('\', '/')
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

function Test-HttpsTimestampUrl {
    param([Parameter(Mandatory)][string]$Value)
    $uri = $null
    return [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -and
        $uri.Scheme -ceq 'https' -and
        [string]::IsNullOrWhiteSpace($uri.UserInfo) -and
        -not [string]::IsNullOrWhiteSpace($uri.Host)
}

function Get-ZipEntryHashMap {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$RelativePaths)
    Add-Type -AssemblyName System.IO.Compression
    $map = @{}
    $stream = [IO.File]::OpenRead($Path)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            foreach ($relative in $RelativePaths) {
                if ($map.ContainsKey($relative)) {
                    throw "Duplicate requested ZIP entry: $relative"
                }
                $entry = $archive.GetEntry("$Root/$relative")
                if (-not $entry -or [string]::IsNullOrEmpty($entry.Name)) {
                    throw "ZIP is missing required provenance input: $relative"
                }
                $entryStream = $entry.Open()
                try {
                    $hasher = [Security.Cryptography.SHA256]::Create()
                    try { $digest = $hasher.ComputeHash($entryStream) }
                    finally { $hasher.Dispose() }
                }
                finally { $entryStream.Dispose() }
                $map[$relative] = ([BitConverter]::ToString($digest)).Replace(
                    '-', '').ToLowerInvariant()
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
    return $map
}

function Resolve-X64SignTool {
    param([string]$ExplicitPath)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $resolved = [IO.Path]::GetFullPath($ExplicitPath)
        if ((Test-Path -LiteralPath $resolved -PathType Leaf) -and
            $resolved -match '\\x64\\signtool\.exe$') { return $resolved }
        throw 'SignToolPath must identify an existing x64 Windows SDK signtool.exe.'
    }
    $roots = @(
        'C:\Program Files (x86)\Windows Kits\10\bin',
        (Join-Path $RepoRoot 'out\wdk-nuget'))
    $candidates = foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        Get-ChildItem -LiteralPath $root -Filter signtool.exe -File -Recurse `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' }
    }
    $selected = $candidates | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $selected) { throw 'An x64 Windows SDK signtool.exe was not found.' }
    return [IO.Path]::GetFullPath($selected.FullName)
}

function Test-HashManifest {
    param([Parameter(Mandatory)][string]$Directory)
    $errors = [Collections.Generic.List[string]]::new()
    $manifest = Join-Path $Directory 'SHA256SUMS.txt'
    $map = @{}
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        $errors.Add('SHA256SUMS.txt is missing.')
        return [pscustomobject]@{ Count = 0; Errors = @($errors); Map = $map }
    }
    foreach ($line in Get-Content -LiteralPath $manifest) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^([0-9a-f]{64})  ([^\\]+)$') {
            $errors.Add("Malformed manifest entry: $line")
            continue
        }
        $relative = $Matches[2]
        $parts = @($relative -split '/')
        if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or
            $parts -contains '' -or $parts -contains '.' -or $parts -contains '..' -or
            $map.ContainsKey($relative)) {
            $errors.Add("Unsafe or duplicate manifest path: $relative")
            continue
        }
        $path = [IO.Path]::GetFullPath((Join-Path $Directory $relative))
        if (-not $path.StartsWith(
                ([IO.Path]::GetFullPath($Directory).TrimEnd('\') + '\'),
                [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $errors.Add("Missing or unsafe manifest file: $relative")
            continue
        }
        $actual = Get-Sha256 $path
        if ($actual -cne $Matches[1]) { $errors.Add("Hash mismatch: $relative") }
        $map[$relative] = $actual
    }
    foreach ($file in Get-ChildItem -LiteralPath $Directory -File -Recurse) {
        if ($file.FullName -eq $manifest) { continue }
        $relative = Get-KdbgRelativePath $Directory $file.FullName
        if (-not $map.ContainsKey($relative)) { $errors.Add("Unmanifested file: $relative") }
    }
    return [pscustomobject]@{ Count = $map.Count; Errors = @($errors); Map = $map }
}

function Get-ProductionSignatureRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$ExpectedPublisherSubject,
        [Parameter(Mandatory)]$Signature)
    $subject = if ($Signature.SignerCertificate) {
        [string]$Signature.SignerCertificate.Subject
    } else { $null }
    $issuer = if ($Signature.SignerCertificate) {
        [string]$Signature.SignerCertificate.Issuer
    } else { $null }
    $timestamp = $Signature.TimeStamperCertificate
    return [ordered]@{
        path = $RelativePath
        sha256 = Get-Sha256 $Path
        status = $Signature.Status.ToString()
        signer_subject = $subject
        signer_issuer = $issuer
        exact_publisher_match = $subject -ceq $ExpectedPublisherSubject
        self_signed = $null -ne $subject -and $subject -ceq $issuer
        rfc3161_timestamp_present = $null -ne $timestamp
        timestamp_subject = if ($timestamp) { [string]$timestamp.Subject } else { $null }
        timestamp_thumbprint = if ($timestamp) { [string]$timestamp.Thumbprint } else { $null }
    }
}

function Test-ProductionSignatureRecord {
    param([Parameter(Mandatory)]$Record)
    return $Record.status -ceq 'Valid' -and
        $Record.exact_publisher_match -eq $true -and
        $Record.self_signed -eq $false -and
        $Record.rfc3161_timestamp_present -eq $true
}

function Invoke-SignToolVerify {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Arguments)
    $output = & $script:ResolvedSignTool @Arguments 2>&1 | Out-String
    return [ordered]@{
        name = $Name
        arguments = @($Arguments | ForEach-Object {
            if ([IO.Path]::IsPathRooted([string]$_)) { [IO.Path]::GetFileName([string]$_) }
            else { [string]$_ }
        })
        exit_code = [int]$LASTEXITCODE
        passed = $LASTEXITCODE -eq 0
        output = $output.Trim()
    }
}

function Get-ProvenanceRecordMap {
    param([Parameter(Mandatory)][object[]]$Records)
    $map = @{}
    foreach ($record in $Records) {
        $path = [string]$record.path
        if ([string]::IsNullOrWhiteSpace($path) -or $map.ContainsKey($path)) {
            throw 'Provenance contains a missing or duplicate path.'
        }
        if ([string]$record.sha256 -notmatch '^[0-9a-f]{64}$') {
            throw "Provenance contains an invalid SHA-256 for $path."
        }
        $map[$path] = $record
    }
    return $map
}

$errors = [Collections.Generic.List[string]]::new()
$signatures = [Collections.Generic.List[object]]::new()
$signToolResults = [Collections.Generic.List[object]]::new()
$packageRoot = [IO.Path]::GetFullPath($PackageDirectory).TrimEnd('\')
$symbolsRoot = [IO.Path]::GetFullPath($SymbolsDirectory).TrimEnd('\')
$inputMain = [IO.Path]::GetFullPath($InputPackagePath)
$inputSymbols = [IO.Path]::GetFullPath($InputSymbolsPath)
$outputMain = [IO.Path]::GetFullPath($OutputPackagePath)
$outputSymbols = [IO.Path]::GetFullPath($OutputSymbolsPath)
$provenanceFull = [IO.Path]::GetFullPath($ProvenancePath)

foreach ($directory in @(
    @{ Path = $packageRoot; Leaf = $ExpectedPackageName },
    @{ Path = $symbolsRoot; Leaf = $ExpectedSymbolsName })) {
    if (-not (Test-Path -LiteralPath $directory.Path -PathType Container) -or
        [IO.Path]::GetFileName($directory.Path) -cne $directory.Leaf) {
        $errors.Add("Required package directory is missing or misnamed: $($directory.Leaf)")
    } elseif (Test-PathHasReparsePoint $directory.Path) {
        $errors.Add("Package directory contains a reparse point: $($directory.Leaf)")
    }
}
foreach ($file in @($inputMain, $inputSymbols, $outputMain, $outputSymbols, $provenanceFull)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        $errors.Add("Required bound file is missing: $([IO.Path]::GetFileName($file))")
    } elseif (Test-PathHasReparsePoint $file) {
        $errors.Add("Bound file path contains a reparse point: $([IO.Path]::GetFileName($file))")
    }
}

$expectedInputMain = $ExpectedInputMainSha256.ToLowerInvariant()
$expectedInputSymbols = $ExpectedInputSymbolsSha256.ToLowerInvariant()
if ((Test-Path -LiteralPath $inputMain -PathType Leaf) -and
    (Get-Sha256 $inputMain) -cne $expectedInputMain) {
    $errors.Add('Input main ZIP SHA-256 mismatch.')
}
if ((Test-Path -LiteralPath $inputSymbols -PathType Leaf) -and
    (Get-Sha256 $inputSymbols) -cne $expectedInputSymbols) {
    $errors.Add('Input symbols ZIP SHA-256 mismatch.')
}

$mainManifest = if (Test-Path -LiteralPath $packageRoot -PathType Container) {
    Test-HashManifest $packageRoot
} else { [pscustomobject]@{ Count = 0; Errors = @('main directory missing'); Map = @{} } }
$symbolManifest = if (Test-Path -LiteralPath $symbolsRoot -PathType Container) {
    Test-HashManifest $symbolsRoot
} else { [pscustomobject]@{ Count = 0; Errors = @('symbols directory missing'); Map = @{} } }
foreach ($failure in @($mainManifest.Errors)) { $errors.Add("Main manifest: $failure") }
foreach ($failure in @($symbolManifest.Errors)) { $errors.Add("Symbols manifest: $failure") }

try {
    $mainMetadata = Get-Content -LiteralPath (Join-Path $packageRoot 'BUILD-METADATA.json') `
        -Raw | ConvertFrom-Json
    $symbolsMetadata = Get-Content -LiteralPath (Join-Path $symbolsRoot 'BUILD-METADATA.json') `
        -Raw | ConvertFrom-Json
    if ($mainMetadata.schema -cne 'kdbg.build-metadata.v1' -or
        $mainMetadata.package_name -cne $ExpectedPackageName -or
        $symbolsMetadata.schema -cne 'kdbg.symbols-metadata.v1' -or
        $symbolsMetadata.package_name -cne $ExpectedSymbolsName -or
        [string]$mainMetadata.source_snapshot_sha256 -cne
            [string]$symbolsMetadata.source_snapshot_sha256) {
        $errors.Add('Main/symbol metadata identity or source snapshot mismatch.')
    }
}
catch { $errors.Add("Package metadata is unreadable: $($_.Exception.Message)") }

$script:ResolvedSignTool = Resolve-X64SignTool $SignToolPath
$appFiles = if (Test-Path -LiteralPath $packageRoot -PathType Container) {
    @(Get-ChildItem -LiteralPath $packageRoot -Filter '*.exe' -File -Recurse |
        Sort-Object FullName)
} else { @() }
$requiredAppPaths = @(
    'KDBG.exe', 'KDBGSetup.exe',
    'plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe',
    'tools/kdbg_live_verify.exe', 'tools/kdbg_process_fixture.exe')
$observedAppPaths = @($appFiles | ForEach-Object {
    Get-KdbgRelativePath $packageRoot $_.FullName
})
foreach ($required in $requiredAppPaths) {
    if ($observedAppPaths -cnotcontains $required) {
        $errors.Add("Required application signature target is missing: $required")
    }
}

foreach ($file in $appFiles) {
    $relative = Get-KdbgRelativePath $packageRoot $file.FullName
    $record = Get-ProductionSignatureRecord $file.FullName $relative `
        $ExpectedAppPublisherSubject (Get-AuthenticodeSignature -LiteralPath $file.FullName)
    $signatures.Add($record)
    if (-not (Test-ProductionSignatureRecord $record)) {
        $errors.Add("Application Authenticode/RFC3161 contract failed: $relative")
    }
    $verify = Invoke-SignToolVerify "pa:$relative" @('verify', '/v', '/pa', $file.FullName)
    $signToolResults.Add($verify)
    if (-not $verify.passed) { $errors.Add("SignTool /pa failed: $relative") }
}

$driverTargets = if (Test-Path -LiteralPath (Join-Path $packageRoot 'drivers') -PathType Container) {
    @(Get-ChildItem -LiteralPath (Join-Path $packageRoot 'drivers') -File |
        Where-Object { $_.Extension -in @('.sys', '.cat') } | Sort-Object Name)
} else { @() }
foreach ($file in $driverTargets) {
    $relative = Get-KdbgRelativePath $packageRoot $file.FullName
    $record = Get-ProductionSignatureRecord $file.FullName $relative `
        $ExpectedDriverPublisherSubject (Get-AuthenticodeSignature -LiteralPath $file.FullName)
    $signatures.Add($record)
    if (-not (Test-ProductionSignatureRecord $record)) {
        $errors.Add("Driver Authenticode/RFC3161 contract failed: $relative")
    }
    $policy = if ($file.Extension -ieq '.sys') { '/kp' } else { '/pa' }
    $verify = Invoke-SignToolVerify "$($policy.TrimStart('/')):$relative" `
        @('verify', '/v', $policy, $file.FullName)
    $signToolResults.Add($verify)
    if (-not $verify.passed) { $errors.Add("SignTool $policy failed: $relative") }
}

foreach ($name in @('KDbgDriver', 'KDbgProbe')) {
    $cat = Join-Path $packageRoot "drivers\$name.cat"
    foreach ($extension in @('sys', 'inf')) {
        $member = Join-Path $packageRoot "drivers\$name.$extension"
        if (-not (Test-Path -LiteralPath $cat -PathType Leaf) -or
            -not (Test-Path -LiteralPath $member -PathType Leaf)) {
            $errors.Add("Catalog pair is incomplete: $name.$extension")
            continue
        }
        $relative = "drivers/$name.$extension"
        $verify = Invoke-SignToolVerify "catalog:$relative" `
            @('verify', '/v', '/pa', '/c', $cat, $member)
        $signToolResults.Add($verify)
        if (-not $verify.passed) { $errors.Add("Catalog membership failed: $relative") }
    }
}

try {
    $provenance = Get-Content -LiteralPath $provenanceFull -Raw | ConvertFrom-Json
    if ($provenance.schema -cne 'kdbg.production-signing-provenance.v1') {
        $errors.Add('Production-signing provenance schema mismatch.')
    }
    if ([string]$provenance.input.main_zip_sha256 -cne $expectedInputMain -or
        [string]$provenance.input.symbols_zip_sha256 -cne $expectedInputSymbols) {
        $errors.Add('Provenance input ZIP binding mismatch.')
    }
    if ([string]$provenance.identity.app_publisher_subject -cne
            $ExpectedAppPublisherSubject -or
        [string]$provenance.identity.driver_profile -cne $DriverProfile -or
        [string]$provenance.identity.driver_publisher_subject -cne
            $ExpectedDriverPublisherSubject) {
        $errors.Add('Provenance publisher/profile binding mismatch.')
    }
    if ([string]$provenance.output.main_zip_sha256 -cne (Get-Sha256 $outputMain) -or
        [string]$provenance.output.symbols_zip_sha256 -cne (Get-Sha256 $outputSymbols)) {
        $errors.Add('Provenance output ZIP hash mismatch.')
    }
    $unsignedMap = Get-ProvenanceRecordMap @($provenance.unsigned_inputs)
    $requiredUnsignedPaths = @(
        $requiredAppPaths + @(
            'drivers/KDbgDriver.sys', 'drivers/KDbgDriver.inf', 'drivers/KDbgDriver.cat',
            'drivers/KDbgProbe.sys', 'drivers/KDbgProbe.inf', 'drivers/KDbgProbe.cat'))
    $inputEntryHashes = Get-ZipEntryHashMap `
        $inputMain $ExpectedPackageName $requiredUnsignedPaths
    foreach ($required in $requiredUnsignedPaths) {
        if (-not $unsignedMap.ContainsKey($required)) {
            $errors.Add("Provenance unsigned input is missing: $required")
        } elseif ([string]$unsignedMap[$required].sha256 -cne
            [string]$inputEntryHashes[$required]) {
            $errors.Add("Provenance unsigned-input hash mismatch: $required")
        }
    }
    $signedMap = Get-ProvenanceRecordMap @($provenance.signed_outputs)
    foreach ($record in $signatures) {
        if (-not $signedMap.ContainsKey([string]$record.path) -or
            [string]$signedMap[[string]$record.path].sha256 -cne [string]$record.sha256 -or
            [string]$signedMap[[string]$record.path].signer_subject -cne
                [string]$record.signer_subject -or
            [bool]$signedMap[[string]$record.path].timestamp_present -ne
                [bool]$record.rfc3161_timestamp_present -or
            [string]$signedMap[[string]$record.path].timestamp_subject -cne
                [string]$record.timestamp_subject -or
            [string]$signedMap[[string]$record.path].timestamp_thumbprint -cne
                [string]$record.timestamp_thumbprint) {
            $errors.Add("Provenance signed-output mismatch: $($record.path)")
        }
    }
    $returnedMap = Get-ProvenanceRecordMap @($provenance.returned_driver_files)
    foreach ($relative in @(
        'drivers/KDbgDriver.sys', 'drivers/KDbgDriver.inf', 'drivers/KDbgDriver.cat',
        'drivers/KDbgProbe.sys', 'drivers/KDbgProbe.inf', 'drivers/KDbgProbe.cat')) {
        $path = Join-Path $packageRoot ($relative.Replace('/', '\'))
        if (-not $returnedMap.ContainsKey($relative) -or
            [string]$returnedMap[$relative].sha256 -cne (Get-Sha256 $path)) {
            $errors.Add("Provenance returned-driver mismatch: $relative")
        }
    }
    if (-not (Test-HttpsTimestampUrl ([string]$provenance.identity.timestamp_url))) {
        $errors.Add('Provenance TimestampUrl is not credential-free absolute HTTPS.')
    }
    $resolvedVersion = (Get-Item -LiteralPath $script:ResolvedSignTool).VersionInfo.FileVersion
    if ([string]$provenance.signtool.sha256 -cne (Get-Sha256 $script:ResolvedSignTool) -or
        [string]$provenance.signtool.version -cne [string]$resolvedVersion) {
        $errors.Add('Provenance SignTool hash mismatch.')
    }
}
catch { $errors.Add("Production-signing provenance is invalid: $($_.Exception.Message)") }

$success = $errors.Count -eq 0
$result = [ordered]@{
    schema = 'kdbg.production-signed-package-verification.v2'
    captured_utc = [DateTime]::UtcNow.ToString('o')
    success = $success
    mode = 'read-only'
    mutation_performed = $false
    package_directory = $packageRoot
    symbols_directory = $symbolsRoot
    input_main_zip_sha256 = if (Test-Path -LiteralPath $inputMain) { Get-Sha256 $inputMain } else { $null }
    input_symbols_zip_sha256 = if (Test-Path -LiteralPath $inputSymbols) { Get-Sha256 $inputSymbols } else { $null }
    output_main_zip_sha256 = if (Test-Path -LiteralPath $outputMain) { Get-Sha256 $outputMain } else { $null }
    output_symbols_zip_sha256 = if (Test-Path -LiteralPath $outputSymbols) { Get-Sha256 $outputSymbols } else { $null }
    app_publisher_subject = $ExpectedAppPublisherSubject
    driver_profile = $DriverProfile
    driver_publisher_subject = $ExpectedDriverPublisherSubject
    main_manifest_record_count = $mainManifest.Count
    symbols_manifest_record_count = $symbolManifest.Count
    signatures = @($signatures)
    signtool_path = $script:ResolvedSignTool
    signtool_sha256 = Get-Sha256 $script:ResolvedSignTool
    signtool_verifications = @($signToolResults)
    errors = @($errors)
    production_signature_contract_pass = $success
    clean_guest_install_and_live_validation_required = $true
    commercial_general_availability_proved = $false
    claim_boundary = 'PASS proves exact input/output binding, manifests, publisher/timestamp policy, and SYS+INF catalog membership only. Clean Win10/Win11 runtime and external operations remain separate.'
}
$json = $result | ConvertTo-Json -Depth 16
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputFull = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $outputFull
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [IO.File]::WriteAllText($outputFull, $json + [Environment]::NewLine, $Utf8NoBom)
}
$json
if (-not $success) { exit 2 }

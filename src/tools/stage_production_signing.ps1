[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Prepare', 'Finalize')]
    [string]$Mode,

    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PackagePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedMainSha256,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SymbolsPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedSymbolsSha256,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputDirectory,

    [string]$PreparedDirectory,
    [string]$SignedAppDirectory,
    [string]$ReturnedDriverDirectory,
    [string]$ExpectedAppPublisherSubject,
    [ValidateSet('MicrosoftReturned', 'DirectPublisher')]
    [string]$DriverProfile,
    [string]$ExpectedDriverPublisherSubject,
    [string]$TimestampUrl,
    [string]$SignToolPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
$PackageName = 'KDBG-1.1.0-win-x64'
$SymbolsName = 'KDBG-1.1.0-win-x64-symbols'
$AppPaths = @(
    'KDBG.exe',
    'KDBGSetup.exe',
    'plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe',
    'tools/kdbg_live_verify.exe',
    'tools/kdbg_process_fixture.exe')
$DriverPaths = @(
    'drivers/KDbgDriver.sys', 'drivers/KDbgDriver.inf', 'drivers/KDbgDriver.cat',
    'drivers/KDbgProbe.sys', 'drivers/KDbgProbe.inf', 'drivers/KDbgProbe.cat')

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

function Assert-ExactZip {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$ExpectedRoot)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Exact ZIP is missing: $full"
    }
    if (Test-PathHasReparsePoint $full) { throw 'Exact ZIP path contains a reparse point.' }
    if ((Get-Sha256 $full) -cne $ExpectedSha256.ToLowerInvariant()) {
        throw "Exact ZIP SHA-256 mismatch: $([IO.Path]::GetFileName($full))"
    }
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::OpenRead($full)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            $prefix = $ExpectedRoot + '/'
            foreach ($entry in $archive.Entries) {
                $name = $entry.FullName.Replace('\', '/')
                $parts = @($name -split '/')
                if (-not $name.StartsWith($prefix, [StringComparison]::Ordinal) -or
                    [IO.Path]::IsPathRooted($name) -or $name.Contains(':') -or
                    $parts -contains '..' -or $parts -contains '.') {
                    throw "ZIP contains an unsafe or unexpected entry: $name"
                }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
    return $full
}

function Get-ZipEntryHashes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$RelativePaths)
    Add-Type -AssemblyName System.IO.Compression
    $wanted = @{}
    foreach ($relative in $RelativePaths) { $wanted[$relative] = $true }
    $records = [Collections.Generic.List[object]]::new()
    $stream = [IO.File]::OpenRead($Path)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            foreach ($relative in $RelativePaths) {
                $entry = $archive.GetEntry("$Root/$relative")
                if (-not $entry -or [string]::IsNullOrEmpty($entry.Name)) {
                    throw "ZIP is missing required signing input: $relative"
                }
                $entryStream = $entry.Open()
                try {
                    $hasher = [Security.Cryptography.SHA256]::Create()
                    try {
                        $digest = $hasher.ComputeHash($entryStream)
                    }
                    finally { $hasher.Dispose() }
                }
                finally { $entryStream.Dispose() }
                $records.Add([ordered]@{
                    path = $relative
                    sha256 = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
                    length = [Int64]$entry.Length
                })
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
    return @($records)
}

function Expand-SafeZip {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Destination)
    [IO.Compression.ZipFile]::ExtractToDirectory($Path, $Destination, $false)
}

function Copy-Tree {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination)
    if (Test-PathHasReparsePoint $Source) { throw 'Copy source contains a reparse point.' }
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($directory in Get-ChildItem -LiteralPath $Source -Directory -Recurse) {
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Copy source contains a reparse point: $($directory.FullName)"
        }
        $relative = [IO.Path]::GetRelativePath($Source, $directory.FullName)
        [IO.Directory]::CreateDirectory((Join-Path $Destination $relative)) | Out-Null
    }
    foreach ($file in Get-ChildItem -LiteralPath $Source -File -Recurse) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Copy source contains a reparse point: $($file.FullName)"
        }
        $relative = [IO.Path]::GetRelativePath($Source, $file.FullName)
        $target = Join-Path $Destination $relative
        [IO.Directory]::CreateDirectory((Split-Path -Parent $target)) | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
}

function Write-HashManifest {
    param([Parameter(Mandatory)][string]$Directory)
    $manifest = Join-Path $Directory 'SHA256SUMS.txt'
    $lines = Get-ChildItem -LiteralPath $Directory -File -Recurse |
        Where-Object { $_.FullName -ne $manifest } |
        ForEach-Object {
            [pscustomobject]@{
                Relative = [IO.Path]::GetRelativePath($Directory, $_.FullName).Replace('\', '/')
                FullName = $_.FullName
            }
        } | Sort-Object Relative | ForEach-Object {
            "$(Get-Sha256 $_.FullName)  $($_.Relative)"
        }
    [IO.File]::WriteAllLines($manifest, [string[]]$lines, [Text.Encoding]::ASCII)
}

function New-DeterministicZip {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::Open($ZipPath, [IO.FileMode]::CreateNew)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($file in Get-ChildItem -LiteralPath $Directory -File -Recurse |
                    ForEach-Object {
                        [pscustomobject]@{
                            Relative = [IO.Path]::GetRelativePath($Directory, $_.FullName).Replace('\', '/')
                            FullName = $_.FullName
                        }
                    } | Sort-Object Relative) {
                $entry = $archive.CreateEntry(
                    "$([IO.Path]::GetFileName($Directory))/$($file.Relative)",
                    [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(
                    2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $input = [IO.File]::OpenRead($file.FullName)
                $output = $entry.Open()
                try { $input.CopyTo($output) }
                finally { $output.Dispose(); $input.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Resolve-ReturnedDriverFile {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Name)
    $candidates = @(
        (Join-Path $Directory $Name),
        (Join-Path $Directory "drivers\$Name"))
    $matches = @($candidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -Unique)
    if ($matches.Count -ne 1) {
        throw "Returned driver directory must contain exactly one $Name."
    }
    return [IO.Path]::GetFullPath($matches[0])
}

function Get-SignatureProvenanceRecord {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RelativePath)
    $path = Join-Path $Root ($RelativePath.Replace('/', '\'))
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    return [ordered]@{
        path = $RelativePath
        sha256 = Get-Sha256 $path
        status = $signature.Status.ToString()
        signer_subject = if ($signature.SignerCertificate) {
            [string]$signature.SignerCertificate.Subject
        } else { $null }
        signer_issuer = if ($signature.SignerCertificate) {
            [string]$signature.SignerCertificate.Issuer
        } else { $null }
        timestamp_present = $null -ne $signature.TimeStamperCertificate
        timestamp_subject = if ($signature.TimeStamperCertificate) {
            [string]$signature.TimeStamperCertificate.Subject
        } else { $null }
        timestamp_thumbprint = if ($signature.TimeStamperCertificate) {
            [string]$signature.TimeStamperCertificate.Thumbprint
        } else { $null }
    }
}

$packageFull = Assert-ExactZip $PackagePath $ExpectedMainSha256 $PackageName
$symbolsFull = Assert-ExactZip $SymbolsPath $ExpectedSymbolsSha256 $SymbolsName
$outputFull = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputFull) { throw 'OutputDirectory must not already exist.' }
$outputParent = Split-Path -Parent $outputFull
if ([string]::IsNullOrWhiteSpace($outputParent)) { throw 'OutputDirectory needs a parent.' }
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    [IO.Directory]::CreateDirectory($outputParent) | Out-Null
}
if (Test-PathHasReparsePoint $outputParent) {
    throw 'OutputDirectory parent contains a reparse point.'
}
$stageRoot = Join-Path $outputParent ('.production-signing-staging-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stageRoot) | Out-Null

try {
    if ($Mode -eq 'Prepare') {
        $unsignedRoot = Join-Path $stageRoot 'unsigned'
        [IO.Directory]::CreateDirectory($unsignedRoot) | Out-Null
        Expand-SafeZip $packageFull $unsignedRoot
        Expand-SafeZip $symbolsFull $unsignedRoot
        $unsignedPackage = Join-Path $unsignedRoot $PackageName
        $unsignedSymbols = Join-Path $unsignedRoot $SymbolsName
        $unsignedInputs = @(Get-ZipEntryHashes $packageFull $PackageName `
            ($AppPaths + $DriverPaths))
        $appInput = Join-Path $stageRoot 'app-signing-input'
        foreach ($relative in $AppPaths) {
            $source = Join-Path $unsignedPackage ($relative.Replace('/', '\'))
            $target = Join-Path $appInput ($relative.Replace('/', '\'))
            [IO.Directory]::CreateDirectory((Split-Path -Parent $target)) | Out-Null
            Copy-Item -LiteralPath $source -Destination $target
        }
        $driverInput = Join-Path $stageRoot 'driver-submission-input'
        foreach ($relative in $DriverPaths) {
            $name = [IO.Path]::GetFileName($relative)
            $source = Join-Path $unsignedPackage ($relative.Replace('/', '\'))
            Copy-Item -LiteralPath $source -Destination (
                [IO.Directory]::CreateDirectory($driverInput).FullName + "\$name")
        }
        foreach ($name in @('KDbgDriver.pdb', 'KDbgProbe.pdb')) {
            Copy-Item -LiteralPath (Join-Path $unsignedSymbols "drivers\$name") `
                -Destination (Join-Path $driverInput $name)
        }
        $request = [ordered]@{
            schema = 'kdbg.production-signing-request.v1'
            generated_utc = [DateTime]::UtcNow.ToString('o')
            signing_performed = $false
            network_submission_performed = $false
            input = [ordered]@{
                main_zip_path = $packageFull
                main_zip_sha256 = $ExpectedMainSha256.ToLowerInvariant()
                symbols_zip_path = $symbolsFull
                symbols_zip_sha256 = $ExpectedSymbolsSha256.ToLowerInvariant()
            }
            unsigned_inputs = $unsignedInputs
            app_signing_input_directory = 'app-signing-input'
            driver_submission_input_directory = 'driver-submission-input'
            required_app_paths = $AppPaths
            required_driver_paths = $DriverPaths
            claim_boundary = 'Prepared exact, hash-bound inputs only. No file was signed, timestamped, submitted, installed, or loaded.'
        }
        [IO.File]::WriteAllText(
            (Join-Path $stageRoot 'production-signing-request.json'),
            ($request | ConvertTo-Json -Depth 12) + [Environment]::NewLine,
            $Utf8NoBom)
        Move-Item -LiteralPath $stageRoot -Destination $outputFull
        Write-Host "Prepared production-signing inputs: $outputFull"
        return
    }

    foreach ($required in @(
        @{ Name = 'PreparedDirectory'; Value = $PreparedDirectory },
        @{ Name = 'SignedAppDirectory'; Value = $SignedAppDirectory },
        @{ Name = 'ReturnedDriverDirectory'; Value = $ReturnedDriverDirectory },
        @{ Name = 'ExpectedAppPublisherSubject'; Value = $ExpectedAppPublisherSubject },
        @{ Name = 'DriverProfile'; Value = $DriverProfile },
        @{ Name = 'ExpectedDriverPublisherSubject'; Value = $ExpectedDriverPublisherSubject },
        @{ Name = 'TimestampUrl'; Value = $TimestampUrl })) {
        if ([string]::IsNullOrWhiteSpace([string]$required.Value)) {
            throw "Finalize requires $($required.Name)."
        }
    }
    if (-not (Test-HttpsTimestampUrl $TimestampUrl)) {
        throw 'Finalize requires an absolute credential-free HTTPS TimestampUrl.'
    }
    $preparedFull = [IO.Path]::GetFullPath($PreparedDirectory)
    $signedAppsFull = [IO.Path]::GetFullPath($SignedAppDirectory)
    $returnedDriversFull = [IO.Path]::GetFullPath($ReturnedDriverDirectory)
    foreach ($directory in @($preparedFull, $signedAppsFull, $returnedDriversFull)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container) -or
            (Test-PathHasReparsePoint $directory)) {
            throw "Finalize input directory is missing or unsafe: $directory"
        }
    }
    $requestPath = Join-Path $preparedFull 'production-signing-request.json'
    $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
    if ($request.schema -cne 'kdbg.production-signing-request.v1' -or
        [string]$request.input.main_zip_sha256 -cne $ExpectedMainSha256.ToLowerInvariant() -or
        [string]$request.input.symbols_zip_sha256 -cne $ExpectedSymbolsSha256.ToLowerInvariant()) {
        throw 'Prepared signing request does not match the exact input ZIP pair.'
    }
    $requestMap = @{}
    foreach ($record in @($request.unsigned_inputs)) {
        if ($requestMap.ContainsKey([string]$record.path)) {
            throw 'Prepared signing request contains a duplicate unsigned input.'
        }
        $requestMap[[string]$record.path] = [string]$record.sha256
    }
    $preparedPackage = Join-Path $preparedFull "unsigned\$PackageName"
    $preparedSymbols = Join-Path $preparedFull "unsigned\$SymbolsName"
    foreach ($relative in $AppPaths + $DriverPaths) {
        $path = Join-Path $preparedPackage ($relative.Replace('/', '\'))
        if (-not $requestMap.ContainsKey($relative) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-Sha256 $path) -cne $requestMap[$relative]) {
            throw "Prepared unsigned input changed or is missing: $relative"
        }
    }

    $candidatePackage = Join-Path $stageRoot $PackageName
    $candidateSymbols = Join-Path $stageRoot $SymbolsName
    Copy-Tree $preparedPackage $candidatePackage
    Copy-Tree $preparedSymbols $candidateSymbols
    foreach ($relative in $AppPaths) {
        $source = Join-Path $signedAppsFull ($relative.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Signed application input is missing: $relative"
        }
        Copy-Item -LiteralPath $source -Destination (
            Join-Path $candidatePackage ($relative.Replace('/', '\'))) -Force
    }
    foreach ($relative in $DriverPaths) {
        $name = [IO.Path]::GetFileName($relative)
        $source = Resolve-ReturnedDriverFile $returnedDriversFull $name
        Copy-Item -LiteralPath $source -Destination (
            Join-Path $candidatePackage ($relative.Replace('/', '\'))) -Force
    }

    $metadataPath = Join-Path $candidatePackage 'BUILD-METADATA.json'
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json -AsHashtable
    $metadata['signature_claim'] = 'production-signature contract must be verified against sibling provenance/report'
    $metadata['production_signing'] = [ordered]@{
        schema = 'kdbg.production-signing-binding.v1'
        input_main_zip_sha256 = $ExpectedMainSha256.ToLowerInvariant()
        input_symbols_zip_sha256 = $ExpectedSymbolsSha256.ToLowerInvariant()
        app_publisher_subject = $ExpectedAppPublisherSubject
        driver_profile = $DriverProfile
        driver_publisher_subject = $ExpectedDriverPublisherSubject
    }
    [IO.File]::WriteAllText(
        $metadataPath, ($metadata | ConvertTo-Json -Depth 12) + [Environment]::NewLine,
        $Utf8NoBom)
    Write-HashManifest $candidatePackage
    Write-HashManifest $candidateSymbols

    $mainZip = Join-Path $stageRoot "$PackageName.zip"
    $symbolsZip = Join-Path $stageRoot "$SymbolsName.zip"
    New-DeterministicZip $candidatePackage $mainZip
    New-DeterministicZip $candidateSymbols $symbolsZip
    $mainOutputHash = Get-Sha256 $mainZip
    $symbolsOutputHash = Get-Sha256 $symbolsZip
    [IO.File]::WriteAllText("$mainZip.sha256", "$mainOutputHash  $PackageName.zip`r`n", [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText("$symbolsZip.sha256", "$symbolsOutputHash  $SymbolsName.zip`r`n", [Text.Encoding]::ASCII)

    $resolvedSignTool = & {
        if (-not [string]::IsNullOrWhiteSpace($SignToolPath)) {
            return [IO.Path]::GetFullPath($SignToolPath)
        }
        $candidate = Get-ChildItem -LiteralPath 'C:\Program Files (x86)\Windows Kits\10\bin' `
            -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if (-not $candidate) { throw 'An x64 Windows SDK SignTool is required.' }
        return $candidate.FullName
    }
    if (-not (Test-Path -LiteralPath $resolvedSignTool -PathType Leaf) -or
        $resolvedSignTool -notmatch '\\x64\\signtool\.exe$') {
        throw 'SignToolPath must identify an existing x64 Windows SDK signtool.exe.'
    }
    $signedOutputRecords = @(
        foreach ($relative in $AppPaths + @(
            'drivers/KDbgDriver.sys', 'drivers/KDbgDriver.cat',
            'drivers/KDbgProbe.sys', 'drivers/KDbgProbe.cat')) {
            Get-SignatureProvenanceRecord $candidatePackage $relative
        })
    $returnedRecords = @(
        foreach ($relative in $DriverPaths) {
            $path = Join-Path $candidatePackage ($relative.Replace('/', '\'))
            [ordered]@{ path = $relative; sha256 = Get-Sha256 $path; length = (Get-Item $path).Length }
        })
    $toolVersion = (Get-Item -LiteralPath $resolvedSignTool).VersionInfo.FileVersion
    $provenance = [ordered]@{
        schema = 'kdbg.production-signing-provenance.v1'
        generated_utc = [DateTime]::UtcNow.ToString('o')
        input = [ordered]@{
            main_zip_sha256 = $ExpectedMainSha256.ToLowerInvariant()
            symbols_zip_sha256 = $ExpectedSymbolsSha256.ToLowerInvariant()
        }
        identity = [ordered]@{
            app_publisher_subject = $ExpectedAppPublisherSubject
            driver_profile = $DriverProfile
            driver_publisher_subject = $ExpectedDriverPublisherSubject
            timestamp_url = ([Uri]$TimestampUrl).AbsoluteUri
        }
        unsigned_inputs = @($request.unsigned_inputs)
        returned_driver_files = $returnedRecords
        signed_outputs = $signedOutputRecords
        signtool = [ordered]@{
            version = $toolVersion
            sha256 = Get-Sha256 $resolvedSignTool
        }
        output = [ordered]@{
            main_zip = "$PackageName.zip"
            main_zip_sha256 = $mainOutputHash
            symbols_zip = "$SymbolsName.zip"
            symbols_zip_sha256 = $symbolsOutputHash
        }
        private_key_material_recorded = $false
        claim_boundary = 'Credential-free provenance for exact signed artifacts. External service approval and clean-guest runtime remain separate.'
    }
    $provenancePath = Join-Path $stageRoot 'production-signing-provenance.json'
    [IO.File]::WriteAllText(
        $provenancePath, ($provenance | ConvertTo-Json -Depth 16) + [Environment]::NewLine,
        $Utf8NoBom)

    $verifyScript = Join-Path $PSScriptRoot 'verify_production_signed_package.ps1'
    $verificationPath = Join-Path $stageRoot 'production-signing-verification.json'
    & $verifyScript `
        -PackageDirectory $candidatePackage `
        -SymbolsDirectory $candidateSymbols `
        -InputPackagePath $packageFull `
        -ExpectedInputMainSha256 $ExpectedMainSha256 `
        -InputSymbolsPath $symbolsFull `
        -ExpectedInputSymbolsSha256 $ExpectedSymbolsSha256 `
        -OutputPackagePath $mainZip `
        -OutputSymbolsPath $symbolsZip `
        -ProvenancePath $provenancePath `
        -ExpectedAppPublisherSubject $ExpectedAppPublisherSubject `
        -DriverProfile $DriverProfile `
        -ExpectedDriverPublisherSubject $ExpectedDriverPublisherSubject `
        -SignToolPath $resolvedSignTool `
        -OutputPath $verificationPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Production-signed candidate verification failed.' }

    Move-Item -LiteralPath $stageRoot -Destination $outputFull
    & $verifyScript `
        -PackageDirectory (Join-Path $outputFull $PackageName) `
        -SymbolsDirectory (Join-Path $outputFull $SymbolsName) `
        -InputPackagePath $packageFull `
        -ExpectedInputMainSha256 $ExpectedMainSha256 `
        -InputSymbolsPath $symbolsFull `
        -ExpectedInputSymbolsSha256 $ExpectedSymbolsSha256 `
        -OutputPackagePath (Join-Path $outputFull "$PackageName.zip") `
        -OutputSymbolsPath (Join-Path $outputFull "$SymbolsName.zip") `
        -ProvenancePath (Join-Path $outputFull 'production-signing-provenance.json') `
        -ExpectedAppPublisherSubject $ExpectedAppPublisherSubject `
        -DriverProfile $DriverProfile `
        -ExpectedDriverPublisherSubject $ExpectedDriverPublisherSubject `
        -SignToolPath $resolvedSignTool `
        -OutputPath (Join-Path $outputFull 'production-signing-verification.json') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Published production-signed candidate re-verification failed.' }
    Write-Host "Verified production-signed candidate: $outputFull"
}
finally {
    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
}

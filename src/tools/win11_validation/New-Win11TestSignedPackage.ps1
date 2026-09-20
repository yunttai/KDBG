<#
.SYNOPSIS
Builds a hash-bound, disposable-VM-only test-signed KDBG package derivative.

.DESCRIPTION
Validates an exact unsigned main/symbols ZIP pair and their common source
snapshot. Build mode signs only KDbgDriver.sys, KDbgProbe.sys, and their newly
generated catalogs. It does not install or load a driver and does not touch a
VM. The output is test trust only and is not a production release.

.EXAMPLE
./New-Win11TestSignedPackage.ps1 -UnsignedPackagePath ./KDBG-1.1.0-win-x64.zip `
  -ExpectedUnsignedPackageSha256 $mainSha -SymbolsPackagePath ./KDBG-1.1.0-win-x64-symbols.zip `
  -ExpectedSymbolsPackageSha256 $symbolsSha -ExpectedSourceSnapshotSha256 $sourceSha `
  -OutputRoot D:/KDBG/out/release-epochs -EpochName win11-test-final -PreflightOnly

.EXAMPLE
$password = Read-Host 'PFX password' -AsSecureString
./New-Win11TestSignedPackage.ps1 -UnsignedPackagePath $mainZip `
  -ExpectedUnsignedPackageSha256 $mainSha -SymbolsPackagePath $symbolsZip `
  -ExpectedSymbolsPackageSha256 $symbolsSha -ExpectedSourceSnapshotSha256 $sourceSha `
  -OutputRoot $safeRoot -EpochName win11-test-final -CertificatePath $cer `
  -PfxPath $pfx -PfxPassword $password
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$UnsignedPackagePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedUnsignedPackageSha256,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SymbolsPackagePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedSymbolsPackageSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedSourceSnapshotSha256,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputRoot,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$EpochName,

    [string]$CertificatePath,
    [string]$PfxPath,
    [Security.SecureString]$PfxPassword,
    [string]$PfxPasswordFilePath,
    [string]$SignToolPath,
    [string]$Inf2CatPath,
    [ValidatePattern('^[A-Za-z0-9_,]+$')][string]$Inf2CatOs = '10_X64',
    [switch]$PreflightOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PackageRootName = 'KDBG-1.1.0-win-x64'
$SymbolsRootName = 'KDBG-1.1.0-win-x64-symbols'
$SignedRelativePaths = @(
    'drivers/KDbgDriver.sys',
    'drivers/KDbgProbe.sys',
    'drivers/KDbgDriver.cat',
    'drivers/KDbgProbe.cat'
)
$RequiredPackagePaths = @(
    'BUILD-METADATA.json',
    'SHA256SUMS.txt',
    'KDBG.exe',
    'KDBGSetup.exe',
    'plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe',
    'tools/kdbg_live_verify.exe',
    'tools/kdbg_process_fixture.exe',
    'drivers/KDbgDriver.sys',
    'drivers/KDbgProbe.sys',
    'drivers/KDbgDriver.inf',
    'drivers/KDbgProbe.inf',
    'drivers/KDbgDriver.cat',
    'drivers/KDbgProbe.cat'
)
$RequiredSymbolsPaths = @(
    'BUILD-METADATA.json',
    'SHA256SUMS.txt',
    'drivers/KDbgDriver.pdb',
    'drivers/KDbgProbe.pdb'
)
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
$Ascii = [Text.Encoding]::ASCII

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Get-RelativePathCompat {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path
    )
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $pathFull = [IO.Path]::GetFullPath($Path)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is not under root: $Path"
    }
    return $pathFull.Substring($prefix.Length)
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
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $false
}

function Assert-LeafInput {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "$Label is missing: $full"
    }
    if (Test-PathHasReparsePoint $full) {
        throw "$Label path contains a reparse point."
    }
    return $full
}

function Get-SafeEpochPaths {
    $root = [IO.Path]::GetFullPath($OutputRoot)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "OutputRoot must be an existing directory: $root"
    }
    if (Test-PathHasReparsePoint $root) {
        throw 'OutputRoot or one of its ancestors contains a reparse point.'
    }
    $epoch = [IO.Path]::GetFullPath((Join-Path $root $EpochName))
    $rootForComparison = if ($root.Length -gt [IO.Path]::GetPathRoot($root).Length) {
        $root.TrimEnd([IO.Path]::DirectorySeparatorChar)
    } else { $root }
    if (-not [IO.Path]::GetDirectoryName($epoch).Equals(
            $rootForComparison,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'EpochName must resolve to a direct child of OutputRoot.'
    }
    if (Test-Path -LiteralPath $epoch) {
        throw "Refusing to overwrite an existing test-signing epoch: $epoch"
    }
    return [pscustomobject]@{ Root = $root; Epoch = $epoch }
}

function Open-ValidatedZip {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$ExpectedRoot,
        [Parameter(Mandatory)][string[]]$RequiredPaths)

    $full = Assert-LeafInput $Path 'Exact ZIP input'
    $actualHash = Get-Sha256 $full
    if ($actualHash -cne $ExpectedSha256.ToLowerInvariant()) {
        throw "Exact ZIP SHA-256 mismatch: $([IO.Path]::GetFileName($full))"
    }

    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::OpenRead($full)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $entries = @{}
        $prefix = "$ExpectedRoot/"
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            $parts = @($name -split '/')
            if ([string]::IsNullOrWhiteSpace($name) -or
                -not $name.StartsWith($prefix, [StringComparison]::Ordinal) -or
                [IO.Path]::IsPathRooted($name) -or $name.Contains(':') -or
                $parts -contains '..' -or $parts -contains '.') {
                throw "ZIP contains an unsafe or unexpected entry: $name"
            }
            if (-not $seen.Add($name)) {
                throw "ZIP contains a duplicate path: $name"
            }
            if (-not [string]::IsNullOrEmpty($entry.Name)) {
                $relative = $name.Substring($prefix.Length)
                $entries[$relative] = $entry
            }
        }
        foreach ($required in $RequiredPaths) {
            if (-not $entries.ContainsKey($required)) {
                throw "ZIP is missing required content: $ExpectedRoot/$required"
            }
        }
        return [pscustomobject]@{
            Path = $full
            Sha256 = $actualHash
            Stream = $stream
            Archive = $archive
            Entries = $entries
            Root = $ExpectedRoot
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Close-ValidatedZip {
    param([Parameter(Mandatory)]$Zip)
    $Zip.Archive.Dispose()
    $Zip.Stream.Dispose()
}

function Get-ZipEntryBytes {
    param([Parameter(Mandatory)]$Zip, [Parameter(Mandatory)][string]$RelativePath)
    $entryStream = $Zip.Entries[$RelativePath].Open()
    $memory = [IO.MemoryStream]::new()
    try {
        $entryStream.CopyTo($memory)
        return $memory.ToArray()
    }
    finally {
        $memory.Dispose()
        $entryStream.Dispose()
    }
}

function Assert-ZipManifest {
    param([Parameter(Mandatory)]$Zip)
    $manifestText = $Ascii.GetString((Get-ZipEntryBytes $Zip 'SHA256SUMS.txt'))
    $declared = @{}
    foreach ($line in @($manifestText -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^([0-9a-f]{64})  ([^\\].*)$') {
            throw "Invalid SHA256SUMS entry in $($Zip.Root)."
        }
        $relative = $Matches[2].Replace('\', '/')
        if ($relative -ceq 'SHA256SUMS.txt' -or $declared.ContainsKey($relative)) {
            throw "Unsafe or duplicate SHA256SUMS entry in $($Zip.Root): $relative"
        }
        $declared[$relative] = $Matches[1]
    }
    $actualPaths = @($Zip.Entries.Keys | Where-Object { $_ -cne 'SHA256SUMS.txt' })
    if ($declared.Count -ne $actualPaths.Count) {
        throw "SHA256SUMS coverage mismatch in $($Zip.Root)."
    }
    foreach ($relative in $actualPaths) {
        if (-not $declared.ContainsKey($relative)) {
            throw "SHA256SUMS does not cover $($Zip.Root)/$relative"
        }
        if ((Get-BytesSha256 (Get-ZipEntryBytes $Zip $relative)) -cne $declared[$relative]) {
            throw "SHA256SUMS hash mismatch in $($Zip.Root): $relative"
        }
    }
}

function Get-ZipSourceSnapshot {
    param([Parameter(Mandatory)]$Zip)
    $metadataText = $Utf8NoBom.GetString((Get-ZipEntryBytes $Zip 'BUILD-METADATA.json'))
    $metadata = $metadataText | ConvertFrom-Json
    $declared = [string]$metadata.source_snapshot_sha256
    if ($declared -notmatch '^[0-9a-f]{64}$') {
        throw "Source snapshot metadata is missing or invalid in $($Zip.Root)."
    }
    if ($Zip.Entries.ContainsKey('SOURCE-SNAPSHOT.sha256')) {
        $manifestDigest = Get-BytesSha256 (Get-ZipEntryBytes $Zip 'SOURCE-SNAPSHOT.sha256')
        if ($declared -cne $manifestDigest) {
            throw "Source snapshot metadata/manifest mismatch in $($Zip.Root)."
        }
    }
    return $declared
}

function Expand-ValidatedZip {
    param(
        [Parameter(Mandatory)]$Zip,
        [Parameter(Mandatory)][string]$Destination)
    $destinationFull = [IO.Path]::GetFullPath($Destination)
    [IO.Directory]::CreateDirectory($destinationFull) | Out-Null
    $prefix = $destinationFull.TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    foreach ($entry in $Zip.Archive.Entries) {
        $relative = $entry.FullName.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $target = [IO.Path]::GetFullPath((Join-Path $destinationFull $relative))
        if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Validated ZIP entry escaped its extraction root.'
        }
        if ([string]::IsNullOrEmpty($entry.Name)) {
            [IO.Directory]::CreateDirectory($target) | Out-Null
            continue
        }
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
        $input = $entry.Open()
        $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        try { $input.CopyTo($output) }
        finally { $output.Dispose(); $input.Dispose() }
    }
}

function Get-TreeHashMap {
    param([Parameter(Mandatory)][string]$Directory)
    $map = @{}
    foreach ($file in Get-ChildItem -LiteralPath $Directory -Recurse -File) {
        $relative = (Get-RelativePathCompat $Directory $file.FullName).Replace('\', '/')
        $map[$relative] = Get-Sha256 $file.FullName
    }
    return $map
}

function Write-HashManifest {
    param([Parameter(Mandatory)][string]$Directory)
    $manifestPath = Join-Path $Directory 'SHA256SUMS.txt'
    $relativePaths = [string[]]@(Get-ChildItem -LiteralPath $Directory -Recurse -File |
        Where-Object { -not $_.FullName.Equals($manifestPath, [StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object { (Get-RelativePathCompat $Directory $_.FullName).Replace('\', '/') })
    [Array]::Sort($relativePaths, [StringComparer]::Ordinal)
    $lines = foreach ($relative in $relativePaths) {
        "$(Get-Sha256 (Join-Path $Directory ($relative.Replace('/', '\'))))  $relative"
    }
    [IO.File]::WriteAllText($manifestPath, (($lines -join "`n") + "`n"), $Ascii)
    return $manifestPath
}

function New-DeterministicZip {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression
    $relativePaths = [string[]]@(Get-ChildItem -LiteralPath $Directory -Recurse -File |
        ForEach-Object { (Get-RelativePathCompat $Directory $_.FullName).Replace('\', '/') })
    [Array]::Sort($relativePaths, [StringComparer]::Ordinal)
    $stream = [IO.File]::Open($ZipPath, [IO.FileMode]::CreateNew)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($relative in $relativePaths) {
                $entry = $archive.CreateEntry(
                    "$([IO.Path]::GetFileName($Directory))/$relative",
                    [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(
                    2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $input = [IO.File]::OpenRead((Join-Path $Directory ($relative.Replace('/', '\'))))
                $output = $entry.Open()
                try { $input.CopyTo($output) }
                finally { $output.Dispose(); $input.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Resolve-SigningTool {
    param(
        [string]$ExplicitPath,
        [Parameter(Mandatory)][string]$Name,
        [switch]$RequireX64)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        return Assert-LeafInput $ExplicitPath $Name
    }
    $candidates = [Collections.Generic.List[string]]::new()
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $command) { $candidates.Add($command.Source) }
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kitsRoot -PathType Container) {
        foreach ($candidate in Get-ChildItem -LiteralPath $kitsRoot -Filter $Name -File -Recurse -ErrorAction SilentlyContinue) {
            if (-not $RequireX64 -or $candidate.FullName -match '\\x64\\signtool\.exe$') {
                $candidates.Add($candidate.FullName)
            }
        }
    }
    $ordered = [string[]]@($candidates | Select-Object -Unique)
    [Array]::Sort($ordered, [StringComparer]::OrdinalIgnoreCase)
    [Array]::Reverse($ordered)
    if ($ordered.Count -eq 0) {
        throw "$Name was not found; pass its explicit path."
    }
    return Assert-LeafInput $ordered[0] $Name
}

function Invoke-CheckedTool {
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Operation)
    $toolOutput = @(& $Tool @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    foreach ($line in $toolOutput) { Write-Host $line }
    if ($exitCode -ne 0) {
        throw "$Operation failed with exit code $exitCode."
    }
}

function Assert-ExactTestSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedThumbprint)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($null -eq $signature.SignerCertificate -or
        $signature.Status -eq [Management.Automation.SignatureStatus]::NotSigned -or
        $signature.SignerCertificate.Thumbprint.ToLowerInvariant() -cne $ExpectedThumbprint) {
        throw "Missing or unexpected test signature: $Path"
    }
    return [ordered]@{
        path = $null
        sha256 = Get-Sha256 $Path
        status_on_build_host = $signature.Status.ToString()
        signer_subject = $signature.SignerCertificate.Subject
        signer_thumbprint = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
        timestamp_present = $null -ne $signature.TimeStamperCertificate
    }
}

$epochPaths = Get-SafeEpochPaths
$mainZip = $null
$symbolsZip = $null
try {
    $mainZip = Open-ValidatedZip $UnsignedPackagePath $ExpectedUnsignedPackageSha256 `
        $PackageRootName $RequiredPackagePaths
    $symbolsZip = Open-ValidatedZip $SymbolsPackagePath $ExpectedSymbolsPackageSha256 `
        $SymbolsRootName $RequiredSymbolsPaths
    Assert-ZipManifest $mainZip
    Assert-ZipManifest $symbolsZip
    $mainSnapshot = Get-ZipSourceSnapshot $mainZip
    $symbolsSnapshot = Get-ZipSourceSnapshot $symbolsZip
    $expectedSnapshot = $ExpectedSourceSnapshotSha256.ToLowerInvariant()
    if ($mainSnapshot -cne $expectedSnapshot -or $symbolsSnapshot -cne $expectedSnapshot) {
        throw 'The exact main/symbols ZIP pair does not match ExpectedSourceSnapshotSha256.'
    }

    if ($PreflightOnly) {
        [ordered]@{
            schema = 'kdbg.win11-test-signing-preflight.v1'
            passed = $true
            mutations_performed = $false
            signing_performed = $false
            vm_touched = $false
            output_epoch_would_be = $epochPaths.Epoch
            source_snapshot_sha256 = $expectedSnapshot
            unsigned_package_sha256 = $mainZip.Sha256
            symbols_package_sha256 = $symbolsZip.Sha256
            only_signable_paths = $SignedRelativePaths
            claim_boundary = 'Preflight only. Disposable VM test trust; not production signing or a commercial release.'
        } | ConvertTo-Json -Depth 8
        return
    }

    foreach ($required in @(
        @{ Name = 'CertificatePath'; Value = $CertificatePath },
        @{ Name = 'PfxPath'; Value = $PfxPath })) {
        if ([string]::IsNullOrWhiteSpace([string]$required.Value)) {
            throw "Build mode requires $($required.Name)."
        }
    }
    if (($null -eq $PfxPassword) -eq [string]::IsNullOrWhiteSpace($PfxPasswordFilePath)) {
        throw 'Build mode requires exactly one of PfxPassword or PfxPasswordFilePath.'
    }

    $certificateFull = Assert-LeafInput $CertificatePath 'Public test certificate'
    $pfxFull = Assert-LeafInput $PfxPath 'Test-signing PFX'
    $signToolFull = Resolve-SigningTool $SignToolPath 'signtool.exe' -RequireX64
    $inf2CatFull = Resolve-SigningTool $Inf2CatPath 'Inf2Cat.exe'
    $securePassword = $PfxPassword
    if ($null -eq $securePassword) {
        $passwordFileFull = Assert-LeafInput $PfxPasswordFilePath 'PFX password input'
        $passwordTextFromFile = (Get-Content -LiteralPath $passwordFileFull -Raw).TrimEnd("`r", "`n")
        $securePassword = ConvertTo-SecureString $passwordTextFromFile -AsPlainText -Force
        $passwordTextFromFile = $null
    }

    $publicCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateFull)
    $pfxCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $pfxFull, $securePassword,
        [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    try {
        $thumbprint = $publicCertificate.Thumbprint.ToLowerInvariant()
        if ($pfxCertificate.Thumbprint.ToLowerInvariant() -cne $thumbprint -or
            -not $pfxCertificate.HasPrivateKey) {
            throw 'The PFX private key does not match the public test certificate.'
        }
        if ($publicCertificate.Subject -cne $publicCertificate.Issuer) {
            throw 'The VM-only test certificate must be self-signed.'
        }
        $now = [DateTime]::Now
        if ($now -lt $publicCertificate.NotBefore -or $now -gt $publicCertificate.NotAfter) {
            throw 'The VM-only test certificate is not currently valid.'
        }
        $codeSigningOid = '1.3.6.1.5.5.7.3.3'
        $hasCodeSigningEku = $false
        foreach ($extension in $publicCertificate.Extensions) {
            if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                foreach ($usage in $extension.EnhancedKeyUsages) {
                    if ($usage.Value -ceq $codeSigningOid) { $hasCodeSigningEku = $true }
                }
            }
        }
        if (-not $hasCodeSigningEku) {
            throw 'The VM-only test certificate lacks the Code Signing EKU.'
        }

        $stagingRoot = Join-Path $epochPaths.Root ('.' + $EpochName + '.staging-' + [Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($stagingRoot) | Out-Null
        try {
            $stageDirectory = Join-Path $stagingRoot 'stage'
            Expand-ValidatedZip $mainZip $stageDirectory
            $packageRoot = Join-Path $stageDirectory $PackageRootName
            $before = Get-TreeHashMap $packageRoot
            $driversRoot = Join-Path $packageRoot 'drivers'

            $bstr = [IntPtr]::Zero
            $plainPassword = $null
            try {
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                foreach ($name in @('KDbgDriver.sys', 'KDbgProbe.sys')) {
                    Invoke-CheckedTool $signToolFull @(
                        'sign', '/fd', 'sha256', '/f', $pfxFull, '/p', $plainPassword,
                        (Join-Path $driversRoot $name)) "SignTool signing $name"
                }
                foreach ($name in @('KDbgDriver.cat', 'KDbgProbe.cat')) {
                    Remove-Item -LiteralPath (Join-Path $driversRoot $name) -Force
                }
                Invoke-CheckedTool $inf2CatFull @(
                    "/driver:$driversRoot", "/os:$Inf2CatOs", '/verbose') 'Inf2Cat catalog generation'
                foreach ($name in @('KDbgDriver', 'KDbgProbe')) {
                    $matches = @(Get-ChildItem -LiteralPath $driversRoot -File | Where-Object {
                        $_.Name.Equals("$name.cat", [StringComparison]::OrdinalIgnoreCase)
                    })
                    if ($matches.Count -ne 1) {
                        throw "Inf2Cat did not generate exactly one $name.cat."
                    }
                    $exact = Join-Path $driversRoot "$name.cat"
                    if (-not $matches[0].FullName.Equals($exact, [StringComparison]::Ordinal)) {
                        $temporary = Join-Path $driversRoot "$name.case-normalization.tmp"
                        Move-Item -LiteralPath $matches[0].FullName -Destination $temporary
                        Move-Item -LiteralPath $temporary -Destination $exact
                    }
                    Invoke-CheckedTool $signToolFull @(
                        'sign', '/fd', 'sha256', '/f', $pfxFull, '/p', $plainPassword,
                        $exact) "SignTool signing $name.cat"
                }
            }
            finally {
                $plainPassword = $null
                if ($bstr -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            }

            $signatureRecords = @()
            foreach ($relative in $SignedRelativePaths) {
                $record = Assert-ExactTestSignature `
                    (Join-Path $packageRoot ($relative.Replace('/', '\'))) $thumbprint
                $record.path = $relative
                $signatureRecords += $record
            }

            $afterSigning = Get-TreeHashMap $packageRoot
            $allowedChanges = @{}
            foreach ($relative in $SignedRelativePaths + @('SHA256SUMS.txt')) {
                $allowedChanges[$relative] = $true
            }
            foreach ($relative in $before.Keys) {
                if (-not $afterSigning.ContainsKey($relative)) {
                    throw "Test signing unexpectedly removed package content: $relative"
                }
                if (-not $allowedChanges.ContainsKey($relative) -and
                    $before[$relative] -cne $afterSigning[$relative]) {
                    throw "Test signing unexpectedly changed non-driver content: $relative"
                }
            }
            foreach ($relative in $afterSigning.Keys) {
                if (-not $before.ContainsKey($relative)) {
                    throw "Test signing unexpectedly added package content: $relative"
                }
            }

            $manifestPath = Write-HashManifest $packageRoot
            $packageDirectory = Join-Path $stagingRoot 'package'
            [IO.Directory]::CreateDirectory($packageDirectory) | Out-Null
            $derivedZipPath = Join-Path $packageDirectory "$PackageRootName.zip"
            New-DeterministicZip $packageRoot $derivedZipPath
            $derivedHash = Get-Sha256 $derivedZipPath
            [IO.File]::WriteAllText(
                "$derivedZipPath.sha256", "$derivedHash  $PackageRootName.zip`n", $Ascii)

            $symbolsOutputPath = Join-Path $packageDirectory "$SymbolsRootName.zip"
            Copy-Item -LiteralPath $symbolsZip.Path -Destination $symbolsOutputPath
            $symbolsOutputHash = Get-Sha256 $symbolsOutputPath
            if ($symbolsOutputHash -cne $symbolsZip.Sha256) {
                throw 'The paired symbols ZIP changed while being copied.'
            }
            [IO.File]::WriteAllText(
                "$symbolsOutputPath.sha256", "$symbolsOutputHash  $SymbolsRootName.zip`n", $Ascii)

            $provenance = [ordered]@{
                schema = 'kdbg.win11-test-signing-provenance.v2'
                generated_utc = [DateTime]::UtcNow.ToString('o')
                epoch = $EpochName
                release_package = $false
                production_trust = $false
                purpose = 'Disposable Windows 11 VM validation with test-signing enabled.'
                source_snapshot_sha256 = $expectedSnapshot
                unsigned_package = [ordered]@{
                    file_name = [IO.Path]::GetFileName($mainZip.Path)
                    sha256 = $mainZip.Sha256
                }
                symbols_package = [ordered]@{
                    file_name = [IO.Path]::GetFileName($symbolsZip.Path)
                    sha256 = $symbolsZip.Sha256
                    derivative_copy_sha256 = $symbolsOutputHash
                    content_preserved = $true
                }
                derivative_package = [ordered]@{
                    file_name = [IO.Path]::GetFileName($derivedZipPath)
                    sha256 = $derivedHash
                    manifest_sha256 = Get-Sha256 $manifestPath
                    file_count = (Get-TreeHashMap $packageRoot).Count
                }
                certificate = [ordered]@{
                    file_name = [IO.Path]::GetFileName($certificateFull)
                    sha256 = Get-Sha256 $certificateFull
                    subject = $publicCertificate.Subject
                    issuer = $publicCertificate.Issuer
                    thumbprint = $thumbprint
                    self_signed = $true
                }
                tools = [ordered]@{
                    signtool_file_version = [Diagnostics.FileVersionInfo]::GetVersionInfo($signToolFull).FileVersion
                    inf2cat_file_version = [Diagnostics.FileVersionInfo]::GetVersionInfo($inf2CatFull).FileVersion
                    inf2cat_os = $Inf2CatOs
                }
                signatures = $signatureRecords
                signable_paths = $SignedRelativePaths
                signed_application_binaries = $false
                unsigned_application_binaries_preserved = $true
                catalog_order = 'sign SYS, regenerate CAT from signed SYS, sign CAT'
                claim_boundary = 'VM-only test trust. Not production signed, not redistributable as a trusted commercial release.'
            }
            $provenancePath = Join-Path $stagingRoot 'test-signing-provenance.json'
            [IO.File]::WriteAllText(
                $provenancePath,
                (($provenance | ConvertTo-Json -Depth 12) + [Environment]::NewLine),
                $Utf8NoBom)

            Move-Item -LiteralPath $stagingRoot -Destination $epochPaths.Epoch
            $stagingRoot = $null
            $provenance | ConvertTo-Json -Depth 12
        }
        finally {
            if (-not [string]::IsNullOrWhiteSpace($stagingRoot) -and
                (Test-Path -LiteralPath $stagingRoot)) {
                Remove-Item -LiteralPath $stagingRoot -Recurse -Force
            }
        }
    }
    finally {
        $pfxCertificate.Dispose()
        $publicCertificate.Dispose()
        $securePassword = $null
    }
}
finally {
    if ($null -ne $symbolsZip) { Close-ValidatedZip $symbolsZip }
    if ($null -ne $mainZip) { Close-ValidatedZip $mainZip }
}

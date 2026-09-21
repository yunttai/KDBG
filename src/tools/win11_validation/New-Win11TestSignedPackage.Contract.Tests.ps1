[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptUnderTest = Join-Path $PSScriptRoot 'New-Win11TestSignedPackage.ps1'
$Ascii = [Text.Encoding]::ASCII
$Utf8NoBom = [Text.UTF8Encoding]::new($false)
$Assertions = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-BytesSha256 {
    param([byte[]]$Bytes)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $hasher.Dispose() }
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

function Write-FixtureFile {
    param([string]$Root, [string]$Relative, [byte[]]$Bytes)
    $path = Join-Path $Root ($Relative.Replace('/', '\'))
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
    [IO.File]::WriteAllBytes($path, $Bytes)
}

function Write-FixtureManifest {
    param([string]$Root)
    $manifest = Join-Path $Root 'SHA256SUMS.txt'
    $relativePaths = [string[]]@(Get-ChildItem -LiteralPath $Root -Recurse -File |
        Where-Object { $_.FullName -ne $manifest } |
        ForEach-Object { (Get-RelativePathCompat $Root $_.FullName).Replace('\', '/') })
    [Array]::Sort($relativePaths, [StringComparer]::Ordinal)
    $lines = foreach ($relative in $relativePaths) {
        "$(Get-Sha256 (Join-Path $Root ($relative.Replace('/', '\'))))  $relative"
    }
    [IO.File]::WriteAllText($manifest, (($lines -join "`n") + "`n"), $Ascii)
}

function New-FixtureZip {
    param([string]$Root, [string]$Path)
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($file in Get-ChildItem -LiteralPath $Root -Recurse -File) {
                $relative = (Get-RelativePathCompat $Root $file.FullName).Replace('\', '/')
                $entry = $archive.CreateEntry(
                    "$([IO.Path]::GetFileName($Root))/$relative",
                    [IO.Compression.CompressionLevel]::Optimal)
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

function Assert-ThrowsLike {
    param([scriptblock]$Action, [string]$Pattern)
    $script:Assertions++
    try {
        & $Action
        throw 'Expected the action to fail.'
    }
    catch {
        if ($_.Exception.Message -notlike $Pattern) {
            throw "Unexpected failure. Expected '$Pattern', got '$($_.Exception.Message)'"
        }
    }
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('kdbg-win11-signing-contract-' + [Guid]::NewGuid().ToString('N'))
try {
    $fixtureRoot = Join-Path $temporaryRoot 'fixture'
    $outputRoot = Join-Path $temporaryRoot 'output'
    $mainRoot = Join-Path $fixtureRoot 'KDBG-1.1.0-win-x64'
    $symbolsRoot = Join-Path $fixtureRoot 'KDBG-1.1.0-win-x64-symbols'
    [IO.Directory]::CreateDirectory($mainRoot) | Out-Null
    [IO.Directory]::CreateDirectory($symbolsRoot) | Out-Null
    [IO.Directory]::CreateDirectory($outputRoot) | Out-Null

    $snapshotBytes = $Utf8NoBom.GetBytes("fixture-source`n")
    $snapshotHash = Get-BytesSha256 $snapshotBytes
    $mainMetadata = [ordered]@{
        schema = 'kdbg.build-metadata.v1'
        source_snapshot_sha256 = $snapshotHash
    } | ConvertTo-Json
    $symbolsMetadata = [ordered]@{
        schema = 'kdbg.symbols-metadata.v1'
        source_snapshot_sha256 = $snapshotHash
    } | ConvertTo-Json
    Write-FixtureFile $mainRoot 'BUILD-METADATA.json' $Utf8NoBom.GetBytes($mainMetadata)
    Write-FixtureFile $mainRoot 'SOURCE-SNAPSHOT.sha256' $snapshotBytes
    Write-FixtureFile $symbolsRoot 'BUILD-METADATA.json' $Utf8NoBom.GetBytes($symbolsMetadata)
    Write-FixtureFile $symbolsRoot 'SOURCE-SNAPSHOT.sha256' $snapshotBytes
    foreach ($relative in @(
        'KDBG.exe', 'KDBGSetup.exe',
        'plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe',
        'tools/kdbg_live_verify.exe', 'tools/kdbg_process_fixture.exe',
        'drivers/KDbgDriver.sys', 'drivers/KDbgProbe.sys',
        'drivers/KDbgDriver.inf', 'drivers/KDbgProbe.inf',
        'drivers/KDbgDriver.cat', 'drivers/KDbgProbe.cat')) {
        Write-FixtureFile $mainRoot $relative $Ascii.GetBytes("fixture:$relative")
    }
    foreach ($relative in @('drivers/KDbgDriver.pdb', 'drivers/KDbgProbe.pdb')) {
        Write-FixtureFile $symbolsRoot $relative $Ascii.GetBytes("fixture:$relative")
    }
    Write-FixtureManifest $mainRoot
    Write-FixtureManifest $symbolsRoot

    $mainZip = Join-Path $temporaryRoot 'main.zip'
    $symbolsZip = Join-Path $temporaryRoot 'symbols.zip'
    New-FixtureZip $mainRoot $mainZip
    New-FixtureZip $symbolsRoot $symbolsZip
    $mainHash = Get-Sha256 $mainZip
    $symbolsHash = Get-Sha256 $symbolsZip
    $common = @{
        UnsignedPackagePath = $mainZip
        ExpectedUnsignedPackageSha256 = $mainHash
        SymbolsPackagePath = $symbolsZip
        ExpectedSymbolsPackageSha256 = $symbolsHash
        ExpectedSourceSnapshotSha256 = $snapshotHash
        OutputRoot = $outputRoot
        EpochName = 'contract-preflight'
        PreflightOnly = $true
    }

    $result = (& $ScriptUnderTest @common | Out-String) | ConvertFrom-Json
    Assert-True ($result.passed -eq $true) 'Synthetic exact package pair must pass preflight.'
    Assert-True ($result.mutations_performed -eq $false) 'Preflight must report no mutation.'
    Assert-True ($result.signing_performed -eq $false) 'Preflight must not sign.'
    Assert-True ($result.vm_touched -eq $false) 'Preflight must not touch a VM.'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $outputRoot 'contract-preflight'))) `
        'Preflight must not create the output epoch.'
    Assert-True (@($result.only_signable_paths).Count -eq 4) 'Exactly four driver paths are signable.'
    Assert-True (@($result.only_signable_paths | Where-Object { $_ -notmatch '^drivers/.+\.(sys|cat)$' }).Count -eq 0) `
        'Only driver SYS/CAT paths may be signable.'
    Assert-True ($result.claim_boundary -match 'not production') 'Preflight must carry the non-production boundary.'

    $wrongHash = ('0' * 64)
    $badHashArgs = $common.Clone()
    $badHashArgs.ExpectedUnsignedPackageSha256 = $wrongHash
    Assert-ThrowsLike { & $ScriptUnderTest @badHashArgs } '*Exact ZIP SHA-256 mismatch*'

    $badSourceArgs = $common.Clone()
    $badSourceArgs.ExpectedSourceSnapshotSha256 = ('1' * 64)
    Assert-ThrowsLike { & $ScriptUnderTest @badSourceArgs } '*does not match ExpectedSourceSnapshotSha256*'

    [IO.Directory]::CreateDirectory((Join-Path $outputRoot 'already-exists')) | Out-Null
    $existingArgs = $common.Clone()
    $existingArgs.EpochName = 'already-exists'
    Assert-ThrowsLike { & $ScriptUnderTest @existingArgs } '*Refusing to overwrite*'

    $source = Get-Content -LiteralPath $ScriptUnderTest -Raw
    Assert-True ($source -notmatch "'KDBG\.exe'.*SignTool") 'The application executable must never be a SignTool target.'
    Assert-True ($source -match "sign SYS, regenerate CAT from signed SYS, sign CAT") `
        'Provenance must state the valid catalog generation order.'
    Assert-True ($source.Contains('KDBGSetup-Test.exe') -and
        $source.Contains('certificate/KDBG-TestSigning.cer') -and
        $source.Contains('tools/test_setup.ps1')) `
        'Test-signed derivatives must carry the explicit development setup payload.'

    Write-Host "PASS: New-Win11TestSignedPackage contract ($Assertions assertions)"
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

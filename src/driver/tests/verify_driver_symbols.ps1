[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactsDirectory,

    [string[]]$PrivatePath = @(),

    [string]$PrivatePdbDirectory,

    [string]$PdbCopyPath,

    [ValidatePattern('^[A-Za-z]:\\$')]
    [string]$StableBuildAlias = "K:\",

    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$ArtifactsDirectory = [IO.Path]::GetFullPath($ArtifactsDirectory)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ArtifactsDirectory "driver-symbol-contract.json"
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if (-not [string]::IsNullOrWhiteSpace($PrivatePdbDirectory)) {
    $PrivatePdbDirectory = [IO.Path]::GetFullPath($PrivatePdbDirectory)
}
if ([string]::IsNullOrWhiteSpace($PdbCopyPath)) {
    $Candidate = Join-Path ${env:ProgramFiles(x86)} `
        "Windows Kits\10\Debuggers\x64\pdbcopy.exe"
    if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
        $PdbCopyPath = $Candidate
    }
}
if (-not [string]::IsNullOrWhiteSpace($PdbCopyPath)) {
    $PdbCopyPath = [IO.Path]::GetFullPath($PdbCopyPath)
    if (-not (Test-Path -LiteralPath $PdbCopyPath -PathType Leaf)) {
        throw "pdbcopy.exe was not found: $PdbCopyPath"
    }
}

function Assert-Range(
    [byte[]]$Bytes,
    [long]$Offset,
    [long]$Length,
    [string]$Label) {
    if ($Offset -lt 0 -or $Length -lt 0 -or
        $Offset -gt $Bytes.LongLength -or
        $Length -gt ($Bytes.LongLength - $Offset)) {
        throw "$Label is outside the file bounds."
    }
}

function Read-UInt16(
    [byte[]]$Bytes,
    [long]$Offset,
    [string]$Label) {
    Assert-Range $Bytes $Offset 2 $Label
    return [BitConverter]::ToUInt16($Bytes, [int]$Offset)
}

function Read-UInt32(
    [byte[]]$Bytes,
    [long]$Offset,
    [string]$Label) {
    Assert-Range $Bytes $Offset 4 $Label
    return [BitConverter]::ToUInt32($Bytes, [int]$Offset)
}

function Read-Guid(
    [byte[]]$Bytes,
    [long]$Offset,
    [string]$Label) {
    Assert-Range $Bytes $Offset 16 $Label
    $GuidBytes = New-Object byte[] 16
    [Buffer]::BlockCopy($Bytes, [int]$Offset, $GuidBytes, 0, 16)
    return New-Object Guid (,$GuidBytes)
}

function Convert-RvaToFileOffset(
    [byte[]]$Bytes,
    [uint32]$Rva,
    [long]$SectionTableOffset,
    [uint16]$SectionCount) {
    for ($Index = 0; $Index -lt $SectionCount; ++$Index) {
        $SectionOffset = $SectionTableOffset + (40L * $Index)
        Assert-Range $Bytes $SectionOffset 40 "PE section header"
        $VirtualSize = Read-UInt32 $Bytes ($SectionOffset + 8) `
            "PE section virtual size"
        $VirtualAddress = Read-UInt32 $Bytes ($SectionOffset + 12) `
            "PE section virtual address"
        $RawSize = Read-UInt32 $Bytes ($SectionOffset + 16) `
            "PE section raw size"
        $RawOffset = Read-UInt32 $Bytes ($SectionOffset + 20) `
            "PE section raw offset"
        $MappedSize = [Math]::Max([uint64]$VirtualSize, [uint64]$RawSize)
        $Rva64 = [uint64]$Rva
        $VirtualAddress64 = [uint64]$VirtualAddress
        if ($MappedSize -ne 0 -and
            $Rva64 -ge $VirtualAddress64 -and
            $Rva64 -lt ($VirtualAddress64 + $MappedSize)) {
            $Delta = $Rva64 - $VirtualAddress64
            if ($Delta -ge [uint64]$RawSize) {
                throw "PE RVA points outside section raw data."
            }
            return [long]([uint64]$RawOffset + $Delta)
        }
    }
    throw ("PE RVA 0x{0:X8} is not backed by a section." -f $Rva)
}

function Get-PeCodeViewIdentity([string]$Path) {
    $Bytes = [IO.File]::ReadAllBytes($Path)
    if ((Read-UInt16 $Bytes 0 "DOS signature") -ne 0x5A4D) {
        throw "Not a DOS/PE image: $Path"
    }
    $PeOffset = Read-UInt32 $Bytes 0x3C "PE header offset"
    Assert-Range $Bytes $PeOffset 24 "PE header"
    if ((Read-UInt32 $Bytes $PeOffset "PE signature") -ne 0x00004550) {
        throw "Invalid PE signature: $Path"
    }
    $SectionCount = Read-UInt16 $Bytes ($PeOffset + 6) "PE section count"
    $OptionalSize = Read-UInt16 $Bytes ($PeOffset + 20) `
        "PE optional-header size"
    $OptionalOffset = $PeOffset + 24L
    $Magic = Read-UInt16 $Bytes $OptionalOffset "PE optional-header magic"
    if ($Magic -ne 0x20B) {
        throw "Expected a PE32+ x64 image: $Path"
    }
    if ($OptionalSize -lt 160) {
        throw "PE optional header is too small for the debug directory."
    }
    $DebugDirectoryEntry = $OptionalOffset + 112L + (6L * 8L)
    $DebugRva = Read-UInt32 $Bytes $DebugDirectoryEntry "PE debug RVA"
    $DebugSize = Read-UInt32 $Bytes ($DebugDirectoryEntry + 4) `
        "PE debug size"
    if ($DebugRva -eq 0 -or $DebugSize -lt 28 -or ($DebugSize % 28) -ne 0) {
        throw "PE image has no well-formed debug directory: $Path"
    }
    $SectionTableOffset = $OptionalOffset + [long]$OptionalSize
    $DebugOffset = Convert-RvaToFileOffset $Bytes $DebugRva `
        $SectionTableOffset $SectionCount
    Assert-Range $Bytes $DebugOffset $DebugSize "PE debug directory"

    for ($Index = 0; $Index -lt ($DebugSize / 28); ++$Index) {
        $EntryOffset = $DebugOffset + (28L * $Index)
        $Type = Read-UInt32 $Bytes ($EntryOffset + 12) "PE debug type"
        if ($Type -ne 2) { continue }
        $DataSize = Read-UInt32 $Bytes ($EntryOffset + 16) `
            "CodeView data size"
        $DataOffset = Read-UInt32 $Bytes ($EntryOffset + 24) `
            "CodeView file offset"
        if ($DataSize -lt 25) {
            throw "CodeView record is too small: $Path"
        }
        Assert-Range $Bytes $DataOffset $DataSize "CodeView record"
        $Signature = [Text.Encoding]::ASCII.GetString($Bytes, $DataOffset, 4)
        if ($Signature -cne "RSDS") { continue }
        $Guid = Read-Guid $Bytes ($DataOffset + 4) "CodeView GUID"
        $Age = Read-UInt32 $Bytes ($DataOffset + 20) "CodeView age"
        $PathLength = [int]$DataSize - 24
        $CodeViewPath = [Text.Encoding]::UTF8.GetString(
            $Bytes,
            [int]$DataOffset + 24,
            $PathLength).TrimEnd([char]0)
        return [ordered]@{
            guid = $Guid.ToString("D").ToLowerInvariant()
            age = [uint32]$Age
            path = $CodeViewPath
        }
    }
    throw "PE image has no RSDS CodeView record: $Path"
}

function Get-PdbIdentity([string]$Path) {
    $Bytes = [IO.File]::ReadAllBytes($Path)
    $Magic = [Text.Encoding]::ASCII.GetString($Bytes, 0, 32)
    if (-not $Magic.StartsWith("Microsoft C/C++ MSF 7.00")) {
        throw "Unsupported PDB/MSF format: $Path"
    }
    $BlockSize = Read-UInt32 $Bytes 32 "PDB block size"
    $BlockCount = Read-UInt32 $Bytes 40 "PDB block count"
    $DirectorySize = Read-UInt32 $Bytes 44 "PDB directory size"
    $BlockMapAddress = Read-UInt32 $Bytes 52 "PDB block-map address"
    if ($BlockSize -lt 512 -or $BlockSize -gt 65536 -or
        ($BlockSize -band ($BlockSize - 1)) -ne 0) {
        throw "PDB block size is invalid: $BlockSize"
    }
    if ($BlockCount -eq 0 -or
        ([uint64]$BlockCount * [uint64]$BlockSize) -gt
            [uint64]$Bytes.LongLength) {
        throw "PDB block table exceeds the file bounds."
    }

    $DirectoryBlockCount = [uint32]([Math]::Ceiling(
        [double]$DirectorySize / [double]$BlockSize))
    $BlockMapOffset = [uint64]$BlockMapAddress * [uint64]$BlockSize
    Assert-Range $Bytes ([long]$BlockMapOffset) `
        ([long]$DirectoryBlockCount * 4L) "PDB block map"
    $Directory = New-Object byte[] ([int]$DirectorySize)
    $Copied = 0
    for ($Index = 0; $Index -lt $DirectoryBlockCount; ++$Index) {
        $Block = Read-UInt32 $Bytes ($BlockMapOffset + (4L * $Index)) `
            "PDB directory block"
        if ($Block -ge $BlockCount) {
            throw "PDB directory references an invalid block."
        }
        $Chunk = [Math]::Min([int]$BlockSize, $Directory.Length - $Copied)
        [Buffer]::BlockCopy(
            $Bytes,
            [int]([uint64]$Block * [uint64]$BlockSize),
            $Directory,
            $Copied,
            $Chunk)
        $Copied += $Chunk
    }

    $Cursor = 0L
    $StreamCount = Read-UInt32 $Directory $Cursor "PDB stream count"
    $Cursor += 4
    if ($StreamCount -lt 2 -or $StreamCount -gt 0x100000) {
        throw "PDB stream count is invalid: $StreamCount"
    }
    $StreamSizes = New-Object uint32[] ([int]$StreamCount)
    for ($Index = 0; $Index -lt $StreamCount; ++$Index) {
        $StreamSizes[$Index] = Read-UInt32 $Directory $Cursor `
            "PDB stream size"
        $Cursor += 4
    }
    $StreamBlocks = @()
    for ($StreamIndex = 0; $StreamIndex -lt $StreamCount; ++$StreamIndex) {
        $Size = $StreamSizes[$StreamIndex]
        if ($Size -eq [uint32]::MaxValue) {
            $StreamBlocks += ,@()
            continue
        }
        $Count = [int][Math]::Ceiling([double]$Size / [double]$BlockSize)
        $Blocks = New-Object uint32[] $Count
        for ($BlockIndex = 0; $BlockIndex -lt $Count; ++$BlockIndex) {
            $Blocks[$BlockIndex] = Read-UInt32 $Directory $Cursor `
                "PDB stream block"
            $Cursor += 4
            if ($Blocks[$BlockIndex] -ge $BlockCount) {
                throw "PDB stream references an invalid block."
            }
        }
        $StreamBlocks += ,$Blocks
    }

    $InfoSize = $StreamSizes[1]
    if ($InfoSize -eq [uint32]::MaxValue -or $InfoSize -lt 28) {
        throw "PDB info stream is missing or too small."
    }
    $Info = New-Object byte[] ([int]$InfoSize)
    $Copied = 0
    foreach ($Block in $StreamBlocks[1]) {
        $Chunk = [Math]::Min([int]$BlockSize, $Info.Length - $Copied)
        [Buffer]::BlockCopy(
            $Bytes,
            [int]([uint64]$Block * [uint64]$BlockSize),
            $Info,
            $Copied,
            $Chunk)
        $Copied += $Chunk
    }
    $Age = Read-UInt32 $Info 8 "PDB age"
    $Guid = Read-Guid $Info 12 "PDB GUID"
    return [ordered]@{
        guid = $Guid.ToString("D").ToLowerInvariant()
        age = [uint32]$Age
    }
}

function Test-ContainsLiteral(
    [byte[]]$Bytes,
    [string]$Literal) {
    foreach ($Encoding in @(
            [Text.Encoding]::GetEncoding(28591),
            [Text.Encoding]::UTF8,
            [Text.Encoding]::Unicode,
            [Text.Encoding]::BigEndianUnicode)) {
        $Decoded = $Encoding.GetString($Bytes)
        if ($Decoded.IndexOf(
                $Literal,
                [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

$EffectivePrivatePaths = @($PrivatePath | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
})
if ($EffectivePrivatePaths.Count -eq 0) {
    $EffectivePrivatePaths = @(
        $RepoRoot,
        [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::UserProfile)
    )
}
$EffectivePrivatePaths = @($EffectivePrivatePaths |
    ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') } |
    Select-Object -Unique)

foreach ($ProjectName in @("KDbgDriver", "KDbgProbe")) {
    $ProjectPath = Join-Path $RepoRoot `
        "src\driver\$ProjectName\$ProjectName.vcxproj"
    $ProjectText = Get-Content -LiteralPath $ProjectPath -Raw
    foreach ($RequiredSetting in @(
            "<DebugInformationFormat>OldStyle</DebugInformationFormat>",
            "/Z7",
            "/experimental:deterministic",
            "/pathmap:`$(KDbgRepositoryRoot)=KDBG_ROOT",
            "<StripPrivateSymbols>`$(OutDir)`$(TargetName).public.pdb</StripPrivateSymbols>",
            "/PDBALTPATH:%_PDB%")) {
        if (-not $ProjectText.Contains($RequiredSetting)) {
            throw "$ProjectName deterministic symbol setting is missing: $RequiredSetting"
        }
    }
    if ($ProjectText.Contains("KDbgProfileRoot") -or
        $ProjectText.Contains("=BUILDUSER")) {
        throw "$ProjectName must not embed a physical user-profile pathmap source."
    }
}

function Assert-PdbCopyParses([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($PdbCopyPath)) { return }
    $Scratch = Join-Path ([IO.Path]::GetTempPath()) `
        ("kdbg-pdbcopy-" + [Guid]::NewGuid().ToString("N") + ".pdb")
    try {
        $Output = @(& $PdbCopyPath $Path $Scratch 2>&1)
        if ($LASTEXITCODE -ne 0 -or
            -not (Test-Path -LiteralPath $Scratch -PathType Leaf) -or
            (Get-Item -LiteralPath $Scratch).Length -eq 0) {
            $Output | ForEach-Object { Write-Host $_ }
            throw "pdbcopy.exe could not parse/copy $Label."
        }
    } finally {
        if (Test-Path -LiteralPath $Scratch -PathType Leaf) {
            Remove-Item -LiteralPath $Scratch -Force
        }
    }
}

$Results = @()
foreach ($Name in @("KDbgDriver", "KDbgProbe")) {
    $SysPath = Join-Path $ArtifactsDirectory "$Name.sys"
    $PdbPath = Join-Path $ArtifactsDirectory "$Name.pdb"
    foreach ($RequiredPath in @($SysPath, $PdbPath)) {
        if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf) -or
            (Get-Item -LiteralPath $RequiredPath).Length -eq 0) {
            throw "Required driver symbol artifact is missing: $RequiredPath"
        }
    }

    $CodeView = Get-PeCodeViewIdentity $SysPath
    $Pdb = Get-PdbIdentity $PdbPath
    if ($CodeView.path -cne "$Name.pdb") {
        throw "$Name CodeView path must be the PDB basename; got '$($CodeView.path)'."
    }
    if ($CodeView.guid -cne $Pdb.guid -or $CodeView.age -ne $Pdb.age) {
        throw ("$Name PE/PDB identity mismatch: PE {0}/{1}, PDB {2}/{3}." -f
            $CodeView.guid, $CodeView.age, $Pdb.guid, $Pdb.age)
    }

    $PdbBytes = [IO.File]::ReadAllBytes($PdbPath)
    foreach ($PrivateRoot in $EffectivePrivatePaths) {
        foreach ($Candidate in @(
                $PrivateRoot,
                $PrivateRoot.Replace('\', '/'))) {
            if (Test-ContainsLiteral $PdbBytes $Candidate) {
                throw "$Name.pdb contains a private build path."
            }
        }
    }
    Assert-PdbCopyParses $PdbPath "$Name public PDB"

    $PrivateResult = $null
    if (-not [string]::IsNullOrWhiteSpace($PrivatePdbDirectory)) {
        $PrivatePdbPath = Join-Path $PrivatePdbDirectory "$Name.pdb"
        if (-not (Test-Path -LiteralPath $PrivatePdbPath -PathType Leaf) -or
            (Get-Item -LiteralPath $PrivatePdbPath).Length -eq 0) {
            throw "Required private driver PDB is missing: $PrivatePdbPath"
        }
        $PrivatePdb = Get-PdbIdentity $PrivatePdbPath
        if ($CodeView.guid -cne $PrivatePdb.guid -or
            $CodeView.age -ne $PrivatePdb.age) {
            throw "$Name PE/private-PDB identity mismatch."
        }
        $PrivateBytes = [IO.File]::ReadAllBytes($PrivatePdbPath)
        foreach ($PrivateRoot in $EffectivePrivatePaths) {
            foreach ($Candidate in @(
                    $PrivateRoot,
                    $PrivateRoot.Replace('\', '/'))) {
                if (Test-ContainsLiteral $PrivateBytes $Candidate) {
                    throw "$Name private PDB contains a private build path."
                }
            }
        }
        Assert-PdbCopyParses $PrivatePdbPath "$Name private PDB"
        $PrivateResult = [ordered]@{
            pdb_sha256 = (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $PrivatePdbPath).Hash.ToLowerInvariant()
            guid = $PrivatePdb.guid
            age = $PrivatePdb.age
            private_path_findings = 0
        }
    }
    $Results += [ordered]@{
        name = $Name
        sys_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SysPath).Hash.ToLowerInvariant()
        pdb_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PdbPath).Hash.ToLowerInvariant()
        guid = $Pdb.guid
        age = $Pdb.age
        codeview_path = $CodeView.path
        private_path_findings = 0
        private_pdb = $PrivateResult
    }
}

$Manifest = [ordered]@{
    schema = "kdbg.driver-symbol-contract.v1"
    deterministic_source_root = "KDBG_ROOT"
    stable_build_alias = $StableBuildAlias
    stable_build_alias_is_private = $false
    symbol_policy = "public-stripped"
    codeview_path_policy = "basename"
    pe_pdb_identity_match = $true
    private_path_findings = 0
    pdbcopy_verified = -not [string]::IsNullOrWhiteSpace($PdbCopyPath)
    artifacts = $Results
}
$OutputParent = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($OutputParent)) {
    [IO.Directory]::CreateDirectory($OutputParent) | Out-Null
}
$Manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath `
    -Encoding UTF8

Write-Host "KDBG driver symbol verification PASS"
Write-Host " - PE CodeView path: basename only"
Write-Host " - PE/PDB GUID and age: exact match"
Write-Host " - private repository/profile paths: 0"
Write-Host " - manifest: $OutputPath"

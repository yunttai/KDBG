[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactsDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$ArtifactsDirectory = [IO.Path]::GetFullPath($ArtifactsDirectory)
$ExpectedFileVersion = "1.1.0.0"
$ExpectedPackageVersion = "1.1.0"
$ExpectedDriverDate = "09/18/2026"
$ExpectedCompany = "KDBG Project"
$ExpectedProduct = "KDBG"
$ExpectedCopyright = "Copyright (C) 2026 KDBG Project"

function Assert-Equal(
    [string]$Label,
    [object]$Actual,
    [object]$Expected) {
    if ([string]$Actual -cne [string]$Expected) {
        throw "$Label mismatch: expected '$Expected', got '$Actual'."
    }
}

function Get-RequiredMatch(
    [string]$Text,
    [string]$Pattern,
    [string]$Label) {
    $Match = [regex]::Match(
        $Text,
        $Pattern,
        [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [Text.RegularExpressions.RegexOptions]::Multiline)
    if (-not $Match.Success) {
        throw "$Label is missing or malformed."
    }
    return $Match.Groups["value"].Value
}

$DriverSourcePath = Join-Path $RepoRoot "src\driver\KDbgDriver\Driver.cpp"
$DriverSource = Get-Content -LiteralPath $DriverSourcePath -Raw
$LargePageReservedChecks = @(
    @{
        Label = "1 GiB PDPTE reserved address bits 29:13"
        Pattern = '(?s)KDBG_PAGING_LEVEL_PDPT.*?reserved_mask\s*=\s*0x000000003FFFE000ULL;.*?\(entry\s*&\s*reserved_mask\).*?return\s+STATUS_INVALID_ADDRESS;.*?mask\s*=\s*0x000FFFFFC0000000ULL;'
    },
    @{
        Label = "2 MiB PDE reserved address bits 20:13"
        Pattern = '(?s)KDBG_PAGING_LEVEL_PD\s*&&.*?reserved_mask\s*=\s*0x00000000001FE000ULL;.*?\(entry\s*&\s*reserved_mask\).*?return\s+STATUS_INVALID_ADDRESS;.*?mask\s*=\s*0x000FFFFFFFE00000ULL;'
    })
foreach ($Check in $LargePageReservedChecks) {
    if (-not [regex]::IsMatch($DriverSource, $Check.Pattern)) {
        throw "KDbgDriver translation contract is missing: $($Check.Label)."
    }
}
$WriteModeCase = [regex]::Match(
    $DriverSource,
    "(?s)case\s+IOCTL_KDBG_SET_WRITE_MODE\s*:\s*\{(?<value>.*?)" +
        "case\s+IOCTL_KDBG_GET_PHYSICAL_RANGES")
if (-not $WriteModeCase.Success) {
    throw "IOCTL_KDBG_SET_WRITE_MODE dispatch case could not be isolated."
}
$WriteModeBody = $WriteModeCase.Groups["value"].Value
$MalformedLengthFailClosed = [regex]::IsMatch(
    $WriteModeBody,
    "(?s)if\s*\(\s*buffer\s*==\s*nullptr.*?" +
        "input_length\s*!=\s*sizeof\(KDBG_WRITE_MODE_REQUEST\).*?" +
        "output_length\s*!=\s*0\s*\)\s*\{\s*" +
        "InterlockedExchange\(&context->WriteEnabled,\s*0\);\s*" +
        "InterlockedIncrement64\(&g_state.RejectedWrites\);\s*" +
        "status\s*=\s*STATUS_BUFFER_TOO_SMALL;")
if (-not $MalformedLengthFailClosed) {
    throw "Malformed SET_WRITE_MODE length path is not fail-closed and counted."
}
$InvalidRequestFailClosed = [regex]::IsMatch(
    $WriteModeBody,
    "(?s)if\s*\(request->Size.*?" +
        "request->Acknowledge\s*!=\s*KDBG_WRITE_ACK_MAGIC\s*\)\s*\{\s*" +
        "InterlockedExchange\(&context->WriteEnabled,\s*0\);\s*" +
        "InterlockedIncrement64\(&g_state.RejectedWrites\);\s*" +
        "status\s*=\s*STATUS_ACCESS_DENIED;")
if (-not $InvalidRequestFailClosed) {
    throw "Invalid SET_WRITE_MODE request path is not fail-closed and counted."
}

$IoctlHeader = Get-Content -LiteralPath (
    Join-Path $RepoRoot "src\shared\KDbgIoctl.h") -Raw
$DriverMajor = Get-RequiredMatch $IoctlHeader `
    "#define\s+KDBG_DRIVER_VERSION_MAJOR\s+(?<value>\d+)u" `
    "KDBG driver major version"
$DriverMinor = Get-RequiredMatch $IoctlHeader `
    "#define\s+KDBG_DRIVER_VERSION_MINOR\s+(?<value>\d+)u" `
    "KDBG driver minor version"
$ProbeHeader = Get-Content -LiteralPath (
    Join-Path $RepoRoot "src\shared\KDbgProbeIoctl.h") -Raw
$ProbeAbiMajor = Get-RequiredMatch $ProbeHeader `
    "#define\s+KDBG_PROBE_ABI_VERSION\s+(?<value>\d+)u" `
    "KDBG Probe ABI version"
$VersionParts = $ExpectedFileVersion.Split('.')
Assert-Equal "KDBG driver product major/ABI-advertised major" `
    $DriverMajor $VersionParts[0]
Assert-Equal "KDBG driver product minor/ABI-advertised minor" `
    $DriverMinor $VersionParts[1]
Assert-Equal "KDBG Probe product major/ABI major" `
    $ProbeAbiMajor $VersionParts[0]

$PackageScript = Get-Content -LiteralPath (
    Join-Path $RepoRoot "src\tools\package_windows.ps1") -Raw
$PackageVersion = Get-RequiredMatch $PackageScript `
    '^\$Version\s*=\s*"(?<value>\d+\.\d+\.\d+)"' `
    "Windows package version"
Assert-Equal "Windows package/product version" `
    $PackageVersion $ExpectedPackageVersion

$Projects = @(
    @{
        Name = "KDbgDriver"
        Description = "KDBG Physical Memory Driver"
    },
    @{
        Name = "KDbgProbe"
        Description = "KDBG Probe Fixture Driver"
    }
)

foreach ($Project in $Projects) {
    $Name = $Project.Name
    $ProjectRoot = Join-Path $RepoRoot "src\driver\$Name"
    $InfText = Get-Content -LiteralPath (
        Join-Path $ProjectRoot "$Name.inf") -Raw
    $InfVersion = Get-RequiredMatch $InfText `
        'DriverVer\s*=\s*\d{2}/\d{2}/\d{4},(?<value>\d+\.\d+\.\d+\.\d+)' `
        "$Name INF DriverVer"
    Assert-Equal "$Name INF/product version" $InfVersion $ExpectedFileVersion
    $InfDate = Get-RequiredMatch $InfText `
        'DriverVer\s*=\s*(?<value>\d{2}/\d{2}/\d{4}),\d+\.\d+\.\d+\.\d+' `
        "$Name INF DriverVer date"
    Assert-Equal "$Name INF/release date" $InfDate $ExpectedDriverDate

    $ProjectText = Get-Content -LiteralPath (
        Join-Path $ProjectRoot "$Name.vcxproj") -Raw
    $ProjectVersion = Get-RequiredMatch $ProjectText `
        '<TimeStamp>(?<value>\d+\.\d+\.\d+\.\d+)</TimeStamp>' `
        "$Name project INF version"
    Assert-Equal "$Name project/product version" `
        $ProjectVersion $ExpectedFileVersion
    $ProjectDate = Get-RequiredMatch $ProjectText `
        '<DateStamp>(?<value>\d{2}/\d{2}/\d{4})</DateStamp>' `
        "$Name project INF date"
    Assert-Equal "$Name project/release date" `
        $ProjectDate $ExpectedDriverDate
    if ($ProjectText -cnotmatch
        "<ResourceCompile Include=`"$Name\.rc`"\s*/>") {
        throw "$Name.vcxproj does not compile $Name.rc."
    }

    $ResourceText = Get-Content -LiteralPath (
        Join-Path $ProjectRoot "$Name.rc") -Raw
    $ResourceVersion = Get-RequiredMatch $ResourceText `
        '#define\s+KDBG_FILE_VERSION_STRING\s+"(?<value>\d+\.\d+\.\d+\.\d+)\\0"' `
        "$Name resource version"
    Assert-Equal "$Name resource/product version" `
        $ResourceVersion $ExpectedFileVersion
    $ResourceNumericVersion = Get-RequiredMatch $ResourceText `
        '#define\s+KDBG_FILE_VERSION\s+(?<value>\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+)' `
        "$Name numeric resource version"
    Assert-Equal "$Name numeric resource/product version" `
        ($ResourceNumericVersion -replace '\s*,\s*', '.') $ExpectedFileVersion
    foreach ($RequiredValue in @(
            $ExpectedCompany,
            $Project.Description,
            $ExpectedProduct,
            $ExpectedCopyright,
            "$Name.sys")) {
        if (-not $ResourceText.Contains($RequiredValue)) {
            throw "$Name resource metadata is missing '$RequiredValue'."
        }
    }

    $BinaryPath = Join-Path $ArtifactsDirectory "$Name.sys"
    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        throw "Built driver is missing: $BinaryPath"
    }
    $VersionInfo = (Get-Item -LiteralPath $BinaryPath).VersionInfo
    $BinaryFileVersion = "{0}.{1}.{2}.{3}" -f
        $VersionInfo.FileMajorPart,
        $VersionInfo.FileMinorPart,
        $VersionInfo.FileBuildPart,
        $VersionInfo.FilePrivatePart
    Assert-Equal "$Name PE file version" `
        $BinaryFileVersion $ExpectedFileVersion
    Assert-Equal "$Name PE product version" `
        $VersionInfo.ProductVersion $ExpectedFileVersion
    Assert-Equal "$Name PE company" `
        $VersionInfo.CompanyName $ExpectedCompany
    Assert-Equal "$Name PE product" `
        $VersionInfo.ProductName $ExpectedProduct
    Assert-Equal "$Name PE description" `
        $VersionInfo.FileDescription $Project.Description
    Assert-Equal "$Name PE original filename" `
        $VersionInfo.OriginalFilename "$Name.sys"
    Assert-Equal "$Name PE copyright" `
        $VersionInfo.LegalCopyright $ExpectedCopyright
}

$VerifierHarnessPath = Join-Path $RepoRoot `
    "src\driver\tests\run_driver_verifier.ps1"
$VerifierHarness = Get-Content -LiteralPath $VerifierHarnessPath -Raw
$VerifierTokens = $null
$VerifierParseErrors = $null
[void][Management.Automation.Language.Parser]::ParseFile(
    $VerifierHarnessPath,
    [ref]$VerifierTokens,
    [ref]$VerifierParseErrors)
if ($VerifierParseErrors.Count -ne 0) {
    throw "Driver Verifier harness PowerShell parse failed: $($VerifierParseErrors[0].Message)"
}
$VerifierAst = [Management.Automation.Language.Parser]::ParseFile(
    $VerifierHarnessPath,
    [ref]$VerifierTokens,
    [ref]$VerifierParseErrors)
$DriverNameParser = $VerifierAst.Find(
    {
        param($Node)
        $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $Node.Name -eq "Get-VerifierDriverNames"
    },
    $true)
if ($null -eq $DriverNameParser) {
    throw "Driver Verifier harness driver-name parser is missing."
}
Invoke-Expression $DriverNameParser.Extent.Text
$ParsedDriverNames = @(Get-VerifierDriverNames @(
    "Verified: KDbgProbe.sys",
    "verified: KDbgDriver.sys",
    "not-a-driver.sysx"))
if ($ParsedDriverNames.Count -ne 2 -or
    $ParsedDriverNames -notcontains "KDbgDriver.sys" -or
    $ParsedDriverNames -notcontains "KDbgProbe.sys") {
    throw "Driver Verifier harness does not parse the exact target image names."
}
$VerifierFlagsParser = $VerifierAst.Find(
    {
        param($Node)
        $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $Node.Name -eq "Get-VerifierFlags"
    },
    $true)
if ($null -eq $VerifierFlagsParser) {
    throw "Driver Verifier harness flag parser is missing."
}
Invoke-Expression $VerifierFlagsParser.Extent.Text
$ParsedVerifierFlags = Get-VerifierFlags @(
    "Verification Flags: 0x00000132",
    "    [X] 0x00000002 Force IRQL Checking")
if ($ParsedVerifierFlags -ne 0x132) {
    throw "Driver Verifier harness does not parse the active flag mask."
}
foreach ($RequiredContract in @(
        '[switch]$ConfirmDedicatedVm',
        '[switch]$ConfirmSnapshot',
        '$VerifierFlags = "0x132"',
        '$DriverImages = @("KDbgDriver.sys", "KDbgProbe.sys")',
        '@("/volatile", "/flags", $VerifierFlags, "/adddriver")',
        '"/volatile", "/removedriver"',
        'RequireTrustedDriverSignatures',
        'kdbg.driver-verifier.v1',
        'cleanup_succeeded',
        'package_restored')) {
    if (-not $VerifierHarness.Contains($RequiredContract)) {
        throw "Driver Verifier harness contract is missing: $RequiredContract"
    }
}
if ($VerifierHarness.Contains('/reset') -or
    $VerifierHarness.Contains('/all') -or
    $VerifierHarness.Contains('*' + '.sys')) {
    throw "Driver Verifier harness may not reset global state or target wildcard/all drivers."
}

Write-Host "KDBG driver contract verification PASS"
Write-Host " - SET_WRITE_MODE malformed-input fail-closed regression: PASS"
Write-Host " - large-page reserved-bit translation fail-closed regression: PASS"
Write-Host " - ABI/INF/project/package/PE version agreement: $ExpectedFileVersion"
Write-Host " - KDbgDriver.sys and KDbgProbe.sys VERSIONINFO: PASS"
Write-Host " - disposable-VM Driver Verifier exact-target/cleanup harness: PASS"

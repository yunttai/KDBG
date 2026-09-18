[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$ReadinessPath = Join-Path $RepoRoot 'src\tools\check_production_signing_readiness.ps1'
$VerifierPath = Join-Path $RepoRoot 'src\tools\verify_production_signed_package.ps1'
$StagerPath = Join-Path $RepoRoot 'src\tools\stage_production_signing.ps1'
$BuildReleasePath = Join-Path $RepoRoot 'src\tools\build_public_release.ps1'
$Checks = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Checks++
    if (-not $Condition) { throw "CHECK FAILED: $Message" }
}

function Assert-Throws {
    param([scriptblock]$Operation, [string]$Message)
    $script:Checks++
    try { & $Operation }
    catch { return }
    throw "CHECK FAILED: $Message"
}

function Get-ScriptAst {
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "PowerShell parse failed for ${Path}: $($errors[0].Message)"
    }
    return $ast
}

function Get-FunctionDefinitions {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Names)
    $ast = Get-ScriptAst $Path
    $definitions = [Collections.Generic.List[string]]::new()
    foreach ($name in $Names) {
        $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $name
        }, $true)
        if (-not $definition) { throw "Function $name was not found in $Path" }
        $definitions.Add($definition.Extent.Text)
    }
    return $definitions -join "`n`n"
}

foreach ($path in @($ReadinessPath, $VerifierPath, $StagerPath, $BuildReleasePath)) {
    $null = Get-ScriptAst $path
    Assert-True $true "script parses: $path"
}

$allText = (Get-Content -LiteralPath $ReadinessPath -Raw) +
    (Get-Content -LiteralPath $VerifierPath -Raw) +
    (Get-Content -LiteralPath $StagerPath -Raw)
Assert-True (-not $allText.Contains("`$expectedPackageSha256 =")) `
    'production signing source must require caller-supplied exact package hashes'
foreach ($required in @(
    'ExpectedMainSha256', 'ExpectedSymbolsSha256',
    'ExpectedAppPublisherSubject', 'ExpectedDriverPublisherSubject',
    'MicrosoftReturned', 'DirectPublisher')) {
    Assert-True $allText.Contains($required) "production signing contract contains $required"
}
Assert-True ((Get-Content -LiteralPath $VerifierPath -Raw).Contains(
    "foreach (`$extension in @('sys', 'inf'))")) `
    'catalog verifier must validate both SYS and INF membership'
Assert-True (-not (Get-Content -LiteralPath $StagerPath -Raw).Contains(
    "@('sign'")) `
    'stager must not invoke a signing operation'
$buildText = Get-Content -LiteralPath $BuildReleasePath -Raw
Assert-True ($buildText.Contains('PrepareProductionSigning') -and
    $buildText.Contains("stage_production_signing.ps1")) `
    'public release build must expose exact production-signing preparation'

$definitions = Get-FunctionDefinitions $ReadinessPath @(
    'Test-HttpsTimestampUrl')
$definitions += "`n`n" + (Get-FunctionDefinitions $VerifierPath @(
    'Get-Sha256', 'Get-ProductionSignatureRecord',
    'Test-ProductionSignatureRecord', 'Test-HashManifest',
    'Get-KdbgRelativePath'))
Invoke-Expression $definitions

Assert-True (Test-HttpsTimestampUrl 'https://timestamp.example.invalid/') `
    'credential-free HTTPS timestamp URL must be accepted structurally'
Assert-True (-not (Test-HttpsTimestampUrl 'http://timestamp.example.invalid/')) `
    'HTTP timestamp URL must be rejected'
Assert-True (-not (Test-HttpsTimestampUrl 'https://user@example.invalid/')) `
    'credential-bearing timestamp URL must be rejected'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'kdbg-production-signing-contract-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $signedFixture = Join-Path $testRoot 'signed.bin'
    [IO.File]::WriteAllBytes($signedFixture, [byte[]](1, 2, 3, 4))
    $validSignature = [pscustomobject]@{
        Status = 'Valid'
        SignerCertificate = [pscustomobject]@{
            Subject = 'CN=KDBG Project'
            Issuer = 'CN=Public Code Signing CA'
        }
        TimeStamperCertificate = [pscustomobject]@{
            Subject = 'CN=RFC3161 TSA'
            Thumbprint = '001122'
        }
    }
    $record = Get-ProductionSignatureRecord $signedFixture 'KDBG.exe' `
        'CN=KDBG Project' $validSignature
    Assert-True (Test-ProductionSignatureRecord $record) `
        'valid exact-publisher non-self-signed timestamped record must pass'
    $wrongPublisher = Get-ProductionSignatureRecord $signedFixture 'KDBG.exe' `
        'CN=Wrong Publisher' $validSignature
    Assert-True (-not (Test-ProductionSignatureRecord $wrongPublisher)) `
        'wrong app publisher must fail'
    $validSignature.SignerCertificate.Issuer = 'CN=KDBG Project'
    $selfSigned = Get-ProductionSignatureRecord $signedFixture 'KDBG.exe' `
        'CN=KDBG Project' $validSignature
    Assert-True (-not (Test-ProductionSignatureRecord $selfSigned)) `
        'self-signed publisher must fail'
    $validSignature.SignerCertificate.Issuer = 'CN=Public Code Signing CA'
    $validSignature.TimeStamperCertificate = $null
    $untimestamped = Get-ProductionSignatureRecord $signedFixture 'KDBG.exe' `
        'CN=KDBG Project' $validSignature
    Assert-True (-not (Test-ProductionSignatureRecord $untimestamped)) `
        'missing RFC3161 timestamp must fail'

    $manifestRoot = Join-Path $testRoot 'manifest'
    [IO.Directory]::CreateDirectory($manifestRoot) | Out-Null
    $payload = Join-Path $manifestRoot 'payload.bin'
    [IO.File]::WriteAllBytes($payload, [byte[]](9, 8, 7))
    [IO.File]::WriteAllText(
        (Join-Path $manifestRoot 'SHA256SUMS.txt'),
        "$(Get-Sha256 $payload)  payload.bin`n",
        [Text.Encoding]::ASCII)
    $manifest = Test-HashManifest $manifestRoot
    Assert-True ($manifest.Count -eq 1 -and $manifest.Errors.Count -eq 0) `
        'complete manifest must pass'
    [IO.File]::WriteAllBytes($payload, [byte[]](9, 8, 6))
    $tamperedManifest = Test-HashManifest $manifestRoot
    Assert-True ($tamperedManifest.Errors.Count -gt 0) `
        'manifest hash mismatch must fail closed'

    $mainSource = Join-Path $testRoot 'main-source'
    $symbolsSource = Join-Path $testRoot 'symbols-source'
    $mainRoot = Join-Path $mainSource 'KDBG-1.1.0-win-x64'
    $symbolsRoot = Join-Path $symbolsSource 'KDBG-1.1.0-win-x64-symbols'
    foreach ($relative in @(
        'KDBG.exe', 'KDBGSetup.exe',
        'plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe',
        'tools/kdbg_live_verify.exe', 'tools/kdbg_process_fixture.exe',
        'drivers/KDbgDriver.sys', 'drivers/KDbgDriver.inf', 'drivers/KDbgDriver.cat',
        'drivers/KDbgProbe.sys', 'drivers/KDbgProbe.inf', 'drivers/KDbgProbe.cat')) {
        $path = Join-Path $mainRoot ($relative.Replace('/', '\'))
        [IO.Directory]::CreateDirectory((Split-Path -Parent $path)) | Out-Null
        [IO.File]::WriteAllText($path, "fixture:$relative", [Text.Encoding]::ASCII)
    }
    foreach ($relative in @(
        'KDBG.pdb', 'KDBGSetup.pdb',
        'drivers/KDbgDriver.pdb', 'drivers/KDbgProbe.pdb')) {
        $path = Join-Path $symbolsRoot ($relative.Replace('/', '\'))
        [IO.Directory]::CreateDirectory((Split-Path -Parent $path)) | Out-Null
        [IO.File]::WriteAllText($path, "fixture:$relative", [Text.Encoding]::ASCII)
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $mainZip = Join-Path $testRoot 'main.zip'
    $symbolsZip = Join-Path $testRoot 'symbols.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($mainSource, $mainZip)
    [IO.Compression.ZipFile]::CreateFromDirectory($symbolsSource, $symbolsZip)
    $readinessJson = & $ReadinessPath `
        -PackagePath $mainZip -ExpectedMainSha256 (Get-Sha256 $mainZip) `
        -SymbolsPath $symbolsZip -ExpectedSymbolsSha256 (Get-Sha256 $symbolsZip) `
        -ExpectedAppPublisherSubject 'CN=KDBG Project' `
        -DriverProfile DirectPublisher `
        -ExpectedDriverPublisherSubject 'CN=KDBG Project' `
        -TimestampUrl 'https://timestamp.example.invalid/'
    $readiness = $readinessJson | ConvertFrom-Json
    Assert-True ($readiness.schema -ceq 'kdbg.production-signing-readiness.v2' -and
        $readiness.ready_for_signing_workflow -eq $false -and
        (@($readiness.blockers) -join ' ').Contains('AppCertificateThumbprint')) `
        'readiness must return a structured blocker when local signing identity is absent'
    $prepared = Join-Path $testRoot 'prepared'
    & $StagerPath -Mode Prepare `
        -PackagePath $mainZip -ExpectedMainSha256 (Get-Sha256 $mainZip) `
        -SymbolsPath $symbolsZip -ExpectedSymbolsSha256 (Get-Sha256 $symbolsZip) `
        -OutputDirectory $prepared | Out-Null
    $request = Get-Content -LiteralPath (
        Join-Path $prepared 'production-signing-request.json') -Raw | ConvertFrom-Json
    Assert-True ($request.schema -ceq 'kdbg.production-signing-request.v1' -and
        $request.signing_performed -eq $false -and
        $request.network_submission_performed -eq $false -and
        @($request.unsigned_inputs).Count -eq 11) `
        'Prepare must emit exact unsigned-input provenance without signing or submission'
    Assert-True ((Get-ChildItem -LiteralPath (
        Join-Path $prepared 'app-signing-input') -File -Recurse).Count -eq 5) `
        'Prepare must stage all five app signing inputs'
    Assert-True ((Get-ChildItem -LiteralPath (
        Join-Path $prepared 'driver-submission-input') -File).Count -eq 8) `
        'Prepare must stage two SYS/INF/CAT/PDB driver submission sets'

    [IO.File]::AppendAllText(
        (Join-Path $prepared 'unsigned\KDBG-1.1.0-win-x64\KDBG.exe'), 'tamper')
    Assert-Throws {
        & $StagerPath -Mode Finalize `
            -PackagePath $mainZip -ExpectedMainSha256 (Get-Sha256 $mainZip) `
            -SymbolsPath $symbolsZip -ExpectedSymbolsSha256 (Get-Sha256 $symbolsZip) `
            -OutputDirectory (Join-Path $testRoot 'must-not-publish') `
            -PreparedDirectory $prepared `
            -SignedAppDirectory (Join-Path $prepared 'app-signing-input') `
            -ReturnedDriverDirectory (Join-Path $prepared 'driver-submission-input') `
            -ExpectedAppPublisherSubject 'CN=KDBG Project' `
            -DriverProfile MicrosoftReturned `
            -ExpectedDriverPublisherSubject 'CN=Microsoft Hardware Publisher' `
            -TimestampUrl 'https://timestamp.example.invalid/'
    } 'Finalize must reject a changed prepared unsigned input before publication'
    Assert-True (-not (Test-Path -LiteralPath (
        Join-Path $testRoot 'must-not-publish'))) `
        'failed Finalize must not publish an output directory'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host "production_signing_contract_tests: $Checks checks passed"

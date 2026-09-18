Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:PackageLeaf = 'KDBG-1.1.0-win-x64.zip'
$script:PackageRootLeaf = 'KDBG-1.1.0-win-x64'
$script:PreviousPackageRootLeaf = 'KDBG-1.0.0-win-x64'

function Get-KdbgExtendedSha256 {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required pinned file is missing: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-KdbgExtendedHash {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Label
    )
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Label expected SHA-256 must be 64 lowercase hexadecimal characters."
    }
    $actual = Get-KdbgExtendedSha256 $Path
    if ($actual -cne $ExpectedSha256) {
        throw "$Label SHA-256 mismatch: $actual"
    }
    return $actual
}

function Test-KdbgExtendedPathUnder {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $fullPath.StartsWith(($fullRoot + '\'), [StringComparison]::OrdinalIgnoreCase)
}

function Assert-KdbgExtendedNoReparsePath {
    param([Parameter(Mandatory)][string]$Path, [switch]$LeafMayBeMissing)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $LeafMayBeMissing -and -not (Test-Path -LiteralPath $full)) {
        throw "Required path is missing: $full"
    }
    $cursor = $full
    while (-not [string]::IsNullOrEmpty($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse points are not allowed in extended-validation paths: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Write-KdbgExtendedJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    [IO.File]::WriteAllText(
        $Path,
        (($Value | ConvertTo-Json -Depth 30) + [Environment]::NewLine),
        $script:Utf8NoBom)
}

function Protect-KdbgExtendedText {
    param([string]$Text, [string[]]$Secrets)
    $safe = if ($null -eq $Text) { '' } else { $Text }
    foreach ($secret in $Secrets) {
        if (-not [string]::IsNullOrWhiteSpace($secret)) {
            $safe = $safe -replace [regex]::Escape($secret), '<REDACTED>'
        }
    }
    return $safe
}

function Get-KdbgPercentileSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][double[]]$Values)
    if ($Values.Count -eq 0) { throw 'At least one value is required.' }
    $ordered = [double[]]($Values | Sort-Object)
    $middle = [int][Math]::Floor($ordered.Count / 2)
    $median = if (($ordered.Count % 2) -eq 1) {
        $ordered[$middle]
    } else {
        ($ordered[$middle - 1] + $ordered[$middle]) / 2.0
    }
    $p95Index = [int][Math]::Max(0, [Math]::Ceiling(0.95 * $ordered.Count) - 1)
    return [pscustomobject]@{
        count = $ordered.Count
        median = [Math]::Round($median, 6)
        p95_nearest_rank = [Math]::Round($ordered[$p95Index], 6)
        minimum = [Math]::Round($ordered[0], 6)
        maximum = [Math]::Round($ordered[$ordered.Count - 1], 6)
    }
}

function New-KdbgExtendedExecutionPlan {
    [CmdletBinding()]
    param(
        [switch]$SkipLifecycle,
        [switch]$SkipSoak,
        [switch]$SkipBenchmarks,
        [ValidateRange(60, 1800)][int]$SoakDurationSeconds = 1800,
        [switch]$AllowCalibrationDuration
    )
    if ($SoakDurationSeconds -ne 1800 -and -not $AllowCalibrationDuration) {
        throw 'A shortened soak is calibration-only and requires -AllowCalibrationDuration.'
    }
    $intervalSeconds = if ($SoakDurationSeconds -eq 1800) { 30 } else {
        [Math]::Max(1, [int][Math]::Floor($SoakDurationSeconds / 6))
    }
    $reportCount = if ($SoakDurationSeconds -eq 1800) { 61 } else {
        [Math]::Max(3, [int][Math]::Floor($SoakDurationSeconds / $intervalSeconds) + 1)
    }
    $phases = [Collections.Generic.List[object]]::new()
    $phases.Add([ordered]@{ name = 'baseline'; host_reboot_after = $false })
    if (-not $SkipLifecycle) {
        foreach ($cycle in 1..2) {
            $phases.Add([ordered]@{ name = "cycle-$cycle-exercise"; host_reboot_after = $true })
            $phases.Add([ordered]@{ name = "cycle-$cycle-post-install-reboot"; host_reboot_after = $false })
            $phases.Add([ordered]@{ name = "cycle-$cycle-uninstall"; host_reboot_after = $true })
            $phases.Add([ordered]@{ name = "cycle-$cycle-post-clean-reboot"; host_reboot_after = $false })
        }
    }
    if (-not $SkipSoak) {
        $phases.Add([ordered]@{ name = 'soak'; host_reboot_after = $false })
    }
    if (-not $SkipBenchmarks) {
        $phases.Add([ordered]@{ name = 'benchmarks'; host_reboot_after = $false })
    }
    $phases.Add([ordered]@{ name = 'finalize'; host_reboot_after = $false })
    return [pscustomobject]@{
        schema = 'kdbg.win11-extended-plan.v1'
        lifecycle = [ordered]@{
            enabled = -not $SkipLifecycle
            cycles = if ($SkipLifecycle) { 0 } else { 2 }
            stop_start_per_cycle = if ($SkipLifecycle) { 0 } else { 5 }
            total_stop_start = if ($SkipLifecycle) { 0 } else { 10 }
            reboot_boundaries = if ($SkipLifecycle) { 0 } else { 4 }
            operations = @('install-previous', 'same-path-repair', 'update-current',
                'rollback-previous', 'forward-current', 'uninstall', 'clean-inventory')
        }
        soak = [ordered]@{
            enabled = -not $SkipSoak
            duration_seconds = if ($SkipSoak) { 0 } else { $SoakDurationSeconds }
            calibration_only = -not $SkipSoak -and $SoakDurationSeconds -ne 1800
            interval_seconds = if ($SkipSoak) { 0 } else { $intervalSeconds }
            report_count = if ($SkipSoak) { 0 } else { $reportCount }
            reads_per_report = if ($SkipSoak) { 0 } else { 8 }
            total_scheduled_reads = if ($SkipSoak) { 0 } else { $reportCount * 8 }
            midpoint_verified_transaction = -not $SkipSoak
        }
        benchmarks = [ordered]@{
            enabled = -not $SkipBenchmarks
            run_count = if ($SkipBenchmarks) { 0 } else { 7 }
            aggregate = 'median-and-nearest-rank-p95'
        }
        phases = @($phases)
        live_execution_performed = $false
    }
}

function Test-KdbgSafeZip {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedRoot)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $files = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })
        $names = @($files | ForEach-Object FullName)
        if ($files.Count -eq 0 -or @($names | Where-Object {
                $_ -match '\\' -or $_ -match '^/' -or $_ -match '^[A-Za-z]:' -or
                $_ -match '(^|/)\.\.(/|$)' -or -not $_.StartsWith("$ExpectedRoot/", [StringComparison]::Ordinal)
            }).Count -ne 0 -or
            @($names | ForEach-Object { $_.ToLowerInvariant() } | Group-Object |
                Where-Object Count -gt 1).Count -ne 0) {
            throw 'Package ZIP contains an unsafe, duplicate, empty, or unexpected-root entry set.'
        }
        foreach ($required in @('BUILD-METADATA.json', 'SHA256SUMS.txt',
                'drivers/KDbgDriver.sys', 'drivers/KDbgProbe.sys',
                'tools/install.ps1', 'tools/start.ps1', 'tools/stop.ps1',
                'tools/uninstall.ps1', 'tools/kdbg_live_verify.exe')) {
            if (@($names | Where-Object { $_ -ceq "$ExpectedRoot/$required" }).Count -ne 1) {
                throw "Package ZIP is missing exactly one required entry: $required"
            }
        }
        return $files.Count
    } finally { $archive.Dispose() }
}

function Test-KdbgSafeEvidenceZip {
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $files = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })
        $names = @($files | ForEach-Object FullName)
        if ($files.Count -eq 0 -or @($names | Where-Object {
                $_ -match '\\' -or $_ -match '^/' -or $_ -match '^[A-Za-z]:' -or
                $_ -match '(^|/)\.\.(/|$)' -or
                -not $_.StartsWith('evidence/', [StringComparison]::Ordinal)
            }).Count -ne 0 -or
            @($names | ForEach-Object { $_.ToLowerInvariant() } | Group-Object |
                Where-Object Count -gt 1).Count -ne 0) {
            throw 'Evidence ZIP contains an unsafe, duplicate, empty, or unexpected-root entry set.'
        }
        if (@($names | Where-Object { $_ -ceq 'evidence/out/guest-summary.json' }).Count -ne 1) {
            throw 'Evidence ZIP does not contain exactly one guest summary.'
        }
        return $files.Count
    } finally { $archive.Dispose() }
}

function Read-KdbgEvidenceJson {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$EntryName
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $entries = @($archive.Entries | Where-Object FullName -ceq $EntryName)
        if ($entries.Count -ne 1) { throw "Evidence entry is not unique: $EntryName" }
        $reader = [IO.StreamReader]::new($entries[0].Open(), [Text.Encoding]::UTF8, $true)
        try { return $reader.ReadToEnd() | ConvertFrom-Json }
        finally { $reader.Dispose() }
    } finally { $archive.Dispose() }
}

function Test-KdbgWin11ExtendedContract {
    [CmdletBinding()]
    param([string]$Root = $PSScriptRoot)
    $required = @(
        'Win11ExtendedLifecycle.psm1',
        'Invoke-Win11ExtendedLifecycle.ps1',
        'Invoke-Win11ExtendedGuest.ps1',
        'Test-Win11ExtendedLifecycle.Contract.ps1')
    $errors = [Collections.Generic.List[string]]::new()
    $records = [Collections.Generic.List[object]]::new()
    foreach ($leaf in $required) {
        $path = Join-Path $Root $leaf
        $tokens = $null
        $parseErrors = $null
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $errors.Add("missing:$leaf")
            continue
        }
        [void][Management.Automation.Language.Parser]::ParseFile(
            $path, [ref]$tokens, [ref]$parseErrors)
        if (@($parseErrors).Count -ne 0) { $errors.Add("parse:$leaf") }
        $records.Add([ordered]@{
            file = $leaf
            sha256 = Get-KdbgExtendedSha256 $path
            parse_error_count = @($parseErrors).Count
        })
    }
    $hostText = Get-Content -LiteralPath (Join-Path $Root 'Win11ExtendedLifecycle.psm1') -Raw
    $guestText = Get-Content -LiteralPath (Join-Path $Root 'Invoke-Win11ExtendedGuest.ps1') -Raw
    $tokens = $null
    $parseErrors = $null
    $moduleAst = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Root 'Win11ExtendedLifecycle.psm1'), [ref]$tokens, [ref]$parseErrors)
    $contractFunction = $moduleAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Test-KdbgWin11ExtendedContract'
    }, $true)
    $hostImplementationText = if ($null -eq $contractFunction) { '' } else {
        $hostText.Remove(
            $contractFunction.Extent.StartOffset,
            $contractFunction.Extent.EndOffset - $contractFunction.Extent.StartOffset)
    }
    $forbiddenCredentialPattern = ('(?i)ConvertFrom-' + 'SecureString') + '|' +
        ('ConvertTo-' + 'SecureString\s+-AsPlainText')
    $invariants = [ordered]@{
        exact_vm_guid = $hostImplementationText.Contains('Get-VM -Id $VmId')
        exact_checkpoint_guid = $hostImplementationText.Contains('$_.Id -eq $CheckpointId')
        dpapi_pscredential = $hostImplementationText.Contains('Import-Clixml') -and
            $hostImplementationText.Contains('-isnot [PSCredential]')
        workspace_static_reused = $hostImplementationText.Contains('Test-KdbgWin11ValidationWorkspace')
        package_and_certificate_pins = $hostImplementationText.Contains('ExpectedPreviousPackageSha256') -and
            $hostImplementationText.Contains('$binding.test_signing_certificate')
        distinct_package_generations = $guestText.Contains("`$currentPackageLeaf = 'KDBG-1.1.0-win-x64'") -and
            $guestText.Contains("`$previousPackageLeaf = 'KDBG-1.0.0-win-x64'") -and
            $guestText.Contains('$ExpectedCurrentPackageSha256 $currentPackageLeaf') -and
            $guestText.Contains('$ExpectedPreviousPackageSha256 $previousPackageLeaf')
        powershell_direct = $hostImplementationText.Contains('New-PSSession -VMName') -and
            $hostImplementationText.Contains('-ToSession')
        two_cycles_ten_stop_start = $guestText.Contains('foreach ($stopStart in 1..5)') -and
            $hostImplementationText.Contains('foreach ($cycle in 1..2)')
        four_reboot_boundaries = $hostImplementationText.Contains('$completedRebootBoundaries -ne 4')
        lifecycle_operations = $guestText.Contains('same-path-repair') -and
            $guestText.Contains('update-current') -and
            $guestText.Contains('rollback-previous') -and
            $guestText.Contains('forward-current') -and
            $guestText.Contains('clean-inventory')
        final_soak_contract = $guestText.Contains('$ReportCount -ne 61') -and
            $guestText.Contains('$SoakDurationSeconds -ne 1800') -and
            $guestText.Contains('total_scheduled_reads = $ReportCount * 8')
        midpoint_write_contract = $guestText.Contains("'--write'") -and
            $guestText.Contains("'--confirm-probe-pfn'") -and
            $guestText.Contains('rollback_requested_bytes') -and
            $guestText.Contains('final_gate_locked')
        seven_benchmark_runs = $guestText.Contains('foreach ($runIndex in 1..7)')
        clean_device_links = $guestText.Contains('device_queries') -and
            $guestText.Contains('device_open_succeeded')
        finally_restore_and_off = $hostImplementationText.Contains('finally {') -and
            $hostImplementationText.Contains('Restore-VMSnapshot -VMSnapshot $checkpointNow[0]') -and
            $hostImplementationText.Contains('$finalVm.State.ToString() -eq ''Off''')
        credentials_not_serialized = $hostImplementationText.Contains('credential_serialized = $false') -and
            $hostImplementationText -notmatch $forbiddenCredentialPattern
        no_live_pass_in_dry_run = $hostImplementationText.Contains('live_execution_performed = $false')
    }
    foreach ($entry in $invariants.GetEnumerator()) {
        if ($entry.Value -ne $true) { $errors.Add("invariant:$($entry.Key)") }
    }
    return [pscustomobject]@{
        schema = 'kdbg.win11-extended-static.v1'
        success = $errors.Count -eq 0
        invariant_count = $invariants.Count
        invariants = $invariants
        files = @($records)
        errors = @($errors)
        live_execution_performed = $false
    }
}

function Invoke-KdbgWin11ExtendedLifecycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter(Mandatory)][Guid]$VmId,
        [Parameter(Mandatory)][string]$CheckpointName,
        [Parameter(Mandatory)][Guid]$CheckpointId,
        [Parameter(Mandatory)][string]$CredentialPath,
        [Parameter(Mandatory)][string]$PreviousPackageZipPath,
        [Parameter(Mandatory)][string]$ExpectedPreviousPackageSha256,
        [Parameter(Mandatory)][string]$PreviousCertificatePath,
        [Parameter(Mandatory)][string]$ExpectedPreviousCertificateSha256,
        [Parameter(Mandatory)][string]$BenchmarkExecutablePath,
        [Parameter(Mandatory)][string]$ExpectedBenchmarkSha256,
        [Parameter(Mandatory)][switch]$ConfirmDisposableVm,
        [Parameter(Mandatory)][switch]$ConfirmCheckpointRestore,
        [ValidateRange(30, 900)][int]$ConnectionTimeoutSeconds = 300,
        [switch]$SkipLifecycle,
        [switch]$SkipSoak,
        [switch]$SkipBenchmarks,
        [ValidateRange(60, 1800)][int]$SoakDurationSeconds = 1800,
        [switch]$AllowCalibrationDuration,
        [switch]$DryRun
    )
    if (-not $ConfirmDisposableVm -or -not $ConfirmCheckpointRestore) {
        throw 'Both disposable-VM and exact-checkpoint-restore confirmations are required.'
    }
    if ($VmId -eq [Guid]::Empty -or $CheckpointId -eq [Guid]::Empty -or
        [string]::IsNullOrWhiteSpace($CheckpointName)) {
        throw 'Exact non-empty VM GUID and checkpoint Name/GUID are required.'
    }
    $plan = New-KdbgExtendedExecutionPlan -SkipLifecycle:$SkipLifecycle `
        -SkipSoak:$SkipSoak -SkipBenchmarks:$SkipBenchmarks `
        -SoakDurationSeconds $SoakDurationSeconds `
        -AllowCalibrationDuration:$AllowCalibrationDuration
    $root = [IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\')
    Assert-KdbgExtendedNoReparsePath $root
    $bindingPath = Join-Path $root 'binding.json'
    $binding = Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json
    if ($binding.schema -cne 'kdbg.win11-validation-binding.v1') {
        throw 'The input is not a Win11 hash-bound validation workspace.'
    }
    $workspaceModule = Join-Path $root 'Win11ValidationHarness.psm1'
    Import-Module $workspaceModule -Force
    $workspaceStatic = Test-KdbgWin11ValidationWorkspace -WorkspaceRoot $root
    if (-not $workspaceStatic.success) { throw 'Required-core workspace static validation failed.' }
    $currentZip = [IO.Path]::GetFullPath((Join-Path $root ($binding.package.relative_path -replace '/', '\')))
    Assert-KdbgExtendedHash $currentZip ([string]$binding.package.sha256) 'current package' | Out-Null
    $currentEntryCount = Test-KdbgSafeZip $currentZip $script:PackageRootLeaf
    $certBinding = $binding.test_signing_certificate
    if ($null -eq $certBinding -or $certBinding.production_trust -ne $false) {
        throw 'A disposable-VM test-signing certificate binding is required.'
    }
    $currentCert = [IO.Path]::GetFullPath((Join-Path $root ([string]$certBinding.relative_path -replace '/', '\')))
    Assert-KdbgExtendedHash $currentCert ([string]$certBinding.sha256) 'current certificate' | Out-Null
    $previousZip = [IO.Path]::GetFullPath($PreviousPackageZipPath)
    $previousCert = [IO.Path]::GetFullPath($PreviousCertificatePath)
    $benchmarkExe = [IO.Path]::GetFullPath($BenchmarkExecutablePath)
    Assert-KdbgExtendedNoReparsePath $previousZip
    Assert-KdbgExtendedNoReparsePath $previousCert
    Assert-KdbgExtendedNoReparsePath $benchmarkExe
    Assert-KdbgExtendedHash $previousZip $ExpectedPreviousPackageSha256 'previous package' | Out-Null
    Assert-KdbgExtendedHash $previousCert $ExpectedPreviousCertificateSha256 'previous certificate' | Out-Null
    Assert-KdbgExtendedHash $benchmarkExe $ExpectedBenchmarkSha256 'benchmark executable' | Out-Null
    $previousEntryCount = Test-KdbgSafeZip $previousZip $script:PreviousPackageRootLeaf
    if ($ExpectedPreviousPackageSha256 -ceq [string]$binding.package.sha256) {
        throw 'Lifecycle rollback requires two distinct hash-pinned package generations.'
    }
    $credentialFull = [IO.Path]::GetFullPath($CredentialPath)
    Assert-KdbgExtendedNoReparsePath $credentialFull
    $credential = Import-Clixml -LiteralPath $credentialFull
    if ($credential -isnot [PSCredential]) {
        throw 'CredentialPath did not contain a current-user DPAPI PSCredential.'
    }
    foreach ($commandName in @('Get-VM', 'Get-VMSnapshot', 'Restore-VMSnapshot',
            'Start-VM', 'Stop-VM', 'New-PSSession', 'Invoke-Command', 'Copy-Item',
            'Remove-PSSession')) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "Required Hyper-V/PowerShell Direct command is unavailable: $commandName"
        }
    }
    $vmMatches = @(Get-VM -Id $VmId -ErrorAction Stop)
    if ($vmMatches.Count -ne 1 -or $vmMatches[0].Name -cne [string]$binding.vm_name) {
        throw 'Exact VM GUID does not match the workspace-bound VM name.'
    }
    $vm = $vmMatches[0]
    if ($vm.State.ToString() -ne 'Off') { throw 'The exact VM must initially be Off.' }
    $checkpointMatches = @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
        $_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId
    })
    if ($checkpointMatches.Count -ne 1) {
        throw 'The exact checkpoint Name/GUID pair was not found exactly once.'
    }
    $checkpoint = $checkpointMatches[0]
    $contract = Test-KdbgWin11ExtendedContract
    if (-not $contract.success) { throw "Extended harness static contract failed: $($contract.errors -join ', ')" }
    $preflight = [ordered]@{
        schema = 'kdbg.win11-extended-preflight.v1'
        success = $true
        captured_utc = [DateTime]::UtcNow.ToString('o')
        vm = [ordered]@{ name = $vm.Name; id = $vm.Id.ToString(); initial_state = 'Off' }
        checkpoint = [ordered]@{ name = $checkpoint.Name; id = $checkpoint.Id.ToString() }
        current_package = [ordered]@{ sha256 = $binding.package.sha256; entry_count = $currentEntryCount }
        previous_package = [ordered]@{ sha256 = $ExpectedPreviousPackageSha256; entry_count = $previousEntryCount }
        certificates = [ordered]@{
            current_sha256 = $certBinding.sha256
            previous_sha256 = $ExpectedPreviousCertificateSha256
            production_trust = $false
        }
        benchmark_sha256 = $ExpectedBenchmarkSha256
        plan = $plan
        credential_supplied = $true
        credential_serialized = $false
        live_execution_performed = $false
    }
    if ($DryRun) { return [pscustomobject]$preflight }

    $runsRoot = Join-Path $root 'extended-runs'
    [IO.Directory]::CreateDirectory($runsRoot) | Out-Null
    Assert-KdbgExtendedNoReparsePath $runsRoot
    $runId = 'extended-{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),
        ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    $hostRunRoot = [IO.Path]::GetFullPath((Join-Path $runsRoot $runId))
    if (-not (Test-KdbgExtendedPathUnder $hostRunRoot $runsRoot) -or
        (Test-Path -LiteralPath $hostRunRoot)) { throw 'Unsafe or existing extended run root.' }
    [IO.Directory]::CreateDirectory($hostRunRoot) | Out-Null
    Write-KdbgExtendedJson (Join-Path $hostRunRoot 'preflight.json') $preflight
    $guestRoot = "C:\KDBG-Win11-Extended\$runId"
    $guestOut = "$guestRoot\out"
    $guestScript = "$guestRoot\Invoke-Win11ExtendedGuest.ps1"
    $guestCurrentZip = "$guestRoot\current.zip"
    $guestPreviousZip = "$guestRoot\previous.zip"
    $guestCurrentCert = "$guestRoot\current.cer"
    $guestPreviousCert = "$guestRoot\previous.cer"
    $guestBenchmark = "$guestRoot\kdbg_benchmarks.exe"
    $guestArchive = "$guestRoot\extended-evidence.zip"
    $hostArchive = Join-Path $hostRunRoot 'extended-evidence.zip'
    $session = $null
    $mutationBegan = $false
    $restored = $false
    $finalOff = $false
    $guestEvidenceValidated = $false
    $completedRebootBoundaries = 0
    $errors = [Collections.Generic.List[string]]::new()
    $phaseRecords = [Collections.Generic.List[object]]::new()

    function Connect-KdbgGuest {
        $deadline = [DateTime]::UtcNow.AddSeconds($ConnectionTimeoutSeconds)
        do {
            try {
                return New-PSSession -VMName $binding.vm_name -Credential $credential -ErrorAction Stop
            } catch { Start-Sleep -Seconds 3 }
        } while ([DateTime]::UtcNow -lt $deadline)
        throw 'PowerShell Direct did not become available before timeout.'
    }
    function Invoke-KdbgGuestPhase([string]$Phase) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $output = Invoke-Command -Session $session -ScriptBlock {
            param($Script, $PhaseName, $RootPath, $CheckpointText, $CurrentHash,
                $PreviousHash, $CurrentCertHash, $PreviousCertHash, $BenchmarkHash,
                $Duration, $ReportCount, $Calibration)
            $arguments = @(
                '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-File', $Script, '-Phase', $PhaseName, '-RunRoot', $RootPath,
                '-CheckpointId', $CheckpointText,
                '-ExpectedCurrentPackageSha256', $CurrentHash,
                '-ExpectedPreviousPackageSha256', $PreviousHash,
                '-ExpectedCurrentCertificateSha256', $CurrentCertHash,
                '-ExpectedPreviousCertificateSha256', $PreviousCertHash,
                '-ExpectedBenchmarkSha256', $BenchmarkHash,
                '-SoakDurationSeconds', [string]$Duration,
                '-ReportCount', [string]$ReportCount)
            if ($Calibration) { $arguments += '-AllowCalibrationDuration' }
            & powershell.exe @arguments
            if ($LASTEXITCODE -ne 0) { throw "Guest phase $PhaseName failed with exit code $LASTEXITCODE." }
        } -ArgumentList $guestScript, $Phase, $guestRoot, $CheckpointId.ToString('D'),
            ([string]$binding.package.sha256), $ExpectedPreviousPackageSha256,
            ([string]$certBinding.sha256), $ExpectedPreviousCertificateSha256,
            $ExpectedBenchmarkSha256, ([int]$plan.soak.duration_seconds),
            ([int]$plan.soak.report_count), ([bool]$plan.soak.calibration_only) -ErrorAction Stop
        $clock.Stop()
        $phaseRecords.Add([ordered]@{ phase = $Phase; elapsed_ms = $clock.ElapsedMilliseconds })
        return $output
    }
    function Restart-KdbgGuestBoundary {
        Invoke-Command -Session $session -ScriptBlock {
            shutdown.exe /r /t 0 /f | Out-Null
        } -ErrorAction SilentlyContinue | Out-Null
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 3
        return Connect-KdbgGuest
    }

    try {
        $mutationBegan = $true
        Restore-VMSnapshot -VMSnapshot $checkpoint -Confirm:$false -ErrorAction Stop
        $vm = Get-VM -Id $VmId -ErrorAction Stop
        if ($vm.State.ToString() -ne 'Off') { throw 'Exact checkpoint restore did not produce Off state.' }
        Start-VM -VM $vm -ErrorAction Stop | Out-Null
        $session = Connect-KdbgGuest
        Invoke-Command -Session $session -ScriptBlock {
            param($RootPath)
            if (Test-Path -LiteralPath $RootPath) { throw 'Guest extended run root already exists.' }
            [IO.Directory]::CreateDirectory($RootPath) | Out-Null
            [IO.Directory]::CreateDirectory((Join-Path $RootPath 'out')) | Out-Null
        } -ArgumentList $guestRoot -ErrorAction Stop
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Invoke-Win11ExtendedGuest.ps1') `
            -Destination $guestScript -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath $currentZip -Destination $guestCurrentZip -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath $previousZip -Destination $guestPreviousZip -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath $currentCert -Destination $guestCurrentCert -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath $previousCert -Destination $guestPreviousCert -ToSession $session -ErrorAction Stop
        Copy-Item -LiteralPath $benchmarkExe -Destination $guestBenchmark -ToSession $session -ErrorAction Stop
        Invoke-KdbgGuestPhase 'baseline' | Out-Null
        if (-not $SkipLifecycle) {
            foreach ($cycle in 1..2) {
                Invoke-KdbgGuestPhase "cycle-$cycle-exercise" | Out-Null
                $session = Restart-KdbgGuestBoundary
                $completedRebootBoundaries++
                Invoke-KdbgGuestPhase "cycle-$cycle-post-install-reboot" | Out-Null
                Invoke-KdbgGuestPhase "cycle-$cycle-uninstall" | Out-Null
                $session = Restart-KdbgGuestBoundary
                $completedRebootBoundaries++
                Invoke-KdbgGuestPhase "cycle-$cycle-post-clean-reboot" | Out-Null
            }
            if ($completedRebootBoundaries -ne 4) { throw 'Lifecycle did not complete exactly four reboot boundaries.' }
        }
        if (-not $SkipSoak) { Invoke-KdbgGuestPhase 'soak' | Out-Null }
        if (-not $SkipBenchmarks) { Invoke-KdbgGuestPhase 'benchmarks' | Out-Null }
        Invoke-KdbgGuestPhase 'finalize' | Out-Null
        Copy-Item -LiteralPath $guestArchive -Destination $hostArchive -FromSession $session -ErrorAction Stop
        Test-KdbgSafeEvidenceZip $hostArchive | Out-Null
        $guestSummary = Read-KdbgEvidenceJson $hostArchive 'evidence/out/guest-summary.json'
        $expectedCycleCount = if ($SkipLifecycle) { 0 } else { 2 }
        $expectedStopStartCount = if ($SkipLifecycle) { 0 } else { 10 }
        if ($guestSummary.success -ne $true -or
            [string]$guestSummary.checkpoint_id -cne $CheckpointId.ToString('D') -or
            [string]$guestSummary.current_package_sha256 -cne [string]$binding.package.sha256 -or
            [string]$guestSummary.previous_package_sha256 -cne $ExpectedPreviousPackageSha256 -or
            [int]$guestSummary.lifecycle_cycle_count -ne $expectedCycleCount -or
            [int]$guestSummary.lifecycle_stop_start_count -ne $expectedStopStartCount -or
            $guestSummary.credential_serialized -ne $false -or
            @($guestSummary.final_clean_inventory.device_queries |
                Where-Object absent -ne $true).Count -ne 0) {
            throw 'Guest summary does not match the exact extended execution plan.'
        }
        if (-not $SkipSoak) {
            $soakSummary = Read-KdbgEvidenceJson $hostArchive 'evidence/out/soak-summary.json'
            if ($soakSummary.success -ne $true -or
                [int]$soakSummary.target_duration_seconds -ne [int]$plan.soak.duration_seconds -or
                [int]$soakSummary.report_count -ne [int]$plan.soak.report_count -or
                [int]$soakSummary.total_scheduled_reads -ne [int]$plan.soak.total_scheduled_reads -or
                $soakSummary.midpoint_write.rollback_verified -ne $true -or
                $soakSummary.final_gate_locked -ne $true) {
                throw 'Guest soak summary does not match the exact execution plan.'
            }
        }
        if (-not $SkipBenchmarks) {
            $benchmarkSummary = Read-KdbgEvidenceJson $hostArchive 'evidence/out/benchmark-summary.json'
            if ($benchmarkSummary.success -ne $true -or [int]$benchmarkSummary.run_count -ne 7 -or
                [string]$benchmarkSummary.executable_sha256 -cne $ExpectedBenchmarkSha256 -or
                $benchmarkSummary.mode -cne 'mock_only' -or
                $benchmarkSummary.timing_represents_product_runtime -ne $false) {
                throw 'Guest benchmark summary does not match the exact seven-run contract.'
            }
        }
        $guestEvidenceValidated = $true
    } catch {
        $errors.Add((Protect-KdbgExtendedText $_.Exception.Message @($root, $credential.UserName)))
        if ($session) {
            try { Invoke-KdbgGuestPhase 'emergency-cleanup' | Out-Null }
            catch { $errors.Add((Protect-KdbgExtendedText $_.Exception.Message @($root, $credential.UserName))) }
        }
    } finally {
        if ($session) {
            try { Remove-PSSession -Session $session -ErrorAction Stop }
            catch { $errors.Add((Protect-KdbgExtendedText $_.Exception.Message @($root, $credential.UserName))) }
        }
        if ($mutationBegan) {
            try {
                $vmNow = Get-VM -Id $VmId -ErrorAction Stop
                if ($vmNow.State.ToString() -ne 'Off') {
                    Stop-VM -VM $vmNow -TurnOff -Force -Confirm:$false -ErrorAction Stop
                }
            } catch { $errors.Add((Protect-KdbgExtendedText $_.Exception.Message @($root, $credential.UserName))) }
            try {
                $boundVm = Get-VM -Id $VmId -ErrorAction Stop
                $checkpointNow = @(Get-VMSnapshot -VM $boundVm -ErrorAction Stop | Where-Object {
                    $_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId
                })
                if ($checkpointNow.Count -ne 1) { throw 'Exact checkpoint identity is no longer unique.' }
                Restore-VMSnapshot -VMSnapshot $checkpointNow[0] -Confirm:$false -ErrorAction Stop
                $restored = $true
            } catch { $errors.Add((Protect-KdbgExtendedText $_.Exception.Message @($root, $credential.UserName))) }
            try {
                $finalVm = Get-VM -Id $VmId -ErrorAction Stop
                if ($finalVm.State.ToString() -ne 'Off') {
                    Stop-VM -VM $finalVm -TurnOff -Force -Confirm:$false -ErrorAction Stop
                    $finalVm = Get-VM -Id $VmId -ErrorAction Stop
                }
                $finalOff = $finalVm.State.ToString() -eq 'Off'
                if (-not $finalOff) { throw 'Final VM state is not Off.' }
            } catch { $errors.Add((Protect-KdbgExtendedText $_.Exception.Message @($root, $credential.UserName))) }
        }
    }
    $success = $errors.Count -eq 0 -and $guestEvidenceValidated -and
        (Test-Path -LiteralPath $hostArchive -PathType Leaf) -and
        $restored -and $finalOff
    $summary = [ordered]@{
        schema = 'kdbg.win11-extended-host.v1'
        success = $success
        completed_utc = [DateTime]::UtcNow.ToString('o')
        vm = [ordered]@{ name = $binding.vm_name; id = $VmId.ToString() }
        checkpoint = [ordered]@{ name = $CheckpointName; id = $CheckpointId.ToString(); restored = $restored }
        final_vm_off = $finalOff
        completed_reboot_boundaries = $completedRebootBoundaries
        guest_evidence_validated = $guestEvidenceValidated
        plan = $plan
        phases = @($phaseRecords)
        evidence_archive_sha256 = if (Test-Path -LiteralPath $hostArchive) { Get-KdbgExtendedSha256 $hostArchive } else { $null }
        errors = @($errors)
        credential_serialized = $false
        live_execution_performed = $true
        claim_boundary = if ($success -and -not $plan.soak.calibration_only) {
            'Selected live extended gates completed and the exact checkpoint was restored with final Off.'
        } elseif ($success) {
            'Calibration run completed; shortened soak is not final 30-minute evidence.'
        } else { 'Extended validation failed or remained incomplete; no passing claim is allowed.' }
    }
    Write-KdbgExtendedJson (Join-Path $hostRunRoot 'host-summary.json') $summary
    if (-not $success) { throw "Win11 extended validation failed; inspect $hostRunRoot\host-summary.json" }
    return [pscustomobject]$summary
}

Export-ModuleMember -Function @(
    'Get-KdbgPercentileSummary',
    'New-KdbgExtendedExecutionPlan',
    'Test-KdbgWin11ExtendedContract',
    'Invoke-KdbgWin11ExtendedLifecycle')

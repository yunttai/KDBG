[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet(
        'baseline',
        'cycle-1-exercise', 'cycle-1-post-install-reboot',
        'cycle-1-uninstall', 'cycle-1-post-clean-reboot',
        'cycle-2-exercise', 'cycle-2-post-install-reboot',
        'cycle-2-uninstall', 'cycle-2-post-clean-reboot',
        'soak', 'benchmarks', 'finalize', 'emergency-cleanup')][string]$Phase,
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][Guid]$CheckpointId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedCurrentPackageSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedPreviousPackageSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedCurrentCertificateSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedPreviousCertificateSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedBenchmarkSha256,
    [Parameter(Mandatory)][ValidateRange(0, 1800)][int]$SoakDurationSeconds,
    [Parameter(Mandatory)][ValidateRange(0, 1801)][int]$ReportCount,
    [switch]$AllowCalibrationDuration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$currentPackageLeaf = 'KDBG-1.1.0-win-x64'
$previousPackageLeaf = 'KDBG-1.0.0-win-x64'
$root = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$expectedParent = [IO.Path]::GetFullPath('C:\KDBG-Win11-Extended').TrimEnd('\')
if (-not $root.StartsWith(($expectedParent + '\'), [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetDirectoryName($root) -cne $expectedParent) {
    throw 'RunRoot must be one direct child of C:\KDBG-Win11-Extended.'
}
$outRoot = Join-Path $root 'out'
$statePath = Join-Path $root 'state.json'
$currentArchive = Join-Path $root 'current.zip'
$previousArchive = Join-Path $root 'previous.zip'
$currentCertificate = Join-Path $root 'current.cer'
$previousCertificate = Join-Path $root 'previous.cer'
$benchmarkExecutable = Join-Path $root 'kdbg_benchmarks.exe'
$currentParent = Join-Path $root 'current'
$previousParent = Join-Path $root 'previous'
$currentPackage = Join-Path $currentParent $currentPackageLeaf
$previousPackage = Join-Path $previousParent $previousPackageLeaf
$evidenceArchive = Join-Path $root 'extended-evidence.zip'

function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText(
        $Path, (($Value | ConvertTo-Json -Depth 30) + [Environment]::NewLine), $utf8)
}

function New-CanonicalEvidenceArchive([string]$SourceRoot, [string]$DestinationPath) {
    if (Test-Path -LiteralPath $DestinationPath) {
        throw 'Refusing to overwrite evidence archive.'
    }
    Add-Type -AssemblyName System.IO.Compression
    $sourceFull = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
    $sourcePrefix = $sourceFull + '\'
    $files = @(Get-ChildItem -LiteralPath $sourceFull -Recurse -File)
    if ($files.Count -eq 0) { throw 'Evidence archive source is empty.' }
    $relativePaths = [Collections.Generic.List[string]]::new()
    $byRelativePath = @{}
    foreach ($file in $files) {
        if (-not $file.FullName.StartsWith(
                $sourcePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Evidence archive input escaped its source root: $($file.FullName)"
        }
        # Windows PowerShell 5.1 runs on .NET Framework, where
        # System.IO.Path.GetRelativePath is unavailable.
        $relative = $file.FullName.Substring($sourcePrefix.Length).Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($relative) -or $relative -match '(^|/)\.\.(/|$)') {
            throw "Unsafe evidence archive relative path: $relative"
        }
        $relativePaths.Add($relative)
        $byRelativePath[$relative] = $file.FullName
    }
    $ordered = [string[]]$relativePaths.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    $fileStream = [IO.File]::Open(
        $DestinationPath, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $fileStream, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($relative in $ordered) {
                $entry = $archive.CreateEntry(
                    "evidence/$relative", [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]'2000-01-01T00:00:00Z'
                $input = [IO.File]::OpenRead([string]$byRelativePath[$relative])
                try {
                    $output = $entry.Open()
                    try { $input.CopyTo($output) } finally { $output.Dispose() }
                }
                finally { $input.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $fileStream.Dispose() }
}

function Get-Sha256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing pinned input: $Path" }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Hash([string]$Path, [string]$Expected, [string]$Label) {
    $actual = Get-Sha256 $Path
    if ($actual -cne $Expected) { throw "$Label SHA-256 mismatch: $actual" }
}

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse point is not allowed: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Guest extended validation requires Administrator.'
    }
}

function Invoke-Captured(
    [string]$Name,
    [string]$FilePath,
    [string[]]$Arguments,
    [switch]$AllowFailure) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& $FilePath @Arguments 2>&1 | ForEach-Object { $_.ToString() })
        $code = [int]$LASTEXITCODE
    } finally { $ErrorActionPreference = $saved }
    $clock.Stop()
    $record = [ordered]@{
        name = $Name
        exit_code = $code
        elapsed_ms = $clock.ElapsedMilliseconds
        output_line_count = $output.Count
    }
    if ($code -ne 0 -and -not $AllowFailure) {
        throw "$Name failed with exit code $code`: $($output -join [Environment]::NewLine)"
    }
    return [pscustomobject]$record
}

function Invoke-PackageScript(
    [string]$PackageRoot,
    [string]$ScriptName,
    [string[]]$Arguments) {
    return Invoke-Captured "$([IO.Path]::GetFileName((Split-Path -Parent $PackageRoot)))-$ScriptName" `
        'powershell.exe' (@('-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PackageRoot "tools\$ScriptName")) + $Arguments)
}

function Get-ServiceQueryCode([string]$Name) {
    & sc.exe query $Name 2>&1 | Out-Null
    return [int]$LASTEXITCODE
}

function Get-CertificateThumbprints {
    $values = [Collections.Generic.List[string]]::new()
    foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
        foreach ($cert in @(Get-ChildItem -Path $store -ErrorAction Stop)) {
            $values.Add("$store|$($cert.Thumbprint.ToLowerInvariant())")
        }
    }
    return @($values | Sort-Object -Unique)
}

function Get-DeviceQuery([string]$Name) {
    if ($null -eq ('KdbgWin11Extended.Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace KdbgWin11Extended {
    public static class Native {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(
            string name, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr templateFile);
    }
}
'@
    }
    # PowerShell parses 0x80000000 as a negative Int32. Pass the native
    # GENERIC_READ bit as an explicitly positive UInt32 so reflection does not
    # reject the P/Invoke argument before CreateFileW is called.
    $genericRead = [uint32]2147483648
    $handle = [KdbgWin11Extended.Native]::CreateFile(
        "\\.\$Name", $genericRead, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    try {
        $opened = -not $handle.IsInvalid
        $nativeError = if ($opened) { 0 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
        return [ordered]@{
            name = $Name
            device_open_succeeded = $opened
            win32_error = $nativeError
            absent = -not $opened -and $nativeError -in @(2, 3)
        }
    } finally { $handle.Dispose() }
}

function Get-CleanInventory {
    $drivers = @()
    foreach ($name in @('KDBG', 'KDBGProbe')) {
        $drivers += [ordered]@{
            name = $name
            sc_query_exit_code = Get-ServiceQueryCode $name
            registry_present = Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
            cim_count = @(Get-CimInstance Win32_SystemDriver -Filter "Name='$name'" -ErrorAction SilentlyContinue).Count
        }
    }
    return [ordered]@{
        captured_utc = [DateTime]::UtcNow.ToString('o')
        drivers = $drivers
        device_queries = @('KDBG', 'KDBGProbe') | ForEach-Object { Get-DeviceQuery $_ }
        kdbg_process_count = @(Get-Process -Name KDBG,kdbg_live_verify -ErrorAction SilentlyContinue).Count
        user_data_present = Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'KDBG')
        certificate_thumbprints = Get-CertificateThumbprints
    }
}

function Assert-CleanInventory($Inventory, [string[]]$BaselineCertificates) {
    foreach ($driver in $Inventory.drivers) {
        if ([int]$driver.sc_query_exit_code -ne 1060 -or $driver.registry_present -ne $false -or
            [int]$driver.cim_count -ne 0) {
            throw "Clean inventory failed for $($driver.name)."
        }
    }
    if (@($Inventory.device_queries | Where-Object absent -ne $true).Count -ne 0) {
        throw 'Clean inventory found a reachable KDBG device link.'
    }
    if ([int]$Inventory.kdbg_process_count -ne 0 -or $Inventory.user_data_present -ne $false) {
        throw 'Clean inventory found KDBG processes or user data.'
    }
    $actual = @($Inventory.certificate_thumbprints | Sort-Object -Unique)
    $expected = @($BaselineCertificates | Sort-Object -Unique)
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw 'Clean inventory certificate set does not match baseline.'
    }
}

function Import-TestCertificate([string]$Path, [string]$ExpectedHash) {
    Assert-Hash $Path $ExpectedHash 'certificate'
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
    if ($certificate.Subject -cne $certificate.Issuer) { throw 'Test certificate must be self-signed.' }
    $addedStores = [Collections.Generic.List[string]]::new()
    foreach ($storeName in @('Root', 'TrustedPublisher')) {
        $storePath = "Cert:\LocalMachine\$storeName"
        $present = @((Get-ChildItem -Path $storePath -ErrorAction Stop) | Where-Object {
                $_.Thumbprint.ToLowerInvariant() -ceq $certificate.Thumbprint.ToLowerInvariant()
            }).Count -ne 0
        if ($present) { continue }
        $output = @(& "$env:SystemRoot\System32\certutil.exe" -f -addstore $storeName $Path 2>&1 |
            ForEach-Object { $_.ToString() })
        if ($LASTEXITCODE -ne 0) {
            throw "certutil import into $storeName failed: $($output -join [Environment]::NewLine)"
        }
        $addedStores.Add($storeName)
    }
    return [pscustomobject]@{
        thumbprint = $certificate.Thumbprint.ToLowerInvariant()
        added_stores = @($addedStores)
    }
}

function Remove-TestCertificate([string]$Thumbprint, [string[]]$StoreNames = @('Root', 'TrustedPublisher')) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return }
    foreach ($storeName in $StoreNames) {
        $query = @(& "$env:SystemRoot\System32\certutil.exe" -store $storeName $Thumbprint 2>&1 |
            ForEach-Object { $_.ToString() })
        if ($LASTEXITCODE -ne 0) { continue }
        & "$env:SystemRoot\System32\certutil.exe" -delstore $storeName $Thumbprint 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "certutil removal from $storeName failed with exit code $LASTEXITCODE."
        }
    }
}

function Expand-PinnedPackage(
    [string]$Archive,
    [string]$Parent,
    [string]$ExpectedHash,
    [string]$ExpectedRootLeaf) {
    Assert-Hash $Archive $ExpectedHash 'package archive'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $names = @($zip.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) } |
            ForEach-Object FullName)
        if ($names.Count -eq 0 -or @($names | Where-Object {
                    $_ -match '\\' -or $_ -match '^/' -or $_ -match '^[A-Za-z]:' -or
                    $_ -match '(^|/)\.\.(/|$)' -or
                    -not $_.StartsWith("$ExpectedRootLeaf/", [StringComparison]::Ordinal)
                }).Count -ne 0 -or
            @($names | ForEach-Object { $_.ToLowerInvariant() } | Group-Object |
                Where-Object Count -gt 1).Count -ne 0) {
            throw 'Package archive entry set is unsafe.'
        }
    } finally { $zip.Dispose() }
    if (Test-Path -LiteralPath $Parent) { throw "Package extraction parent already exists: $Parent" }
    [IO.Directory]::CreateDirectory($Parent) | Out-Null
    Expand-Archive -LiteralPath $Archive -DestinationPath $Parent
}

function Get-PackageDriverHashes([string]$PackageRoot) {
    return [ordered]@{
        driver = Get-Sha256 (Join-Path $PackageRoot 'drivers\KDbgDriver.sys')
        probe = Get-Sha256 (Join-Path $PackageRoot 'drivers\KDbgProbe.sys')
    }
}

function Invoke-Readiness([string]$PackageRoot, [string]$Label, [int]$ReadSamples = 3) {
    $reportPath = Join-Path $outRoot "$Label.json"
    $verifier = Join-Path $PackageRoot 'tools\kdbg_live_verify.exe'
    [void](Invoke-Captured $Label $verifier @(
            '--output', $reportPath, '--build-id', "KDBG-win11-extended-$Label",
            '--read-samples', [string]$ReadSamples))
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $hashes = Get-PackageDriverHashes $PackageRoot
    if ($report.success -ne $true -or $report.mode -cne 'read-only' -or
        $report.runtime_identity.verified -ne $true -or
        [int]$report.backend.abi_version -ne 7 -or
        $report.backend.supports_physical_page_compare_write -ne $true -or
        [int]$report.probe_before.byte_count -ne 4096 -or
        $report.write_cleanup.final_gate_locked -ne $true -or
        [string]$report.runtime_identity.kdbg_service.binary.sha256 -cne $hashes.driver -or
        [string]$report.runtime_identity.probe_service.binary.sha256 -cne $hashes.probe) {
        throw "$Label readiness identity/ABI/Probe/gate contract failed."
    }
    return $report
}

function Install-And-Verify([string]$PackageRoot, [string]$Label) {
    [void](Invoke-PackageScript $PackageRoot 'install.ps1' @(
            '-Start', '-ConfirmDedicatedVm', '-ConfirmSnapshot'))
    return Invoke-Readiness $PackageRoot $Label 3
}

function Uninstall-Current {
    if (Test-Path -LiteralPath (Join-Path $currentPackage 'tools\uninstall.ps1')) {
        [void](Invoke-PackageScript $currentPackage 'uninstall.ps1' @(
                '-ConfirmKdbgServices', '-PurgeUserData'))
    }
}

function Read-State {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { throw 'Guest state is missing.' }
    return Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
}

function Save-State($State) { Write-Json $statePath $State }

function Invoke-LifecycleExercise([int]$Cycle) {
    $state = Read-State
    $currentCertState = Import-TestCertificate $currentCertificate $ExpectedCurrentCertificateSha256
    $previousCertState = Import-TestCertificate $previousCertificate $ExpectedPreviousCertificateSha256
    $records = [Collections.Generic.List[object]]::new()
    $records.Add([ordered]@{ operation = 'install-previous'; readiness = Install-And-Verify $previousPackage "cycle-$Cycle-install-previous" })
    foreach ($stopStart in 1..5) {
        [void](Invoke-PackageScript $previousPackage 'stop.ps1' @())
        [void](Invoke-PackageScript $previousPackage 'start.ps1' @(
                '-ConfirmDedicatedVm', '-ConfirmSnapshot'))
        $records.Add([ordered]@{
            operation = 'stop/start'
            index = $stopStart
            readiness = Invoke-Readiness $previousPackage "cycle-$Cycle-stop-start-$stopStart" 3
        })
    }
    $records.Add([ordered]@{ operation = 'same-path-repair'; readiness = Install-And-Verify $previousPackage "cycle-$Cycle-same-path-repair" })
    $records.Add([ordered]@{ operation = 'update-current'; readiness = Install-And-Verify $currentPackage "cycle-$Cycle-update-current" })
    $records.Add([ordered]@{ operation = 'rollback-previous'; readiness = Install-And-Verify $previousPackage "cycle-$Cycle-rollback-previous" })
    $records.Add([ordered]@{ operation = 'forward-current'; readiness = Install-And-Verify $currentPackage "cycle-$Cycle-forward-current" })
    $state.cycle_records += [pscustomobject]@{
        cycle = $Cycle
        exercise_completed_utc = [DateTime]::UtcNow.ToString('o')
        stop_start_count = 5
        current_certificate = $currentCertState
        previous_certificate = $previousCertState
        operations = @($records)
    }
    Save-State $state
    Write-Json (Join-Path $outRoot "cycle-$Cycle-exercise.json") $state.cycle_records[-1]
}

function Invoke-PostInstallReboot([int]$Cycle) {
    $state = Read-State
    $start = Invoke-PackageScript $currentPackage 'start.ps1' @(
        '-ConfirmDedicatedVm', '-ConfirmSnapshot')
    $readiness = Invoke-Readiness $currentPackage "cycle-$Cycle-post-install-reboot" 3
    $record = [ordered]@{
        cycle = $Cycle
        operation = 'post-install-reboot-readiness'
        boot_time = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        explicit_demand_start = $start
        readiness = $readiness
    }
    Write-Json (Join-Path $outRoot "cycle-$Cycle-post-install-reboot.json") $record
}

function Invoke-CycleUninstall([int]$Cycle) {
    $state = Read-State
    Uninstall-Current
    foreach ($record in @($state.cycle_records | Where-Object cycle -eq $Cycle)) {
        Remove-TestCertificate ([string]$record.current_certificate.thumbprint) `
            @($record.current_certificate.added_stores)
        Remove-TestCertificate ([string]$record.previous_certificate.thumbprint) `
            @($record.previous_certificate.added_stores)
    }
    $inventory = Get-CleanInventory
    Assert-CleanInventory $inventory @($state.baseline_certificate_thumbprints)
    $record = [ordered]@{ cycle = $Cycle; operation = 'uninstall'; clean_inventory = $inventory }
    Write-Json (Join-Path $outRoot "cycle-$Cycle-uninstall.json") $record
}

function Invoke-PostCleanReboot([int]$Cycle) {
    $state = Read-State
    $inventory = Get-CleanInventory
    Assert-CleanInventory $inventory @($state.baseline_certificate_thumbprints)
    $record = [ordered]@{
        cycle = $Cycle
        operation = 'clean-inventory-after-reboot'
        boot_time = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        clean_inventory = $inventory
    }
    Write-Json (Join-Path $outRoot "cycle-$Cycle-post-clean-reboot.json") $record
}

function Invoke-Soak {
    $state = Read-State
    if ($SoakDurationSeconds -ne 1800 -and -not $AllowCalibrationDuration) {
        throw 'Short soak duration is calibration-only and requires AllowCalibrationDuration.'
    }
    if ($SoakDurationSeconds -eq 1800 -and $ReportCount -ne 61) {
        throw 'Final soak requires exactly 1800 seconds and 61 reports.'
    }
    if ($SoakDurationSeconds -ne 1800 -and $ReportCount -lt 3) {
        throw 'Calibration soak requires at least three reports.'
    }
    $certificateState = Import-TestCertificate $currentCertificate $ExpectedCurrentCertificateSha256
    $readReports = [Collections.Generic.List[object]]::new()
    $writeRecord = $null
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        [void](Install-And-Verify $currentPackage 'soak-installed')
        $verifier = Join-Path $currentPackage 'tools\kdbg_live_verify.exe'
        $intervalSeconds = if ($SoakDurationSeconds -eq 1800) { 30.0 } else {
            [double]$SoakDurationSeconds / [double]($ReportCount - 1)
        }
        $midpointIndex = [int][Math]::Floor(($ReportCount - 1) / 2)
        $baselinePfn = $null
        $baselinePhysicalAddress = $null
        $baselineGeneration = $null
        $baselineCrc32 = $null
        $currentHashes = Get-PackageDriverHashes $currentPackage
        for ($index = 0; $index -lt $ReportCount; $index++) {
            $due = $intervalSeconds * $index
            while ($clock.Elapsed.TotalSeconds -lt $due) {
                $remaining = $due - $clock.Elapsed.TotalSeconds
                Start-Sleep -Milliseconds ([int][Math]::Min(1000, [Math]::Max(1, $remaining * 1000)))
            }
            $leaf = 'soak-read-{0:d3}.json' -f ($index + 1)
            $path = Join-Path $outRoot $leaf
            [void](Invoke-Captured "soak-read-$($index + 1)" $verifier @(
                    '--output', $path, '--build-id', "KDBG-win11-soak-$($index + 1)",
                    '--read-samples', '8'))
            $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($report.success -ne $true -or $report.mode -cne 'read-only' -or
                $report.cancelled -ne $false -or
                $report.backend.connected -ne $true -or $report.backend.is_mock -ne $false -or
                [int]$report.backend.abi_version -ne 7 -or
                $report.backend.supports_physical_page_compare_write -ne $true -or
                [int]$report.probe_before.byte_count -ne 4096 -or
                @($report.latency.read_samples_ms).Count -ne 8 -or
                $report.runtime_identity.verified -ne $true -or
                [string]$report.runtime_identity.kdbg_service.binary.sha256 -cne $currentHashes.driver -or
                [string]$report.runtime_identity.probe_service.binary.sha256 -cne $currentHashes.probe -or
                @($report.errors).Count -ne 0 -or
                @($report.operations | Where-Object passed -ne $true).Count -ne 0 -or
                @($report.comparisons | Where-Object {
                        $_.match -ne $true -or [int]$_.mismatch_count -ne 0
                    }).Count -ne 0 -or
                $report.write_cleanup.final_gate_locked -ne $true -or
                [int]$report.write_cleanup.apply_requested_bytes -ne 0 -or
                [int]$report.write_cleanup.rollback_requested_bytes -ne 0) {
                throw "Soak read report $($index + 1) failed its exact contract."
            }
            if ($null -eq $baselinePfn) {
                $baselinePfn = [uint64]$report.probe_before.pfn
                $baselinePhysicalAddress = [uint64]$report.probe_before.physical_address
                $baselineGeneration = [uint64]$report.probe_before.generation
                $baselineCrc32 = [uint32]$report.probe_before.crc32
            }
            if ([uint64]$report.probe_before.pfn -ne $baselinePfn -or
                [uint64]$report.probe_before.physical_address -ne $baselinePhysicalAddress -or
                [uint64]$report.probe_before.generation -ne $baselineGeneration -or
                [uint32]$report.probe_before.crc32 -ne $baselineCrc32) {
                throw 'Probe identity or baseline CRC changed during soak.'
            }
            $readReports.Add([ordered]@{
                index = $index + 1
                elapsed_seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 3)
                file = $leaf
                sha256 = Get-Sha256 $path
                pfn = $baselinePfn
                crc32 = [uint32]$report.probe_before.crc32
                read_samples = 8
                final_gate_locked = [bool]$report.write_cleanup.final_gate_locked
            })
            if ($index -eq $midpointIndex) {
                $writePath = Join-Path $outRoot 'soak-midpoint-write-rollback.json'
                [void](Invoke-Captured 'soak-midpoint-write-rollback' $verifier @(
                        '--write', '--confirm-disposable-vm',
                        '--snapshot-id', $CheckpointId.ToString('D'),
                        '--confirm-probe-pfn', [string]$baselinePfn,
                        '--output', $writePath, '--build-id', 'KDBG-win11-soak-midpoint',
                        '--read-samples', '16'))
                $write = Get-Content -LiteralPath $writePath -Raw | ConvertFrom-Json
                if ($write.success -ne $true -or $write.mode -cne 'probe-write-rollback' -or
                    $write.cancelled -ne $false -or
                    $write.operator_confirmed_disposable_vm -ne $true -or
                    [string]$write.snapshot_id -cne $CheckpointId.ToString('D') -or
                    $write.backend.connected -ne $true -or $write.backend.is_mock -ne $false -or
                    [int]$write.backend.abi_version -ne 7 -or
                    $write.backend.supports_physical_page_compare_write -ne $true -or
                    $write.runtime_identity.verified -ne $true -or
                    [uint64]$write.probe_before.pfn -ne $baselinePfn -or
                    [uint64]$write.probe_before.physical_address -ne $baselinePhysicalAddress -or
                    [uint64]$write.probe_before.generation -ne $baselineGeneration -or
                    [uint32]$write.probe_before.crc32 -ne $baselineCrc32 -or
                    [int]$write.write_cleanup.rollback_requested_bytes -ne 4096 -or
                    $write.write_cleanup.rollback_attempted -ne $true -or
                    $write.write_cleanup.rollback_verified -ne $true -or
                    $write.write_cleanup.final_relock_attempted -ne $true -or
                    $write.write_cleanup.final_gate_locked -ne $true -or
                    [int]$write.write_cleanup.edit_offset -ne 256 -or
                    [int]$write.write_cleanup.edit_length -ne 8 -or
                    [int]$write.write_cleanup.apply_requested_bytes -ne 8 -or
                    [uint32]$write.probe_after_rollback.crc32 -ne $baselineCrc32 -or
                    @($write.errors).Count -ne 0 -or
                    @($write.operations | Where-Object passed -ne $true).Count -ne 0 -or
                    @($write.comparisons | Where-Object {
                            $_.match -ne $true -or [int]$_.mismatch_count -ne 0
                        }).Count -ne 0) {
                    throw 'Midpoint verified write/read-back/reload/rollback/relock contract failed.'
                }
                $writeRecord = [ordered]@{
                    at_report = $index + 1
                    file = 'soak-midpoint-write-rollback.json'
                    sha256 = Get-Sha256 $writePath
                    pfn = $baselinePfn
                    rollback_requested_bytes = 4096
                    rollback_verified = $true
                    final_gate_locked = $true
                }
            }
        }
        $clock.Stop()
        if ($null -eq $writeRecord) { throw 'The midpoint verified transaction did not run.' }
        if ($SoakDurationSeconds -eq 1800 -and ($clock.Elapsed.TotalSeconds -lt 1800 -or $readReports.Count -ne 61)) {
            throw 'Final soak did not reach the 30-minute/61-report contract.'
        }
        $last = Get-Content -LiteralPath (Join-Path $outRoot $readReports[-1].file) -Raw | ConvertFrom-Json
        if ($last.write_cleanup.final_gate_locked -ne $true) { throw 'Final soak gate is not locked.' }
        $summary = [ordered]@{
            schema = 'kdbg.win11-extended-soak.v1'
            success = $true
            calibration_only = $SoakDurationSeconds -ne 1800
            target_duration_seconds = $SoakDurationSeconds
            elapsed_seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 3)
            report_count = $readReports.Count
            reads_per_report = 8
            total_scheduled_reads = $ReportCount * 8
            midpoint_write = $writeRecord
            final_gate_locked = $true
            reports = @($readReports)
        }
        Write-Json (Join-Path $outRoot 'soak-summary.json') $summary
    } finally {
        try { Uninstall-Current } catch {}
        Remove-TestCertificate ([string]$certificateState.thumbprint) @($certificateState.added_stores)
        $inventory = Get-CleanInventory
        Assert-CleanInventory $inventory @($state.baseline_certificate_thumbprints)
        Write-Json (Join-Path $outRoot 'soak-clean-inventory.json') $inventory
    }
}

function Get-Percentile([double[]]$Values) {
    $ordered = [double[]]($Values | Sort-Object)
    $middle = [int][Math]::Floor($ordered.Count / 2)
    $median = if (($ordered.Count % 2) -eq 1) { $ordered[$middle] } else {
        ($ordered[$middle - 1] + $ordered[$middle]) / 2.0
    }
    $p95Index = [int][Math]::Max(0, [Math]::Ceiling(0.95 * $ordered.Count) - 1)
    return [ordered]@{ median = $median; p95_nearest_rank = $ordered[$p95Index] }
}

function Invoke-Benchmarks {
    Assert-Hash $benchmarkExecutable $ExpectedBenchmarkSha256 'benchmark executable'
    $runs = [Collections.Generic.List[object]]::new()
    foreach ($runIndex in 1..7) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $saved = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $stdout = @(& $benchmarkExecutable 2>&1 | ForEach-Object { $_.ToString() })
            $code = [int]$LASTEXITCODE
        } finally { $ErrorActionPreference = $saved }
        $clock.Stop()
        if ($code -ne 0) { throw "Benchmark run $runIndex failed with exit code $code." }
        $text = $stdout -join [Environment]::NewLine
        $document = $text | ConvertFrom-Json
        if ([int]$document.schema_version -ne 2 -or $document.mode -cne 'mock_only' -or
            $document.live_driver_access -ne $false -or
            $document.timing_represents_product_runtime -ne $false -or
            $document.overall_pass -ne $true -or
            @($document.metrics | Where-Object pass -ne $true).Count -ne 0) {
            throw "Benchmark run $runIndex violated its declared mock-only contract."
        }
        $leaf = 'benchmark-run-{0:d2}.json' -f $runIndex
        Write-Json (Join-Path $outRoot $leaf) $document
        $runs.Add([ordered]@{
            run = $runIndex
            elapsed_ms = [Math]::Round($clock.Elapsed.TotalMilliseconds, 6)
            file = $leaf
            sha256 = Get-Sha256 (Join-Path $outRoot $leaf)
            document = $document
        })
    }
    $elapsed = [double[]]@($runs | ForEach-Object { [double]$_.elapsed_ms })
    $aggregates = [Collections.Generic.List[object]]::new()
    foreach ($metricName in @($runs[0].document.metrics | ForEach-Object name)) {
        $metricRuns = @($runs | ForEach-Object {
                @($_.document.metrics | Where-Object name -ceq $metricName)[0]
            })
        $fields = [ordered]@{}
        foreach ($property in $metricRuns[0].PSObject.Properties) {
            if ($property.Name -in @('name', 'pass') -or $property.Value -is [bool] -or
                $property.Value -isnot [ValueType]) { continue }
            $values = [double[]]@($metricRuns | ForEach-Object { [double]$_.PSObject.Properties[$property.Name].Value })
            $fields[$property.Name] = Get-Percentile $values
        }
        $aggregates.Add([ordered]@{ name = $metricName; fields = $fields })
    }
    $summary = [ordered]@{
        schema = 'kdbg.win11-extended-benchmarks.v1'
        success = $true
        executable_sha256 = $ExpectedBenchmarkSha256
        run_count = 7
        process_elapsed_ms = Get-Percentile $elapsed
        aggregate_method = 'median-and-nearest-rank-p95-across-seven-process-runs'
        mode = 'mock_only'
        timing_represents_product_runtime = $false
        aggregates = @($aggregates)
        raw_runs = @($runs | ForEach-Object {
                [ordered]@{ run = $_.run; elapsed_ms = $_.elapsed_ms; file = $_.file; sha256 = $_.sha256 }
            })
    }
    Write-Json (Join-Path $outRoot 'benchmark-summary.json') $summary
}

function Invoke-EmergencyCleanup {
    foreach ($process in @(Get-Process -Name KDBG,kdbg_live_verify -ErrorAction SilentlyContinue)) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction Stop } catch {}
    }
    try { Uninstall-Current } catch {}
    if (Test-Path -LiteralPath (Join-Path $previousPackage 'tools\uninstall.ps1')) {
        try { [void](Invoke-PackageScript $previousPackage 'uninstall.ps1' @('-ConfirmKdbgServices', '-PurgeUserData')) } catch {}
    }
    foreach ($path in @($currentCertificate, $previousCertificate)) {
        if (Test-Path -LiteralPath $path) {
            try {
                $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($path)
                Remove-TestCertificate $cert.Thumbprint.ToLowerInvariant()
            } catch {}
        }
    }
}

Assert-Administrator
Assert-NoReparse $root
foreach ($pair in @(
        @($currentArchive, $ExpectedCurrentPackageSha256, 'current package'),
        @($previousArchive, $ExpectedPreviousPackageSha256, 'previous package'),
        @($currentCertificate, $ExpectedCurrentCertificateSha256, 'current certificate'),
        @($previousCertificate, $ExpectedPreviousCertificateSha256, 'previous certificate'),
        @($benchmarkExecutable, $ExpectedBenchmarkSha256, 'benchmark executable'))) {
    Assert-Hash $pair[0] $pair[1] $pair[2]
}
if ($ExpectedCurrentPackageSha256 -ceq $ExpectedPreviousPackageSha256) {
    throw 'Current and previous package generations must be distinct.'
}

switch ($Phase) {
    'baseline' {
        if (Test-Path -LiteralPath $statePath) { throw 'Baseline phase cannot overwrite state.' }
        [IO.Directory]::CreateDirectory($outRoot) | Out-Null
        $baseline = Get-CleanInventory
        Assert-CleanInventory $baseline @($baseline.certificate_thumbprints)
        Expand-PinnedPackage $currentArchive $currentParent `
            $ExpectedCurrentPackageSha256 $currentPackageLeaf
        Expand-PinnedPackage $previousArchive $previousParent `
            $ExpectedPreviousPackageSha256 $previousPackageLeaf
        $state = [ordered]@{
            schema = 'kdbg.win11-extended-guest-state.v1'
            started_utc = [DateTime]::UtcNow.ToString('o')
            checkpoint_id = $CheckpointId.ToString('D')
            current_package_sha256 = $ExpectedCurrentPackageSha256
            previous_package_sha256 = $ExpectedPreviousPackageSha256
            baseline_certificate_thumbprints = @($baseline.certificate_thumbprints)
            cycle_records = @()
        }
        Save-State $state
        Write-Json (Join-Path $outRoot 'baseline-inventory.json') $baseline
    }
    'cycle-1-exercise' { Invoke-LifecycleExercise 1 }
    'cycle-1-post-install-reboot' { Invoke-PostInstallReboot 1 }
    'cycle-1-uninstall' { Invoke-CycleUninstall 1 }
    'cycle-1-post-clean-reboot' { Invoke-PostCleanReboot 1 }
    'cycle-2-exercise' { Invoke-LifecycleExercise 2 }
    'cycle-2-post-install-reboot' { Invoke-PostInstallReboot 2 }
    'cycle-2-uninstall' { Invoke-CycleUninstall 2 }
    'cycle-2-post-clean-reboot' { Invoke-PostCleanReboot 2 }
    'soak' { Invoke-Soak }
    'benchmarks' { Invoke-Benchmarks }
    'emergency-cleanup' { Invoke-EmergencyCleanup }
    'finalize' {
        $state = Read-State
        $inventory = Get-CleanInventory
        Assert-CleanInventory $inventory @($state.baseline_certificate_thumbprints)
        $files = @(Get-ChildItem -LiteralPath $outRoot -File | Sort-Object Name)
        $summary = [ordered]@{
            schema = 'kdbg.win11-extended-guest.v1'
            success = $true
            completed_utc = [DateTime]::UtcNow.ToString('o')
            checkpoint_id = $CheckpointId.ToString('D')
            current_package_sha256 = $ExpectedCurrentPackageSha256
            previous_package_sha256 = $ExpectedPreviousPackageSha256
            lifecycle_cycle_count = @($state.cycle_records).Count
            lifecycle_stop_start_count = (@($state.cycle_records).Count * 5)
            final_clean_inventory = $inventory
            files = @($files | ForEach-Object {
                    [ordered]@{ name = $_.Name; sha256 = Get-Sha256 $_.FullName; bytes = $_.Length }
                })
            credential_serialized = $false
        }
        Write-Json (Join-Path $outRoot 'guest-summary.json') $summary
        $archiveParent = Join-Path $root 'evidence'
        [IO.Directory]::CreateDirectory($archiveParent) | Out-Null
        Copy-Item -LiteralPath $outRoot -Destination $archiveParent -Recurse
        New-CanonicalEvidenceArchive $archiveParent $evidenceArchive
    }
}

Write-Output ([ordered]@{
        phase = $Phase
        success = $true
        completed_utc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress)

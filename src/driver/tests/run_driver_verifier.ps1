[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidateRange(1, 100)]
    [int]$Cycles = 10,

    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedPackageLeaf = "KDBG-1.1.0-win-x64"
$VerifierFlags = "0x132"
$DriverImages = @("KDbgDriver.sys", "KDbgProbe.sys")
$PackageDirectory = [IO.Path]::GetFullPath($PackageDirectory)
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

function Get-RelativeChildPath([string]$Root, [string]$Path) {
    $RootFull = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $PathFull = [IO.Path]::GetFullPath($Path)
    $Prefix = $RootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $PathFull.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    return $PathFull.Substring($Prefix.Length)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-TextSha256([string[]]$Lines) {
    $Text = $Lines -join "`n"
    $Bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($Hasher.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $Hasher.Dispose()
    }
}

function Invoke-CapturedCommand([string]$FilePath, [string[]]$Arguments) {
    $PreviousPreference = $ErrorActionPreference
    try {
        $script:ErrorActionPreference = "Continue"
        $Output = @(& $FilePath @Arguments 2>&1 | ForEach-Object { $_.ToString() })
        $ExitCode = $LASTEXITCODE
    } finally {
        $script:ErrorActionPreference = $PreviousPreference
    }
    return [pscustomobject]@{
        file = [IO.Path]::GetFileName($FilePath)
        arguments = @($Arguments)
        exit_code = [int]$ExitCode
        output = @($Output)
        output_sha256 = Get-TextSha256 @($Output)
    }
}

function Get-VerifierDriverNames([string[]]$Output) {
    $Names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($Line in $Output) {
        foreach ($Match in [regex]::Matches(
                $Line,
                '(?i)(?<![A-Za-z0-9_.-])(?<name>[A-Za-z0-9_.-]+\.sys)(?![A-Za-z0-9_.-])')) {
            [void]$Names.Add($Match.Groups['name'].Value)
        }
    }
    return @($Names | Sort-Object)
}

function Get-VerifierFlags([string[]]$Output) {
    foreach ($Line in $Output) {
        $Match = [regex]::Match(
            $Line,
            '(?i)0x(?<value>[0-9a-f]{1,8})(?![0-9a-f])')
        if ($Match.Success) {
            return [Convert]::ToUInt32($Match.Groups['value'].Value, 16)
        }
    }
    throw "Driver Verifier output does not contain a flag value."
}

function Assert-CommandPassed([object]$Command, [string]$Operation) {
    if ($Command.exit_code -ne 0) {
        throw "$Operation failed with exit code $($Command.exit_code)."
    }
}

if (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot) {
    throw "Driver Verifier requires -ConfirmDedicatedVm and -ConfirmSnapshot."
}
if ([IO.Path]::GetFileName($PackageDirectory) -cne $ExpectedPackageLeaf) {
    throw "Package directory must remain named $ExpectedPackageLeaf."
}
if (-not (Test-Path -LiteralPath $PackageDirectory -PathType Container)) {
    throw "Package directory does not exist: $PackageDirectory"
}
if ($null -ne (Get-RelativeChildPath $PackageDirectory $OutputPath)) {
    throw "Driver Verifier evidence must be written outside the immutable package directory."
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator in a disposable snapshot VM."
}

$OutputDirectory = Split-Path -Parent $OutputPath
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    throw "OutputPath must include a parent directory."
}
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)

$Diagnose = Join-Path $PackageDirectory "tools\diagnose.ps1"
$Stop = Join-Path $PackageDirectory "tools\stop.ps1"
$Start = Join-Path $PackageDirectory "tools\start.ps1"
$ReadinessPath = Join-Path $env:LOCALAPPDATA "KDBG\readiness\start-latest.json"
$ManifestPath = Join-Path $PackageDirectory "SHA256SUMS.txt"
$VerifierPath = Join-Path $env:SystemRoot "System32\verifier.exe"
foreach ($Required in @($Diagnose, $Stop, $Start, $ManifestPath, $VerifierPath)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Required Driver Verifier input is missing: $Required"
    }
}

$Signatures = [Collections.Generic.List[object]]::new()
foreach ($Relative in @(
        "drivers\KDbgDriver.sys",
        "drivers\KDbgDriver.cat",
        "drivers\KDbgProbe.sys",
        "drivers\KDbgProbe.cat")) {
    $Path = Join-Path $PackageDirectory $Relative
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required signed driver artifact is missing: $Relative"
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($Signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $Signature.SignerCertificate) {
        throw "$Relative is not trusted on this guest (status=$($Signature.Status))."
    }
    $Signer = $Signature.SignerCertificate
    $HasTimestamp = $null -ne $Signature.TimeStamperCertificate
    $SelfSigned = $Signer.Subject -ceq $Signer.Issuer
    $Signatures.Add([ordered]@{
        package_relative_path = $Relative.Replace('\', '/')
        sha256 = Get-Sha256 $Path
        status = [string]$Signature.Status
        signer_subject = $Signer.Subject
        signer_issuer = $Signer.Issuer
        signer_thumbprint = $Signer.Thumbprint.ToLowerInvariant()
        signer_not_after_utc = $Signer.NotAfter.ToUniversalTime().ToString("o")
        self_signed = $SelfSigned
        timestamp_present = $HasTimestamp
        profile = if ($SelfSigned -or -not $HasTimestamp) {
            "trusted-test-or-private"
        } else {
            "production-candidate"
        }
    })
}

$DiagnosticArguments = @{
    VerifyPackage = $true
    RequireAdministrator = $true
    RequireInstalled = $true
    RequireRunning = $true
}
$DiagnosticCommand = Get-Command $Diagnose -ErrorAction Stop
if ($DiagnosticCommand.Parameters.ContainsKey("RequireTrustedDriverSignatures")) {
    $DiagnosticArguments.RequireTrustedDriverSignatures = $true
}
& $Diagnose @DiagnosticArguments
if ($LASTEXITCODE -ne 0) {
    throw "Package diagnostics failed before Driver Verifier configuration."
}

$Os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$Report = [ordered]@{
    schema = "kdbg.driver-verifier.v1"
    success = $false
    generated_utc = [DateTime]::UtcNow.ToString("o")
    operator_confirmed_disposable_vm = $true
    operator_confirmed_snapshot = $true
    package = [ordered]@{
        leaf = $ExpectedPackageLeaf
        manifest_sha256 = Get-Sha256 $ManifestPath
        signatures = @($Signatures)
        signing_profile = if (@($Signatures | Where-Object {
                    $_.profile -ne "production-candidate"
                }).Count -eq 0) {
            "production-candidate"
        } else {
            "trusted-test-or-private"
        }
    }
    system = [ordered]@{
        caption = $Os.Caption
        build = [int]$Os.BuildNumber
        architecture = $Os.OSArchitecture
    }
    verifier = [ordered]@{
        mode = "volatile"
        flags = $VerifierFlags
        exact_driver_images = @($DriverImages)
        precondition_query = $null
        configuration_command = $null
        configured_query = $null
        post_cycles_query = $null
        cleanup_commands = @()
        cleanup_query = $null
        cleanup_succeeded = $false
        package_restored = $false
    }
    requested_cycles = $Cycles
    completed_cycles = 0
    cycles = @()
    errors = @()
}

$VerifierChanged = $false
$RunSucceeded = $false
try {
    $Before = Invoke-CapturedCommand $VerifierPath @("/query")
    Assert-CommandPassed $Before "Initial Driver Verifier query"
    $Report.verifier.precondition_query = $Before
    $BeforeNames = @(Get-VerifierDriverNames $Before.output)
    if ($BeforeNames.Count -ne 0) {
        throw "Driver Verifier already targets drivers: $($BeforeNames -join ', ')."
    }

    # Volatile flags and targets must be supplied in one verifier.exe call.
    # On Windows 10, a later /volatile /adddriver call without /flags resets
    # the volatile flag mask to zero while still registering the targets.
    & $Stop
    if ($LASTEXITCODE -ne 0) {
        throw "Stopping KDBG before Driver Verifier configuration failed."
    }
    # From this point onward always attempt cleanup and package restoration,
    # including when verifier.exe reports a partial configuration failure.
    $VerifierChanged = $true
    $Configure = Invoke-CapturedCommand $VerifierPath (
        @("/volatile", "/flags", $VerifierFlags, "/adddriver") +
            $DriverImages)
    $Report.verifier.configuration_command = $Configure
    Assert-CommandPassed $Configure "Volatile Driver Verifier configuration"

    $Configured = Invoke-CapturedCommand $VerifierPath @("/query")
    Assert-CommandPassed $Configured "Configured Driver Verifier query"
    $Report.verifier.configured_query = $Configured
    $ConfiguredNames = @(Get-VerifierDriverNames $Configured.output)
    if ($ConfiguredNames.Count -ne $DriverImages.Count -or
        @($DriverImages | Where-Object { $ConfiguredNames -notcontains $_ }).Count -ne 0) {
        throw "Driver Verifier target set is not the exact KDBG pair: $($ConfiguredNames -join ', ')."
    }
    $ExpectedFlags = [Convert]::ToUInt32($VerifierFlags.Substring(2), 16)
    $ConfiguredFlags = Get-VerifierFlags $Configured.output
    if ($ConfiguredFlags -ne $ExpectedFlags) {
        throw ("Driver Verifier flag mask mismatch: expected {0}, got 0x{1:x8}." -f
            $VerifierFlags, $ConfiguredFlags)
    }

    $CycleRecords = [Collections.Generic.List[object]]::new()
    for ($Cycle = 1; $Cycle -le $Cycles; $Cycle++) {
        $Started = [Diagnostics.Stopwatch]::StartNew()
        & $Stop
        if ($LASTEXITCODE -ne 0) {
            throw "Cycle $Cycle stop failed."
        }
        & $Start -ConfirmDedicatedVm -ConfirmSnapshot
        if ($LASTEXITCODE -ne 0) {
            throw "Cycle $Cycle start/readiness failed."
        }
        if (-not (Test-Path -LiteralPath $ReadinessPath -PathType Leaf)) {
            throw "Cycle $Cycle readiness report is missing."
        }
        $Readiness = Get-Content -LiteralPath $ReadinessPath -Raw | ConvertFrom-Json
        if ($Readiness.schema -cne "kdbg.live-verify.v1" -or
            $Readiness.mode -cne "read-only" -or
            $Readiness.success -ne $true -or
            $Readiness.runtime_identity.verified -ne $true -or
            $Readiness.backend.abi_version -ne 6 -or
            $Readiness.probe_before.byte_count -ne 4096 -or
            $Readiness.write_cleanup.final_gate_locked -ne $true) {
            throw "Cycle $Cycle readiness report is incomplete or failed."
        }
        $Started.Stop()
        $CycleRecords.Add([ordered]@{
            cycle = $Cycle
            elapsed_ms = $Started.Elapsed.TotalMilliseconds
            readiness_sha256 = Get-Sha256 $ReadinessPath
            probe_pfn = [uint64]$Readiness.probe_before.pfn
            probe_crc32 = [uint32]$Readiness.probe_before.crc32
            final_gate_locked = [bool]$Readiness.write_cleanup.final_gate_locked
        })
        $Report.completed_cycles = $Cycle
        $Report.cycles = @($CycleRecords)
    }

    $PostCycles = Invoke-CapturedCommand $VerifierPath @("/query")
    Assert-CommandPassed $PostCycles "Post-cycle Driver Verifier query"
    $Report.verifier.post_cycles_query = $PostCycles
    $PostCycleNames = @(Get-VerifierDriverNames $PostCycles.output)
    if ($PostCycleNames.Count -ne $DriverImages.Count -or
        @($DriverImages | Where-Object {
                $PostCycleNames -notcontains $_
            }).Count -ne 0) {
        throw "Driver Verifier target set changed during the run: $($PostCycleNames -join ', ')."
    }
    $PostCycleFlags = Get-VerifierFlags $PostCycles.output
    if ($PostCycleFlags -ne $ExpectedFlags) {
        throw ("Driver Verifier flag mask changed during the run: expected {0}, got 0x{1:x8}." -f
            $VerifierFlags, $PostCycleFlags)
    }
    $RunSucceeded = $true
} catch {
    $Report.errors = @($Report.errors) + @($_.Exception.Message)
} finally {
    if ($VerifierChanged) {
        try {
            $CleanupErrors = [Collections.Generic.List[string]]::new()
            try {
                & $Stop
                if ($LASTEXITCODE -ne 0) {
                    throw "Stopping KDBG before Driver Verifier cleanup failed."
                }
            } catch {
                $CleanupErrors.Add($_.Exception.Message)
            }
            $CleanupCommands = [Collections.Generic.List[object]]::new()
            foreach ($DriverImage in $DriverImages) {
                try {
                    $RemoveDriver = Invoke-CapturedCommand $VerifierPath @(
                        "/volatile", "/removedriver", $DriverImage)
                    $CleanupCommands.Add($RemoveDriver)
                    Assert-CommandPassed $RemoveDriver (
                        "Driver Verifier target cleanup for $DriverImage")
                } catch {
                    $CleanupErrors.Add($_.Exception.Message)
                }
            }
            try {
                $ClearFlags = Invoke-CapturedCommand $VerifierPath @(
                    "/volatile", "/flags", "0x0")
                $CleanupCommands.Add($ClearFlags)
                Assert-CommandPassed $ClearFlags "Driver Verifier volatile flag cleanup"
            } catch {
                $CleanupErrors.Add($_.Exception.Message)
            }
            $Report.verifier.cleanup_commands = @($CleanupCommands)
            try {
                $Cleanup = Invoke-CapturedCommand $VerifierPath @("/query")
                Assert-CommandPassed $Cleanup "Post-cleanup Driver Verifier query"
                $Report.verifier.cleanup_query = $Cleanup
                $Remaining = @(Get-VerifierDriverNames $Cleanup.output)
                if (@($DriverImages | Where-Object {
                            $Remaining -contains $_
                        }).Count -ne 0) {
                    throw "KDBG Driver Verifier targets remain after cleanup."
                }
            } catch {
                $CleanupErrors.Add($_.Exception.Message)
            }
            if ($CleanupErrors.Count -ne 0) {
                throw ($CleanupErrors -join "; ")
            }
            $Report.verifier.cleanup_succeeded = $true

            & $Start -ConfirmDedicatedVm -ConfirmSnapshot
            if ($LASTEXITCODE -ne 0) {
                throw "Restarting KDBG after Driver Verifier cleanup failed."
            }
            $Report.verifier.package_restored = $true
        } catch {
            $Report.errors = @($Report.errors) + @(
                "Driver Verifier cleanup failed: $($_.Exception.Message)")
        }
    }
    $Report.success = $RunSucceeded -and
        $Report.completed_cycles -eq $Cycles -and
        $Report.verifier.cleanup_succeeded -and
        $Report.verifier.package_restored -and
        @($Report.errors).Count -eq 0
    $Json = $Report | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText(
        $OutputPath,
        $Json + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

if (-not $Report.success) {
    Write-Error "Driver Verifier run failed; see $OutputPath"
    exit 1
}
Write-Host "Driver Verifier PASS: $Cycles/$Cycles cycles, exact volatile KDBG targets, cleanup verified."
Write-Host "Evidence: $OutputPath"
exit 0

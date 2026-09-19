[CmdletBinding()]
param(
    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot,
    [ValidateSet("DisposableVm", "LocalHost")]
    [string]$TargetProfile,
    [ValidateSet("DistributionSource", "InstalledProduct")]
    [string]$PackageRootMode = "DistributionSource"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ResolvedTargetProfile = if ([string]::IsNullOrWhiteSpace($TargetProfile)) {
    if ($ConfirmDedicatedVm -and $ConfirmSnapshot) { "DisposableVm" }
    else { "LocalHost" }
} else { $TargetProfile }
if ($ResolvedTargetProfile -eq "DisposableVm" -and
    (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot)) {
    throw "Starting drivers requires -ConfirmDedicatedVm and -ConfirmSnapshot."
}
Import-Module (Join-Path $PSScriptRoot "TargetProfile.psm1") -Force
$null = Assert-KdbgTargetProfile `
    -TargetProfile $ResolvedTargetProfile `
    -ConfirmDedicatedVm:$ConfirmDedicatedVm `
    -ConfirmSnapshot:$ConfirmSnapshot
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator on the selected target."
}

& (Join-Path $PSScriptRoot "diagnose.ps1") `
    -VerifyPackage -RequireAdministrator -RequireTrustedDriverSignatures `
    -RequireInstalled -PackageRootMode $PackageRootMode
if ($LASTEXITCODE -ne 0) { throw "Installed-package readiness check failed." }

$Started = [Collections.Generic.List[string]]::new()
try {
    foreach ($Name in @("KDBG", "KDBGProbe")) {
        $Service = Get-Service -Name $Name -ErrorAction Stop
        if ($Service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Start-Service -Name $Name -ErrorAction Stop
            # Journal the successful state-changing call before waiting.  A
            # slow driver can time out in WaitForStatus after SCM accepted the
            # start; rollback must still stop that service.
            $Started.Add($Name)
            $Service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(15))
        }
    }
    & (Join-Path $PSScriptRoot "diagnose.ps1") `
        -VerifyPackage -RequireAdministrator -RequireTrustedDriverSignatures `
        -RequireRunning -PackageRootMode $PackageRootMode
    if ($LASTEXITCODE -ne 0) { throw "Running-package readiness check failed." }

    $PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    $Verifier = Join-Path $PackageRoot "tools\kdbg_live_verify.exe"
    $ReadinessDirectory = Join-Path $env:LOCALAPPDATA "KDBG\readiness"
    $ReadinessReport = Join-Path $ReadinessDirectory "start-latest.json"
    & $Verifier --output $ReadinessReport --build-id "KDBG-1.1.0-start" --read-samples 3
    if ($LASTEXITCODE -ne 0) {
        throw "Packaged live verifier rejected the running driver pair; see $ReadinessReport."
    }
    $Readiness = Get-Content -LiteralPath $ReadinessReport -Raw | ConvertFrom-Json
    if ($Readiness.schema -ne "kdbg.live-verify.v1" -or
        $Readiness.mode -ne "read-only" -or
        $Readiness.success -ne $true -or
        $Readiness.runtime_identity.verified -ne $true -or
        $Readiness.runtime_identity.verifier.package_relative_path -ne "tools/kdbg_live_verify.exe" -or
        $Readiness.runtime_identity.kdbg_service.name -ne "KDBG" -or
        $Readiness.runtime_identity.kdbg_service.binary.package_relative_path -ne "drivers/KDbgDriver.sys" -or
        $Readiness.runtime_identity.kdbg_service.service_type -ne 1 -or
        $Readiness.runtime_identity.kdbg_service.current_state -ne 4 -or
        $Readiness.runtime_identity.kdbg_service.running_kernel_driver -ne $true -or
        $Readiness.runtime_identity.probe_service.name -ne "KDBGProbe" -or
        $Readiness.runtime_identity.probe_service.binary.package_relative_path -ne "drivers/KDbgProbe.sys" -or
        $Readiness.runtime_identity.probe_service.service_type -ne 1 -or
        $Readiness.runtime_identity.probe_service.current_state -ne 4 -or
        $Readiness.runtime_identity.probe_service.running_kernel_driver -ne $true -or
        $Readiness.backend.abi_version -ne 7 -or
        $Readiness.backend.supports_physical_page_compare_write -ne $true -or
        $Readiness.probe_before.byte_count -ne 4096 -or
        $Readiness.write_cleanup.final_gate_locked -ne $true) {
        throw "Packaged live verifier report did not prove runtime identity, ABI 7, exact Probe read, and a locked gate."
    }
    Write-Host "Read-only ABI/Probe readiness report: $ReadinessReport"
} catch {
    $StartFailure = $_
    $CleanupErrors = [Collections.Generic.List[string]]::new()
    $Rollback = @($Started)
    [Array]::Reverse($Rollback)
    foreach ($Name in $Rollback) {
        try {
            $Service = Get-Service -Name $Name -ErrorAction Stop
            if ($Service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                Stop-Service -Name $Name -ErrorAction Stop
                $Service.WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                    [TimeSpan]::FromSeconds(15))
            }
            $Service.Refresh()
            if ($Service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                throw "service did not reach Stopped"
            }
        } catch {
            $CleanupErrors.Add("stop ${Name}: $($_.Exception.Message)")
        }
    }
    if ($CleanupErrors.Count -gt 0) {
        throw "Startup failed: $($StartFailure.Exception.Message); rollback errors: $($CleanupErrors -join '; ')"
    }
    throw $StartFailure
}
Write-Host "KDBG and KDBGProbe are running and bound to this package on target profile $ResolvedTargetProfile."
exit 0

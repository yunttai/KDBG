[CmdletBinding()]
param(
    [switch]$Start,
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
    throw "Installation requires -ConfirmDedicatedVm and -ConfirmSnapshot."
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

$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ExpectedPackageLeaf = "KDBG-1.1.0-win-x64"
if ($PackageRootMode -eq "DistributionSource") {
    if ([IO.Path]::GetFileName($PackageRoot) -cne $ExpectedPackageLeaf) {
        throw "Distribution source directory must remain named $ExpectedPackageLeaf."
    }
} else {
    $ProgramFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($ProgramFiles)) {
        throw "Program Files could not be resolved for InstalledProduct mode."
    }
    $ExpectedInstalledRoot = [IO.Path]::GetFullPath((
        Join-Path $ProgramFiles "KDBG\Product"))
    if (-not $PackageRoot.Equals(
            $ExpectedInstalledRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "InstalledProduct mode requires the exact Program Files KDBG Product root."
    }
}
$Drivers = @(
    @{ Service = "KDBG"; File = "KDbgDriver.sys"; Display = "KDBG Physical Memory Driver" },
    @{ Service = "KDBGProbe"; File = "KDbgProbe.sys"; Display = "KDBG Probe Fixture Driver" }
)

function Invoke-Sc(
    [string[]]$Arguments,
    [switch]$AllowFailure,
    [switch]$Quiet) {
    $Output = & sc.exe @Arguments 2>&1
    $Code = $LASTEXITCODE
    if ($Output -and -not $Quiet) { $Output | ForEach-Object { Write-Host $_ } }
    if ($Code -ne 0 -and -not $AllowFailure) {
        throw "sc.exe failed with exit code $Code."
    }
    return [int]$Code
}

function Wait-ServiceAbsent([string]$Name) {
    $Deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $Code = Invoke-Sc @("query", $Name) -AllowFailure -Quiet
        if ($Code -eq 1060) { return }
        if ($Code -notin @(0, 1072)) {
            throw "sc.exe query $Name failed with exit code $Code."
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw "Service $Name remains registered or pending deletion after 30 seconds (sc.exe $Code)."
}

function Get-NormalizedServicePath([string]$ImagePath) {
    $Expanded = [Environment]::ExpandEnvironmentVariables($ImagePath).Trim().Trim('"')
    if ($Expanded.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase) -or
        $Expanded.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        $Expanded = $Expanded.Substring(4)
    }
    try { return [IO.Path]::GetFullPath($Expanded) }
    catch { return $Expanded }
}

function Get-ScStartMode([int]$StartValue) {
    switch ($StartValue) {
        0 { return "boot" }
        1 { return "system" }
        2 { return "auto" }
        3 { return "demand" }
        4 { return "disabled" }
        default { throw "Unsupported original service Start value: $StartValue" }
    }
}

function Stop-ServiceAndWait([string]$Name) {
    $Code = Invoke-Sc @("stop", $Name) -AllowFailure -Quiet
    if ($Code -eq 1060) { return }
    if ($Code -eq 1072) {
        Wait-ServiceAbsent $Name
        return
    }
    if ($Code -notin @(0, 1062)) {
        throw "sc.exe stop failed with exit code $Code"
    }
    $Service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Service) {
        $QueryCode = Invoke-Sc @("query", $Name) -AllowFailure -Quiet
        if ($QueryCode -eq 1060) { return }
        if ($QueryCode -eq 1072) {
            Wait-ServiceAbsent $Name
            return
        }
        throw "Service $Name exists in SCM but Get-Service could not open it."
    }
    if ($Service.Status -ne
        [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        $Service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(15))
    }
    $Service.Refresh()
    if ($Service.Status -ne
        [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw "Service $Name did not reach Stopped."
    }
}

function New-PairLifecyclePlan(
    [object[]]$InstallPlan,
    [bool]$ReloadPair) {
    $ByService = @{}
    foreach ($Item in $InstallPlan) {
        $ByService[[string]$Item.Driver.Service] = $Item
    }
    foreach ($Required in @("KDBG", "KDBGProbe")) {
        if (-not $ByService.ContainsKey($Required)) {
            throw "Install plan is missing required service $Required."
        }
    }

    $Actions = [Collections.Generic.List[object]]::new()
    # Stop the dependent Probe first. Both stop/absent confirmations must
    # complete before either SCM path is changed.
    foreach ($Name in @("KDBGProbe", "KDBG")) {
        $Actions.Add([pscustomobject]@{
            Action = "StopOrConfirmAbsent"
            Service = $Name
            Item = $ByService[$Name]
        })
    }
    foreach ($Name in @("KDBG", "KDBGProbe")) {
        $Actions.Add([pscustomobject]@{
            Action = "Configure"
            Service = $Name
            Item = $ByService[$Name]
        })
    }
    if ($ReloadPair) {
        $Actions.Add([pscustomobject]@{
            Action = "ReloadPair"
            Service = "KDBG+KDBGProbe"
            Item = $null
        })
    }
    return @($Actions)
}

function Set-InstalledService([object]$Item) {
    $Driver = $Item.Driver
    $QuotedPath = '"' + $Item.Path + '"'
    $QueryCode = Invoke-Sc @("query", $Driver.Service) -AllowFailure -Quiet
    if ($QueryCode -eq 1072) {
        Wait-ServiceAbsent $Driver.Service
        $QueryCode = 1060
    }
    if ($QueryCode -eq 0) {
        $Service = Get-Service -Name $Driver.Service -ErrorAction Stop
        $Service.Refresh()
        if ($Service.Status -ne
            [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw "$($Driver.Service) must be stopped before configuration."
        }
        $Code = Invoke-Sc @(
            "config", $Driver.Service, "type=", "kernel", "start=", "demand",
            "binPath=", $QuotedPath, "DisplayName=", $Driver.Display) -AllowFailure
        if ($Code -ne 0) {
            throw "sc.exe config $($Driver.Service) failed with exit code $Code."
        }
        return
    }
    if ($QueryCode -ne 1060) {
        throw "sc.exe query $($Driver.Service) failed with exit code $QueryCode."
    }
    $Code = Invoke-Sc @(
        "create", $Driver.Service, "type=", "kernel", "start=", "demand",
        "binPath=", $QuotedPath, "DisplayName=", $Driver.Display) -AllowFailure
    if ($Code -eq 1072) {
        Wait-ServiceAbsent $Driver.Service
        $Code = Invoke-Sc @(
            "create", $Driver.Service, "type=", "kernel", "start=", "demand",
            "binPath=", $QuotedPath, "DisplayName=", $Driver.Display) -AllowFailure
    }
    if ($Code -ne 0) {
        throw "sc.exe create $($Driver.Service) failed with exit code $Code."
    }
}

function Remove-ServiceRegistration([string]$Name) {
    Stop-ServiceAndWait $Name
    $Code = Invoke-Sc @("query", $Name) -AllowFailure -Quiet
    if ($Code -eq 1060) { return }
    if ($Code -eq 0) {
        $Code = Invoke-Sc @("delete", $Name) -AllowFailure -Quiet
        if ($Code -notin @(0, 1060, 1072)) {
            throw "sc.exe delete $Name failed with exit code $Code."
        }
    } elseif ($Code -ne 1072) {
        throw "sc.exe query $Name failed with exit code $Code."
    }
    Wait-ServiceAbsent $Name
}

function Restore-OriginalService([object]$Item) {
    if (-not $Item.Existing) {
        Remove-ServiceRegistration ([string]$Item.Driver.Service)
        return
    }

    $Name = [string]$Item.Driver.Service
    $OriginalPath = Get-NormalizedServicePath ([string]$Item.Original.ImagePath)
    $OriginalType = [int]$Item.Original.Type
    $OriginalStart = [int]$Item.Original.Start
    if ($OriginalType -ne 1) {
        throw "Original service $Name is no longer a kernel driver."
    }
    $DisplayProperty = $Item.Original.PSObject.Properties['DisplayName']
    $OriginalDisplay = if ($null -eq $DisplayProperty) {
        $Name
    } else {
        [string]$DisplayProperty.Value
    }
    $Arguments = @(
        "config", $Name,
        "type=", "kernel",
        "start=", (Get-ScStartMode $OriginalStart),
        "binPath=", ('"' + $OriginalPath + '"'),
        "DisplayName=", $OriginalDisplay)
    $QueryCode = Invoke-Sc @("query", $Name) -AllowFailure -Quiet
    if ($QueryCode -eq 1072) {
        Wait-ServiceAbsent $Name
        $QueryCode = 1060
    }
    if ($QueryCode -eq 1060) {
        $Arguments[0] = "create"
    } elseif ($QueryCode -ne 0) {
        throw "sc.exe query $Name failed with exit code $QueryCode."
    }
    $RestoreCode = Invoke-Sc $Arguments -AllowFailure -Quiet
    if ($RestoreCode -ne 0) {
        throw "sc.exe $($Arguments[0]) restore failed with exit code $RestoreCode."
    }

    $Key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $Restored = Get-ItemProperty -LiteralPath $Key -ErrorAction Stop
    if (-not (Get-NormalizedServicePath ([string]$Restored.ImagePath)).Equals(
            $OriginalPath, [StringComparison]::OrdinalIgnoreCase) -or
        [int]$Restored.Type -ne $OriginalType -or
        [int]$Restored.Start -ne $OriginalStart) {
        throw "SCM configuration for $Name did not match the original path/type/start."
    }
    $RestoredDisplay = $Restored.PSObject.Properties['DisplayName']
    if ($null -eq $RestoredDisplay -or
        [string]$RestoredDisplay.Value -cne $OriginalDisplay) {
        throw "SCM display name for $Name did not match the original value."
    }
}

& (Join-Path $PSScriptRoot "diagnose.ps1") `
    -VerifyPackage -RequireAdministrator -RequireTrustedDriverSignatures `
    -PackageRootMode $PackageRootMode
if ($LASTEXITCODE -ne 0) { throw "Package diagnostics failed; no service was changed." }

# Validate both service names before mutating either one.
$Plan = @()
foreach ($Driver in $Drivers) {
    $Path = [IO.Path]::GetFullPath((Join-Path $PackageRoot "drivers\$($Driver.File)"))
    $Key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Driver.Service)"
    $QueryCode = Invoke-Sc @("query", $Driver.Service) -AllowFailure -Quiet
    if ($QueryCode -eq 1072 -or
        ($QueryCode -eq 0 -and -not (Test-Path -LiteralPath $Key))) {
        Wait-ServiceAbsent $Driver.Service
        $QueryCode = 1060
    }
    if ($QueryCode -notin @(0, 1060)) {
        throw "sc.exe query $($Driver.Service) failed with exit code $QueryCode."
    }
    $Existing = $QueryCode -eq 0
    $WasRunning = $false
    if ($Existing) {
        $Properties = Get-ItemProperty -LiteralPath $Key -ErrorAction Stop
        if ([int]$Properties.Type -ne 1) {
            throw "$($Driver.Service) exists but is not a kernel driver service."
        }
        $Service = Get-Service -Name $Driver.Service -ErrorAction Stop
        if ($Service.Status -notin @(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [System.ServiceProcess.ServiceControllerStatus]::Stopped)) {
            throw "$($Driver.Service) is not in a stable Running/Stopped state."
        }
        $WasRunning =
            $Service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running
    }
    $Plan += [pscustomobject]@{
        Driver = $Driver
        Path = $Path
        Existing = $Existing
        Original = if ($Existing) { $Properties } else { $null }
        WasRunning = $WasRunning
    }
}

$ReloadPair = [bool]$Start -or
    @($Plan | Where-Object { $_.WasRunning }).Count -ne 0
$Lifecycle = New-PairLifecyclePlan $Plan $ReloadPair
try {
    foreach ($Action in $Lifecycle) {
        switch ($Action.Action) {
            "StopOrConfirmAbsent" {
                Stop-ServiceAndWait ([string]$Action.Service)
            }
            "Configure" {
                Set-InstalledService $Action.Item
            }
            "ReloadPair" {
                & (Join-Path $PSScriptRoot "start.ps1") `
                    -TargetProfile $ResolvedTargetProfile `
                    -ConfirmDedicatedVm:$ConfirmDedicatedVm `
                    -ConfirmSnapshot:$ConfirmSnapshot `
                    -PackageRootMode $PackageRootMode
                if ($LASTEXITCODE -ne 0) {
                    throw "Driver pair reload/readiness failed."
                }
            }
            default {
                throw "Unknown install lifecycle action: $($Action.Action)"
            }
        }
    }
    & (Join-Path $PSScriptRoot "diagnose.ps1") `
        -VerifyPackage -RequireAdministrator -RequireTrustedDriverSignatures `
        -RequireInstalled -PackageRootMode $PackageRootMode
    if ($LASTEXITCODE -ne 0) { throw "Installed service readiness check failed." }
    if ($ReloadPair) {
        & (Join-Path $PSScriptRoot "diagnose.ps1") `
            -VerifyPackage -RequireAdministrator -RequireTrustedDriverSignatures `
            -RequireRunning -PackageRootMode $PackageRootMode
        if ($LASTEXITCODE -ne 0) {
            throw "Final reloaded-pair readiness check failed."
        }
    }
} catch {
    $InstallFailure = $_
    $CleanupErrors = [Collections.Generic.List[string]]::new()
    $SafeToRestore = @{}
    foreach ($Name in @("KDBGProbe", "KDBG")) {
        $SafeToRestore[$Name] = $false
        try {
            Stop-ServiceAndWait $Name
            $SafeToRestore[$Name] = $true
        } catch {
            $CleanupErrors.Add("stop ${Name}: $($_.Exception.Message)")
        }
    }
    foreach ($Item in $Plan) {
        $Name = [string]$Item.Driver.Service
        if (-not $SafeToRestore[$Name]) { continue }
        try {
            Restore-OriginalService $Item
        } catch {
            $CleanupErrors.Add("restore ${Name}: $($_.Exception.Message)")
            $SafeToRestore[$Name] = $false
        }
    }
    foreach ($Name in @("KDBG", "KDBGProbe")) {
        $Item = $Plan | Where-Object {
            [string]$_.Driver.Service -eq $Name
        } | Select-Object -First 1
        if ($null -eq $Item -or -not $Item.Existing -or
            -not $Item.WasRunning -or -not $SafeToRestore[$Name]) {
            continue
        }
        try {
            $Service = Get-Service -Name $Name -ErrorAction Stop
            Start-Service -Name $Name -ErrorAction Stop
            $Service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(15))
            $Service.Refresh()
            if ($Service.Status -ne
                [System.ServiceProcess.ServiceControllerStatus]::Running) {
                throw "service did not return to Running"
            }
        } catch {
            $CleanupErrors.Add("restart original ${Name}: $($_.Exception.Message)")
        }
    }
    if ($CleanupErrors.Count -gt 0) {
        throw "Installation failed: $($InstallFailure.Exception.Message); cleanup errors: $($CleanupErrors -join '; ')"
    }
    throw $InstallFailure
}
if ($ReloadPair) {
    $RuntimeLabel = if ($ResolvedTargetProfile -eq "DisposableVm") { "guest" } else { "local host" }
    Write-Host "KDBG services were stopped as a pair, rebound, reloaded, and verified against this package. Driver SYS/CAT trust is valid on this $RuntimeLabel."
} else {
    $RuntimeLabel = if ($ResolvedTargetProfile -eq "DisposableVm") { "guest" } else { "local host" }
    Write-Host "KDBG services were confirmed stopped/absent as a pair and bound to this package. Driver SYS/CAT trust is valid on this $RuntimeLabel."
}
exit 0

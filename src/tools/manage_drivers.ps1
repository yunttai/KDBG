[CmdletBinding()]
param(
    [ValidateSet("Install", "Update", "Repair", "Start", "Stop", "Restart", "Remove", "Status")]
    [string]$Action = "Status",

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [string]$DriverDirectory,

    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 30,

    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") { throw "Driver management is Windows-only." }
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

$LoadActions = @("Install", "Update", "Repair", "Start", "Restart")
if ($Action -in $LoadActions) {
    if (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot) {
        throw "$Action requires -ConfirmDedicatedVm and -ConfirmSnapshot."
    }
}

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($DriverDirectory)) {
    $DriverDirectory = Join-Path $RepoRoot "out\drivers\$Configuration"
}
$DriverDirectory = [System.IO.Path]::GetFullPath($DriverDirectory)

$Drivers = @(
    [pscustomobject]@{
        Service = "KDBG"
        Display = "KDBG Physical Memory Driver"
        File = "KDbgDriver.sys"
        Device = "\\.\KDBG"
    },
    [pscustomobject]@{
        Service = "KDBGProbe"
        Display = "KDBG Probe Fixture Driver"
        File = "KDbgProbe.sys"
        Device = "\\.\KDBGProbe"
    }
)
$ReverseDrivers = @($Drivers)
[Array]::Reverse($ReverseDrivers)

function Invoke-Sc {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [int[]]$AllowedExitCodes = @(0)
    )

    $Output = @(& sc.exe @Arguments 2>&1)
    $Code = [int]$LASTEXITCODE
    foreach ($Line in $Output) { Write-Host $Line }
    if ($Code -notin $AllowedExitCodes) {
        throw "sc.exe $($Arguments -join ' ') failed with exit code $Code."
    }
    return [pscustomobject]@{ Code = $Code; Output = $Output }
}

function Get-ServiceState([string]$ServiceName) {
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $Service) { return "Absent" }
    try {
        $Service.Refresh()
        return $Service.Status.ToString()
    } finally {
        $Service.Dispose()
    }
}

function Get-ServiceQueryCode([string]$ServiceName) {
    $null = @(& sc.exe query $ServiceName 2>&1)
    $Code = [int]$LASTEXITCODE
    if ($Code -notin @(0, 1060, 1072)) {
        throw "sc.exe query $ServiceName failed with exit code $Code."
    }
    return $Code
}

function Wait-ServiceAbsent([string]$ServiceName) {
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $Code = Get-ServiceQueryCode $ServiceName
        if ($Code -eq 1060) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw "Timed out after $TimeoutSeconds seconds waiting for $ServiceName deletion; sc.exe query returned $Code."
}

function Wait-ServiceState([string]$ServiceName, [string]$DesiredState) {
    if ($DesiredState -eq "Absent") {
        Wait-ServiceAbsent $ServiceName
        return
    }
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $State = Get-ServiceState $ServiceName
        if ($State -eq $DesiredState) { return }
        if ($DesiredState -ne "Absent" -and $State -eq "Absent") {
            throw "Service $ServiceName disappeared while waiting for $DesiredState."
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw "Timed out after $TimeoutSeconds seconds waiting for $ServiceName state $DesiredState; current state is $State."
}

function Show-TestSigningDiagnostic {
    try {
        $Control = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control"
        $Options = [string]$Control.SystemStartOptions
        if ($Options -notmatch "(?i)(^|\s)TESTSIGNING(\s|$)") {
            Write-Warning "The current boot does not report TESTSIGNING. Windows may reject the lab drivers when they start."
        }
    } catch {
        Write-Warning "TESTSIGNING status could not be read: $_"
    }
}

function Get-DriverPath($Driver) {
    $Candidate = Join-Path $DriverDirectory $Driver.File
    if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
        throw "Driver binary not found: $Candidate"
    }
    $Resolved = (Resolve-Path -LiteralPath $Candidate).Path
    if ([System.IO.Path]::GetExtension($Resolved) -ine ".sys") {
        throw "Driver binary does not have a .sys extension: $Resolved"
    }
    return $Resolved
}

function Show-DriverSignatureDiagnostic([string]$Path) {
    try {
        $Signature = Get-AuthenticodeSignature -LiteralPath $Path
        if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            Write-Warning "Driver signature status for ${Path}: $($Signature.Status) $($Signature.StatusMessage)"
        }
    } catch {
        Write-Warning "Driver signature status could not be read for ${Path}: $_"
    }
}

function Test-AllDriverInputs {
    foreach ($Driver in $Drivers) {
        $Path = Get-DriverPath $Driver
        Show-DriverSignatureDiagnostic $Path
    }
}

function Confirm-ServiceConfiguration($Driver, [string]$ExpectedPath) {
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Driver.Service)"
    $Config = Get-ItemProperty -LiteralPath $RegistryPath
    $ConfiguredPath = [Environment]::ExpandEnvironmentVariables(
        ([string]$Config.ImagePath).Trim().Trim('"'))
    $ConfiguredPath = [System.IO.Path]::GetFullPath($ConfiguredPath)
    if ([int]$Config.Type -ne 1 -or
        [int]$Config.Start -ne 3 -or
        [int]$Config.ErrorControl -ne 1 -or
        $ConfiguredPath -ine $ExpectedPath) {
        throw "Service configuration verification failed for $($Driver.Service)."
    }
}

function Get-DriverServiceSnapshot($Driver) {
    $QueryCode = Get-ServiceQueryCode $Driver.Service
    if ($QueryCode -eq 1072) {
        Wait-ServiceAbsent $Driver.Service
        $QueryCode = 1060
    }
    if ($QueryCode -eq 1060) {
        return [pscustomobject]@{
            Driver = $Driver
            Exists = $false
            WasRunning = $false
            Type = 1
            Start = 3
            ErrorControl = 1
            ImagePath = ""
            DisplayName = $Driver.Display
        }
    }

    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Driver.Service)"
    $Config = Get-ItemProperty -LiteralPath $RegistryPath
    return [pscustomobject]@{
        Driver = $Driver
        Exists = $true
        WasRunning = (Get-ServiceState $Driver.Service) -eq "Running"
        Type = [int]$Config.Type
        Start = [int]$Config.Start
        ErrorControl = [int]$Config.ErrorControl
        ImagePath = [string]$Config.ImagePath
        DisplayName = [string]$Config.DisplayName
    }
}

function Convert-ServiceTypeToSc([int]$Value) {
    switch ($Value) {
        1 { return "kernel" }
        2 { return "filesys" }
        default { throw "Unsupported original service type $Value." }
    }
}

function Convert-ServiceStartToSc([int]$Value) {
    switch ($Value) {
        0 { return "boot" }
        1 { return "system" }
        2 { return "auto" }
        3 { return "demand" }
        4 { return "disabled" }
        default { throw "Unsupported original service start value $Value." }
    }
}

function Convert-ServiceErrorToSc([int]$Value) {
    switch ($Value) {
        0 { return "ignore" }
        1 { return "normal" }
        2 { return "severe" }
        3 { return "critical" }
        default { throw "Unsupported original service error value $Value." }
    }
}

function Restore-DriverServiceConfig($Snapshot) {
    if (-not $Snapshot.Exists) {
        Remove-Driver $Snapshot.Driver
        return
    }

    $Driver = $Snapshot.Driver
    $Type = Convert-ServiceTypeToSc $Snapshot.Type
    $Start = Convert-ServiceStartToSc $Snapshot.Start
    $ErrorControl = Convert-ServiceErrorToSc $Snapshot.ErrorControl
    $QueryCode = Get-ServiceQueryCode $Driver.Service
    if ($QueryCode -eq 1072) {
        Wait-ServiceAbsent $Driver.Service
        $QueryCode = 1060
    }
    $Verb = if ($QueryCode -eq 1060) { "create" } else { "config" }
    Invoke-Sc -Arguments @(
        $Verb, $Driver.Service,
        "type=", $Type,
        "start=", $Start,
        "error=", $ErrorControl,
        "binPath=", $Snapshot.ImagePath,
        "DisplayName=", $Snapshot.DisplayName) | Out-Null
}

function Restore-DriverTransaction([object[]]$Snapshots) {
    $Failures = [System.Collections.Generic.List[string]]::new()

    foreach ($Driver in $ReverseDrivers) {
        try { Stop-Driver $Driver } catch {
            $Failures.Add("stop $($Driver.Service): $($_.Exception.Message)") | Out-Null
        }
    }

    $AbsentSnapshots = @($Snapshots | Where-Object { -not $_.Exists })
    [Array]::Reverse($AbsentSnapshots)
    foreach ($Snapshot in $AbsentSnapshots) {
        try { Remove-Driver $Snapshot.Driver } catch {
            $Failures.Add("remove $($Snapshot.Driver.Service): $($_.Exception.Message)") | Out-Null
        }
    }
    foreach ($Snapshot in @($Snapshots | Where-Object { $_.Exists })) {
        try { Restore-DriverServiceConfig $Snapshot } catch {
            $Failures.Add("config $($Snapshot.Driver.Service): $($_.Exception.Message)") | Out-Null
        }
    }
    foreach ($Snapshot in $Snapshots) {
        if (-not $Snapshot.Exists -or -not $Snapshot.WasRunning) { continue }
        try {
            Start-Driver $Snapshot.Driver
            Wait-DriverDevicePresent $Snapshot.Driver
        } catch {
            $Failures.Add("start $($Snapshot.Driver.Service): $($_.Exception.Message)") | Out-Null
        }
    }

    if ($Failures.Count -ne 0) {
        throw ($Failures -join " | ")
    }
}

function Invoke-DriverTransaction(
    [string]$Name,
    [object[]]$Snapshots,
    [scriptblock]$Operation) {
    try {
        & $Operation
    } catch {
        $PrimaryFailure = $_.Exception.Message
        try {
            Restore-DriverTransaction $Snapshots
        } catch {
            throw "$Name failed: $PrimaryFailure | recovery also failed: $($_.Exception.Message)"
        }
        throw "$Name failed: $PrimaryFailure | original service configuration and running state restored."
    }
}

function Install-Driver($Driver) {
    $Path = Get-DriverPath $Driver
    $QuotedPath = '"' + $Path + '"'
    $State = Get-ServiceState $Driver.Service
    if ($State -eq "Running") {
        Write-Warning "$($Driver.Service) is running; the updated binary path takes effect on its next start."
    }

    $Existing = Invoke-Sc -Arguments @("query", $Driver.Service) -AllowedExitCodes @(0, 1060, 1072)
    if ($Existing.Code -eq 1072) {
        Wait-ServiceState $Driver.Service "Absent"
        $Existing = [pscustomobject]@{ Code = 1060; Output = @() }
    }
    if ($Existing.Code -eq 0) {
        $Configured = Invoke-Sc -Arguments @(
            "config", $Driver.Service,
            "type=", "kernel",
            "start=", "demand",
            "error=", "normal",
            "binPath=", $QuotedPath,
            "DisplayName=", $Driver.Display) -AllowedExitCodes @(0, 1072)
    } else {
        $Configured = Invoke-Sc -Arguments @(
            "create", $Driver.Service,
            "type=", "kernel",
            "start=", "demand",
            "error=", "normal",
            "binPath=", $QuotedPath,
            "DisplayName=", $Driver.Display) -AllowedExitCodes @(0, 1072)
    }
    if ($Configured.Code -eq 1072) {
        Wait-ServiceState $Driver.Service "Absent"
        Invoke-Sc -Arguments @(
            "create", $Driver.Service,
            "type=", "kernel",
            "start=", "demand",
            "error=", "normal",
            "binPath=", $QuotedPath,
            "DisplayName=", $Driver.Display) | Out-Null
    }

    Confirm-ServiceConfiguration $Driver $Path
    $Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    Write-Host "$($Driver.Service) configured (SHA256 $Hash)."
}

function Start-Driver($Driver) {
    $State = Get-ServiceState $Driver.Service
    if ($State -eq "Absent") { throw "Service $($Driver.Service) is not installed." }
    if ($State -eq "Running") { return }
    if ($State -eq "StartPending") {
        Wait-ServiceState $Driver.Service "Running"
        return
    }
    if ($State -eq "StopPending") {
        Wait-ServiceState $Driver.Service "Stopped"
    } elseif ($State -ne "Stopped") {
        throw "Service $($Driver.Service) is not in a startable state: $State."
    }
    Invoke-Sc -Arguments @("start", $Driver.Service) -AllowedExitCodes @(0, 1056) | Out-Null
    Wait-ServiceState $Driver.Service "Running"
}

function Stop-Driver($Driver) {
    $QueryCode = Get-ServiceQueryCode $Driver.Service
    if ($QueryCode -eq 1060) { return }
    if ($QueryCode -eq 1072) {
        Wait-ServiceAbsent $Driver.Service
        return
    }
    $State = Get-ServiceState $Driver.Service
    if ($State -in @("Absent", "Stopped")) { return }
    if ($State -eq "StopPending") {
        Wait-ServiceState $Driver.Service "Stopped"
        return
    }
    if ($State -eq "StartPending") {
        try {
            Wait-ServiceState $Driver.Service "Running"
        } catch {
            $FinalState = Get-ServiceState $Driver.Service
            if ($FinalState -in @("Absent", "Stopped")) { return }
            throw
        }
    }
    $Stopped = Invoke-Sc -Arguments @("stop", $Driver.Service) -AllowedExitCodes @(0, 1060, 1061, 1062, 1072)
    if ($Stopped.Code -eq 1072) {
        Wait-ServiceAbsent $Driver.Service
        return
    }
    if ($Stopped.Code -eq 1061) {
        $CurrentState = Get-ServiceState $Driver.Service
        if ($CurrentState -eq "StopPending") {
            Wait-ServiceState $Driver.Service "Stopped"
            return
        }
        if ($CurrentState -in @("Absent", "Stopped")) { return }
        throw "Service $($Driver.Service) rejected stop control while in state $CurrentState."
    }
    if ((Get-ServiceState $Driver.Service) -ne "Absent") {
        Wait-ServiceState $Driver.Service "Stopped"
    }
}

function Remove-Driver($Driver) {
    Stop-Driver $Driver
    $QueryCode = Get-ServiceQueryCode $Driver.Service
    if ($QueryCode -eq 1060) { return }
    if ($QueryCode -eq 1072) {
        Wait-ServiceAbsent $Driver.Service
        return
    }
    Invoke-Sc -Arguments @("delete", $Driver.Service) -AllowedExitCodes @(0, 1060, 1072) | Out-Null
    Wait-ServiceAbsent $Driver.Service
}

function Initialize-DeviceOpenApi {
    if ("KdbgDriverDeviceOpen" -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class KdbgDriverDeviceOpen {
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;
    private static readonly IntPtr InvalidHandle = new IntPtr(-1);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static int Probe(string name) {
        IntPtr handle = CreateFileW(
            name, GenericRead | GenericWrite, 0, IntPtr.Zero,
            OpenExisting, 0, IntPtr.Zero);
        if (handle == InvalidHandle) {
            return Marshal.GetLastWin32Error();
        }
        if (!CloseHandle(handle)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return 0;
    }
}
'@
}

function Wait-DriverDevicePresent($Driver) {
    Initialize-DeviceOpenApi
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $Code = [KdbgDriverDeviceOpen]::Probe($Driver.Device)
        if ($Code -in @(0, 32)) {
            Write-Host "$($Driver.Service) device is present (opened or exclusively busy); ABI is not claimed."
            return
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw "Service $($Driver.Service) is running but device $($Driver.Device) presence could not be confirmed (Win32 $Code); ABI was not checked."
}

function Start-AllDrivers {
    $Started = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($Driver in $Drivers) {
            $WasRunning = (Get-ServiceState $Driver.Service) -eq "Running"
            Start-Driver $Driver
            if (-not $WasRunning) { $Started.Add($Driver) | Out-Null }
            Wait-DriverDevicePresent $Driver
        }
    } catch {
        $Rollback = @($Started)
        [Array]::Reverse($Rollback)
        foreach ($Driver in $Rollback) {
            try { Stop-Driver $Driver } catch { Write-Warning $_ }
        }
        throw
    }
}

function Stop-AllDrivers {
    foreach ($Driver in $ReverseDrivers) { Stop-Driver $Driver }
}

switch ($Action) {
    "Install" {
        Test-AllDriverInputs
        $Snapshots = @(
            foreach ($Driver in $Drivers) {
                Get-DriverServiceSnapshot $Driver
            }
        )
        Invoke-DriverTransaction "Install" $Snapshots {
            foreach ($Driver in $Drivers) { Install-Driver $Driver }
        }
    }
    "Update" {
        Show-TestSigningDiagnostic
        Test-AllDriverInputs
        $Snapshots = @(
            foreach ($Driver in $Drivers) {
                Get-DriverServiceSnapshot $Driver
            }
        )
        Invoke-DriverTransaction "Update" $Snapshots {
            Stop-AllDrivers
            foreach ($Driver in $Drivers) { Install-Driver $Driver }
            foreach ($Snapshot in $Snapshots) {
                if (-not $Snapshot.WasRunning) { continue }
                Start-Driver $Snapshot.Driver
                Wait-DriverDevicePresent $Snapshot.Driver
            }
        }
    }
    "Repair" {
        Show-TestSigningDiagnostic
        Test-AllDriverInputs
        $Snapshots = @(
            foreach ($Driver in $Drivers) {
                Get-DriverServiceSnapshot $Driver
            }
        )
        Invoke-DriverTransaction "Repair" $Snapshots {
            Stop-AllDrivers
            foreach ($Driver in $Drivers) { Install-Driver $Driver }
            Start-AllDrivers
        }
    }
    "Start" {
        Show-TestSigningDiagnostic
        Start-AllDrivers
    }
    "Stop" {
        Stop-AllDrivers
    }
    "Restart" {
        Show-TestSigningDiagnostic
        $Snapshots = @(
            foreach ($Driver in $Drivers) {
                Get-DriverServiceSnapshot $Driver
            }
        )
        Invoke-DriverTransaction "Restart" $Snapshots {
            Stop-AllDrivers
            Start-AllDrivers
        }
    }
    "Remove" {
        foreach ($Driver in $ReverseDrivers) { Remove-Driver $Driver }
    }
    "Status" {
        foreach ($Driver in $Drivers) {
            $State = Get-ServiceState $Driver.Service
            Write-Host "$($Driver.Service): $State"
            if ($State -ne "Absent") {
                Invoke-Sc -Arguments @("qc", $Driver.Service) | Out-Null
            }
        }
    }
}

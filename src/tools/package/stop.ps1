[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}
$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$Drivers = @(
    @{ Service = "KDBGProbe"; File = "KDbgProbe.sys" },
    @{ Service = "KDBG"; File = "KDbgDriver.sys" }
)

function Get-NormalizedServicePath([string]$ImagePath) {
    $Expanded = [Environment]::ExpandEnvironmentVariables($ImagePath).Trim().Trim('"')
    if ($Expanded.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase) -or
        $Expanded.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        $Expanded = $Expanded.Substring(4)
    }
    try { return [IO.Path]::GetFullPath($Expanded) }
    catch { return $Expanded }
}

function Invoke-ScQuery([string]$Name) {
    $Output = & sc.exe query $Name 2>&1
    $Code = $LASTEXITCODE
    if ($Code -notin @(0, 1060, 1072)) {
        if ($Output) { $Output | ForEach-Object { Write-Host $_ } }
        throw "sc.exe query $Name failed with exit code $Code."
    }
    return [int]$Code
}

function Wait-ServiceAbsent([string]$Name) {
    $Deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $Code = Invoke-ScQuery $Name
        if ($Code -eq 1060) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw "Service $Name remains registered or pending deletion after 30 seconds (sc.exe $Code)."
}

$StopCandidates = [Collections.Generic.List[object]]::new()
foreach ($Driver in $Drivers) {
    $Key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Driver.Service)"
    $QueryCode = Invoke-ScQuery $Driver.Service
    if ($QueryCode -eq 1060) { continue }
    if ($QueryCode -eq 1072) {
        Wait-ServiceAbsent $Driver.Service
        continue
    }
    if (-not (Test-Path -LiteralPath $Key)) {
        Wait-ServiceAbsent $Driver.Service
        continue
    }
    $Properties = Get-ItemProperty -LiteralPath $Key -ErrorAction Stop
    $Actual = Get-NormalizedServicePath ([string]$Properties.ImagePath)
    $Expected = [IO.Path]::GetFullPath((Join-Path $PackageRoot "drivers\$($Driver.File)"))
    if (-not $Actual.Equals($Expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$($Driver.Service) belongs to another package; this script will not stop it."
    }
    $StopCandidates.Add($Driver)
}

foreach ($Driver in $StopCandidates) {
    $Service = Get-Service -Name $Driver.Service -ErrorAction SilentlyContinue
    if ($null -eq $Service) {
        $QueryCode = Invoke-ScQuery $Driver.Service
        if ($QueryCode -eq 1060) { continue }
        if ($QueryCode -eq 1072) {
            Wait-ServiceAbsent $Driver.Service
            continue
        }
        throw "Service $($Driver.Service) exists in SCM but Get-Service could not open it."
    }
    if ($Service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        continue
    }
    try {
        Stop-Service -Name $Driver.Service -ErrorAction Stop
        $Service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(15))
    } catch {
        $StopFailure = $_
        $QueryCode = Invoke-ScQuery $Driver.Service
        if ($QueryCode -eq 1060) { continue }
        if ($QueryCode -eq 1072) {
            Wait-ServiceAbsent $Driver.Service
            continue
        }
        throw $StopFailure
    }
}
Write-Host "KDBG and KDBGProbe are stopped (or were not registered)."
exit 0

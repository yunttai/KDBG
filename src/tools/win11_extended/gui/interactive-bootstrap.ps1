[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunRoot,
    [int]$Width = 1024,
    [int]$Height = 768,
    [int]$Dpi = 96
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

$preparedPath = Join-Path $RunRoot 'guest-prepared.json'
$evidenceRoot = Join-Path $RunRoot 'evidence'
$resultPath = Join-Path $evidenceRoot 'interactive-bootstrap.json'
$errorPath = Join-Path $evidenceRoot 'interactive-bootstrap-error.txt'
if (-not (Test-Path -LiteralPath $preparedPath -PathType Leaf)) { throw 'Guest prepared record is missing.' }
$prepared = Get-Content -LiteralPath $preparedPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($prepared.success -ne $true) { throw 'Guest prepared record is not successful.' }

try {
    New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
    $desktopKey = 'HKCU:\Control Panel\Desktop'
    New-ItemProperty -LiteralPath $desktopKey -Name LogPixels -PropertyType DWord -Value $Dpi -Force | Out-Null
    New-ItemProperty -LiteralPath $desktopKey -Name Win8DpiScaling -PropertyType DWord -Value 1 -Force | Out-Null
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KdbgBootstrapDisplayNative {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi)]
  public struct DevMode {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string dmDeviceName;
    public short dmSpecVersion, dmDriverVersion, dmSize, dmDriverExtra;
    public int dmFields, dmPositionX, dmPositionY, dmDisplayOrientation, dmDisplayFixedOutput;
    public short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string dmFormName;
    public short dmLogPixels;
    public int dmBitsPerPel, dmPelsWidth, dmPelsHeight, dmDisplayFlags, dmDisplayFrequency;
    public int dmICMMethod, dmICMIntent, dmMediaType, dmDitherType, dmReserved1, dmReserved2;
    public int dmPanningWidth, dmPanningHeight;
  }
  [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern bool EnumDisplaySettings(string name, int mode, ref DevMode value);
  [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern int ChangeDisplaySettings(ref DevMode value, int flags);
  [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
  [DllImport("user32.dll")] public static extern uint GetDpiForSystem();
}
'@
    $mode = [KdbgBootstrapDisplayNative+DevMode]::new()
    $mode.dmSize = [Runtime.InteropServices.Marshal]::SizeOf($mode)
    $beforeWidth = [KdbgBootstrapDisplayNative]::GetSystemMetrics(0)
    $beforeHeight = [KdbgBootstrapDisplayNative]::GetSystemMetrics(1)
    $beforeDpi = [int][KdbgBootstrapDisplayNative]::GetDpiForSystem()
    $enumSucceeded = [KdbgBootstrapDisplayNative]::EnumDisplaySettings($null,-1,[ref]$mode)
    $before = [ordered]@{ width=$beforeWidth; height=$beforeHeight; dpi=$beforeDpi;
        enum_display_settings=$enumSucceeded }
    if ($beforeWidth -ne $Width -or $beforeHeight -ne $Height) {
        if (-not $enumSucceeded) {
            throw "Interactive display is ${beforeWidth}x${beforeHeight}; EnumDisplaySettings cannot select ${Width}x${Height}."
        }
        $mode.dmPelsWidth = $Width
        $mode.dmPelsHeight = $Height
        $mode.dmFields = $mode.dmFields -bor 0x00080000 -bor 0x00100000
        $displayResult = [KdbgBootstrapDisplayNative]::ChangeDisplaySettings([ref]$mode,1)
        if ($displayResult -ne 0) { throw "Display mode change failed: $displayResult" }
        Start-Sleep -Seconds 2
    }
    $observedWidth = [KdbgBootstrapDisplayNative]::GetSystemMetrics(0)
    $observedHeight = [KdbgBootstrapDisplayNative]::GetSystemMetrics(1)
    $observedDpi = [int][KdbgBootstrapDisplayNative]::GetDpiForSystem()
    if ($observedWidth -ne $Width -or $observedHeight -ne $Height -or $observedDpi -ne $Dpi) {
        throw "Interactive display mismatch: ${observedWidth}x${observedHeight} dpi=$observedDpi"
    }

    $fixtureExe = Join-Path ([string]$prepared.package_root) 'tools\kdbg_process_fixture.exe'
    if (-not (Test-Path -LiteralPath $fixtureExe -PathType Leaf)) { throw 'Packaged process fixture is missing.' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $fixtureExe
    $start.WorkingDirectory = [string]$prepared.package_root
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $fixtureProcess = [Diagnostics.Process]::new()
    $fixtureProcess.StartInfo = $start
    if (-not $fixtureProcess.Start()) { throw 'Unable to start the packaged process fixture.' }
    $firstLineTask = $fixtureProcess.StandardOutput.ReadLineAsync()
    if (-not $firstLineTask.Wait(15000)) {
        try { $fixtureProcess.Kill() } catch {}
        throw 'Process fixture did not publish INFO within 15 seconds.'
    }
    $firstLine = $firstLineTask.Result
    if ([string]::IsNullOrWhiteSpace($firstLine)) { throw 'Process fixture returned empty INFO.' }
    $fixture = $firstLine | ConvertFrom-Json
    if ([string]$fixture.schema -cne 'kdbg.process-fixture.v1' -or $fixture.ok -ne $true -or
        [uint32]$fixture.pid -ne [uint32]$fixtureProcess.Id -or [uint32]$fixture.byte_count -ne 4096 -or
        $fixture.virtual_locked -ne $true) {
        try { $fixtureProcess.Kill() } catch {}
        throw 'Process fixture INFO contract failed.'
    }
    $fixtureEvidencePath = Join-Path $evidenceRoot 'fixture-info.json'
    [IO.File]::WriteAllText($fixtureEvidencePath,$firstLine + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
    $fixtureProcess.Dispose()

    $result = [ordered]@{
        schema='kdbg.win11-extended-gui-interactive-bootstrap.v1'
        success=$true
        completed_utc=[DateTime]::UtcNow.ToString('o')
        identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
        session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId
        display=[ordered]@{
            requested=[ordered]@{ width=$Width; height=$Height; dpi=$Dpi }
            before=$before
            after=[ordered]@{ width=$observedWidth; height=$observedHeight; dpi=$observedDpi }
        }
        fixture_pid=[uint32]$fixture.pid
        fixture_info_path=$fixtureEvidencePath
    }
    Write-Json $resultPath $result
    $result | ConvertTo-Json -Depth 20
} catch {
    [IO.File]::WriteAllText($errorPath,($_ | Out-String),[Text.UTF8Encoding]::new($false))
    throw
}

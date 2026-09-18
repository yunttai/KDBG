[CmdletBinding()]
param(
    [switch]$ConfirmKdbgServices,
    [switch]$PurgePackage,
    [switch]$PurgeUserData,
    [ValidateSet("DistributionSource", "InstalledProduct")]
    [string]$PackageRootMode = "DistributionSource"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $ConfirmKdbgServices) {
    throw "Removal requires -ConfirmKdbgServices."
}
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}
$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ExpectedPackageName = "KDBG-1.1.0-win-x64"
$ExpectedRootLeaf = if ($PackageRootMode -eq "InstalledProduct") {
    "Product"
} else { $ExpectedPackageName }
$Drivers = @(
    @{ Service = "KDBG"; File = "KDbgDriver.sys" },
    @{ Service = "KDBGProbe"; File = "KDbgProbe.sys" }
)

function Invoke-Sc(
    [string[]]$Arguments,
    [int[]]$AllowedExitCodes = @(0),
    [switch]$Quiet) {
    $Output = & sc.exe @Arguments 2>&1
    $Code = $LASTEXITCODE
    if ($Output -and -not $Quiet) { $Output | ForEach-Object { Write-Host $_ } }
    if ($Code -notin $AllowedExitCodes) {
        throw "sc.exe failed with exit code $Code."
    }
    return [int]$Code
}

function Wait-ServiceAbsent([string]$Name) {
    $Deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $Code = Invoke-Sc @("query", $Name) @(0, 1060, 1072) -Quiet
        if ($Code -eq 1060) { return }
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

function Assert-NoReparsePoints([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $Entries = @((Get-Item -LiteralPath $Path -Force)) +
        @(Get-ChildItem -LiteralPath $Path -Recurse -Force)
    foreach ($Entry in $Entries) {
        if (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing recursive removal through a reparse point: $($Entry.FullName)"
        }
    }
}

function Assert-KdbgPackageRoot([string]$Path) {
    $Full = [IO.Path]::GetFullPath($Path)
    $RootMatches = if ($PackageRootMode -eq "InstalledProduct") {
        $ProgramFiles = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::ProgramFiles)
        if ([string]::IsNullOrWhiteSpace($ProgramFiles)) { $false }
        else {
            $Full.Equals(
                [IO.Path]::GetFullPath((Join-Path $ProgramFiles "KDBG\Product")),
                [StringComparison]::OrdinalIgnoreCase)
        }
    } else {
        [IO.Path]::GetFileName($Full) -ceq $ExpectedPackageName
    }
    if (-not $RootMatches -or
        [IO.Path]::GetFileName($Full) -cne $ExpectedRootLeaf -or
        -not ([IO.Path]::GetFullPath($PSScriptRoot)).Equals(
            (Join-Path $Full "tools"), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing purge outside the exact packaged KDBG root: $Full"
    }
    $MetadataPath = Join-Path $Full "BUILD-METADATA.json"
    $ManifestPath = Join-Path $Full "SHA256SUMS.txt"
    if (-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Refusing purge because package identity files are missing: $Full"
    }
    $Metadata = Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json
    if ($Metadata.schema -ne "kdbg.build-metadata.v1" -or
        $Metadata.product -ne "KDBG" -or
        $Metadata.package_name -ne $ExpectedPackageName) {
        throw "Refusing purge because BUILD-METADATA.json does not identify the exact KDBG package."
    }
    Assert-NoReparsePoints $Full
    return $Full
}

function Remove-ValidatedChildDirectory(
    [string]$Parent,
    [string]$Path,
    [string]$ExpectedLeaf) {
    $ParentFull = [IO.Path]::GetFullPath($Parent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $Full = [IO.Path]::GetFullPath($Path)
    $Expected = [IO.Path]::GetFullPath((Join-Path $ParentFull $ExpectedLeaf))
    if (-not $Full.Equals($Expected, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($Full) -ne $ExpectedLeaf) {
        throw "Refusing removal outside the exact expected child directory: $Full"
    }
    if (-not (Test-Path -LiteralPath $Full)) { return }
    Assert-NoReparsePoints $Full
    Remove-Item -LiteralPath $Full -Recurse -Force
}

function Start-KdbgDetachedPowerShell(
    [string]$PowerShellPath,
    [string]$Arguments) {
    if ($null -eq ("KdbgDetachedProcess" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class KdbgDetachedProcess
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public uint cb;
        public string reserved;
        public string desktop;
        public string title;
        public uint x;
        public uint y;
        public uint xSize;
        public uint ySize;
        public uint xCountChars;
        public uint yCountChars;
        public uint fillAttribute;
        public uint flags;
        public ushort showWindow;
        public ushort reservedSize;
        public IntPtr reservedPointer;
        public IntPtr standardInput;
        public IntPtr standardOutput;
        public IntPtr standardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public uint processId;
        public uint threadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    public static int Start(string application, string arguments, string currentDirectory)
    {
        if (application.IndexOf('"') >= 0)
        {
            throw new ArgumentException("Application path contains a quote.", "application");
        }
        StartupInfo startup = new StartupInfo();
        startup.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));
        ProcessInformation process;
        StringBuilder command = new StringBuilder(
            "\"" + application + "\" " + arguments);
        const uint CreateNoWindow = 0x08000000;
        if (!CreateProcessW(
                application, command, IntPtr.Zero, IntPtr.Zero, false,
                CreateNoWindow, IntPtr.Zero, currentDirectory,
                ref startup, out process))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "Detached purge worker launch failed.");
        }
        try
        {
            return unchecked((int)process.processId);
        }
        finally
        {
            CloseHandle(process.thread);
            CloseHandle(process.process);
        }
    }
}
'@
    }

    $Application = [IO.Path]::GetFullPath($PowerShellPath)
    if (-not (Test-Path -LiteralPath $Application -PathType Leaf)) {
        throw "Detached purge-worker PowerShell is missing: $Application"
    }
    $WorkingDirectory = [IO.Path]::GetDirectoryName($Application)
    return [KdbgDetachedProcess]::Start(
        $Application, $Arguments, $WorkingDirectory)
}

function Start-PackageSelfPurge(
    [string]$VerifiedPackageRoot,
    [string]$StatusDirectory = "") {
    $MetadataPath = Join-Path $VerifiedPackageRoot "BUILD-METADATA.json"
    $MetadataHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $MetadataPath).Hash
    $TransactionId = [Guid]::NewGuid().ToString("N")
    if ([string]::IsNullOrWhiteSpace($StatusDirectory)) {
        $ProgramData = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonApplicationData)
        if ([string]::IsNullOrWhiteSpace($ProgramData)) {
            throw "ProgramData could not be resolved for purge status."
        }
        $StatusDirectory = Join-Path $ProgramData "KDBG\Setup"
    }
    $StatusDirectory = [IO.Path]::GetFullPath($StatusDirectory)
    New-Item -ItemType Directory -Path $StatusDirectory -Force | Out-Null
    $StatusPath = Join-Path $StatusDirectory "purge-$TransactionId.json"
    $LogPath = Join-Path $StatusDirectory "purge-$TransactionId.log"
    $HelperPath = Join-Path ([IO.Path]::GetTempPath()) (
        "kdbg-package-purge-$TransactionId.ps1")
    $Helper = @'
param(
    [int]$ParentProcessId,
    [string]$PackageParent,
    [string]$PackagePath,
    [string]$ExpectedLeaf,
    [string]$ExpectedPackageName,
    [string]$MetadataHash,
    [string]$HelperPath,
    [string]$TransactionId,
    [string]$StatusPath,
    [string]$LogPath
)
$ErrorActionPreference = "Stop"
function Write-Log([string]$Message) {
    Add-Content -LiteralPath $LogPath -Encoding utf8 -Value ("{0} {1}" -f [DateTime]::UtcNow.ToString("o"), $Message)
}
function Write-Status([string]$State,[string]$ErrorMessage = "") {
    $Document = [ordered]@{schema="kdbg.setup-purge.v1";transaction_id=$TransactionId;state=$State;updated_utc=[DateTime]::UtcNow.ToString("o");product_root=$PackagePath;log_file=$LogPath;error=$ErrorMessage}
    $Temporary = "$StatusPath.tmp"
    $Document | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Temporary -Encoding utf8
    Move-Item -LiteralPath $Temporary -Destination $StatusPath -Force
}
try {
    Write-Status "waiting"
    Write-Log "waiting for uninstaller process to exit"
    Wait-Process -Id $ParentProcessId -Timeout 60 -ErrorAction SilentlyContinue
    if ($null -ne (Get-Process -Id $ParentProcessId -ErrorAction SilentlyContinue)) {
        throw "Uninstaller did not exit before the package purge timeout."
    }
    Write-Status "purging"
    $ParentFull = [IO.Path]::GetFullPath($PackageParent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $Full = [IO.Path]::GetFullPath($PackagePath)
    $Expected = [IO.Path]::GetFullPath((Join-Path $ParentFull $ExpectedLeaf))
    if (-not $Full.Equals($Expected, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($Full) -ne $ExpectedLeaf) {
        throw "Package purge target changed."
    }
    $MetadataPath = Join-Path $Full "BUILD-METADATA.json"
    $ManifestPath = Join-Path $Full "SHA256SUMS.txt"
    if (-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $MetadataPath).Hash -ne $MetadataHash) {
        throw "Package identity changed before purge."
    }
    $Metadata = Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json
    if ($Metadata.schema -ne "kdbg.build-metadata.v1" -or
        $Metadata.product -ne "KDBG" -or
        $Metadata.package_name -ne $ExpectedPackageName) {
        throw "Package metadata identity changed before purge."
    }
    $Entries = @((Get-Item -LiteralPath $Full -Force)) +
        @(Get-ChildItem -LiteralPath $Full -Recurse -Force)
    foreach ($Entry in $Entries) {
        if (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Package contains a reparse point: $($Entry.FullName)"
        }
    }
    Remove-Item -LiteralPath $Full -Recurse -Force
    Write-Log "verified package purge succeeded"
    Write-Status "succeeded"
} catch {
    Write-Log ("purge failed: " + $_.Exception.Message)
    Write-Status "failed" $_.Exception.Message
} finally {
    Remove-Item -LiteralPath $HelperPath -Force -ErrorAction SilentlyContinue
}
'@
    Set-Content -LiteralPath $HelperPath -Value $Helper -Encoding utf8
    Set-Content -LiteralPath $LogPath -Encoding utf8 -Value (
        "{0} purge scheduled root={1}" -f [DateTime]::UtcNow.ToString("o"), $VerifiedPackageRoot)
    [ordered]@{
        schema = "kdbg.setup-purge.v1"
        transaction_id = $TransactionId
        state = "scheduled"
        updated_utc = [DateTime]::UtcNow.ToString("o")
        product_root = $VerifiedPackageRoot
        log_file = $LogPath
        error = ""
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatusPath -Encoding utf8
    $PowerShellPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    $Quote = {
        param([string]$Value)
        '"' + $Value.Replace('"', '""') + '"'
    }
    $Arguments = @(
        "-NoProfile", "-NonInteractive", "-File", (& $Quote $HelperPath),
        "-ParentProcessId", [string]$PID,
        "-PackageParent", (& $Quote ([IO.Path]::GetDirectoryName($VerifiedPackageRoot))),
        "-PackagePath", (& $Quote $VerifiedPackageRoot),
        "-ExpectedLeaf", (& $Quote $ExpectedRootLeaf),
        "-ExpectedPackageName", (& $Quote $ExpectedPackageName),
        "-MetadataHash", $MetadataHash,
        "-HelperPath", (& $Quote $HelperPath),
        "-TransactionId", $TransactionId,
        "-StatusPath", (& $Quote $StatusPath),
        "-LogPath", (& $Quote $LogPath))
    try {
        $WorkerPid = Start-KdbgDetachedPowerShell $PowerShellPath ($Arguments -join " ")
    } catch {
        Add-Content -LiteralPath $LogPath -Encoding utf8 -Value (
            "{0} purge launch failed: {1}" -f [DateTime]::UtcNow.ToString("o"), $_.Exception.Message)
        [ordered]@{
            schema = "kdbg.setup-purge.v1"
            transaction_id = $TransactionId
            state = "failed"
            updated_utc = [DateTime]::UtcNow.ToString("o")
            product_root = $VerifiedPackageRoot
            log_file = $LogPath
            error = $_.Exception.Message
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatusPath -Encoding utf8
        throw
    }
    return [pscustomobject]@{
        schema = "kdbg.setup-purge.v1"
        transaction_id = $TransactionId
        state = "scheduled"
        worker_pid = $WorkerPid
        status_file = $StatusPath
        log_file = $LogPath
    }
}

$VerifiedPackageRoot = Assert-KdbgPackageRoot $PackageRoot
if ($PurgePackage) {
    $VerifiedPackageRoot = Assert-KdbgPackageRoot $PackageRoot
}
$LocalDataParent = $null
if ($PurgeUserData) {
    $LocalDataParent = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($LocalDataParent)) {
        throw "LocalApplicationData could not be resolved; no service or user data was changed."
    }
}

# Refuse to remove an identically named service owned by another package.
foreach ($Driver in $Drivers) {
    $Key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Driver.Service)"
    $QueryCode = Invoke-Sc @("query", $Driver.Service) @(0, 1060, 1072) -Quiet
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
        throw "$($Driver.Service) belongs to another package; this uninstaller will not remove it."
    }
}

& (Join-Path $PSScriptRoot "stop.ps1")

foreach ($Driver in @($Drivers[1], $Drivers[0])) {
    $QueryCode = Invoke-Sc @("query", $Driver.Service) @(0, 1060, 1072) -Quiet
    if ($QueryCode -eq 1060) { continue }
    if ($QueryCode -eq 0) {
        Invoke-Sc @("delete", $Driver.Service) @(0, 1060, 1072) | Out-Null
    }
    Wait-ServiceAbsent $Driver.Service
}
if ($PurgeUserData) {
    Remove-ValidatedChildDirectory `
        $LocalDataParent (Join-Path $LocalDataParent "KDBG") "KDBG"
}
if ($PurgePackage) {
    $Purge = Start-PackageSelfPurge $VerifiedPackageRoot
    Write-Host (
        "KDBG service registrations were removed. Package purge is pending, not complete. " +
        "PURGE_SCHEDULED id=$($Purge.transaction_id) status=$($Purge.status_file) " +
        "log=$($Purge.log_file)")
} elseif ($PurgeUserData) {
    Write-Host "KDBG service registrations and exact KDBG user-data directory were removed. Package files were retained."
} else {
    Write-Host "KDBG service registrations were removed. Package files and user data were retained."
}
exit 0

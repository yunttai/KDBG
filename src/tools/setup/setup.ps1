[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Install", "Repair", "Update", "Uninstall")]
    [string]$Action,

    [switch]$ConfirmDedicatedVm,
    [switch]$ConfirmSnapshot,

    [ValidateSet("DisposableVm", "LocalHost")]
    [string]$TargetProfile,

    [ValidateRange(0, 2147483647)]
    [int]$HostProcessId = 0,

    [string]$DestinationRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot "setup_contract.psm1") -Force
Import-Module (Join-Path $PSScriptRoot "TargetProfile.psm1") -Force
$Contract = Get-KdbgSetupContract
$Plan = Get-KdbgSetupPlan -Action $Action

$ResolvedTargetProfile = if ([string]::IsNullOrWhiteSpace($TargetProfile)) {
    if ($ConfirmDedicatedVm -and $ConfirmSnapshot) { "DisposableVm" }
    else { "LocalHost" }
} else { $TargetProfile }
if ($ResolvedTargetProfile -eq "DisposableVm" -and
    (-not $ConfirmDedicatedVm -or -not $ConfirmSnapshot)) {
    throw "Setup requires dedicated disposable-VM and snapshot confirmations."
}
$null = Assert-KdbgTargetProfile `
    -TargetProfile $ResolvedTargetProfile `
    -ConfirmDedicatedVm:$ConfirmDedicatedVm `
    -ConfirmSnapshot:$ConfirmSnapshot
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "KDBG Setup must run as Administrator."
}

$SourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ProgramFiles = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)
if ([string]::IsNullOrWhiteSpace($ProgramFiles)) {
    throw "Program Files could not be resolved."
}
$InstallParent = [IO.Path]::GetFullPath((Join-Path $ProgramFiles $Contract.InstallParentLeaf))
$DefaultDestination = Join-Path $InstallParent $Contract.InstallLeaf
if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
    $DestinationRoot = $DefaultDestination
}
$DestinationRoot = [IO.Path]::GetFullPath($DestinationRoot)
if (-not $DestinationRoot.Equals(
        [IO.Path]::GetFullPath($DefaultDestination),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "DestinationRoot must be the exact KDBG Program Files package directory: $DefaultDestination"
}

function Assert-NoReparsePoints([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $Entries = @((Get-Item -LiteralPath $Path -Force)) +
        @(Get-ChildItem -LiteralPath $Path -Recurse -Force)
    foreach ($Entry in $Entries) {
        if (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Setup refuses a package tree containing a reparse point: $($Entry.FullName)"
        }
    }
}

function Assert-ExactPackageRoot(
    [string]$Path,
    [ValidateSet("DistributionSource", "SetupStaging", "InstalledProduct")]
    [string]$Mode) {
    $Full = [IO.Path]::GetFullPath($Path)
    switch ($Mode) {
        "DistributionSource" {
            if ([IO.Path]::GetFileName($Full) -cne $Contract.PackageLeaf) {
                throw "Distribution source must retain the exact package directory name $($Contract.PackageLeaf): $Full"
            }
        }
        "InstalledProduct" {
            if (-not $Full.Equals(
                    [IO.Path]::GetFullPath($DefaultDestination),
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "Installed product root must be the exact Program Files KDBG Product directory: $Full"
            }
        }
        "SetupStaging" {
            $Parent = [IO.Path]::GetDirectoryName($Full)
            $GrandParent = [IO.Path]::GetDirectoryName($Parent)
            if ([IO.Path]::GetFileName($Full) -cne $Contract.InstallLeaf -or
                [IO.Path]::GetFileName($Parent) -cnotmatch '^\.staging-[0-9a-f]{32}$' -or
                [string]::IsNullOrWhiteSpace($GrandParent) -or
                -not $GrandParent.Equals(
                    $InstallParent, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Setup staging root is outside the exact KDBG staging contract: $Full"
            }
        }
    }
    foreach ($Relative in @(
            "KDBG.exe", "KDBGSetup.exe", "BUILD-METADATA.json",
            "SHA256SUMS.txt", "tools\diagnose.ps1", "tools\install.ps1",
            "tools\TargetProfile.psm1",
            "tools\uninstall.ps1", "tools\setup.ps1",
            "tools\setup_contract.psm1")) {
        $Required = Join-Path $Full $Relative
        if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
            throw "Setup package input is missing: $Required"
        }
    }
    $Metadata = Get-Content -LiteralPath (
        Join-Path $Full "BUILD-METADATA.json") -Raw | ConvertFrom-Json
    if ($Metadata.schema -ne "kdbg.build-metadata.v1" -or
        $Metadata.product -ne "KDBG" -or
        $Metadata.version -ne $Contract.Version -or
        $Metadata.package_name -ne $Contract.PackageLeaf) {
        throw "BUILD-METADATA.json does not identify the exact distribution payload."
    }
    Assert-NoReparsePoints $Full
    return $Full
}

function Assert-NoActivePackageProcesses(
    [string]$Root,
    [int]$AllowedProcessId = 0) {
    $Prefix = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    $Active = [Collections.Generic.List[string]]::new()
    foreach ($Process in Get-Process -ErrorAction SilentlyContinue) {
        if ($Process.Id -eq $AllowedProcessId) { continue }
        try { $Path = [string]$Process.Path }
        catch { continue }
        if (-not [string]::IsNullOrWhiteSpace($Path) -and
            [IO.Path]::GetFullPath($Path).StartsWith(
                $Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            $Active.Add("$($Process.ProcessName)($($Process.Id))")
        }
    }
    if ($Active.Count -gt 0) {
        throw "Close KDBG package processes before setup continues: $($Active -join ', ')"
    }
}

function Invoke-PackageDiagnostics(
    [string]$Root,
    [ValidateSet("DistributionSource", "SetupStaging", "InstalledProduct")]
    [string]$Mode) {
    & (Join-Path $Root "tools\diagnose.ps1") `
        -VerifyPackage -RequireAdministrator -RequireTrustedDriverSignatures `
        -PackageRootMode $Mode
    if ($LASTEXITCODE -ne 0) {
        throw "Exact package integrity or driver trust verification failed: $Root"
    }
}

function Write-SetupRegistration([string]$Root) {
    $Key = $Contract.UninstallKey
    New-Item -Path $Key -Force | Out-Null
    $SetupPath = Join-Path $Root "KDBGSetup.exe"
    $QuotedSetup = '"' + $SetupPath + '" /uninstall'
    $QuotedRepair = '"' + $SetupPath + '" /repair'
    $Values = [ordered]@{
        DisplayName = "KDBG"
        DisplayVersion = $Contract.Version
        Publisher = "KDBG Project"
        InstallLocation = $Root
        DisplayIcon = (Join-Path $Root "KDBG.exe")
        UninstallString = $QuotedSetup
        ModifyPath = $QuotedRepair
        NoModify = 0
        NoRepair = 0
        EstimatedSize = [int][Math]::Ceiling((
            (Get-ChildItem -LiteralPath $Root -Recurse -File |
                Measure-Object -Property Length -Sum).Sum) / 1KB)
    }
    foreach ($Item in $Values.GetEnumerator()) {
        $Type = if ($Item.Value -is [int]) { "DWord" } else { "String" }
        New-ItemProperty -LiteralPath $Key -Name $Item.Key -Value $Item.Value `
            -PropertyType $Type -Force | Out-Null
    }

    $Programs = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonPrograms)
    if ([string]::IsNullOrWhiteSpace($Programs)) {
        throw "The common Start Menu could not be resolved."
    }
    $ShortcutDirectory = Join-Path $Programs $Contract.StartMenuFolder
    New-Item -ItemType Directory -Path $ShortcutDirectory -Force | Out-Null
    $Shell = New-Object -ComObject WScript.Shell
    $Shortcut = $Shell.CreateShortcut((Join-Path $ShortcutDirectory "KDBG.lnk"))
    $Shortcut.TargetPath = Join-Path $Root "KDBG.exe"
    $Shortcut.WorkingDirectory = $Root
    $Shortcut.Description = "KDBG physical and process memory research GUI"
    $Shortcut.IconLocation = (Join-Path $Root "KDBG.exe") + ",0"
    $Shortcut.Save()
}

function Remove-SetupRegistration {
    Remove-Item -LiteralPath $Contract.UninstallKey -Recurse -Force `
        -ErrorAction SilentlyContinue
    $Programs = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonPrograms)
    if (-not [string]::IsNullOrWhiteSpace($Programs)) {
        $ShortcutDirectory = Join-Path $Programs $Contract.StartMenuFolder
        $Shortcut = Join-Path $ShortcutDirectory "KDBG.lnk"
        Remove-Item -LiteralPath $Shortcut -Force -ErrorAction SilentlyContinue
        if ((Test-Path -LiteralPath $ShortcutDirectory -PathType Container) -and
            @(Get-ChildItem -LiteralPath $ShortcutDirectory -Force).Count -eq 0) {
            Remove-Item -LiteralPath $ShortcutDirectory -Force
        }
    }
}

function Write-PurgeStatus(
    [string]$Path,
    [string]$TransactionId,
    [string]$State,
    [string]$Root,
    [string]$LogPath,
    [string]$ErrorMessage = "") {
    $Document = [ordered]@{
        schema = "kdbg.setup-purge.v1"
        transaction_id = $TransactionId
        state = $State
        updated_utc = [DateTime]::UtcNow.ToString("o")
        product_root = $Root
        log_file = $LogPath
        error = $ErrorMessage
    }
    $Temporary = "$Path.tmp"
    $Document | ConvertTo-Json -Depth 4 | Set-Content `
        -LiteralPath $Temporary -Encoding utf8
    Move-Item -LiteralPath $Temporary -Destination $Path -Force
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

function Prepare-ExactPackagePurge([string]$Root) {
    $Root = Assert-ExactPackageRoot $Root -Mode InstalledProduct
    if (-not ([IO.Path]::GetDirectoryName($Root)).Equals(
            $InstallParent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Setup refuses to purge a package outside the exact KDBG install parent."
    }
    $Metadata = Join-Path $Root "BUILD-METADATA.json"
    $MetadataHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Metadata).Hash
    $TransactionId = [Guid]::NewGuid().ToString("N")
    $ProgramData = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($ProgramData)) {
        throw "ProgramData could not be resolved for persistent purge status."
    }
    $StatusDirectory = Join-Path $ProgramData "KDBG\Setup"
    New-Item -ItemType Directory -Path $StatusDirectory -Force | Out-Null
    $StatusPath = Join-Path $StatusDirectory "purge-$TransactionId.json"
    $LogPath = Join-Path $StatusDirectory "purge-$TransactionId.log"
    $CommitPath = Join-Path $StatusDirectory "purge-$TransactionId.commit"
    $HelperPath = Join-Path ([IO.Path]::GetTempPath()) (
        "kdbg-setup-purge-$TransactionId.ps1")
    $Helper = @'
param([int]$SetupPid,[int]$ScriptPid,[string]$Root,[string]$Parent,[string]$Leaf,[string]$MetadataHash,[string]$Self,[string]$TransactionId,[string]$StatusPath,[string]$LogPath,[string]$CommitPath)
$ErrorActionPreference = "Stop"
function Write-Log([string]$Message) {
    Add-Content -LiteralPath $LogPath -Encoding utf8 -Value ("{0} {1}" -f [DateTime]::UtcNow.ToString("o"), $Message)
}
function Write-Status([string]$State,[string]$ErrorMessage = "") {
    $Document = [ordered]@{schema="kdbg.setup-purge.v1";transaction_id=$TransactionId;state=$State;updated_utc=[DateTime]::UtcNow.ToString("o");product_root=$Root;log_file=$LogPath;error=$ErrorMessage}
    $Temporary = "$StatusPath.tmp"
    $Document | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Temporary -Encoding utf8
    Move-Item -LiteralPath $Temporary -Destination $StatusPath -Force
}
try {
    Write-Log "waiting for setup processes to exit"
    Write-Status "waiting"
    foreach ($ProcessId in @($SetupPid, $ScriptPid)) {
        if ($ProcessId -gt 0) { Wait-Process -Id $ProcessId -Timeout 60 -ErrorAction SilentlyContinue }
    }
    foreach ($ProcessId in @($SetupPid, $ScriptPid)) {
        if ($ProcessId -gt 0 -and (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { throw "Setup process $ProcessId did not exit before timeout." }
    }
    if (-not (Test-Path -LiteralPath $CommitPath -PathType Leaf) -or
        (Get-Content -LiteralPath $CommitPath -Raw).Trim() -cne $TransactionId) {
        Write-Log "purge cancelled because commit marker was absent or invalid; Product root preserved"
        Write-Status "cancelled"
        return
    }
    Write-Status "purging"
    $Full = [IO.Path]::GetFullPath($Root)
    $Expected = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetFullPath($Parent)) $Leaf))
    if (-not $Full.Equals($Expected, [StringComparison]::OrdinalIgnoreCase)) { throw "Purge target changed." }
    $Metadata = Join-Path $Full "BUILD-METADATA.json"
    if (-not (Test-Path -LiteralPath $Metadata -PathType Leaf) -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $Metadata).Hash -ne $MetadataHash) { throw "Purge identity changed." }
    $Entries = @((Get-Item -LiteralPath $Full -Force)) + @(Get-ChildItem -LiteralPath $Full -Recurse -Force)
    if (@($Entries | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -ne 0) { throw "Purge tree contains a reparse point." }
    Remove-Item -LiteralPath $Full -Recurse -Force
    if ((Test-Path -LiteralPath $Parent -PathType Container) -and @(Get-ChildItem -LiteralPath $Parent -Force).Count -eq 0) { Remove-Item -LiteralPath $Parent -Force }
    Write-Log "verified product purge succeeded"
    Write-Status "succeeded"
} catch {
    Write-Log ("purge failed: " + $_.Exception.Message)
    Write-Status "failed" $_.Exception.Message
} finally {
    Remove-Item -LiteralPath $CommitPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Self -Force -ErrorAction SilentlyContinue
}
'@
    Set-Content -LiteralPath $HelperPath -Value $Helper -Encoding utf8
    Set-Content -LiteralPath $LogPath -Encoding utf8 -Value (
        "{0} purge scheduled root={1}" -f [DateTime]::UtcNow.ToString("o"), $Root)
    Write-PurgeStatus $StatusPath $TransactionId "ready" $Root $LogPath
    $PowerShellPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    $Arguments = @(
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", (ConvertTo-KdbgCommandLineArgument $HelperPath),
        "-SetupPid", [string]$HostProcessId,
        "-ScriptPid", [string]$PID,
        "-Root", (ConvertTo-KdbgCommandLineArgument $Root),
        "-Parent", (ConvertTo-KdbgCommandLineArgument $InstallParent),
        "-Leaf", $Contract.InstallLeaf,
        "-MetadataHash", $MetadataHash,
        "-Self", (ConvertTo-KdbgCommandLineArgument $HelperPath),
        "-TransactionId", $TransactionId,
        "-StatusPath", (ConvertTo-KdbgCommandLineArgument $StatusPath),
        "-LogPath", (ConvertTo-KdbgCommandLineArgument $LogPath),
        "-CommitPath", (ConvertTo-KdbgCommandLineArgument $CommitPath)) -join " "
    try {
        $WorkerPid = Start-KdbgDetachedPowerShell $PowerShellPath $Arguments
    } catch {
        Write-PurgeStatus $StatusPath $TransactionId "failed" $Root $LogPath `
            $_.Exception.Message
        throw
    }
    return [pscustomobject]@{
        schema = "kdbg.setup-purge.v1"
        transaction_id = $TransactionId
        state = "ready"
        worker_pid = $WorkerPid
        status_file = $StatusPath
        log_file = $LogPath
        commit_marker = $CommitPath
    }
}

function Commit-ExactPackagePurge([object]$Prepared) {
    if ($null -eq $Prepared -or $Prepared.state -ne "ready" -or
        [string]::IsNullOrWhiteSpace([string]$Prepared.commit_marker)) {
        throw "Purge commit requires the exact ready-state contract."
    }
    $CommitPath = [IO.Path]::GetFullPath([string]$Prepared.commit_marker)
    $StatusParent = [IO.Path]::GetDirectoryName(
        [IO.Path]::GetFullPath([string]$Prepared.status_file))
    if (-not [IO.Path]::GetDirectoryName($CommitPath).Equals(
            $StatusParent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($CommitPath) -cne
            "purge-$($Prepared.transaction_id).commit") {
        throw "Purge commit marker is outside the exact persistent status directory."
    }
    Set-Content -LiteralPath $CommitPath -Encoding ascii -NoNewline `
        -Value ([string]$Prepared.transaction_id)
    Write-PurgeStatus $Prepared.status_file $Prepared.transaction_id `
        "scheduled" $DefaultDestination $Prepared.log_file
    return [pscustomobject]@{
        schema = "kdbg.setup-purge.v1"
        transaction_id = $Prepared.transaction_id
        state = "scheduled"
        status_file = $Prepared.status_file
        log_file = $Prepared.log_file
        commit_marker = $CommitPath
    }
}

Write-Host "KDBG Setup $Action"
Write-Host "Contract: $($Plan.Schema)"
Write-Host "Phases: $($Plan.Phases -join ' -> ')"

if ($Action -eq "Uninstall") {
    $InstalledRoot = $DestinationRoot
    if (Test-Path -LiteralPath $Contract.UninstallKey) {
        $Registered = Get-ItemProperty -LiteralPath $Contract.UninstallKey
        if (-not [string]::IsNullOrWhiteSpace([string]$Registered.InstallLocation)) {
            $InstalledRoot = [IO.Path]::GetFullPath([string]$Registered.InstallLocation)
        }
    }
    if (-not $InstalledRoot.Equals(
            $DestinationRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Registered KDBG install location is outside the exact product destination."
    }
    Assert-NoActivePackageProcesses $InstalledRoot $HostProcessId
    $Purge = Invoke-KdbgSetupUninstallTransaction `
        -InstalledRoot $InstalledRoot `
        -VerifyInstalled {
            param($Root)
            Assert-ExactPackageRoot $Root -Mode InstalledProduct | Out-Null
            Invoke-PackageDiagnostics $Root -Mode InstalledProduct
        } `
        -RemoveLifecycle {
            param($Root)
            & (Join-Path $Root "tools\uninstall.ps1") `
                -ConfirmKdbgServices -PackageRootMode InstalledProduct
            if ($LASTEXITCODE -ne 0) { throw "Driver service removal failed." }
        } `
        -PreparePurge { param($Root) Prepare-ExactPackagePurge $Root } `
        -UnregisterProduct { Remove-SetupRegistration } `
        -RegisterProduct { param($Root) Write-SetupRegistration $Root } `
        -CommitPurge { param($Prepared) Commit-ExactPackagePurge $Prepared }
    Write-Host (
        "KDBG driver services and product registration were removed. " +
        "Package purge is pending, not complete. PURGE_SCHEDULED " +
        "id=$($Purge.transaction_id) status=$($Purge.status_file) " +
        "log=$($Purge.log_file)")
    exit 0
}

$SourceMode = if ($SourceRoot.Equals(
        $DestinationRoot, [StringComparison]::OrdinalIgnoreCase)) {
    "InstalledProduct"
} else {
    "DistributionSource"
}
$SourceRoot = Assert-ExactPackageRoot $SourceRoot -Mode $SourceMode
Invoke-PackageDiagnostics $SourceRoot -Mode $SourceMode
New-Item -ItemType Directory -Path $InstallParent -Force | Out-Null
Assert-NoReparsePoints $InstallParent

$SameRoot = $SourceRoot.Equals(
    $DestinationRoot, [StringComparison]::OrdinalIgnoreCase)
if (-not $SameRoot -and
    (Test-Path -LiteralPath $DestinationRoot -PathType Container)) {
    Assert-ExactPackageRoot $DestinationRoot -Mode InstalledProduct | Out-Null
    Assert-NoActivePackageProcesses $DestinationRoot $HostProcessId
}

$Result = Invoke-KdbgSetupFileTransaction `
    -SourceRoot $SourceRoot `
    -DestinationRoot $DestinationRoot `
    -InstallParent $InstallParent `
    -VerifySource {
        param($Root)
        $Mode = if ([IO.Path]::GetFullPath($Root).Equals(
                [IO.Path]::GetFullPath($DefaultDestination),
                [StringComparison]::OrdinalIgnoreCase)) {
            "InstalledProduct"
        } else { "DistributionSource" }
        Assert-ExactPackageRoot $Root -Mode $Mode | Out-Null
        Invoke-PackageDiagnostics $Root -Mode $Mode
    } `
    -VerifyStaging {
        param($Root, $StagingRoot)
        Assert-ExactPackageRoot $Root -Mode SetupStaging | Out-Null
        Invoke-PackageDiagnostics $Root -Mode SetupStaging
    } `
    -ApplyLifecycle {
        param($Root)
        Assert-ExactPackageRoot $Root -Mode InstalledProduct | Out-Null
        $InstallArguments = @{
            Start = $true
            TargetProfile = $ResolvedTargetProfile
            PackageRootMode = "InstalledProduct"
        }
        if ($ResolvedTargetProfile -eq "DisposableVm") {
            $InstallArguments.ConfirmDedicatedVm = $true
            $InstallArguments.ConfirmSnapshot = $true
        }
        & (Join-Path $Root "tools\install.ps1") @InstallArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Transactional package driver lifecycle failed."
        }
    } `
    -RemoveLifecycle {
        param($Root)
        & (Join-Path $Root "tools\uninstall.ps1") `
            -ConfirmKdbgServices -PackageRootMode InstalledProduct
        if ($LASTEXITCODE -ne 0) {
            throw "Failed-candidate driver service removal failed."
        }
    } `
    -RegisterProduct { param($Root) Write-SetupRegistration $Root } `
    -UnregisterProduct { Remove-SetupRegistration }

Write-Host (
    "KDBG $Action completed with transaction $($Result.transaction_id). " +
    "Package, driver pair, uninstall entry, and Start Menu shortcut are verified.")

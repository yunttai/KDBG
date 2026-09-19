[CmdletBinding()]
param(
    [switch]$VerifyPackage,
    [switch]$RequireAdministrator,
    [switch]$RequireTrustedDriverSignatures,
    [switch]$RequireProductionDriverSignatures,
    [string]$ExpectedDriverPublisherSubject,
    [ValidateSet("DistributionSource", "SetupStaging", "InstalledProduct")]
    [string]$PackageRootMode = "DistributionSource",
    [switch]$RequireInstalled,
    [switch]$RequireRunning
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest
$Failed = $false
$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ExpectedPackageName = "KDBG-1.1.0-win-x64"
$ExpectedInstallLeaf = "Product"
$Drivers = @(
    @{ Service = "KDBG"; File = "KDbgDriver.sys"; Inf = "KDbgDriver.inf"; Catalog = "KDbgDriver.cat"; Device = "\\.\KDBG" },
    @{ Service = "KDBGProbe"; File = "KDbgProbe.sys"; Inf = "KDbgProbe.inf"; Catalog = "KDbgProbe.cat"; Device = "\\.\KDBGProbe" }
)

function Add-Failure([string]$Message) {
    Write-Error $Message
    $script:Failed = $true
}

function Test-IsTrustedDriverSignature([object]$Signature) {
    return $null -ne $Signature -and
        $Signature.Status -eq [Management.Automation.SignatureStatus]::Valid -and
        $null -ne $Signature.SignerCertificate
}

function Test-IsProductionDriverSignature(
    [object]$Signature,
    [string]$ExpectedPublisherSubject) {
    return (Test-IsTrustedDriverSignature $Signature) -and
        -not [string]::IsNullOrWhiteSpace($ExpectedPublisherSubject) -and
        $Signature.SignerCertificate.Subject -ceq $ExpectedPublisherSubject -and
        $Signature.SignerCertificate.Subject -cne $Signature.SignerCertificate.Issuer -and
        $null -ne $Signature.TimeStamperCertificate
}

function Get-KdbgRelativePath([string]$BasePath, [string]$TargetPath) {
    $BaseFull = [IO.Path]::GetFullPath($BasePath).TrimEnd([char[]]@('\', '/'))
    $TargetFull = [IO.Path]::GetFullPath($TargetPath)
    $Prefix = $BaseFull + [IO.Path]::DirectorySeparatorChar
    if (-not $TargetFull.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the package root."
    }
    return $TargetFull.Substring($Prefix.Length).Replace('\', '/')
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

function Initialize-DeviceOpenApi {
    if ("KdbgPackageDeviceOpen" -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class KdbgPackageDeviceOpen {
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

Write-Host "KDBG package diagnostics"
Write-Host "Package: $([IO.Path]::GetFileName($PackageRoot)) mode=$PackageRootMode"
$ProgramFiles = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)
$ExpectedInstallParent = if ([string]::IsNullOrWhiteSpace($ProgramFiles)) {
    $null
} else { [IO.Path]::GetFullPath((Join-Path $ProgramFiles "KDBG")) }
$ExpectedInstalledRoot = if ($null -eq $ExpectedInstallParent) {
    $null
} else { [IO.Path]::GetFullPath((Join-Path $ExpectedInstallParent $ExpectedInstallLeaf)) }
switch ($PackageRootMode) {
    "DistributionSource" {
        if ([IO.Path]::GetFileName($PackageRoot) -cne $ExpectedPackageName) {
            Add-Failure "Distribution source directory must remain named $ExpectedPackageName."
        }
    }
    "InstalledProduct" {
        if ($null -eq $ExpectedInstalledRoot -or -not $PackageRoot.Equals(
                $ExpectedInstalledRoot, [StringComparison]::OrdinalIgnoreCase)) {
            Add-Failure "Installed product diagnostics require the exact Program Files KDBG Product root."
        }
    }
    "SetupStaging" {
        $Parent = [IO.Path]::GetDirectoryName($PackageRoot)
        $GrandParent = [IO.Path]::GetDirectoryName($Parent)
        if ($null -eq $ExpectedInstallParent -or
            [IO.Path]::GetFileName($PackageRoot) -cne $ExpectedInstallLeaf -or
            [IO.Path]::GetFileName($Parent) -cnotmatch '^\.staging-[0-9a-f]{32}$' -or
            [string]::IsNullOrWhiteSpace($GrandParent) -or
            -not $GrandParent.Equals(
                $ExpectedInstallParent, [StringComparison]::OrdinalIgnoreCase)) {
            Add-Failure "Setup staging diagnostics require the exact Program Files KDBG .staging-<id>\\Product root."
        }
    }
}
if ($env:OS -ne "Windows_NT") {
    Add-Failure "KDBG package diagnostics require Windows."
}

try {
    $Os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-Host "OS: $($Os.Caption), build $($Os.BuildNumber), $($Os.OSArchitecture)"
    if ($Os.OSArchitecture -notmatch "64") {
        Add-Failure "KDBG requires an x64 Windows guest."
    }
    if ([int]$Os.BuildNumber -lt 19041) {
        Add-Failure "KDBG requires Windows x64 build 19041 or newer."
    }
} catch {
    Add-Failure "OS query failed: $($_.Exception.Message)"
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
$IsAdministrator = $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Administrator: $IsAdministrator"
if ($RequireAdministrator -and -not $IsAdministrator) {
    Add-Failure "Administrator PowerShell is required for this lifecycle operation."
}

Write-Host "Visual C++ Redistributable: not required (static MSVC runtime)"
if ($RequireProductionDriverSignatures -and
    [string]::IsNullOrWhiteSpace($ExpectedDriverPublisherSubject)) {
    Add-Failure (
        "-RequireProductionDriverSignatures requires the exact " +
        "-ExpectedDriverPublisherSubject value.")
}

if ($VerifyPackage) {
    $Manifest = Join-Path $PackageRoot "SHA256SUMS.txt"
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
        Add-Failure "SHA256SUMS.txt is missing."
    } else {
        $Seen = @{}
        foreach ($Line in Get-Content -LiteralPath $Manifest) {
            if ($Line -notmatch '^([0-9a-f]{64})  ([^\\]+)$') {
                Add-Failure "Invalid SHA256SUMS entry."
                continue
            }
            $Expected = $Matches[1]
            $Relative = $Matches[2]
            $Parts = @($Relative -split '/')
            if ([IO.Path]::IsPathRooted($Relative) -or $Relative.Contains(':') -or
                $Parts -contains '' -or $Parts -contains '.' -or $Parts -contains '..' -or
                $Seen.ContainsKey($Relative)) {
                Add-Failure "Unsafe or duplicate SHA256SUMS path: $Relative"
                continue
            }
            $Seen[$Relative] = $true
            $Path = Join-Path $PackageRoot $Relative
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                Add-Failure "Manifest file missing: $Relative"
                continue
            }
            $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
            if ($Actual -ne $Expected) { Add-Failure "Hash mismatch: $Relative" }
        }
        foreach ($File in Get-ChildItem -LiteralPath $PackageRoot -Recurse -File) {
            $Relative = Get-KdbgRelativePath $PackageRoot $File.FullName
            if ($Relative -ne "SHA256SUMS.txt" -and -not $Seen.ContainsKey($Relative)) {
                Add-Failure "Package file is not covered by SHA256SUMS.txt: $Relative"
            }
        }
    }

    $Metadata = Join-Path $PackageRoot "BUILD-METADATA.json"
    if (-not (Test-Path -LiteralPath $Metadata -PathType Leaf)) {
        Add-Failure "BUILD-METADATA.json is missing."
    } else {
        try {
            $BuildMetadata = Get-Content -LiteralPath $Metadata -Raw | ConvertFrom-Json
            if ($BuildMetadata.schema -ne "kdbg.build-metadata.v1" -or
                $BuildMetadata.product -ne "KDBG" -or
                $BuildMetadata.version -ne "1.1.0" -or
                $BuildMetadata.package_name -ne $ExpectedPackageName) {
                Add-Failure "BUILD-METADATA.json does not identify the exact KDBG distribution payload."
            }
            foreach ($Tool in @(
                "msvc_compiler", "msvc_toolset", "windows_sdk", "wdk",
                "powershell", "cmake", "python", "syft")) {
                $Value = $BuildMetadata.tool_versions.$Tool
                if (-not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace($Value)) {
                    Add-Failure "BUILD-METADATA.json tool version is missing: $Tool"
                }
            }
        } catch {
            Add-Failure "BUILD-METADATA.json is unreadable: $($_.Exception.Message)"
        }
    }

    foreach ($Relative in @(
        "tools/capture_demo.ps1", "tools/new_live_evidence.ps1",
        "tools/live-evidence.example.json", "tools/validate_release.py")) {
        if (-not (Test-Path -LiteralPath (Join-Path $PackageRoot $Relative) -PathType Leaf)) {
            Add-Failure "Package-only VM evidence tool is missing: $Relative"
        }
    }
}

foreach ($Driver in $Drivers) {
    $InfPath = Join-Path $PackageRoot "drivers\$($Driver.Inf)"
    $CatalogPath = Join-Path $PackageRoot "drivers\$($Driver.Catalog)"
    if (-not (Test-Path -LiteralPath $InfPath -PathType Leaf)) {
        Add-Failure "Missing driver INF: drivers/$($Driver.Inf)"
    } else {
        $CatalogDeclarations = @(Get-Content -LiteralPath $InfPath |
            Where-Object { $_ -match '^\s*CatalogFile\s*=\s*(\S+)\s*$' } |
            ForEach-Object { ([regex]::Match($_, '^\s*CatalogFile\s*=\s*(\S+)\s*$')).Groups[1].Value })
        if ($CatalogDeclarations.Count -ne 1 -or
            -not $CatalogDeclarations[0].Equals(
                [string]$Driver.Catalog, [StringComparison]::OrdinalIgnoreCase)) {
            Add-Failure "drivers/$($Driver.Inf) does not declare its exact packaged CAT."
        }
    }
    if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf)) {
        Add-Failure "Missing driver catalog: drivers/$($Driver.Catalog)"
    } else {
        $CatalogSignature = Get-AuthenticodeSignature -LiteralPath $CatalogPath
        Write-Host "drivers/$($Driver.Catalog) signature=$($CatalogSignature.Status)"
        if ($RequireTrustedDriverSignatures -and
            -not (Test-IsTrustedDriverSignature $CatalogSignature)) {
            Add-Failure (
                "drivers/$($Driver.Catalog) does not have a trusted Authenticode signature " +
                "on this Windows instance (status=$($CatalogSignature.Status)).")
        }
        if ($RequireProductionDriverSignatures -and
            -not (Test-IsProductionDriverSignature `
                $CatalogSignature $ExpectedDriverPublisherSubject)) {
            Add-Failure (
                "drivers/$($Driver.Catalog) is not production-signing ready: " +
                "require trusted exact publisher, a non-self-signed leaf, and a timestamp.")
        }
    }
}

foreach ($Relative in @(
    "KDBG.exe",
    "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
    "tools/kdbg_live_verify.exe",
    "drivers/KDbgDriver.sys",
    "drivers/KDbgProbe.sys")) {
    $Path = Join-Path $PackageRoot $Relative
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Failure "Missing binary: $Relative"
        continue
    }
    $Version = (Get-Item -LiteralPath $Path).VersionInfo.FileVersion
    $Signature = Get-AuthenticodeSignature -LiteralPath $Path
    Write-Host "$Relative version=$Version signature=$($Signature.Status)"
    if ($RequireTrustedDriverSignatures -and
        $Relative.StartsWith("drivers/", [StringComparison]::OrdinalIgnoreCase) -and
        -not (Test-IsTrustedDriverSignature $Signature)) {
        Add-Failure (
            "$Relative does not have a trusted Authenticode signature on this Windows instance " +
            "(status=$($Signature.Status)).")
    }
    if ($RequireProductionDriverSignatures -and
        $Relative.StartsWith("drivers/", [StringComparison]::OrdinalIgnoreCase) -and
        -not (Test-IsProductionDriverSignature `
            $Signature $ExpectedDriverPublisherSubject)) {
        Add-Failure (
            "$Relative is not production-signing ready: require trusted exact " +
            "publisher, a non-self-signed leaf, and a timestamp.")
    }
}

foreach ($Driver in $Drivers) {
    $Name = $Driver.Service
    $Key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $ExpectedPath = [IO.Path]::GetFullPath(
        (Join-Path $PackageRoot "drivers\$($Driver.File)"))
    if (-not (Test-Path -LiteralPath $Key)) {
        Write-Host "$Name service: not registered"
        if ($RequireInstalled -or $RequireRunning) {
            Add-Failure "$Name service is not installed."
        }
        continue
    }
    try {
        $Properties = Get-ItemProperty -LiteralPath $Key -ErrorAction Stop
        $RegisteredPath = Get-NormalizedServicePath ([string]$Properties.ImagePath)
        $PathMatches = $RegisteredPath.Equals(
            $ExpectedPath, [StringComparison]::OrdinalIgnoreCase)
        $TypeMatches = [int]$Properties.Type -eq 1
        $Service = Get-Service -Name $Name -ErrorAction Stop
        Write-Host "$Name service: registered, state=$($Service.Status), packagePath=$PathMatches"
        if (($RequireInstalled -or $RequireRunning) -and -not $PathMatches) {
            Add-Failure "$Name is registered to a different package. Stop it and perform the documented update."
        }
        if (($RequireInstalled -or $RequireRunning) -and -not $TypeMatches) {
            Add-Failure "$Name is not registered as a kernel driver service."
        }
        if ($RequireRunning -and $Service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Add-Failure "$Name is not running."
        }
    } catch {
        Add-Failure "$Name service inspection failed: $($_.Exception.Message)"
    }
}

if ($RequireRunning -and -not $Failed) {
    try {
        Initialize-DeviceOpenApi
        foreach ($Driver in $Drivers) {
            $Code = [KdbgPackageDeviceOpen]::Probe([string]$Driver.Device)
            if ($Code -notin @(0, 32)) {
                Add-Failure "$($Driver.Service) is running but device $($Driver.Device) is not ready (Win32 $Code)."
            } else {
                Write-Host "$($Driver.Service) device: ready"
            }
        }
    } catch {
        Add-Failure "Driver device readiness check failed: $($_.Exception.Message)"
    }
}

if ($Failed) { exit 1 }
Write-Host "KDBG diagnostics PASS for the requested checks."
exit 0

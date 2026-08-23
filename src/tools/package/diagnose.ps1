[CmdletBinding()]
param([switch]$VerifyPackage)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest
$Failed = $false
$PackageRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

function Get-KdbgRelativePath([string]$BasePath, [string]$TargetPath) {
    $BaseFull = [IO.Path]::GetFullPath($BasePath).TrimEnd([char[]]@('\', '/'))
    $TargetFull = [IO.Path]::GetFullPath($TargetPath)
    $Prefix = $BaseFull + [IO.Path]::DirectorySeparatorChar
    if (-not $TargetFull.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the package root: $TargetFull"
    }
    return $TargetFull.Substring($Prefix.Length).Replace('\', '/')
}

Write-Host "KDBG package diagnostics"
Write-Host "Package: $([IO.Path]::GetFileName($PackageRoot))"
try {
    $Os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-Host "OS: $($Os.Caption), build $($Os.BuildNumber), $($Os.OSArchitecture)"
} catch {
    Write-Error "OS query failed: $($_.Exception.Message)"
    $Failed = $true
}
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
Write-Host "Administrator: $($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
foreach ($Runtime in @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")) {
    $RuntimePath = Join-Path $env:WINDIR "System32\$Runtime"
    if (Test-Path -LiteralPath $RuntimePath -PathType Leaf) {
        Write-Host "$Runtime runtime: present"
    } else {
        Write-Error "$Runtime runtime: missing; install the supported Microsoft VC++ Redistributable."
        $Failed = $true
    }
}

$Manifest = Join-Path $PackageRoot "SHA256SUMS.txt"
if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    Write-Error "SHA256SUMS.txt is missing."
    $Failed = $true
} else {
    $Seen = @{}
    foreach ($Line in Get-Content -LiteralPath $Manifest) {
        if ($Line -notmatch '^([0-9a-f]{64})  ([^\\]+)$') {
            Write-Error "Invalid SHA256SUMS entry."
            $Failed = $true
            continue
        }
        $Expected = $Matches[1]
        $Relative = $Matches[2]
        if ($Relative -split '/' -contains '..' -or $Seen.ContainsKey($Relative)) {
            Write-Error "Unsafe or duplicate SHA256SUMS path: $Relative"
            $Failed = $true
            continue
        }
        $Seen[$Relative] = $true
        $Path = Join-Path $PackageRoot $Relative
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Write-Error "Manifest file missing: $Relative"
            $Failed = $true
            continue
        }
        $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
        if ($Actual -ne $Expected) {
            Write-Error "Hash mismatch: $Relative"
            $Failed = $true
        }
    }
    foreach ($File in Get-ChildItem -LiteralPath $PackageRoot -Recurse -File) {
        $Relative = Get-KdbgRelativePath $PackageRoot $File.FullName
        if ($Relative -ne "SHA256SUMS.txt" -and -not $Seen.ContainsKey($Relative)) {
            Write-Error "Package file is not covered by SHA256SUMS.txt: $Relative"
            $Failed = $true
        }
    }
}

foreach ($Relative in @(
    "KDBG.exe",
    "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
    "drivers/KDbgDriver.sys",
    "drivers/KDbgProbe.sys")) {
    $Path = Join-Path $PackageRoot $Relative
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Error "Missing binary: $Relative"
        $Failed = $true
        continue
    }
    $Version = (Get-Item -LiteralPath $Path).VersionInfo.FileVersion
    $Signature = Get-AuthenticodeSignature -LiteralPath $Path
    Write-Host "$Relative version=$Version signature=$($Signature.Status)"
}

foreach ($Service in @("KDBG", "KDBGProbe")) {
    $Output = & sc.exe query $Service 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "$Service service: registered"
    } else {
        Write-Host "$Service service: not registered"
    }
}
if ($VerifyPackage) {
    $Metadata = Join-Path $PackageRoot "BUILD-METADATA.json"
    if (-not (Test-Path -LiteralPath $Metadata -PathType Leaf)) {
        Write-Error "BUILD-METADATA.json is missing."
        $Failed = $true
    }
}
if ($Failed) { exit 1 }
exit 0

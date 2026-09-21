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
    [int]$HostProcessId = 0
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "KDBG Test Setup must run as Administrator."
    }
}

Assert-Administrator

$ResolvedTargetProfile = if ([string]::IsNullOrWhiteSpace($TargetProfile)) {
    "LocalHost"
} else { $TargetProfile }
if ($ResolvedTargetProfile -ne "LocalHost") {
    throw "KDBG Test Setup is only for the LocalHost test-signing lane. Use the normal Setup for DisposableVm."
}
if ($ConfirmDedicatedVm -or $ConfirmSnapshot) {
    throw "KDBG Test Setup does not accept DisposableVm confirmations."
}

$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$CertificatePath = Join-Path $Root "certificate\KDBG-TestSigning.cer"
$CertificateMetadataPath = Join-Path $Root "certificate\KDBG-TestSigning.json"
$TestSetupPath = Join-Path $Root "KDBGSetup-Test.exe"
$NormalSetupPath = Join-Path $Root "tools\setup.ps1"
$StateDirectory = Join-Path $env:ProgramData "KDBG\TestSetup"
$StatePath = Join-Path $StateDirectory "state.json"
$RunOncePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$RunOnceName = "KDBGTestSetupResume"

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-TestCertificate {
    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "The public test certificate is missing: $CertificatePath"
    }
    if (Test-Path -LiteralPath $CertificatePath -PathType Container) {
        throw "The test certificate path is not a file: $CertificatePath"
    }
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $CertificatePath)
    try {
        if ($certificate.HasPrivateKey) {
            throw "The test package must contain a public .cer certificate, not a private-key container."
        }
        if ($certificate.Subject -cne $certificate.Issuer) {
            throw "The test certificate must be self-signed."
        }
        $now = [DateTime]::Now
        if ($now -lt $certificate.NotBefore -or $now -gt $certificate.NotAfter) {
            throw "The test certificate is not currently valid."
        }
        $hasCodeSigningEku = $false
        foreach ($extension in $certificate.Extensions) {
            if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                foreach ($oid in $extension.EnhancedKeyUsages) {
                    if ($oid.Value -eq "1.3.6.1.5.5.7.3.3") {
                        $hasCodeSigningEku = $true
                    }
                }
            }
        }
        if (-not $hasCodeSigningEku) {
            throw "The test certificate lacks the Code Signing EKU."
        }
        $record = [pscustomobject]@{
            Certificate = $certificate
            Sha256 = Get-Sha256 $CertificatePath
            Thumbprint = $certificate.Thumbprint.ToLowerInvariant()
            Subject = $certificate.Subject
            Issuer = $certificate.Issuer
        }
        if (Test-Path -LiteralPath $CertificateMetadataPath -PathType Leaf) {
            $metadata = Get-Content -LiteralPath $CertificateMetadataPath -Raw |
                ConvertFrom-Json
            if ($metadata.schema -ne "kdbg.test-signing-certificate.v1" -or
                $metadata.production_trust -ne $false -or
                [string]$metadata.sha256 -cne $record.Sha256 -or
                [string]$metadata.thumbprint -cne $record.Thumbprint) {
                throw "The test certificate metadata does not match the bundled public certificate."
            }
        }
        return $record
    }
    catch {
        $certificate.Dispose()
        throw
    }
}

function Get-StoreCertificate([string]$StoreName, [string]$Thumbprint) {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        $StoreName,
        [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        foreach ($item in $store.Certificates) {
            if ($item.Thumbprint -and
                $item.Thumbprint.Replace(' ', '').ToLowerInvariant() -ceq $Thumbprint) {
                return $true
            }
        }
        return $false
    }
    finally {
        $store.Close()
    }
}

function Add-TestCertificate([object]$Identity) {
    $addedStores = [Collections.Generic.List[string]]::new()
    foreach ($storeName in @("Root", "TrustedPublisher")) {
        if (Get-StoreCertificate $storeName $Identity.Thumbprint) {
            Write-Host "Test certificate already present in $storeName."
            continue
        }
        $store = [Security.Cryptography.X509Certificates.X509Store]::new(
            $storeName,
            [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $store.Add($Identity.Certificate)
            $addedStores.Add($storeName)
        }
        finally {
            $store.Close()
        }
        if (-not (Get-StoreCertificate $storeName $Identity.Thumbprint)) {
            throw "The test certificate could not be verified in $storeName."
        }
        Write-Host "Installed test certificate in $storeName."
    }
    return @($addedStores)
}

function Get-TestSigningEnabled {
    $output = & (Join-Path $env:SystemRoot "System32\bcdedit.exe") `
        /enum "{current}" 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query the current Windows boot configuration."
    }
    return $output -match '(?im)^\s*testsigning\s+Yes\s*$'
}

function Assert-SecureBootOff {
    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) {
            throw "Secure Boot is enabled. Disable Secure Boot in firmware before using KDBG Test Setup."
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        # Legacy BIOS or a PowerShell build without Confirm-SecureBootUEFI.
    }
    catch {
        if ($_.Exception.Message -like "Secure Boot is enabled.*") {
            throw
        }
        # The cmdlet reports an unsupported firmware mode on some hosts. The
        # authoritative test-signing state is still checked with bcdedit.
    }
}

function Enable-TestSigning {
    Assert-SecureBootOff
    & (Join-Path $env:SystemRoot "System32\bcdedit.exe") /set testsigning on 2>&1 |
        ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Windows rejected test-signing mode. Check Secure Boot and boot-policy permissions."
    }
}

function Write-State([object]$State) {
    New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    [IO.File]::WriteAllText(
        $StatePath,
        (($State | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
}

function Read-State {
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        return $null
    }
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($state.schema -ne "kdbg.test-setup.state.v1" -or
        [IO.Path]::GetFullPath([string]$state.package_root).TrimEnd('\') -cne
            $Root.TrimEnd('\')) {
        throw "The stored test-setup state belongs to another package root."
    }
    return $state
}

function Set-ResumeCommand {
    if (-not (Test-Path -LiteralPath $TestSetupPath -PathType Leaf)) {
        throw "The test setup executable is missing: $TestSetupPath"
    }
    New-Item -Path $RunOncePath -Force | Out-Null
    $command = '"' + $TestSetupPath + '" /test-resume'
    New-ItemProperty -LiteralPath $RunOncePath -Name $RunOnceName `
        -Value $command -PropertyType String -Force | Out-Null
}

function Clear-ResumeCommand {
    Remove-ItemProperty -LiteralPath $RunOncePath -Name $RunOnceName `
        -Force -ErrorAction SilentlyContinue
}

function Invoke-NormalSetup([string]$SetupAction) {
    if (-not (Test-Path -LiteralPath $NormalSetupPath -PathType Leaf)) {
        throw "The normal setup script is missing: $NormalSetupPath"
    }
    $arguments = @{
        Action = $SetupAction
        TargetProfile = "LocalHost"
        HostProcessId = $HostProcessId
    }
    & $NormalSetupPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "The normal KDBG Setup transaction failed with exit code $LASTEXITCODE."
    }
}

function Remove-AddedCertificates([object]$State) {
    foreach ($storeName in @($State.added_stores)) {
        $store = [Security.Cryptography.X509Certificates.X509Store]::new(
            [string]$storeName,
            [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            foreach ($item in @($store.Certificates)) {
                if ($item.Thumbprint -and
                    $item.Thumbprint.Replace(' ', '').ToLowerInvariant() -ceq
                    [string]$State.certificate_thumbprint) {
                    $store.Remove($item)
                }
            }
        }
        finally {
            $store.Close()
        }
        Write-Host "Removed the test certificate from $storeName."
    }
}

Write-Host "KDBG Test Setup $Action"
Write-Host "This is a development-only test-signing flow; it is not production trust."

$existingState = Read-State
if ($Action -eq "Uninstall") {
    Invoke-NormalSetup $Action
    if ($null -ne $existingState) {
        if (-not [bool]$existingState.previous_testsigning -and
            (Get-TestSigningEnabled)) {
            & (Join-Path $env:SystemRoot "System32\bcdedit.exe") /set testsigning off 2>&1 |
                ForEach-Object { Write-Host $_ }
            if ($LASTEXITCODE -ne 0) {
                throw "The test-signing boot option could not be restored."
            }
            Write-Host "Test-signing mode was restored to its previous disabled state. Reboot is required."
        }
        Remove-AddedCertificates $existingState
        Clear-ResumeCommand
        Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

$identity = Read-TestCertificate
$previousTestSigning = Get-TestSigningEnabled
Assert-SecureBootOff
$addedStores = @()
if ($null -eq $existingState) {
    $addedStores = Add-TestCertificate $identity
    $state = [ordered]@{
        schema = "kdbg.test-setup.state.v1"
        package_root = $Root
        action = $Action
        target_profile = $ResolvedTargetProfile
        previous_testsigning = $previousTestSigning
        added_stores = @($addedStores)
        certificate_sha256 = $identity.Sha256
        certificate_thumbprint = $identity.Thumbprint
        created_utc = [DateTime]::UtcNow.ToString("o")
    }
    Write-State $state
} else {
    $state = $existingState
    $Action = [string]$state.action
    if ([string]$state.certificate_thumbprint -cne $identity.Thumbprint) {
        throw "The resumed test setup certificate does not match the original transaction."
    }
}

if (-not (Get-TestSigningEnabled)) {
    Enable-TestSigning
    Set-ResumeCommand
    Write-Host "Windows test-signing was enabled. The computer will restart and KDBG Test Setup will resume automatically."
    & (Join-Path $env:SystemRoot "System32\shutdown.exe") /r /t 15 /d p:2:4 `
        /c "KDBG Test Setup requires a reboot to load the test-signed drivers." |
        ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "The restart could not be scheduled. Reboot manually, then run KDBGSetup-Test.exe again."
    }
    exit 0
}

Clear-ResumeCommand
Invoke-NormalSetup $Action

if ($state -is [Collections.IDictionary]) {
    $state["phase"] = "installed"
    $state["last_action"] = $Action
    $state["updated_utc"] = [DateTime]::UtcNow.ToString("o")
} else {
    $state | Add-Member -MemberType NoteProperty -Name phase `
        -Value "installed" -Force
    $state | Add-Member -MemberType NoteProperty -Name last_action `
        -Value $Action -Force
    $state | Add-Member -MemberType NoteProperty -Name updated_utc `
        -Value ([DateTime]::UtcNow.ToString("o")) -Force
}
Write-State $state
Write-Host "KDBG Test Setup completed. Test-signing mode remains enabled for this development host."

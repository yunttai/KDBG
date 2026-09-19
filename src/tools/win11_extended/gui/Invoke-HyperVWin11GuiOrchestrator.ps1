[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VMName,
    [Parameter(Mandatory = $true)][Guid]$VMId,
    [Parameter(Mandatory = $true)][string]$CheckpointName,
    [Parameter(Mandatory = $true)][Guid]$CheckpointId,
    [Parameter(Mandatory = $true)][string]$PackageZipPath,
    [Parameter(Mandatory = $true)][string]$SymbolsZipPath,
    [Parameter(Mandatory = $true)][string]$CertificatePath,
    [Parameter(Mandatory = $true)][string]$ExpectedPackageSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSymbolsSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedCertificateSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSourceSnapshotSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory = $true)][string]$CredentialPath,
    [Parameter(Mandatory = $true)][string]$HostEvidenceRoot,
    [ValidateSet('calibration-smoke','full')][string]$CaptureMode = 'calibration-smoke',
    [string]$InteractiveUser = 'kdbgtest',
    [ValidateRange(60,900)][int]$ConnectionTimeoutSeconds = 300,
    [switch]$ConfirmDisposableVm,
    [switch]$ConfirmCheckpointRestore,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Write-Json([string]$Path, [object]$Value) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($Path),
        ($Value | ConvertTo-Json -Depth 30) + [Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
function Assert-Hash([string]$Value, [int]$Length, [string]$Name) {
    if ($Value -cnotmatch "^[0-9a-f]{$Length}$") { throw "$Name must be lowercase $Length-hex." }
}
function Test-Zip([string]$Path, [string[]]$RequiredEntries) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entries = @($archive.Entries | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })
        $names = @($entries | ForEach-Object FullName)
        if ($names.Count -eq 0 -or @($names | Where-Object {
                    $_ -match '\\' -or $_ -match '^/' -or $_ -match '^[A-Za-z]:' -or $_ -match '(^|/)\.\.(/|$)'
                }).Count -ne 0 -or @($names | ForEach-Object ToLowerInvariant | Group-Object | Where-Object Count -gt 1).Count -ne 0) {
            throw "Archive has an unsafe or duplicate entry set: $Path"
        }
        foreach ($required in $RequiredEntries) {
            if (@($names | Where-Object { $_ -ceq $required }).Count -ne 1) {
                throw "Archive is missing an exact entry: $required"
            }
        }
        $names.Count
    } finally { $archive.Dispose() }
}
function Read-ZipJson([string]$Path, [string]$EntryName) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $matches = @($archive.Entries | Where-Object FullName -ceq $EntryName)
        if ($matches.Count -ne 1) { throw "Archive JSON entry is not unique: $EntryName" }
        $reader = [IO.StreamReader]::new($matches[0].Open(),[Text.Encoding]::UTF8,$true)
        try { $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
    } finally { $archive.Dispose() }
}
function Wait-PowerShellDirect([string]$Name, [PSCredential]$Credential, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastMessage = $null
    do {
        try { return New-PSSession -VMName $Name -Credential $Credential -ErrorAction Stop }
        catch { $lastMessage = $_.Exception.Message; Start-Sleep -Seconds 3 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "PowerShell Direct did not become available: $lastMessage"
}
function Wait-PowerShellDirectAfterBoot([string]$Name, [PSCredential]$Credential,
        [DateTime]$PreviousBootUtc, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastMessage = $null
    do {
        $candidate = $null
        try {
            $candidate = New-PSSession -VMName $Name -Credential $Credential -ErrorAction Stop
            $boot = Invoke-Command -Session $candidate -ScriptBlock {
                (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
            } -ErrorAction Stop
            if ([DateTime]$boot -gt $PreviousBootUtc) { return $candidate }
        } catch { $lastMessage = $_.Exception.Message }
        if ($null -ne $candidate) { try { Remove-PSSession $candidate -ErrorAction SilentlyContinue } catch {} }
        Start-Sleep -Seconds 3
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "PowerShell Direct did not observe the requested reboot: $lastMessage"
}
function Protect-Text([string]$Value, [string[]]$PrivateValues) {
    $result = $Value
    foreach ($privateValue in $PrivateValues) {
        if (-not [string]::IsNullOrWhiteSpace($privateValue)) {
            $result = $result -replace [regex]::Escape($privateValue),'<REDACTED>'
        }
    }
    $result
}

Assert-Hash $ExpectedPackageSha256 64 'ExpectedPackageSha256'
Assert-Hash $ExpectedSymbolsSha256 64 'ExpectedSymbolsSha256'
Assert-Hash $ExpectedCertificateSha256 64 'ExpectedCertificateSha256'
Assert-Hash $ExpectedSourceSnapshotSha256 64 'ExpectedSourceSnapshotSha256'
Assert-Hash $ExpectedSignerThumbprint 40 'ExpectedSignerThumbprint'
if ($VMId -eq [Guid]::Empty -or $CheckpointId -eq [Guid]::Empty) { throw 'Exact VM and checkpoint GUIDs are required.' }
if ([string]::IsNullOrWhiteSpace($VMName) -or [string]::IsNullOrWhiteSpace($CheckpointName)) {
    throw 'Exact VM and checkpoint names are required.'
}
$hostEvidenceFull = [IO.Path]::GetFullPath($HostEvidenceRoot)
if ($DryRun) {
    New-Item -ItemType Directory -Path $hostEvidenceFull -Force | Out-Null
    $dryResult = [ordered]@{
        schema='kdbg.win11-extended-gui-host-orchestrator.v1'
        success=$true
        execution_status='NOT_RUN'
        vm_executed=$false
        capture_mode=$CaptureMode
        exact_identity_fields_valid=$true
        credential_loaded=$false
        credential_serialized=$false
        plaintext_password_logged=$false
        required_sequence=@('exact-preflight','restore-start','powershell-direct','guest-stage-prepare',
            'temporary-autologon','postboot-driver-readiness','interactive-bootstrap','gui-capture','evidence-recovery',
            'guest-cleanup','exact-restore-final-off')
    }
    Write-Json (Join-Path $hostEvidenceFull 'orchestrator-dry-run.json') $dryResult
    $dryResult | ConvertTo-Json -Depth 20
    return
}

if (-not $ConfirmDisposableVm -or -not $ConfirmCheckpointRestore) {
    throw 'Live orchestration requires both disposable-VM and checkpoint-restore confirmations.'
}
foreach ($path in @($PackageZipPath,$SymbolsZipPath,$CertificatePath,$CredentialPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required host input is missing: $path" }
}
$packageFull = [IO.Path]::GetFullPath($PackageZipPath)
$symbolsFull = [IO.Path]::GetFullPath($SymbolsZipPath)
$certificateFull = [IO.Path]::GetFullPath($CertificatePath)
$credentialFull = [IO.Path]::GetFullPath($CredentialPath)
$actualHashes = [ordered]@{
    package=Get-Sha $packageFull; symbols=Get-Sha $symbolsFull; certificate=Get-Sha $certificateFull
}
if ($actualHashes.package -cne $ExpectedPackageSha256 -or $actualHashes.symbols -cne $ExpectedSymbolsSha256 -or
    $actualHashes.certificate -cne $ExpectedCertificateSha256) { throw 'Host artifact hash preflight failed.' }
$mainEntries = Test-Zip $packageFull @('KDBG-1.1.0-win-x64/BUILD-METADATA.json',
    'KDBG-1.1.0-win-x64/KDBG.exe','KDBG-1.1.0-win-x64/tools/kdbg_live_verify.exe',
    'KDBG-1.1.0-win-x64/tools/kdbg_process_fixture.exe','KDBG-1.1.0-win-x64/drivers/KDbgDriver.sys',
    'KDBG-1.1.0-win-x64/drivers/KDbgProbe.sys')
$symbolEntries = Test-Zip $symbolsFull @('KDBG-1.1.0-win-x64-symbols/BUILD-METADATA.json',
    'KDBG-1.1.0-win-x64-symbols/drivers/KDbgDriver.pdb')
$mainMetadata = Read-ZipJson $packageFull 'KDBG-1.1.0-win-x64/BUILD-METADATA.json'
$symbolsMetadata = Read-ZipJson $symbolsFull 'KDBG-1.1.0-win-x64-symbols/BUILD-METADATA.json'
if ([string]$mainMetadata.source_snapshot_sha256 -cne $ExpectedSourceSnapshotSha256 -or
    [string]$symbolsMetadata.source_snapshot_sha256 -cne $ExpectedSourceSnapshotSha256) {
    throw 'Host package/symbol source snapshot preflight failed.'
}
$hostCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateFull)
if ($hostCertificate.Thumbprint.ToLowerInvariant() -cne $ExpectedSignerThumbprint) {
    throw 'Host certificate thumbprint preflight failed.'
}
$credential = Import-Clixml -LiteralPath $credentialFull
if ($credential -isnot [PSCredential]) { throw 'DPAPI credential did not deserialize as PSCredential.' }
$credentialLeaf = ($credential.UserName -split '[\\]')[-1]
if ($credentialLeaf -ine $InteractiveUser) { throw 'Credential username does not match InteractiveUser.' }

foreach ($commandName in @('Get-VM','Get-VMSnapshot','Restore-VMSnapshot','Start-VM','Stop-VM',
        'New-PSSession','Invoke-Command','Copy-Item','Remove-PSSession')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) { throw "Required host command is missing: $commandName" }
}
$vmMatches = @(Get-VM -Name $VMName -ErrorAction Stop)
if ($vmMatches.Count -ne 1 -or $vmMatches[0].Id -ne $VMId) { throw 'Exact VM Name/GUID pair did not resolve once.' }
$vm = $vmMatches[0]
if ($vm.State.ToString() -ne 'Off') { throw 'Exact VM must initially be Off.' }
$checkpointMatches = @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object {
        $_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId
    })
if ($checkpointMatches.Count -ne 1) { throw 'Exact checkpoint Name/GUID pair did not resolve once.' }
$checkpoint = $checkpointMatches[0]

$runId = 'run-{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),([Guid]::NewGuid().ToString('N').Substring(0,8))
$hostRunRoot = Join-Path $hostEvidenceFull $runId
if (Test-Path -LiteralPath $hostRunRoot) { throw 'Refusing to overwrite an existing host run directory.' }
New-Item -ItemType Directory -Path $hostRunRoot -Force | Out-Null
$summaryPath = Join-Path $hostRunRoot 'host-orchestrator-summary.json'
$checkpointIdText = $CheckpointId.ToString('D')
$guestRunRoot = "C:\KDBG-Win11-Extended\$runId"
$guestPackage = Join-Path $guestRunRoot 'KDBG-1.1.0-win-x64.zip'
$guestSymbols = Join-Path $guestRunRoot 'KDBG-1.1.0-win-x64-symbols.zip'
$guestCertificate = Join-Path $guestRunRoot 'test-signing.cer'
$guestArchive = Join-Path $guestRunRoot 'guest-evidence.zip'
$hostArchive = Join-Path $hostRunRoot 'guest-evidence.zip'
$hostExpanded = Join-Path $hostRunRoot 'guest-evidence'
$taskBootstrap = 'KDBG-Win11-Extended-Bootstrap'
$taskGui = 'KDBG-Win11-Extended-GUI'
$taskAutoLogon = 'KDBG-Win11-Extended-AutoLogonCleanup'
$privateValues = @($credential.UserName,$credentialFull,[Environment]::UserName,[Environment]::MachineName)

$hostIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$hostPrincipal = [Security.Principal.WindowsPrincipal]::new($hostIdentity)
$isElevated = $hostPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$hyperVSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-578')
$isHyperVAdministrator = @($hostIdentity.Groups | Where-Object { $_ -eq $hyperVSid }).Count -ne 0
$preflight = [ordered]@{
    schema='kdbg.win11-extended-gui-host-preflight.v1'
    captured_utc=[DateTime]::UtcNow.ToString('o')
    vm=[ordered]@{ name=$VMName; id=$VMId.ToString('D'); initial_state='Off'; generation=[int]$vm.Generation }
    checkpoint=[ordered]@{ name=$CheckpointName; id=$checkpointIdText; creation_time_utc=$checkpoint.CreationTime.ToUniversalTime().ToString('o') }
    artifacts=[ordered]@{
        package=[ordered]@{ sha256=$actualHashes.package; zip_entries=$mainEntries }
        symbols=[ordered]@{ sha256=$actualHashes.symbols; zip_entries=$symbolEntries }
        certificate=[ordered]@{ sha256=$actualHashes.certificate; signer_thumbprint=$ExpectedSignerThumbprint }
        source_snapshot_sha256=$ExpectedSourceSnapshotSha256
    }
    host_authorization=[ordered]@{ elevated=$isElevated; hyper_v_administrators=$isHyperVAdministrator; cmdlets_succeeded=$true }
    credential=[ordered]@{ dpapi_loaded=$true; serialized=$false; plaintext_logged=$false }
    confirmations=[ordered]@{ disposable_vm=$true; checkpoint_restore=$true }
}
Write-Json (Join-Path $hostRunRoot 'host-preflight.json') $preflight

$session = $null
$mutationBegan = $false
$captureSucceeded = $false
$guestCleanupSucceeded = $false
$evidenceRecovered = $false
$restored = $false
$finalOff = $false
$autoLogonClearedAfterExplorer = $false
$postbootReadinessSucceeded = $false
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$phases = [Collections.Generic.List[object]]::new()

try {
    $mutationBegan = $true
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Restore-VMSnapshot -VMSnapshot $checkpoint -Confirm:$false -ErrorAction Stop
    $restoredVm = Get-VM -Name $VMName -ErrorAction Stop
    if ($restoredVm.State.ToString() -ne 'Off' -or $restoredVm.Id -ne $VMId) { throw 'Checkpoint restore did not return the exact VM Off.' }
    Start-VM -VM $restoredVm -ErrorAction Stop | Out-Null
    $timer.Stop(); $phases.Add([ordered]@{ phase='restore-start'; elapsed_ms=$timer.ElapsedMilliseconds })

    $timer = [Diagnostics.Stopwatch]::StartNew()
    $session = Wait-PowerShellDirect $VMName $credential $ConnectionTimeoutSeconds
    $timer.Stop(); $phases.Add([ordered]@{ phase='powershell-direct-connect'; elapsed_ms=$timer.ElapsedMilliseconds })
    $bootBefore = Invoke-Command -Session $session -ScriptBlock {
        (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
    }
    Invoke-Command -Session $session -ScriptBlock {
        param($Root)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'PowerShell Direct guest identity is not Administrator.'
        }
        if (Test-Path -LiteralPath $Root) { throw 'Guest run root already exists.' }
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    } -ArgumentList $guestRunRoot
    Copy-Item -LiteralPath $packageFull -Destination $guestPackage -ToSession $session
    Copy-Item -LiteralPath $symbolsFull -Destination $guestSymbols -ToSession $session
    Copy-Item -LiteralPath $certificateFull -Destination $guestCertificate -ToSession $session
    foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -File)) {
        Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $guestRunRoot $file.Name) -ToSession $session -Force
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Command -Session $session -ScriptBlock {
        param($Script,$Root,$Package,$Symbols,$Certificate,$PackageHash,$SymbolsHash,$CertificateHash,$SourceHash,$Signer,$Checkpoint)
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        & $Script -RunRoot $Root -PackageZipPath $Package -SymbolsZipPath $Symbols `
            -CertificatePath $Certificate -ExpectedPackageSha256 $PackageHash `
            -ExpectedSymbolsSha256 $SymbolsHash -ExpectedCertificateSha256 $CertificateHash `
            -ExpectedSourceSnapshotSha256 $SourceHash -ExpectedSignerThumbprint $Signer `
            -CheckpointId $Checkpoint | Out-Null
    } -ArgumentList (Join-Path $guestRunRoot 'Prepare-Win11GuiGuest.ps1'),$guestRunRoot,$guestPackage,
        $guestSymbols,$guestCertificate,$ExpectedPackageSha256,$ExpectedSymbolsSha256,
        $ExpectedCertificateSha256,$ExpectedSourceSnapshotSha256,$ExpectedSignerThumbprint,$checkpointIdText
    $timer.Stop(); $phases.Add([ordered]@{ phase='guest-stage-verify-install-readonly'; elapsed_ms=$timer.ElapsedMilliseconds })

    $timer = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Command -Session $session -ScriptBlock {
        param($Root,$Evidence,$User,$CredentialValue,$CleanupTask,$TimeoutSeconds)
        $userRecord = Get-LocalUser -Name $User -ErrorAction Stop
        if (-not $userRecord.Enabled) { throw 'Interactive user is disabled.' }
        New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
        & icacls.exe $Root /grant ("$User`:(OI)(CI)RX") /T /C | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not grant harness read access.' }
        & icacls.exe $Evidence /grant ("$User`:(OI)(CI)M") /T /C | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not grant evidence modify access.' }
        $leaf = ($CredentialValue.UserName -split '[\\]')[-1]
        if ($leaf -ine $User) { throw 'Transient credential user mismatch.' }
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CredentialValue.Password)
        try {
            New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '1' -PropertyType String -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultUserName -Value $User -PropertyType String -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultDomainName -Value $env:COMPUTERNAME -PropertyType String -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name AutoLogonCount -Value '1' -PropertyType String -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultPassword `
                -Value ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)) -PropertyType String -Force | Out-Null
        } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        $cleanupScript = Join-Path $Root 'Clear-Win11AutoLogonAfterExplorer.ps1'
        $cleanupResult = Join-Path $Evidence 'autologon-cleanup.json'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
            '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -InteractiveUser "{1}" -ResultPath "{2}" -TimeoutSeconds {3}' -f
            $cleanupScript,$User,$cleanupResult,$TimeoutSeconds) -WorkingDirectory $Root
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSeconds + 60)) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $CleanupTask -Action $action -Trigger $trigger -Principal $principal `
            -Settings $settings -Force | Out-Null
    } -ArgumentList $guestRunRoot,(Join-Path $guestRunRoot 'evidence'),$InteractiveUser,$credential,
        $taskAutoLogon,$ConnectionTimeoutSeconds
    try { Invoke-Command -Session $session -ScriptBlock { Restart-Computer -Force } -ErrorAction Stop }
    catch { }
    try { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } catch {}
    $session = $null
    $session = Wait-PowerShellDirectAfterBoot $VMName $credential ([DateTime]$bootBefore) $ConnectionTimeoutSeconds
    $interactive = Invoke-Command -Session $session -ScriptBlock {
        param($User,$TimeoutSeconds)
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        try {
            do {
                foreach ($candidate in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)) {
                    try {
                        $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwner -ErrorAction Stop
                        if ([uint32]$owner.ReturnValue -eq 0 -and [uint32]$candidate.SessionId -gt 0 -and
                            [string]$owner.User -ieq $User) {
                            return [pscustomobject]@{ user=[string]$owner.User; domain=[string]$owner.Domain;
                                session_id=[uint32]$candidate.SessionId; explorer_pid=[uint32]$candidate.ProcessId }
                        }
                    } catch {}
                }
                Start-Sleep -Milliseconds 250
            } while ([DateTime]::UtcNow -lt $deadline)
            throw 'Interactive Explorer did not appear before timeout.'
        } finally {
            Remove-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue
            Remove-ItemProperty -LiteralPath $key -Name AutoLogonCount -ErrorAction SilentlyContinue
            New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '0' -PropertyType String -Force | Out-Null
        }
    } -ArgumentList $InteractiveUser,$ConnectionTimeoutSeconds
    $secretPresentAfterExplorer = Invoke-Command -Session $session -ScriptBlock {
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $null -ne (Get-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue)
    }
    $autoLogonRecord = Invoke-Command -Session $session -ScriptBlock {
        param($Path)
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
            }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)
        throw 'SYSTEM AutoAdminLogon cleanup result did not appear.'
    } -ArgumentList (Join-Path $guestRunRoot 'evidence\autologon-cleanup.json')
    $autoLogonClearedAfterExplorer = $null -ne $interactive -and $secretPresentAfterExplorer -eq $false -and
        $autoLogonRecord.success -eq $true -and $autoLogonRecord.default_password_present -eq $false
    if (-not $autoLogonClearedAfterExplorer) { throw 'Winlogon secret was not cleared immediately after Explorer appeared.' }
    $timer.Stop(); $phases.Add([ordered]@{ phase='temporary-autologon-explorer-clear'; elapsed_ms=$timer.ElapsedMilliseconds })

    $timer = [Diagnostics.Stopwatch]::StartNew()
    $postbootReadiness = Invoke-Command -Session $session -ScriptBlock {
        param($Root,$TimeoutSeconds)
        $evidenceRoot = Join-Path $Root 'evidence'
        $preparedPath = Join-Path $Root 'guest-prepared.json'
        if (-not (Test-Path -LiteralPath $preparedPath -PathType Leaf)) {
            throw 'Guest prepared record is missing before postboot readiness.'
        }
        $prepared = Get-Content -LiteralPath $preparedPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($prepared.success -ne $true) { throw 'Guest prepared record is not successful.' }
        $packageRoot = [IO.Path]::GetFullPath([string]$prepared.package_root).TrimEnd('\')
        if (-not $packageRoot.StartsWith(
                ([IO.Path]::GetFullPath((Join-Path $Root 'expanded')).TrimEnd('\') + '\'),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Prepared package root escaped the staged expansion root.'
        }

        $serviceRecords = [Collections.Generic.List[object]]::new()
        foreach ($name in @('KDBGProbe','KDBG')) {
            $service = Get-Service -Name $name -ErrorAction Stop
            if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                Stop-Service -Name $name -ErrorAction Stop
                $service.WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                    [TimeSpan]::FromSeconds([Math]::Min(30,$TimeoutSeconds)))
            }
        }
        foreach ($name in @('KDBG','KDBGProbe')) {
            $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
            $serviceConfig = Get-ItemProperty -LiteralPath $serviceKey -ErrorAction Stop
            if ([uint32]$serviceConfig.Start -ne 3 -or [uint32]$serviceConfig.Type -ne 1) {
                throw "Postboot service is not a demand-start kernel driver: $name"
            }
            $service = Get-Service -Name $name -ErrorAction Stop
            Start-Service -Name $name -ErrorAction Stop
            $service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds([Math]::Min(30,$TimeoutSeconds)))
            $service.Refresh()
            if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                throw "Postboot service did not reach Running: $name"
            }
            $serviceRecords.Add([ordered]@{
                    name=$name
                    start_value=[uint32]$serviceConfig.Start
                    type_value=[uint32]$serviceConfig.Type
                    status=$service.Status.ToString()
                })
        }

        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $diagnoseStdout = Join-Path $evidenceRoot 'postboot-diagnose.stdout.log'
        $diagnoseStderr = Join-Path $evidenceRoot 'postboot-diagnose.stderr.log'
        $diagnose = Start-Process -FilePath $powershell -ArgumentList @(
            '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',(Join-Path $packageRoot 'tools\diagnose.ps1'),
            '-VerifyPackage','-RequireAdministrator','-RequireTrustedDriverSignatures',
            '-RequireRunning','-PackageRootMode','DistributionSource') -Wait -PassThru `
            -WindowStyle Hidden -RedirectStandardOutput $diagnoseStdout -RedirectStandardError $diagnoseStderr
        if (-not $diagnose.HasExited -or $diagnose.ExitCode -ne 0) {
            throw 'Postboot exact-package diagnostic readiness failed.'
        }

        $verifier = Join-Path $packageRoot 'tools\kdbg_live_verify.exe'
        $reportPath = Join-Path $evidenceRoot 'postboot-readonly-probe.json'
        $verifyStdout = Join-Path $evidenceRoot 'postboot-readonly-probe.stdout.log'
        $verifyStderr = Join-Path $evidenceRoot 'postboot-readonly-probe.stderr.log'
        $verifyProcess = Start-Process -FilePath $verifier -ArgumentList @(
            '--output',$reportPath,'--build-id','win11-extended-gui-postboot-readonly',
            '--read-samples','8') -Wait -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $verifyStdout -RedirectStandardError $verifyStderr
        if (-not $verifyProcess.HasExited -or $verifyProcess.ExitCode -ne 0) {
            throw 'Postboot synchronous read-only verifier failed.'
        }
        if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
            throw 'Postboot read-only verifier report is missing.'
        }
        $report = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $expectedVerifierSha = (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash.ToLowerInvariant()
        $expectedDriverSha = (Get-FileHash -LiteralPath (
                Join-Path $packageRoot 'drivers\KDbgDriver.sys') -Algorithm SHA256).Hash.ToLowerInvariant()
        $expectedProbeSha = (Get-FileHash -LiteralPath (
                Join-Path $packageRoot 'drivers\KDbgProbe.sys') -Algorithm SHA256).Hash.ToLowerInvariant()
        if ([string]$report.schema -cne 'kdbg.live-verify.v1' -or
            [string]$report.mode -cne 'read-only' -or $report.success -ne $true -or
            $report.cancelled -ne $false -or $report.runtime_identity.verified -ne $true -or
            [string]$report.runtime_identity.verifier.package_relative_path -cne 'tools/kdbg_live_verify.exe' -or
            [string]$report.runtime_identity.verifier.sha256 -cne $expectedVerifierSha -or
            [string]$report.runtime_identity.kdbg_service.name -cne 'KDBG' -or
            [string]$report.runtime_identity.kdbg_service.binary.package_relative_path -cne 'drivers/KDbgDriver.sys' -or
            [string]$report.runtime_identity.kdbg_service.binary.sha256 -cne $expectedDriverSha -or
            [uint32]$report.runtime_identity.kdbg_service.service_type -ne 1 -or
            [uint32]$report.runtime_identity.kdbg_service.current_state -ne 4 -or
            $report.runtime_identity.kdbg_service.running_kernel_driver -ne $true -or
            [string]$report.runtime_identity.probe_service.name -cne 'KDBGProbe' -or
            [string]$report.runtime_identity.probe_service.binary.package_relative_path -cne 'drivers/KDbgProbe.sys' -or
            [string]$report.runtime_identity.probe_service.binary.sha256 -cne $expectedProbeSha -or
            [uint32]$report.runtime_identity.probe_service.service_type -ne 1 -or
            [uint32]$report.runtime_identity.probe_service.current_state -ne 4 -or
            $report.runtime_identity.probe_service.running_kernel_driver -ne $true -or
            $report.backend.connected -ne $true -or [uint32]$report.backend.abi_version -ne 7 -or
            $report.backend.supports_physical_page_compare_write -ne $true -or
            $report.backend.is_mock -ne $false -or $report.backend.write_enabled -ne $false -or
            [uint32]$report.probe_before.byte_count -ne 4096 -or
            [uint64]$report.probe_before.pfn -eq 0 -or
            $report.write_cleanup.final_gate_locked -ne $true -or
            [uint32]$report.write_cleanup.apply_requested_bytes -ne 0 -or
            [uint32]$report.write_cleanup.rollback_requested_bytes -ne 0 -or
            @($report.errors).Count -ne 0 -or
            @($report.operations | Where-Object passed -ne $true).Count -ne 0 -or
            @($report.comparisons | Where-Object {
                    $_.match -ne $true -or [uint32]$_.mismatch_count -ne 0
                }).Count -ne 0) {
            throw 'Postboot verifier did not prove exact packaged driver identity, connected ABI 7, Probe read, and locked gate.'
        }

        $completedUtc = [DateTime]::UtcNow.ToString('o')
        $prepared.probe_pfn = [uint64]$report.probe_before.pfn
        $prepared.probe_pfn_hex = '0x{0:X}' -f [uint64]$report.probe_before.pfn
        $prepared | Add-Member -NotePropertyName postboot_probe_physical_address `
            -NotePropertyValue ([uint64]$report.probe_before.physical_address) -Force
        $prepared | Add-Member -NotePropertyName postboot_probe_generation `
            -NotePropertyValue ([uint64]$report.probe_before.generation) -Force
        $prepared | Add-Member -NotePropertyName postboot_probe_crc32 `
            -NotePropertyValue ([uint32]$report.probe_before.crc32) -Force
        $prepared | Add-Member -NotePropertyName postboot_readiness_report `
            -NotePropertyValue 'evidence/postboot-readonly-probe.json' -Force
        $prepared | Add-Member -NotePropertyName postboot_readiness_completed_utc `
            -NotePropertyValue $completedUtc -Force
        $preparedTemp = "$preparedPath.postboot.tmp"
        [IO.File]::WriteAllText($preparedTemp,
            ($prepared | ConvertTo-Json -Depth 30) + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $preparedTemp -Destination $preparedPath -Force

        $readiness = [ordered]@{
            schema='kdbg.win11-extended-gui-postboot-readiness.v1'
            success=$true
            completed_utc=$completedUtc
            services=@($serviceRecords)
            diagnose=[ordered]@{ exit_code=$diagnose.ExitCode; stdout='postboot-diagnose.stdout.log'; stderr='postboot-diagnose.stderr.log' }
            verifier=[ordered]@{
                exit_code=$verifyProcess.ExitCode
                exited_before_gui=$verifyProcess.HasExited
                stdout='postboot-readonly-probe.stdout.log'
                stderr='postboot-readonly-probe.stderr.log'
                report='postboot-readonly-probe.json'
                sha256=$expectedVerifierSha
            }
            drivers=[ordered]@{ kdbg_sha256=$expectedDriverSha; probe_sha256=$expectedProbeSha }
            backend=[ordered]@{
                connected=$true; abi_version=7; gate_locked=$true
                supports_physical_page_compare_write=$true
            }
            probe=[ordered]@{
                pfn=[uint64]$report.probe_before.pfn
                pfn_hex=('0x{0:X}' -f [uint64]$report.probe_before.pfn)
                physical_address=[uint64]$report.probe_before.physical_address
                generation=[uint64]$report.probe_before.generation
                crc32=[uint32]$report.probe_before.crc32
                byte_count=[uint32]$report.probe_before.byte_count
            }
        }
        [IO.File]::WriteAllText((Join-Path $evidenceRoot 'postboot-readiness.json'),
            ($readiness | ConvertTo-Json -Depth 30) + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
        [pscustomobject]$readiness
    } -ArgumentList $guestRunRoot,$ConnectionTimeoutSeconds
    $postbootReadinessSucceeded = $postbootReadiness.success -eq $true -and
        $postbootReadiness.verifier.exited_before_gui -eq $true -and
        $postbootReadiness.backend.connected -eq $true -and
        [uint32]$postbootReadiness.backend.abi_version -eq 7 -and
        $postbootReadiness.backend.supports_physical_page_compare_write -eq $true -and
        $postbootReadiness.backend.gate_locked -eq $true
    if (-not $postbootReadinessSucceeded) { throw 'Postboot driver readiness did not complete successfully.' }
    $timer.Stop(); $phases.Add([ordered]@{ phase='postboot-driver-readiness'; elapsed_ms=$timer.ElapsedMilliseconds })

    $timer = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Command -Session $session -ScriptBlock {
        param($Root,$User,$TaskName,$TimeoutSeconds)
        $result = Join-Path $Root 'evidence\interactive-bootstrap.json'
        $errorPath = Join-Path $Root 'evidence\interactive-bootstrap-error.txt'
        Remove-Item -LiteralPath $result,$errorPath -Force -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
            '-NoLogo -NoProfile -ExecutionPolicy Bypass -Sta -File "{0}" -RunRoot "{1}"' -f
            (Join-Path $Root 'interactive-bootstrap.ps1'),$Root) -WorkingDirectory $Root
        $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        try {
            Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName $TaskName
            $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
            do {
                Start-Sleep -Milliseconds 500
                if (Test-Path -LiteralPath $result -PathType Leaf) { return }
                if (Test-Path -LiteralPath $errorPath -PathType Leaf) { throw (Get-Content -LiteralPath $errorPath -Raw -Encoding UTF8) }
            } while ([DateTime]::UtcNow -lt $deadline)
            throw 'Interactive bootstrap timed out.'
        } finally {
            if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
                Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    } -ArgumentList $guestRunRoot,$InteractiveUser,$taskBootstrap,$ConnectionTimeoutSeconds
    $timer.Stop(); $phases.Add([ordered]@{ phase='interactive-resolution-dpi-fixture'; elapsed_ms=$timer.ElapsedMilliseconds })

    $timer = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Command -Session $session -ScriptBlock {
        param($Script,$Root,$Mode,$User)
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        & $Script -RunRoot $Root -CaptureMode $Mode -InteractiveUser $User | Out-Null
    } -ArgumentList (Join-Path $guestRunRoot 'Invoke-Win11GuiGuestCapture.ps1'),$guestRunRoot,$CaptureMode,$InteractiveUser
    $captureSucceeded = $true
    $timer.Stop(); $phases.Add([ordered]@{ phase='extended-gui-capture'; elapsed_ms=$timer.ElapsedMilliseconds })
} catch {
    $primaryError = Protect-Text ($_ | Out-String) $privateValues
} finally {
    if ($mutationBegan) {
        if ($null -eq $session) {
            try { $session = Wait-PowerShellDirect $VMName $credential 90 } catch { $cleanupErrors.Add('Could not reconnect for guest cleanup.') }
        }
        if ($null -ne $session) {
            try {
                $guestCleanup = Invoke-Command -Session $session -ScriptBlock {
                    param($Root,$User,$BootstrapTask,$GuiTask,$AutoLogonTask,$Signer)
                    $errors = [Collections.Generic.List[string]]::new()
                    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                    try {
                        Remove-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue
                        Remove-ItemProperty -LiteralPath $key -Name AutoLogonCount -ErrorAction SilentlyContinue
                        New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '0' -PropertyType String -Force | Out-Null
                    } catch { $errors.Add('AutoAdminLogon cleanup failed.') }
                    foreach ($name in @($BootstrapTask,$GuiTask,$AutoLogonTask)) {
                        try {
                            if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
                                Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
                                Unregister-ScheduledTask -TaskName $name -Confirm:$false
                            }
                        } catch { $errors.Add("Scheduled task cleanup failed: $name") }
                    }
                    $fixturePath = Join-Path $Root 'evidence\fixture-info.json'
                    if (Test-Path -LiteralPath $fixturePath -PathType Leaf) {
                        try {
                            $fixture = Get-Content -LiteralPath $fixturePath -Raw -Encoding UTF8 | ConvertFrom-Json
                            Stop-Process -Id ([uint32]$fixture.pid) -Force -ErrorAction SilentlyContinue
                        } catch { $errors.Add('Fixture cleanup failed.') }
                    }
                    $preparedPath = Join-Path $Root 'guest-prepared.json'
                    if (Test-Path -LiteralPath $preparedPath -PathType Leaf) {
                        $prepared = Get-Content -LiteralPath $preparedPath -Raw -Encoding UTF8 | ConvertFrom-Json
                        foreach ($guiProcess in @(Get-Process -Name 'KDBG' -ErrorAction SilentlyContinue)) {
                            try {
                                if ([string]$guiProcess.Path -and [string]$guiProcess.Path.StartsWith(
                                        [string]$prepared.package_root,[StringComparison]::OrdinalIgnoreCase)) {
                                    Stop-Process -Id $guiProcess.Id -Force -ErrorAction Stop
                                }
                            } catch { $errors.Add('KDBG GUI process cleanup failed.') }
                        }
                        $uninstall = Join-Path ([string]$prepared.package_root) 'tools\uninstall.ps1'
                        if (Test-Path -LiteralPath $uninstall -PathType Leaf) {
                            try {
                                & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $uninstall `
                                    -ConfirmKdbgServices -PurgeUserData *> (Join-Path $Root 'evidence\uninstall.log')
                                if ($LASTEXITCODE -ne 0) { $errors.Add('Package uninstall returned nonzero.') }
                            } catch { $errors.Add('Package uninstall failed.') }
                        }
                    }
                    foreach ($store in @('Root','TrustedPublisher')) {
                        try {
                            & certutil.exe -delstore $store $Signer *> (Join-Path $Root "evidence\cert-remove-$store.log")
                            if ($LASTEXITCODE -ne 0) { $errors.Add("Certificate removal returned nonzero: $store") }
                        } catch { $errors.Add("Certificate removal failed: $store") }
                    }
                    $services = @('KDBG','KDBGProbe') | ForEach-Object { [ordered]@{ name=$_; present=$null -ne (Get-Service -Name $_ -ErrorAction SilentlyContinue) } }
                    if (@($services | Where-Object present).Count -ne 0) { $errors.Add('KDBG services remain after cleanup.') }
                    $result = [ordered]@{
                        schema='kdbg.win11-extended-gui-guest-cleanup.v1'; success=$errors.Count -eq 0
                        completed_utc=[DateTime]::UtcNow.ToString('o'); autologon_secret_present=$null -ne (Get-ItemProperty `
                            -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue)
                        tasks=@(@($BootstrapTask,$GuiTask,$AutoLogonTask) | ForEach-Object { [ordered]@{ name=$_; present=$null -ne (Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue) } })
                        services=$services; errors=@($errors); credential_serialized=$false
                    }
                    [IO.File]::WriteAllText((Join-Path $Root 'evidence\guest-cleanup.json'),
                        ($result | ConvertTo-Json -Depth 20) + [Environment]::NewLine,[Text.UTF8Encoding]::new($false))
                    [pscustomobject]$result
                } -ArgumentList $guestRunRoot,$InteractiveUser,$taskBootstrap,$taskGui,$taskAutoLogon,$ExpectedSignerThumbprint
                $guestCleanupSucceeded = $guestCleanup.success -eq $true -and $guestCleanup.autologon_secret_present -eq $false
            } catch { $cleanupErrors.Add((Protect-Text $_.Exception.Message $privateValues)) }
            try {
                Invoke-Command -Session $session -ScriptBlock {
                    param($Root,$Archive)
                    if (Test-Path -LiteralPath $Archive) { Remove-Item -LiteralPath $Archive -Force }
                    Add-Type -AssemblyName System.IO.Compression
                    $source = [IO.Path]::GetFullPath((Join-Path $Root 'evidence')).TrimEnd('\')
                    $prefix = $source + '\'
                    $files = @(Get-ChildItem -LiteralPath $source -Recurse -File)
                    if ($files.Count -eq 0) { throw 'Guest evidence directory is empty.' }
                    $relativePaths = [Collections.Generic.List[string]]::new()
                    $byRelative = @{}
                    foreach ($file in $files) {
                        if (-not $file.FullName.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
                            throw 'Guest evidence input escaped its source root.'
                        }
                        $relative = $file.FullName.Substring($prefix.Length).Replace('\','/')
                        if ([string]::IsNullOrWhiteSpace($relative) -or $relative -match '(^|/)\.\.(/|$)') {
                            throw "Unsafe guest evidence path: $relative"
                        }
                        $relativePaths.Add($relative); $byRelative[$relative] = $file.FullName
                    }
                    $ordered = [string[]]$relativePaths.ToArray()
                    [Array]::Sort($ordered,[StringComparer]::Ordinal)
                    $stream = [IO.File]::Open($Archive,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
                    try {
                        $zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
                        try {
                            foreach ($relative in $ordered) {
                                $entry = $zip.CreateEntry($relative,[IO.Compression.CompressionLevel]::Optimal)
                                $entry.LastWriteTime = [DateTimeOffset]'2000-01-01T00:00:00Z'
                                $input = [IO.File]::OpenRead([string]$byRelative[$relative])
                                try { $output = $entry.Open(); try { $input.CopyTo($output) } finally { $output.Dispose() } }
                                finally { $input.Dispose() }
                            }
                        } finally { $zip.Dispose() }
                    } finally { $stream.Dispose() }
                } -ArgumentList $guestRunRoot,$guestArchive
                Copy-Item -LiteralPath $guestArchive -Destination $hostArchive -FromSession $session
                [void](Test-Zip $hostArchive @('guest-cleanup.json'))
                New-Item -ItemType Directory -Path $hostExpanded -Force | Out-Null
                Expand-Archive -LiteralPath $hostArchive -DestinationPath $hostExpanded -Force
                $evidenceRecovered = $true
            } catch { $cleanupErrors.Add((Protect-Text $_.Exception.Message $privateValues)) }
            try { Remove-PSSession -Session $session -ErrorAction Stop } catch { $cleanupErrors.Add('PowerShell Direct session cleanup failed.') }
            $session = $null
        }
        try {
            $vmNow = Get-VM -Name $VMName -ErrorAction Stop
            if ($vmNow.State.ToString() -ne 'Off') { Stop-VM -VM $vmNow -TurnOff -Force -Confirm:$false -ErrorAction Stop }
        } catch { $cleanupErrors.Add('VM stop before restore failed.') }
        try {
            $checkpointNow = @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop | Where-Object {
                    $_.Name -ceq $CheckpointName -and $_.Id -eq $CheckpointId
                })
            if ($checkpointNow.Count -ne 1) { throw 'Exact checkpoint identity is no longer unique.' }
            Restore-VMSnapshot -VMSnapshot $checkpointNow[0] -Confirm:$false -ErrorAction Stop
            $restored = $true
        } catch { $cleanupErrors.Add('Exact checkpoint restore failed.') }
        try {
            $finalVm = Get-VM -Name $VMName -ErrorAction Stop
            if ($finalVm.State.ToString() -ne 'Off') {
                Stop-VM -VM $finalVm -TurnOff -Force -Confirm:$false -ErrorAction Stop
                $finalVm = Get-VM -Name $VMName -ErrorAction Stop
            }
            $finalOff = $finalVm.State.ToString() -eq 'Off' -and $finalVm.Id -eq $VMId
        } catch { $cleanupErrors.Add('Final Off verification failed.') }
    }
}

$success = $captureSucceeded -and $postbootReadinessSucceeded -and $guestCleanupSucceeded -and $evidenceRecovered -and
    $autoLogonClearedAfterExplorer -and $restored -and $finalOff -and $cleanupErrors.Count -eq 0
$summary = [ordered]@{
    schema='kdbg.win11-extended-gui-host-orchestrator.v1'
    success=$success
    execution_status=if (-not $success) { 'FAILED' } elseif ($CaptureMode -ceq 'calibration-smoke') {
        'CALIBRATION_SMOKE_NOT_EVIDENCE'
    } else { 'CAPTURED_UNREVIEWED' }
    capture_mode=$CaptureMode
    vm=[ordered]@{ name=$VMName; id=$VMId.ToString('D'); final_off=$finalOff }
    checkpoint=[ordered]@{ name=$CheckpointName; id=$checkpointIdText; restored=$restored }
    capture_succeeded=$captureSucceeded
    postboot_readiness_succeeded=$postbootReadinessSucceeded
    guest_cleanup_succeeded=$guestCleanupSucceeded
    evidence_recovered=$evidenceRecovered
    autologon_secret_cleared_after_explorer=$autoLogonClearedAfterExplorer
    evidence_pass=$false
    human_review_complete=$false
    guest_evidence_archive=if ($evidenceRecovered) { [ordered]@{ file='guest-evidence.zip'; sha256=Get-Sha $hostArchive } } else { $null }
    primary_error=$primaryError
    cleanup_errors=@($cleanupErrors)
    phases=@($phases)
    credential_serialized=$false
    plaintext_password_logged=$false
    completed_utc=[DateTime]::UtcNow.ToString('o')
}
Write-Json $summaryPath $summary
if (-not $success) { throw "Win11 extended GUI orchestration failed; inspect $summaryPath" }
$summary | ConvertTo-Json -Depth 30

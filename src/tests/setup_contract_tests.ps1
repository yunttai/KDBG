[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Module = Join-Path $PSScriptRoot "..\tools\setup\setup_contract.psm1"
Import-Module $Module -Force

function Assert-Equal([object]$Expected, [object]$Actual, [string]$Message) {
    if ([string]$Expected -cne [string]$Actual) {
        throw "$Message (expected '$Expected', actual '$Actual')"
    }
}

function Assert-True([bool]$Value, [string]$Message) {
    if (-not $Value) { throw $Message }
}

$Contract = Get-KdbgSetupContract
Assert-Equal "kdbg.setup-contract.v1" $Contract.Schema "schema mismatch"
Assert-Equal "KDBG-1.1.0-win-x64" $Contract.PackageLeaf `
    "distribution source leaf mismatch"
Assert-Equal "KDBG" $Contract.InstallParentLeaf "install parent mismatch"
Assert-Equal "Product" $Contract.InstallLeaf "stable install leaf mismatch"
Assert-Equal 4 @($Contract.Actions).Count "action count mismatch"

$Policy = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot "..\config\safety_policy.example.json") -Raw |
    ConvertFrom-Json
Assert-True (-not $Policy.environment.dedicated_vm_required) `
    "packaged policy must not require a dedicated VM"
Assert-True (-not $Policy.environment.restorable_snapshot_required) `
    "packaged policy must not require a restorable snapshot"

$LiveEvidenceExample = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot "..\tools\live-evidence.example.json") -Raw |
    ConvertFrom-Json
Assert-Equal 7 $LiveEvidenceExample.abi_version `
    "current live-evidence template ABI mismatch"

foreach ($Action in @("Install", "Repair", "Update")) {
    $Plan = Get-KdbgSetupPlan -Action $Action
    Assert-Equal $Action $Plan.Action "action mismatch"
    Assert-True $Plan.MutatesDriverServicesOnlyThroughPackageLifecycle `
        "driver lifecycle delegation must remain explicit"
    Assert-True (-not $Plan.RequiresDedicatedVmConfirmation) `
        "ordinary setup must not require dedicated VM confirmation"
    Assert-True (-not $Plan.RequiresSnapshotConfirmation) `
        "ordinary setup must not require snapshot confirmation"
    Assert-Equal "DisposableVm,LocalHost" `
        (@($Plan.SupportedTargetProfiles) -join ",") `
        "setup target profiles mismatch"
    Assert-Equal "LocalHost" $Plan.DefaultTargetProfile `
        "LocalHost must be the ordinary setup target"
    Assert-Equal `
        "VerifySourcePackage,StagePackage,VerifyStagedPackage,CommitPackage,InstallOrRepairDriverPair,RegisterProduct" `
        (@($Plan.Phases) -join ",") "install-family phase order mismatch"
}

$Uninstall = Get-KdbgSetupPlan -Action "Uninstall"
Assert-Equal `
    "VerifyInstalledPackage,RemoveDriverServices,UnregisterProduct,ScheduleVerifiedPackagePurge" `
    (@($Uninstall.Phases) -join ",") "uninstall phase order mismatch"

$Rejected = $false
try { Get-KdbgSetupPlan -Action "Bypass" | Out-Null }
catch { $Rejected = $_.Exception.Message -like "*Unsupported KDBG setup action*" }
Assert-True $Rejected "unsupported action was not rejected"

$ModeFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "kdbg-setup-mode-$([Guid]::NewGuid().ToString('N'))")
try {
    $ModeParent = Join-Path $ModeFixtureRoot "install"
    $ModeSource = Join-Path $ModeFixtureRoot $Contract.PackageLeaf
    New-Item -ItemType Directory -Path $ModeParent,$ModeSource -Force | Out-Null
    $UppercaseRejected = $false
    try {
        Invoke-KdbgSetupFileTransaction `
            -SourceRoot $ModeSource `
            -DestinationRoot (Join-Path $ModeParent $Contract.InstallLeaf) `
            -InstallParent $ModeParent `
            -TransactionId "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" `
            -VerifySource {} -VerifyStaging {} -ApplyLifecycle {} `
            -RemoveLifecycle {} -RegisterProduct {} -UnregisterProduct {} | Out-Null
    } catch { $UppercaseRejected = $_.Exception.Message -like "*lowercase hexadecimal*" }
    Assert-True $UppercaseRejected `
        "uppercase Setup transaction/staging identifiers must be rejected"
} finally {
    Remove-Item -LiteralPath $ModeFixtureRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
}

Assert-Equal '""' (ConvertTo-KdbgCommandLineArgument "") `
    "empty argument quoting mismatch"
Assert-Equal "plain" (ConvertTo-KdbgCommandLineArgument "plain") `
    "plain argument quoting mismatch"
Assert-Equal '"two words"' (ConvertTo-KdbgCommandLineArgument "two words") `
    "space argument quoting mismatch"
Assert-Equal '"C:\Program Files\KDBG\\"' `
    (ConvertTo-KdbgCommandLineArgument 'C:\Program Files\KDBG\') `
    "trailing slash quoting mismatch"
Assert-Equal '"a\\\"b"' (ConvertTo-KdbgCommandLineArgument 'a\"b') `
    "embedded quote quoting mismatch"

$SetupScript = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot "..\tools\setup\setup.ps1") -Raw
foreach ($Token in @(
        "RequireTrustedDriverSignatures", "tools\install.ps1",
        "TargetProfile", "LocalHost", "tools\TargetProfile.psm1",
        "tools\uninstall.ps1", "UninstallString", "WScript.Shell",
        "Prepare-ExactPackagePurge", "Commit-ExactPackagePurge",
        "Assert-NoReparsePoints",
        "DistributionSource", "SetupStaging", "InstalledProduct",
        "kdbg.setup-purge.v1", "PURGE_SCHEDULED",
        "Package purge is pending, not complete",
        "Start-KdbgDetachedPowerShell", "KdbgDetachedProcess",
        "CreateProcessW", "inheritHandles", "worker_pid")) {
    Assert-True $SetupScript.Contains($Token) "setup script lacks marker: $Token"
}
Assert-True (-not $SetupScript.Contains("QuietUninstallString")) `
    "interactive-only setup must not advertise a quiet uninstall command"
$SetupUi = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot "..\tools\setup\main.cpp") -Raw
Assert-True (-not $SetupUi.Contains("exact signed package") -and
    -not $SetupUi.Contains("Package and driver signatures are verified")) `
    "Setup UI must not overstate user-mode Authenticode verification"
Assert-True ($SetupUi.Contains("package purge remains pending") -and
    $SetupUi.Contains("publisher signing is a separate release gate")) `
    "Setup UI must distinguish pending purge and user-mode signing gates"
Assert-True ($SetupUi.Contains('L"DisposableVm"') -and
    $SetupUi.Contains('L"LocalHost"') -and
    $SetupUi.Contains('L" -TargetProfile "')) `
    "Setup UI must forward the explicitly selected target profile"
foreach ($State in @('"ready"', '"scheduled"', '"waiting"', '"purging"', '"succeeded"', '"failed"', '"cancelled"')) {
    Assert-True $SetupScript.Contains($State) `
        "persistent purge contract lacks state $State"
}
Assert-True ($SetupScript.Contains("CommonApplicationData") -and
    $SetupScript.Contains('"KDBG\Setup"')) `
    "purge status and logs must live outside the asynchronously deleted Product root"

$Tokens = $null
$ParseErrors = $null
$SetupAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "..\tools\setup\setup.ps1"),
    [ref]$Tokens, [ref]$ParseErrors)
Assert-Equal 0 $ParseErrors.Count "setup parser error count mismatch"
$StatusFunction = $SetupAst.Find({
    param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -eq "Write-PurgeStatus"
}, $true)
Assert-True ($null -ne $StatusFunction) "Write-PurgeStatus function missing"
Invoke-Expression $StatusFunction.Extent.Text
$StatusFixture = Join-Path ([IO.Path]::GetTempPath()) (
    "kdbg-purge-status-$([Guid]::NewGuid().ToString('N')).json")
try {
    Write-PurgeStatus $StatusFixture `
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "scheduled" `
        "C:\Program Files\KDBG\Product" "$StatusFixture.log"
    $Status = Get-Content -LiteralPath $StatusFixture -Raw | ConvertFrom-Json
    Assert-Equal "kdbg.setup-purge.v1" $Status.schema "purge status schema mismatch"
    Assert-Equal "scheduled" $Status.state "purge scheduled state mismatch"
    Write-PurgeStatus $StatusFixture `
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "failed" `
        "C:\Program Files\KDBG\Product" "$StatusFixture.log" "fixture failure"
    $Status = Get-Content -LiteralPath $StatusFixture -Raw | ConvertFrom-Json
    Assert-Equal "failed" $Status.state "purge failure state mismatch"
    Assert-Equal "fixture failure" $Status.error "purge error persistence mismatch"
} finally {
    Remove-Item -LiteralPath $StatusFixture,"$StatusFixture.tmp" -Force `
        -ErrorAction SilentlyContinue
}

function New-SetupFixture(
    [string]$Root,
    [string]$SourceValue,
    [string]$DestinationValue = "") {
    $Source = Join-Path $Root $Contract.PackageLeaf
    $Parent = Join-Path $Root "install"
    $Destination = Join-Path $Parent $Contract.InstallLeaf
    New-Item -ItemType Directory -Path $Source,$Parent -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Source "payload.txt") `
        -Value $SourceValue -NoNewline
    if ($DestinationValue.Length -gt 0) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $Destination "payload.txt") `
            -Value $DestinationValue -NoNewline
    }
    return [pscustomobject]@{
        Source = $Source
        Parent = $Parent
        Destination = $Destination
    }
}

function Invoke-FixtureTransaction(
    [object]$Fixture,
    [string]$TransactionId,
    [Collections.Generic.List[string]]$Calls,
    [scriptblock]$FaultInjector = $null,
    [switch]$EmitCallbackOutput,
    [switch]$FailRestoredLifecycle) {
    return Invoke-KdbgSetupFileTransaction `
        -SourceRoot $Fixture.Source `
        -DestinationRoot $Fixture.Destination `
        -InstallParent $Fixture.Parent `
        -TransactionId $TransactionId `
        -VerifySource {
            param($Root)
            if ([IO.Path]::GetFileName($Root) -cne $Contract.PackageLeaf) {
                throw "fixture source identity mismatch"
            }
            if ($EmitCallbackOutput) {
                Write-Output "fixture callback transcript"
            }
            $Calls.Add("verify-source")
        } `
        -VerifyStaging {
            param($Root, $StagingRoot)
            if ([IO.Path]::GetFileName($Root) -cne $Contract.InstallLeaf -or
                [IO.Path]::GetFileName($StagingRoot) -cnotmatch '^\.staging-[0-9a-f]{32}$') {
                throw "fixture staging identity mismatch"
            }
            $Calls.Add("verify-staging")
        } `
        -ApplyLifecycle {
            param($Root)
            $Value = Get-Content -LiteralPath (Join-Path $Root "payload.txt") -Raw
            $Calls.Add("apply:$Value")
            if ($FailRestoredLifecycle -and $Value -eq "old") {
                throw "injected restored lifecycle failure"
            }
        } `
        -RemoveLifecycle {
            param($Root)
            $Calls.Add("remove-new")
        } `
        -RegisterProduct {
            param($Root)
            $Value = Get-Content -LiteralPath (Join-Path $Root "payload.txt") -Raw
            $Calls.Add("register:$Value")
        } `
        -UnregisterProduct { $Calls.Add("unregister") } `
        -FaultInjector $FaultInjector
}

$TestRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "kdbg-setup-contract-$([Guid]::NewGuid().ToString('N'))")
try {
    # Install invokes the real transaction path and callbacks in order.
    $InstallFixture = New-SetupFixture (Join-Path $TestRoot "install-action") "new"
    $Calls = [Collections.Generic.List[string]]::new()
    $Result = Invoke-FixtureTransaction $InstallFixture `
        "11111111111111111111111111111111" $Calls -EmitCallbackOutput
    Assert-True ($Result -is [pscustomobject]) `
        "callback transcript output polluted the transaction result"
    Assert-Equal "committed" $Result.state "Install transaction did not commit"
    Assert-Equal "new" (Get-Content -LiteralPath (
        Join-Path $InstallFixture.Destination "payload.txt") -Raw) `
        "Install did not publish source payload"
    Assert-Equal "verify-source,verify-staging,apply:new,register:new" `
        ($Calls -join ",") "Install callback order mismatch"

    # Update moves the prior product, commits the new payload, and removes the
    # backup only after lifecycle plus registration complete.
    $UpdateFixture = New-SetupFixture (Join-Path $TestRoot "update-action") "new" "old"
    $Calls = [Collections.Generic.List[string]]::new()
    $Result = Invoke-FixtureTransaction $UpdateFixture `
        "22222222222222222222222222222222" $Calls
    Assert-True $Result.prior_moved "Update did not record prior_moved"
    Assert-True $Result.new_committed "Update did not record new_committed"
    Assert-True (-not (Test-Path -LiteralPath (
        Join-Path $UpdateFixture.Parent ".backup-22222222222222222222222222222222"))) `
        "verified Update retained a stale backup"

    # Repair from the installed Product root executes lifecycle/registration
    # without treating Product as a distribution source directory.
    $Calls = [Collections.Generic.List[string]]::new()
    $Repair = Invoke-KdbgSetupFileTransaction `
        -SourceRoot $UpdateFixture.Destination `
        -DestinationRoot $UpdateFixture.Destination `
        -InstallParent $UpdateFixture.Parent `
        -TransactionId "33333333333333333333333333333333" `
        -VerifySource { param($Root) $Calls.Add("verify-installed") } `
        -VerifyStaging { throw "Repair must not stage" } `
        -ApplyLifecycle { param($Root) $Calls.Add("apply-repair") } `
        -RemoveLifecycle { throw "Repair must not remove" } `
        -RegisterProduct { param($Root) $Calls.Add("register-repair") } `
        -UnregisterProduct { throw "Repair must not unregister" }
    Assert-Equal "verify-installed,apply-repair,register-repair" `
        ($Calls -join ",") "Repair callback order mismatch"

    # Uninstall completes only the synchronous service/registration phase and
    # returns an explicit pending purge contract.
    $Calls = [Collections.Generic.List[string]]::new()
    $PurgeStatus = Join-Path $TestRoot "purge.json"
    $PurgeLog = Join-Path $TestRoot "purge.log"
    $Purge = Invoke-KdbgSetupUninstallTransaction `
        -InstalledRoot $UpdateFixture.Destination `
        -VerifyInstalled { param($Root) $Calls.Add("verify-installed") } `
        -RemoveLifecycle { param($Root) $Calls.Add("remove-services") } `
        -PreparePurge {
            param($Root)
            $Calls.Add("prepare-purge")
            [pscustomobject]@{state="ready";status_file=$PurgeStatus;log_file=$PurgeLog;commit_marker="$PurgeStatus.commit"}
        } `
        -UnregisterProduct { $Calls.Add("unregister") } `
        -RegisterProduct { param($Root) $Calls.Add("restore-registration") } `
        -CommitPurge {
            param($Prepared)
            $Calls.Add("commit-purge")
            [pscustomobject]@{state="scheduled";status_file=$Prepared.status_file;log_file=$Prepared.log_file}
        }
    Assert-Equal "scheduled" $Purge.state "Uninstall overstated async purge"
    Assert-Equal "verify-installed,remove-services,prepare-purge,unregister,commit-purge" `
        ($Calls -join ",") "Uninstall callback order mismatch"

    # A purge-helper prepare/launch failure occurs before product registration
    # removal, so Apps & Features and shortcuts remain recoverable.
    $Registration = [pscustomobject]@{ Present = $true }
    $PrepareFailed = $false
    try {
        Invoke-KdbgSetupUninstallTransaction `
            -InstalledRoot $UpdateFixture.Destination `
            -VerifyInstalled {} -RemoveLifecycle {} `
            -PreparePurge { throw "injected purge prepare failure" } `
            -UnregisterProduct { $Registration.Present = $false } `
            -RegisterProduct { param($Root) $Registration.Present = $true } `
            -CommitPurge { throw "must not commit" } | Out-Null
    } catch { $PrepareFailed = $_.Exception.Message -like "*prepare failure*" }
    Assert-True $PrepareFailed "purge prepare fault was not surfaced"
    Assert-True $Registration.Present `
        "purge scheduler failure removed product registration"

    # If commit-marker creation fails after unregister, registration is
    # restored and the unarmed helper preserves Product.
    $Registration.Present = $true
    $CommitFailed = $false
    try {
        Invoke-KdbgSetupUninstallTransaction `
            -InstalledRoot $UpdateFixture.Destination `
            -VerifyInstalled {} -RemoveLifecycle {} `
            -PreparePurge {
                [pscustomobject]@{state="ready";status_file=$PurgeStatus;log_file=$PurgeLog;commit_marker="$PurgeStatus.commit"}
            } `
            -UnregisterProduct { $Registration.Present = $false } `
            -RegisterProduct { param($Root) $Registration.Present = $true } `
            -CommitPurge { throw "injected commit marker failure" } | Out-Null
    } catch { $CommitFailed = $_.Exception.Message -like "*commit marker failure*" }
    Assert-True $CommitFailed "purge commit fault was not surfaced"
    Assert-True $Registration.Present `
        "purge commit failure did not restore product registration"

    # A commit fault after prior_moved must restore and verify the old product.
    $CommitFault = New-SetupFixture (Join-Path $TestRoot "commit-fault") "new" "old"
    $Calls = [Collections.Generic.List[string]]::new()
    $Failed = $false
    try {
        Invoke-FixtureTransaction $CommitFault `
            "44444444444444444444444444444444" $Calls {
                param($Phase)
                if ($Phase -eq "AfterPriorMove") { throw "injected commit failure" }
            } | Out-Null
    } catch { $Failed = $_.Exception.Message -like "*injected commit failure*" }
    Assert-True $Failed "commit fault was not surfaced"
    Assert-Equal "old" (Get-Content -LiteralPath (
        Join-Path $CommitFault.Destination "payload.txt") -Raw) `
        "commit fault did not restore prior product"

    # If rollback verification fails, the last known-good backup must remain
    # byte-for-byte available and must never be deleted by finally cleanup.
    $RollbackFault = New-SetupFixture (Join-Path $TestRoot "rollback-fault") "new" "old"
    $Calls = [Collections.Generic.List[string]]::new()
    $Failed = $false
    try {
        Invoke-FixtureTransaction $RollbackFault `
            "55555555555555555555555555555555" $Calls {
                param($Phase)
                if ($Phase -eq "AfterNewCommit") { throw "injected new commit failure" }
            } -FailRestoredLifecycle | Out-Null
    } catch {
        $Failed = $_.Exception.Message -like "*backup preserved=True*"
    }
    $PreservedBackup = Join-Path $RollbackFault.Parent `
        ".backup-55555555555555555555555555555555"
    Assert-True $Failed "rollback fault did not report preserved backup"
    Assert-True (Test-Path -LiteralPath $PreservedBackup -PathType Container) `
        "rollback fault deleted last-known-good backup"
    Assert-Equal "old" (Get-Content -LiteralPath (
        Join-Path $PreservedBackup "payload.txt") -Raw) `
        "preserved backup content changed"
} finally {
    if (Test-Path -LiteralPath $TestRoot) {
        Remove-Item -LiteralPath $TestRoot -Recurse -Force
    }
}

Write-Host "KDBG setup contract tests PASS"

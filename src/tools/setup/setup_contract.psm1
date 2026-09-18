Set-StrictMode -Version Latest

$script:KdbgSetupContract = [ordered]@{
    Schema = "kdbg.setup-contract.v1"
    Product = "KDBG"
    Version = "1.1.0"
    PackageLeaf = "KDBG-1.1.0-win-x64"
    InstallParentLeaf = "KDBG"
    InstallLeaf = "Product"
    UninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KDBG"
    StartMenuFolder = "KDBG"
    Actions = @("Install", "Repair", "Update", "Uninstall")
}

function Invoke-KdbgSetupFileTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][string]$InstallParent,
        [Parameter(Mandatory)][scriptblock]$VerifySource,
        [Parameter(Mandatory)][scriptblock]$VerifyStaging,
        [Parameter(Mandatory)][scriptblock]$ApplyLifecycle,
        [Parameter(Mandatory)][scriptblock]$RemoveLifecycle,
        [Parameter(Mandatory)][scriptblock]$RegisterProduct,
        [Parameter(Mandatory)][scriptblock]$UnregisterProduct,
        [scriptblock]$FaultInjector = $null,
        [string]$TransactionId = ([Guid]::NewGuid().ToString("N"))
    )

    if ($TransactionId -cnotmatch '^[0-9a-f]{32}$') {
        throw "Setup transaction id must be 32 lowercase hexadecimal characters."
    }
    $SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
    $DestinationRoot = [IO.Path]::GetFullPath($DestinationRoot)
    $InstallParent = [IO.Path]::GetFullPath($InstallParent)
    $ExpectedDestination = [IO.Path]::GetFullPath((
        Join-Path $InstallParent $script:KdbgSetupContract.InstallLeaf))
    if (-not $DestinationRoot.Equals(
            $ExpectedDestination, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Setup transaction destination is outside the exact Product root."
    }

    $InvokeFault = {
        param([string]$Phase)
        if ($null -ne $FaultInjector) {
            & $FaultInjector $Phase | Out-Host
        }
    }
    & $VerifySource $SourceRoot | Out-Host
    $SameRoot = $SourceRoot.Equals(
        $DestinationRoot, [StringComparison]::OrdinalIgnoreCase)
    if ($SameRoot) {
        & $ApplyLifecycle $DestinationRoot | Out-Host
        & $RegisterProduct $DestinationRoot | Out-Host
        return [pscustomobject]@{
            schema = "kdbg.setup-transaction.v1"
            transaction_id = $TransactionId
            state = "committed"
            prior_moved = $false
            new_committed = $false
            rollback_completed = $false
            backup_preserved = $false
        }
    }

    $StagingRoot = Join-Path $InstallParent ".staging-$TransactionId"
    $StagingProduct = Join-Path $StagingRoot $script:KdbgSetupContract.InstallLeaf
    $BackupRoot = Join-Path $InstallParent ".backup-$TransactionId"
    $FailedRoot = Join-Path $InstallParent ".failed-$TransactionId"
    $PriorMoved = $false
    $NewCommitted = $false
    $RollbackCompleted = $false
    $HadDestination = Test-Path -LiteralPath $DestinationRoot -PathType Container
    $Succeeded = $false

    try {
        New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
        Copy-Item -LiteralPath $SourceRoot -Destination $StagingProduct `
            -Recurse -Force
        & $VerifyStaging $StagingProduct $StagingRoot | Out-Host
        & $InvokeFault "BeforePriorMove"
        if ($HadDestination) {
            Move-Item -LiteralPath $DestinationRoot -Destination $BackupRoot
            $PriorMoved = $true
            & $InvokeFault "AfterPriorMove"
        }
        & $InvokeFault "BeforeNewCommit"
        Move-Item -LiteralPath $StagingProduct -Destination $DestinationRoot
        $NewCommitted = $true
        & $InvokeFault "AfterNewCommit"
        & $ApplyLifecycle $DestinationRoot | Out-Host
        & $RegisterProduct $DestinationRoot | Out-Host
        & $InvokeFault "AfterRegister"
        $Succeeded = $true
        $BackupPreserved = $false
        if ($PriorMoved -and (Test-Path -LiteralPath $BackupRoot)) {
            try {
                Remove-Item -LiteralPath $BackupRoot -Recurse -Force
            } catch {
                $BackupPreserved = Test-Path -LiteralPath $BackupRoot -PathType Container
                Write-Warning (
                    "Setup committed successfully but obsolete backup cleanup failed; " +
                    "retained=$BackupPreserved path=$BackupRoot error=$($_.Exception.Message)")
            }
        }
        return [pscustomobject]@{
            schema = "kdbg.setup-transaction.v1"
            transaction_id = $TransactionId
            state = "committed"
            prior_moved = $PriorMoved
            new_committed = $NewCommitted
            rollback_completed = $false
            backup_preserved = $BackupPreserved
        }
    } catch {
        $Failure = $_
        try {
            & $InvokeFault "BeforeRollback"
            if ($NewCommitted -and (Test-Path -LiteralPath $DestinationRoot)) {
                & $RemoveLifecycle $DestinationRoot | Out-Host
                if (Test-Path -LiteralPath $FailedRoot) {
                    throw "Unexpected failed-candidate recovery path already exists."
                }
                Move-Item -LiteralPath $DestinationRoot -Destination $FailedRoot
            }
            & $UnregisterProduct | Out-Host
            if ($PriorMoved -and (Test-Path -LiteralPath $BackupRoot)) {
                # Copy, rather than move, the last known-good backup into the
                # stable destination. The backup remains intact until the
                # restored lifecycle and registration both succeed.
                Copy-Item -LiteralPath $BackupRoot -Destination $DestinationRoot `
                    -Recurse -Force
                & $ApplyLifecycle $DestinationRoot | Out-Host
                & $RegisterProduct $DestinationRoot | Out-Host
                & $InvokeFault "AfterRestoredRegistration"
                $RollbackCompleted = $true
                try {
                    Remove-Item -LiteralPath $BackupRoot -Recurse -Force
                } catch {
                    Write-Warning (
                        "Setup rollback verified the restored Product root but obsolete " +
                        "backup cleanup failed; path=$BackupRoot error=$($_.Exception.Message)")
                }
            } elseif (-not $HadDestination) {
                $RollbackCompleted = $true
            }
        } catch {
            $BackupPreserved = $PriorMoved -and
                (Test-Path -LiteralPath $BackupRoot -PathType Container)
            throw (
                "Setup transaction failed: $($Failure.Exception.Message); " +
                "rollback failed: $($_.Exception.Message); " +
                "last-known-good backup preserved=$BackupPreserved path=$BackupRoot")
        }
        throw $Failure
    } finally {
        # Staging and a failed new candidate are never last-known-good state.
        # The backup is intentionally absent here: only successful commit or
        # fully verified rollback is allowed to remove it.
        foreach ($Path in @($StagingRoot, $FailedRoot)) {
            if (Test-Path -LiteralPath $Path) {
                Remove-Item -LiteralPath $Path -Recurse -Force `
                    -ErrorAction SilentlyContinue
            }
        }
        if (-not $Succeeded -and -not $RollbackCompleted -and $PriorMoved -and
            -not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
            throw "Setup lost the last-known-good backup during failed rollback: $BackupRoot"
        }
    }
}

function Invoke-KdbgSetupUninstallTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstalledRoot,
        [Parameter(Mandatory)][scriptblock]$VerifyInstalled,
        [Parameter(Mandatory)][scriptblock]$RemoveLifecycle,
        [Parameter(Mandatory)][scriptblock]$PreparePurge,
        [Parameter(Mandatory)][scriptblock]$UnregisterProduct,
        [Parameter(Mandatory)][scriptblock]$RegisterProduct,
        [Parameter(Mandatory)][scriptblock]$CommitPurge
    )
    $InstalledRoot = [IO.Path]::GetFullPath($InstalledRoot)
    & $VerifyInstalled $InstalledRoot | Out-Host
    & $RemoveLifecycle $InstalledRoot | Out-Host
    $PreparedOutput = @(& $PreparePurge $InstalledRoot)
    if ($PreparedOutput.Count -ne 1) {
        throw "Uninstall purge prepare must return exactly one ready-state object."
    }
    $Prepared = $PreparedOutput[0]
    if ($null -eq $Prepared -or $Prepared.state -ne "ready" -or
        [string]::IsNullOrWhiteSpace([string]$Prepared.status_file) -or
        [string]::IsNullOrWhiteSpace([string]$Prepared.log_file) -or
        [string]::IsNullOrWhiteSpace([string]$Prepared.commit_marker)) {
        throw "Uninstall purge scheduler did not return the persistent ready-state contract."
    }
    $RegistrationTouched = $false
    try {
        $RegistrationTouched = $true
        & $UnregisterProduct | Out-Host
        $PurgeOutput = @(& $CommitPurge $Prepared)
        if ($PurgeOutput.Count -ne 1) {
            throw "Uninstall purge commit must return exactly one scheduled-state object."
        }
        $Purge = $PurgeOutput[0]
        if ($null -eq $Purge -or $Purge.state -ne "scheduled") {
            throw "Uninstall purge commit did not return scheduled state."
        }
    } catch {
        $Failure = $_
        if ($RegistrationTouched) {
            try { & $RegisterProduct $InstalledRoot | Out-Host }
            catch {
                throw (
                    "Uninstall failed: $($Failure.Exception.Message); " +
                    "product registration restore failed: $($_.Exception.Message)")
            }
        }
        throw $Failure
    }
    return $Purge
}

function Get-KdbgSetupContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]$script:KdbgSetupContract
}

function Get-KdbgSetupPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Action
    )

    if ($Action -notin $script:KdbgSetupContract.Actions) {
        throw "Unsupported KDBG setup action: $Action"
    }

    $Phases = if ($Action -eq "Uninstall") {
        @(
            "VerifyInstalledPackage",
            "RemoveDriverServices",
            "UnregisterProduct",
            "ScheduleVerifiedPackagePurge")
    } else {
        @(
            "VerifySourcePackage",
            "StagePackage",
            "VerifyStagedPackage",
            "CommitPackage",
            "InstallOrRepairDriverPair",
            "RegisterProduct")
    }

    return [pscustomobject]@{
        Schema = $script:KdbgSetupContract.Schema
        Action = $Action
        MutatesDriverServicesOnlyThroughPackageLifecycle = $true
        RequiresDedicatedVmConfirmation = $true
        RequiresSnapshotConfirmation = $true
        Phases = $Phases
    }
}

function ConvertTo-KdbgCommandLineArgument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -eq 0) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    # CommandLineToArgvW-compatible quoting. Backslashes immediately before a
    # quote (and trailing backslashes before the closing quote) are doubled.
    $Builder = [Text.StringBuilder]::new()
    [void]$Builder.Append('"')
    $Backslashes = 0
    foreach ($Character in $Value.ToCharArray()) {
        if ($Character -eq '\') {
            $Backslashes++
            continue
        }
        if ($Character -eq '"') {
            [void]$Builder.Append(('\' * ($Backslashes * 2 + 1)))
            [void]$Builder.Append('"')
            $Backslashes = 0
            continue
        }
        if ($Backslashes -gt 0) {
            [void]$Builder.Append(('\' * $Backslashes))
            $Backslashes = 0
        }
        [void]$Builder.Append($Character)
    }
    if ($Backslashes -gt 0) {
        [void]$Builder.Append(('\' * ($Backslashes * 2)))
    }
    [void]$Builder.Append('"')
    return $Builder.ToString()
}

Export-ModuleMember -Function @(
    "Get-KdbgSetupContract",
    "Get-KdbgSetupPlan",
    "ConvertTo-KdbgCommandLineArgument",
    "Invoke-KdbgSetupFileTransaction",
    "Invoke-KdbgSetupUninstallTransaction")

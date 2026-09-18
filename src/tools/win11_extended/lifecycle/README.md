# Win11 extended lifecycle, soak, and benchmark runner

This directory adds the optional Win11 gates without weakening or replacing the
required-core Win11 harness. It consumes an already generated, hash-bound
`out/win11-validation/<epoch>` workspace and refuses to run unless that
workspace passes `Test-KdbgWin11ValidationWorkspace`.

The live runner binds all mutable work to an exact Hyper-V VM GUID and exact
checkpoint name/GUID pair. It imports a current-user DPAPI `PSCredential`, but
never serializes the credential or its path into evidence. Every run restores
the exact checkpoint in `finally` and verifies the final VM state is `Off`.

## What the final run does

- Two lifecycle cycles, each with install, five stop/start pairs, same-path
  repair, update, technical rollback, forward update, uninstall, and clean
  inventory.
- Four guest reboot boundaries: installed and clean boundaries in each cycle.
- A separate 1,800-second soak with exactly 61 read-only reports, eight reads
  per report (488 scheduled reads), one midpoint Probe write/read-back/reload/
  rollback transaction, and a final locked write gate.
- Seven separate mock-core benchmark processes with preserved raw JSON and
  median/nearest-rank-p95 aggregation. These are not claimed as live-driver or
  GUI timings.

No live result is produced by the static test or `-DryRun`.

## Static test (does not query or mutate a VM)

```powershell
pwsh -NoLogo -NoProfile -File `
  .\src\tools\win11_extended\lifecycle\Test-Win11ExtendedLifecycle.Contract.ps1
```

## Resolve the required pins

Replace every `<...>` placeholder with an exact value. The previous archive is
a distinct technical lifecycle fixture, not a published rollback release.

```powershell
$workspace = '<D:\KDBG\out\win11-validation\exact-epoch>'
$previousZip = '<D:\KDBG\out\lifecycle-closeout\KDBG-previous-candidate-win-x64.zip>'
$previousCert = '<D:\KDBG\out\certificates\KDBG-Disposable-VM-Test.cer>'
$benchmark = '<D:\KDBG\out\build\windows-release\benchmarks\kdbg_benchmarks.exe>'

$previousZipSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $previousZip).Hash.ToLowerInvariant()
$previousCertSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $previousCert).Hash.ToLowerInvariant()
$benchmarkSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $benchmark).Hash.ToLowerInvariant()
```

## Read-only preflight

This validates the workspace/package/certificate/benchmark pins, decrypts the
DPAPI credential for type checking, and resolves the exact VM/checkpoint. It
does not start, stop, reboot, restore, or stage into the VM.

```powershell
$common = @{
  WorkspaceRoot = $workspace
  VmId = [Guid]'<exact-vm-guid>'
  CheckpointName = '<exact-checkpoint-name>'
  CheckpointId = [Guid]'<exact-checkpoint-guid>'
  CredentialPath = '<C:\Users\you\AppData\Local\KDBG\secrets\guest.credential.clixml>'
  PreviousPackageZipPath = $previousZip
  ExpectedPreviousPackageSha256 = $previousZipSha
  PreviousCertificatePath = $previousCert
  ExpectedPreviousCertificateSha256 = $previousCertSha
  BenchmarkExecutablePath = $benchmark
  ExpectedBenchmarkSha256 = $benchmarkSha
  ConfirmDisposableVm = $true
  ConfirmCheckpointRestore = $true
}

& .\src\tools\win11_extended\lifecycle\Invoke-Win11ExtendedLifecycle.ps1 `
  @common -DryRun
```

## 60-second calibration soak

This is an actually live but explicitly non-final calibration. It skips the
lifecycle and benchmark gates, schedules seven reports (56 reads), still runs
the midpoint verified transaction, cleans the guest, restores the exact
checkpoint, and leaves the VM off.

```powershell
& .\src\tools\win11_extended\lifecycle\Invoke-Win11ExtendedLifecycle.ps1 `
  @common -SkipLifecycle -SkipBenchmarks `
  -SoakDurationSeconds 60 -AllowCalibrationDuration
```

## Final full run

Omitting soak overrides is deliberate: the final contract is fail-closed at
1,800 seconds, 61 reports, and 488 scheduled reads.

```powershell
& .\src\tools\win11_extended\lifecycle\Invoke-Win11ExtendedLifecycle.ps1 @common
```

Live evidence is written below the input workspace at
`extended-runs/extended-<UTC>-<nonce>/`. A failed run remains failed even when
checkpoint restoration succeeds; inspect `host-summary.json` and the guest
evidence archive separately.

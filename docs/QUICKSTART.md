# KDBG 1.1.0 quick start

The product target is the local physical RAM of the bare-metal Windows x64
`runtime_host` where KDBG and its driver execute. RawPfn read/write is a normal
product path. Select `-TargetProfile LocalHost` for that path; it does not use
VM/snapshot confirmation flags. Select `-TargetProfile DisposableVm` plus both
confirmations for the separate regression lane. Source availability does not
promote either live gate without target-bound execution evidence. The package
does not change boot or Code Integrity policy.

`LocalHost` is the product default; the examples below still specify it
explicitly so command logs preserve the intended target role.

For a controlled development host that intentionally uses the disposable
test-signed driver pair, the test-signed derivative also contains
`KDBGSetup-Test.exe`. It is a separate, administrator-only flow: it verifies
the public `certificate/KDBG-TestSigning.cer`, installs that certificate in the
machine `Root` and `TrustedPublisher` stores, enables Windows test-signing,
and schedules a reboot before resuming the LocalHost install. It never ships
the PFX/private key, never claims production trust, and must not be used as a
commercial distribution. The normal `KDBGSetup.exe` does not change boot or
Code Integrity policy.

1. Verify both main and symbols ZIP SHA-256 sidecars, extract them as sibling
   directories, and keep the names `KDBG-1.1.0-win-x64` and
   `KDBG-1.1.0-win-x64-symbols` unchanged.
2. Run `KDBGSetup.exe`, accept the UAC prompt, select the `LocalHost` target
   profile, then choose **Install**. Setup verifies
   the package and trusted driver signatures, stages the product under
   `%ProgramFiles%\KDBG\Product`, starts the driver pair through the packaged
   transactional lifecycle, and registers Windows Apps & Features plus a Start
   Menu shortcut.

3. The explicit PowerShell path remains available for diagnostics, automation,
   and recovery:

```powershell
.\tools\diagnose.ps1 -VerifyPackage -RequireAdministrator
python .\tools\validate_release.py
.\tools\install.ps1 -TargetProfile LocalHost
.\tools\start.ps1 -TargetProfile LocalHost
.\tools\run.ps1 -TargetProfile LocalHost
```

The regression_guest variant is explicit and separate:

```powershell
.\tools\install.ps1 -TargetProfile DisposableVm -ConfirmDedicatedVm -ConfirmSnapshot
.\tools\start.ps1 -TargetProfile DisposableVm -ConfirmDedicatedVm -ConfirmSnapshot
.\tools\run.ps1 -TargetProfile DisposableVm -ConfirmDedicatedVm -ConfirmSnapshot
```

Run Setup from a newly extracted, validated package to use **Update**. Its
stable Program Files destination permits later versions to replace and roll
back the same product root instead of leaving version-named directories.

`diagnose.ps1` checks package hashes, required binaries/runtime, signature
status, service type/state, and package-path binding. With `-RequireRunning` it
also opens both device names using the same readiness rule as the developer
driver manager. A displayed signature status is an observation, not a
production-trust claim.

When run from the immutable package with no arguments, the packaged Python
validator infers the current main directory and its sibling
`KDBG-1.1.0-win-x64-symbols` directory and validates them as one pair.
It also requires the packaged security, support, privacy, license/EULA,
update/rollback, vulnerability-intake, and release-note documents; deleting or
replacing one invalidates `SHA256SUMS.txt` and the release contract.

`start.ps1` then runs the packaged live verifier in read-only mode inside the
startup rollback transaction. It retains the latest ABI/Probe readiness result
at `%LOCALAPPDATA%\KDBG\readiness\start-latest.json`; a failed ABI 7 check,
short Probe page, runtime identity check, or open final gate rolls back only
the services started by that attempt.

The package also includes a non-interactive live verifier. Its default mode is
read-only and records the ABI, Probe PFN, exact 4096-byte reads, session state,
and median/p95 latency. Evidence is written outside the immutable package:

```powershell
$EvidenceRoot = Join-Path $env:LOCALAPPDATA "KDBG\evidence"
New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
$FixtureInfo = Join-Path $EvidenceRoot "fixture-startup.json"
$Fixture = Start-Process -FilePath ".\tools\kdbg_process_fixture.exe" `
  -RedirectStandardOutput $FixtureInfo -PassThru -WindowStyle Hidden
$ReviewTemplate = Join-Path $EvidenceRoot "scene-review.template.json"
.\tools\capture_demo.ps1 -Executable .\KDBG.exe `
  -SceneReviewTemplate $ReviewTemplate -Reviewer "<reviewer-name-or-handle>" `
  -ConfirmDedicatedVm -ConfirmSnapshot -ConfirmFixtureReset
.\tools\kdbg_live_verify.exe `
  --output (Join-Path $EvidenceRoot "read-only.json") --build-id KDBG-1.1.0
```

After recording the current Probe PFN and the VM snapshot identifier, the
controlled write transaction is one explicit command:

```powershell
.\tools\kdbg_live_verify.exe --write --confirm-disposable-vm `
  --snapshot-id "<current-checkpoint-id>" --confirm-probe-pfn "<current-pfn>" `
  --output (Join-Path $EvidenceRoot "probe-write-rollback.json") `
  --build-id KDBG-1.1.0
```

It applies one eight-byte Probe edit, verifies the entire page, performs an
independent reload, restores all 4096 baseline bytes, independently reads the
page again, and exits nonzero unless the final session reports the gate locked.
The verifier never installs or starts either driver. Restore the named snapshot
after a write-mode run. Omitting `--output` also uses
`%LOCALAPPDATA%\KDBG\evidence`; a path inside the validated package is rejected
before either device is opened.

After the GUI has exported its completed transaction, keep the verifier report,
reviewed command log, and the legacy v4 evidence GIF in that same exported directory.
Start the packaged dedicated fixture first, retain its startup JSON outside the
package, and attach the exact PID printed by that same run. Complete the GUI
process write/Freeze, ownership, page-table, process-vs-physical 4096-byte read,
and Kernel Explorer workflow against that fixture. Its VA/PFN must be distinct
from KDbgProbe. The GUI exports `analysis_metadata.json` plus every hash-bound
raw file into a separate `analysis-*` directory. Copy those files without
overwriting anything into the completed Probe `live-*` session, because every
v4 reference is a sibling-only filename. Then create and validate the final v4
bundle with one complete command:

```powershell
$PackageRoot = (Get-Location).Path
$SymbolsRoot = (Resolve-Path "..\KDBG-1.1.0-win-x64-symbols").Path
$Session = "<full GUI live-* evidence directory>"
$AnalysisSession = "<full GUI analysis-* evidence directory>"
Get-ChildItem -LiteralPath $AnalysisSession -File | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Session $_.Name)
}
$SceneReview = Join-Path $Session "scene-review.json"
Move-Item -LiteralPath $ReviewTemplate -Destination $SceneReview
.\tools\new_live_evidence.ps1 `
  -OutputPath (Join-Path $Session "kdbg-live-evidence-v4.json") `
  -PackageDirectory $PackageRoot -SymbolsDirectory $SymbolsRoot `
  -GuiMetadata (Join-Path $Session "metadata.json") `
  -AnalysisMetadata (Join-Path $Session "analysis_metadata.json") `
  -CommandLog (Join-Path $Session "commands.log") `
  -Video (Join-Path $Session "demo.gif") `
  -SceneReview $SceneReview `
  -LiveRunReport (Join-Path $Session "probe-write-rollback.json") `
  -DedicatedVmConfirmed -SnapshotConfirmed -ProbeTargetConfirmed `
  -WriteGateRelocked -PrivatePathsRedacted `
  -UnrelatedProcessDataRedacted -VideoReviewed -ConfirmRequiredScenes
```

Before running the legacy v4 generator, fill the scene-review JSON with the real GIF
filename/hash, review UTC time, both redaction confirmations, and an
observed millisecond range plus concrete note for each of its 20 ordered scene
IDs. Ranges must be non-overlapping, in order, and at least 500 ms each; the GIF
must contain at least 20 frames over at least 20 seconds. The generator derives PFN, PA, page hashes, Probe generation/CRC,
and the fixed edit from GUI metadata and cross-checks them against the live
report. The separately hash-bound analysis metadata binds the fixture INFO,
image, exact process/physical page pair, ownership, complete x64 entry chain,
and Kernel Explorer proof. The generator atomically publishes the JSON only
after paired package validation.

For the reproducible automated destructive-evidence transaction, query
KDbgProbe and open its PFN. RawPfn remains the general product path; the current
automated evidence generator does not verify that separate bare-metal gate.
In either case,
read exactly 4096 bytes, edit locally, review the diff, type the same PFN, and
apply once. Require the full read-back and independent reload to match, roll
back to the baseline, and confirm that the write gate is locked.

Stop and remove the services when finished:

```powershell
.\tools\stop.ps1
.\tools\uninstall.ps1 -ConfirmKdbgServices
```

The default uninstaller retains the extracted package and user data. For the
clean-guest release gate, remove only the verified package root and the exact
`%LOCALAPPDATA%\KDBG` directory with:

```powershell
.\tools\uninstall.ps1 -ConfirmKdbgServices -PurgePackage -PurgeUserData
```

Package self-removal completes after the uninstalling PowerShell process exits.
Restore the VM snapshot if a driver cannot be stopped or the guest no longer
has a known state.

`KDBGSetup.exe` provides the normal interactive uninstall path. It removes the
driver services and product registration, then deletes only the verified stable
product root after Setup exits. The package does not advertise a silent
uninstall mode.

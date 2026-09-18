# Win11 extended GUI capture harness

This directory is the reusable Hyper-V/PowerShell Direct capture path for the
Windows 11 extended GUI matrix. It is intentionally independent of the older
VMware/IP-specific evidence scripts.

`Invoke-HyperVWin11GuiOrchestrator.ps1` is the complete entry point. It binds an
exact VM/checkpoint Name+GUID, verifies the main ZIP, symbols ZIP, certificate,
source snapshot, and signer identity before mutation, restores and starts the
VM, stages and installs the package, discovers the live Probe PFN read-only,
creates a one-use interactive desktop, launches the current fixture, captures
evidence, cleans the guest, restores the same checkpoint, and proves final Off.
The older `Invoke-HyperVWin11GuiCapture.ps1` remains a lower-level entry point
for an already prepared/running guest.

The plan contains 24 PNG frames covering the validator's 20 scene families:
driver/Probe readiness, Probe PFN discovery, exact 4 KiB read, staged hex diff,
undo/redo, typed-PFN unlock, one-shot apply/read-back, independent reload,
rollback, PFN ownership, PTView, first/next process scan, verified Freeze and
restore, pointer scan, Zydis disassembly, snapshot diff, kernel module catalog,
symbol resolution, kernel read/disassembly, and About/version.

## Status boundary

`calibration.win11-1024x768-v1.json` is a reviewed coordinate profile for this
exact display/client geometry. Its `validated_build_id` records the build on
which the coordinates were last smoke-reviewed; it is provenance, not a claim
that later builds have already been reviewed. If layout or geometry changes,
reset the profile to `UNCALIBRATED_WIN11_SMOKE_REQUIRED`, run the
non-destructive calibration smoke, and record the reviewed build. Dry-run and
smoke results never claim evidence PASS; every full run reports
`CAPTURED_UNREVIEWED` until a person checks readability, redaction, and scene
meaning for that exact capture.

## Static/dry-run validation (does not connect to or start a VM)

```powershell
& .\src\tools\win11_extended\gui\Test-Win11ExtendedGuiHarness.ps1 `
  -OutputPath .\out\win11-extended-gui-static.json
```

Direct host-wrapper dry run:

```powershell
& .\src\tools\win11_extended\gui\Invoke-HyperVWin11GuiCapture.ps1 `
  -DryRun `
  -GuestPackageRoot 'C:\KDBG-Lab\rc1\KDBG-1.1.0-win-x64' `
  -HostEvidenceRoot .\out\win11-extended-gui-dryrun
```

Complete-orchestrator dry run also performs no VM operation:

```powershell
$h64 = 'a' * 64
$h40 = 'b' * 40
& .\src\tools\win11_extended\gui\Invoke-HyperVWin11GuiOrchestrator.ps1 `
  -DryRun -VMName 'KDBG-Win11-25H2' `
  -VMId '66935024-37f7-4f21-b2c8-12ca5fe677bf' `
  -CheckpointName 'KDBG-Win11-Clean-TestSigning-20260918' `
  -CheckpointId 'f60a775a-26f6-4ef9-bb19-f61c93346bb4' `
  -PackageZipPath 'D:\exact\KDBG-1.1.0-win-x64.zip' `
  -SymbolsZipPath 'D:\exact\KDBG-1.1.0-win-x64-symbols.zip' `
  -CertificatePath 'D:\exact\kdbg-test-signing.cer' `
  -ExpectedPackageSha256 $h64 -ExpectedSymbolsSha256 $h64 `
  -ExpectedCertificateSha256 $h64 -ExpectedSourceSnapshotSha256 $h64 `
  -ExpectedSignerThumbprint $h40 `
  -CredentialPath "$env:LOCALAPPDATA\KDBG\secrets\KDBG-Win11-25H2.credential.clixml" `
  -HostEvidenceRoot .\out\win11-extended-orchestrator-dryrun
```

## Complete calibration-smoke command

Use the hashes from the exact frozen artifacts, not values copied from an older
run. The VM must initially be Off. The caller can be elevated or an enabled
Hyper-V Administrators member as long as all required Hyper-V cmdlets succeed.

```powershell
$package = (Resolve-Path 'D:\exact\KDBG-1.1.0-win-x64.zip').Path
$symbols = (Resolve-Path 'D:\exact\KDBG-1.1.0-win-x64-symbols.zip').Path
$certificate = (Resolve-Path 'D:\exact\kdbg-test-signing.cer').Path
$packageSha = (Get-FileHash $package -Algorithm SHA256).Hash.ToLowerInvariant()
$symbolsSha = (Get-FileHash $symbols -Algorithm SHA256).Hash.ToLowerInvariant()
$certificateSha = (Get-FileHash $certificate -Algorithm SHA256).Hash.ToLowerInvariant()
$signer = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate).Thumbprint.ToLowerInvariant()
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($package)
try {
  $entry = $archive.Entries | Where-Object FullName -CEQ 'KDBG-1.1.0-win-x64/BUILD-METADATA.json'
  $reader = [IO.StreamReader]::new($entry.Open(), [Text.Encoding]::UTF8, $true)
  try { $sourceSha = ($reader.ReadToEnd() | ConvertFrom-Json).source_snapshot_sha256 }
  finally { $reader.Dispose() }
} finally { $archive.Dispose() }

& .\src\tools\win11_extended\gui\Invoke-HyperVWin11GuiOrchestrator.ps1 `
  -VMName 'KDBG-Win11-25H2' `
  -VMId '66935024-37f7-4f21-b2c8-12ca5fe677bf' `
  -CheckpointName 'KDBG-Win11-Clean-TestSigning-20260918' `
  -CheckpointId 'f60a775a-26f6-4ef9-bb19-f61c93346bb4' `
  -PackageZipPath $package -SymbolsZipPath $symbols -CertificatePath $certificate `
  -ExpectedPackageSha256 $packageSha -ExpectedSymbolsSha256 $symbolsSha `
  -ExpectedCertificateSha256 $certificateSha -ExpectedSourceSnapshotSha256 $sourceSha `
  -ExpectedSignerThumbprint $signer `
  -CredentialPath "$env:LOCALAPPDATA\KDBG\secrets\KDBG-Win11-25H2.credential.clixml" `
  -HostEvidenceRoot .\out\win11-extended-orchestrator `
  -CaptureMode calibration-smoke -InteractiveUser 'kdbgtest' `
  -ConfirmDisposableVm -ConfirmCheckpointRestore
```

The credential file remains on the host. Only an in-memory `PSCredential`
crosses PowerShell Direct; plaintext is never written to a harness file or log.
The guest places the password temporarily in the Winlogon value required by
AutoAdminLogon. A one-use SYSTEM startup task polls every 200 ms and removes
that value as soon as Explorer appears; the host independently verifies/removes
it and cleanup repeats removal. Exact checkpoint restore then discards the
entire guest run.

## Lower-level calibration smoke

Use this only when guest staging was intentionally handled elsewhere. The VM
must already be running at its clean snapshot with the `kdbgtest`
Explorer desktop open at exactly 1024x768, 100% scaling (96 DPI). The package,
drivers, KDbgProbe page, process fixture, and exact PDB must already be staged.
The host runner never starts or restores the VM itself.

```powershell
$fixture = Get-Content 'D:\evidence-input\fixture-info.json' -Raw | ConvertFrom-Json
$probe = Get-Content 'D:\evidence-input\probe-info.json' -Raw | ConvertFrom-Json

& .\src\tools\win11_extended\gui\Invoke-HyperVWin11GuiCapture.ps1 `
  -VMName 'KDBG-Win11-25H2' `
  -CredentialPath "$env:LOCALAPPDATA\KDBG\secrets\KDBG-Win11-25H2.credential.clixml" `
  -GuestPackageRoot 'C:\KDBG-Lab\rc1\KDBG-1.1.0-win-x64' `
  -HostEvidenceRoot .\out\win11-extended-gui-calibration-smoke `
  -ProbePfn ([uint64]$probe.pfn) `
  -FixturePid ([uint32]$fixture.pid) `
  -FixtureVirtualAddress ([uint64]$fixture.virtual_address) `
  -FixturePointerTarget ([uint64]$fixture.pointer_target_address) `
  -FixtureCodeAddress ([uint64]$fixture.x64_code_address) `
  -FixturePipeName ([string]$fixture.pipe_name) `
  -FixtureScanOffset ([string]$fixture.corpus.freeze_value) `
  -FixtureSnapshotOffset ([string]$fixture.corpus.aob) `
  -FixtureBaselineCrc32 ([string]$fixture.baseline_crc32) `
  -FixtureFreezeExpectedCrc32 ([string]$fixture.freeze_value_crc32) `
  -KernelPdbPath 'C:\KDBG-Lab\symbols\drivers\KDbgDriver.pdb' `
  -InteractiveUser 'kdbgtest' `
  -ConfirmDedicatedVm -ConfirmSnapshot -CalibrationSmoke
```

Review `01-driver-probe-ready.png` plus the recorded display/DPI/client values.
Every point and region in the calibration JSON remains a candidate for adjustment
until that review. Only after saving the reviewed calibration identity should the
same command be repeated without `-CalibrationSmoke` for the full 24-frame run.

Inputs that cannot be guessed or reused across boots are the fixture PID and
addresses, fixture pipe/offsets/CRCs, Probe PFN, guest package root, and exact PDB
path. Supply them from the current live session; never paste an old PID or PFN.

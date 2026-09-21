# Operator guide

## Preconditions and readiness

- Administrator PowerShell and supported test-signing configuration
- Package ZIP hash verified before extraction
- `tools/diagnose.ps1 -VerifyPackage -RequireAdministrator` passes
- Select and record the target role: bare-metal `runtime_host` for the product
  path, or `regression_guest` plus snapshot identity for the VM regression lane.
- `orchestrator_host` is lifecycle/evidence control only and is not an implicit
  memory target. Tools may automatically capture machine/boot/session values as
  evidence provenance or stale-backend-session diagnostics; operators do not
  confirm them and their absence does not block LocalHost RawPfn read/write.
- RawPfn is a normal product target. KDbgProbe is the default automated
  destructive-evidence target and does not limit RawPfn capability.

After installation, use `-RequireInstalled`; after start, use `-RequireRunning`:

```powershell
.\tools\diagnose.ps1 -VerifyPackage -RequireAdministrator -RequireInstalled
.\tools\diagnose.ps1 -VerifyPackage -RequireAdministrator -RequireRunning
```

Readiness means the packaged files and service registrations passed these
checks and both device names could be opened (or were exclusively held by the
single controller). `diagnose.ps1` alone is not an ABI transaction. A successful
`start.ps1` additionally produces the packaged verifier's read-only ABI 7,
runtime identity, exact Probe 4096-byte read, and final-gate-lock report at
`%LOCALAPPDATA%\KDBG\readiness\start-latest.json`. Neither result is physical-
write evidence.

## Lifecycle

The intended normal product path is the elevated `KDBGSetup.exe` UI on the
bare-metal runtime_host. It provides
Install/Repair/Update/Uninstall, uses the stable
`%ProgramFiles%\KDBG\Product` destination, and delegates driver mutations to the
same transactional package scripts below. Apps & Features and the Start Menu
point to the installed setup and GUI. The explicit script interface selects the
target profile directly.

The test-signed derivative has a deliberately separate `KDBGSetup-Test.exe`
entry point. Its manifest still requires an administrator token, and its
`tools/test_setup.ps1` wrapper verifies the public-only
`certificate/KDBG-TestSigning.cer`, installs it into the machine `Root` and
`TrustedPublisher` stores, enables test-signing, and resumes after a reboot.
The wrapper records exactly which stores and boot option it changed so test
uninstall can restore them. It is development-only; the PFX/private key is
never packaged and the normal Setup never changes Code Integrity policy.

`LocalHost` is the product default. The commands below pass it explicitly so
the evidence log is unambiguous:

```powershell
.\tools\install.ps1 -TargetProfile LocalHost
.\tools\start.ps1 -TargetProfile LocalHost
.\tools\run.ps1 -TargetProfile LocalHost
.\tools\stop.ps1
.\tools\uninstall.ps1 -ConfirmKdbgServices
```

Separate regression_guest lane:

```powershell
.\tools\install.ps1 -TargetProfile DisposableVm -ConfirmDedicatedVm -ConfirmSnapshot
.\tools\start.ps1 -TargetProfile DisposableVm -ConfirmDedicatedVm -ConfirmSnapshot
.\tools\run.ps1 -TargetProfile DisposableVm -ConfirmDedicatedVm -ConfirmSnapshot
.\tools\stop.ps1
.\tools\uninstall.ps1 -ConfirmKdbgServices
```

`run.ps1 -StartDrivers` starts an already installed package before launch.
`-StopDriversOnExit` stops both services after the GUI exits. Start order is
KDBG then KDBGProbe; stop order is reversed.

`LocalHost` does not require the VM/snapshot switches. `DisposableVm` requires
both confirmations. Source availability of either profile is not live evidence;
the corresponding target gate remains unverified until its exact command and
artifacts are recorded.

`install.ps1` also enforces that stop-before-rebind order itself. A repair or
update cannot skip the pair stop merely because the registered path already
matches the new package. If the pair was running, install reloads both services
and accepts the transition only after the packaged read-only verifier succeeds;
on failure it attempts to restore the captured SCM configuration and running
state.

Setup verifies source and staged package hashes plus driver catalog trust, refuses active
package processes and reparse-point package trees, atomically swaps the stable
product directory, and restores the prior directory and service binding if the
new lifecycle fails. Interactive uninstall schedules an identity-checked purge
after Setup and its script exit; no quiet-uninstall capability is advertised.
The lifecycle scripts distinguish `DistributionSource` (the immutable
`KDBG-1.1.0-win-x64` folder), Setup's internal exact
`%ProgramFiles%\KDBG\.staging-<32 lowercase hex>\Product` root, and
`InstalledProduct` (`%ProgramFiles%\KDBG\Product`). A backup directory is never
accepted as an execution root. If rollback cannot be fully verified, the
`.backup-<transaction>` directory remains intact for recovery.

Uninstall success in the Setup window means the synchronous service and product
registration phase succeeded; package deletion is still pending. Setup prints a
`PURGE_SCHEDULED` record with persistent JSON status and log paths under
`%ProgramData%\KDBG\Setup`. Treat removal as complete only when that JSON reports
`state: succeeded`; retain a `failed` status and its log for diagnosis. An
unarmed helper records `state: cancelled` and preserves Product when setup did
not finish removing registration and writing the exact commit marker.

## Physical transaction

For a RawPfn product transaction, record target kind, runtime-host identity,
PFN, physical address and containing local RAM range. Read exactly 4096 bytes
and retain the baseline. Review local edits, verify the full-page preflight
still matches, type the same PFN, apply once, require full-page read-back, and
retain rollback state.

For automated destructive evidence, additionally record Probe PFN, generation,
and CRC32. For v4 evidence, click `Stage Evidence Probe Pattern`; it XORs
the shared mask `4B 44 42 47 A5 5A 3C C3` into baseline offsets
`0x100..0x107` locally and issues no write. Review the one exact dirty run and
Undo/Redo, verify the preflight still matches the baseline, type the same PFN
to unlock one write, then issue one ABI 7 exact-page compare/write transaction.
The local `dirty_bytes` remains 8 for diff review while
`driver_transferred_bytes` is 4096. Require a full-page expected/read-back
match. Reload independently, query Probe CRC, perform verified
rollback, and check that the gate returned to LOCKED.

## Update and Migration

1. Close KDBG and save user-chosen address lists, snapshots, and command logs.
2. Copy `%LOCALAPPDATA%\KDBG` to a backup outside the package directory if UI
   layout or local diagnostic logs must be retained.
3. Stop the old package with its own `tools\stop.ps1`.
4. Verify and extract the new package without overwriting the old directory.
5. Run the new diagnostics. Then use its installer to rebind the stopped KDBG
   services to the new package and start them.
6. Reopen saved data deliberately. Loading an address list does not reactivate
   Freeze; review entries and the target PID before enabling writes.
7. Keep the old package and backup until the new package passes read-only
   readiness and the controlled Probe workflow.

AddressList text v1 and WatchList binary v1 are migrated when loaded and are
saved in v2 format; pointer paths are retained and persisted Freeze state is
always loaded disarmed. Snapshot compatibility remains version-checked rather
than rewritten automatically. The default uninstall preserves user-selected
paths and `%LOCALAPPDATA%\KDBG`. The commercial clean-guest command may add
`-PurgePackage -PurgeUserData`; those switches are restricted to the verified
package root and exact `%LOCALAPPDATA%\KDBG` child.

The normative offline channel, update transaction and rollback record are in
`UPDATE_AND_ROLLBACK.md`. Support scope is in `SUPPORT.md`; do not infer an SLA
or automatic updater from the lifecycle scripts.

## Recovery

If start or its packaged read-only verifier fails, `start.ps1` stops only the
services it started in that attempt and retains the failed readiness JSON.
If update diagnostics fail, stop the services, run the old package installer,
and verify `-RequireRunning`. If a driver remains
pending stop/deletion, reboot the active Windows target and retry removal. If
page read-back or rollback fails, perform no further writes and retain the log.
For a regression_guest run, restore the named snapshot.

## Evidence and privacy

Show only the fixture PID/name/VA. Hide notifications, private paths, unrelated
processes, usernames, and unrelated memory. The automated destructive-evidence
demonstration must show target role and runtime identity, Probe PFN discovery,
4096-byte physical read, local hex edit, diff review, typed PFN
unlock, one-shot apply, full read-back match, process/VA ownership evidence, and
the page-table walk. Keep the six raw page files, successful live-run JSON,
dedicated fixture `INFO` JSON, process/physical page pair, analysis metadata,
reviewed command log, video, and completed scene-review JSON beside the v4
evidence JSON; do not mark the
live gate PASS until the exact main/symbol package pair validates with all
hashes and runtime identities bound.

GUI raw-page export and the verifier's default JSON output are stored under
`%LOCALAPPDATA%\KDBG\evidence`, never under the extracted package. Keep the
validated package immutable; the verifier rejects an explicit package-local
output path before device access.

The packaged `PRIVACY.md`, `SECURITY.md`, and
`VULNERABILITY_DISCLOSURE.md` govern any diagnostic or evidence shared outside
the VM. The project license and no-separate-EULA decision are recorded in
`LICENSE_AND_EULA.md` beside the bundled license notices.

For legacy `kdbg.live-evidence.v4` compatibility, run
`tools\new_live_evidence.ps1` from the package root using the exact
`-GuiMetadata`, `-AnalysisMetadata`,
reviewed command log/GIF, and successful `kdbg.live-verify.v1` report from the
same exported `live-*` directory. All inputs and the output JSON must be sibling
files. This GIF is a validator input, not the current 1.1.0 submission artifact;
the 1.1.0 submission deliverable remains MP4-only. The scene review must bind
the GIF hash and record the real reviewer,
UTC review time, redaction decisions, and an observed time range plus concrete
note for every ordered scene. The complete invocation is in
`docs\QUICKSTART.md`; the
generator refuses missing confirmations, reused Probe/fixture targets,
mismatched translation or fixture identity, invalid GIF structure, stale
package/symbol identity, or an output inside the immutable package. Launch
`tools\kdbg_process_fixture.exe`, retain its startup JSON outside the package,
and attach the exact PID from that run; see `PROCESS_FIXTURE.md`.

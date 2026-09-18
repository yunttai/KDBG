# Troubleshooting

Begin with the non-mutating package check:

```powershell
.\tools\diagnose.ps1 -VerifyPackage -RequireAdministrator
```

Use `-RequireInstalled` after install and `-RequireRunning` after start. Resolve
the first reported failure before changing a service.

## Package hash or metadata failure

Do not install. Re-extract the ZIP whose SHA-256 sidecar was verified. The
manifest covers every packaged file except `SHA256SUMS.txt` itself; local files
added inside the extracted directory also fail the coverage check.

## Service points to another package

Close KDBG, run the old package's `tools\stop.ps1`, verify
the new package, and run its installer. Lifecycle
scripts refuse to stop or remove a same-named service whose binary path belongs
to another package.

## Driver start or device open failure

Check Administrator execution, service state, the supported test-signing
configuration, signature status, Event Viewer CodeIntegrity entries, HVCI
compatibility, device symbolic links, and matching user/kernel ABI. Do not use
a Code Integrity bypass. A SYS/CAT file or a reported signature status does not
by itself prove that the driver loaded.

## ABI mismatch

Stop and remove the previous package, clean-build GUI/bridge and both drivers
from one source snapshot, package again, then reinstall. Do not mix binaries
from different package directories.

The latest startup report is
`%LOCALAPPDATA%\KDBG\readiness\start-latest.json`. It also records the packaged
verifier identity and the two running driver service identities; preserve it
before reinstalling when diagnosing a mismatch.

## Short 4096-byte physical read

Record requested and completed lengths and the physical-range boundary. Never
present a partial read as a loaded editable page.

## Write attempt fails

Check typed PFN/PID confirmation, one-shot gate state, acknowledgement, owner
handle, transfer size, physical range, preflight baseline, and backend result.
Do not retry blindly.

## Read-back or rollback mismatch

Perform no additional writes. Save the mismatch offsets and log, confirm the
target is KDbgProbe, attempt only the explicit verified rollback, and restore
the disposable VM snapshot if the baseline cannot be recovered.

## PFN ownership has no result

The PFN may be free, standby, prototype, shared, outside the selected-process
mapping bound, or observed through an unavailable/stale optional MemProcFS
backend. Record the bridge error separately and use the bounded selected-process
fallback; this does not change the physical read result.

## Page-table result differs

Check selected PID lifetime, canonical VA, CR3/DTB and PCID masking, LA57,
large-page handling, present/transition/prototype flags, and each entry physical
address. Ownership PFN and final translated PFN must agree in live evidence.

## Update or uninstall recovery

If stop times out, close the GUI and other controller handles, retry stop, then
reboot the guest. If a service is pending deletion, reboot before reinstalling.
The uninstaller retains `%LOCALAPPDATA%\KDBG` and user-selected address lists or
snapshots. Restore those only after package readiness passes; Freeze remains off
until explicitly reviewed and enabled.

## Hex editor callback causes an IOCTL per cell

This is an invalid integration. `WriteFn` may update only the local working
copy. The Apply command is the only path that may perform the physical write.

## Build dependency download failure

Confirm that immutable commits in `THIRD_PARTY.lock.json` match the `GIT_TAG`
values in `src/cmake/Dependencies.cmake`. Do not claim an offline/vendor mode
that the build does not implement; add and document explicit CMake source/cache
overrides before using one.

## Release package validator failure

Resolve the first failure from packaged `tools/diagnose.ps1 -VerifyPackage` or
repository `validate_release.py --windows-package` before installation. Common
causes include Debug CRT imports, x64/version mismatch, missing hash/SBOM/license
coverage, PDB leakage into the main package, private paths, or invalid lifecycle
PowerShell syntax.

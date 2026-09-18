# KDBG update and rollback contract

## Update channel

KDBG 1.1.0 uses a manual, offline update channel. There is no automatic update
check or background downloader. A release is one immutable main ZIP, one
matching symbols ZIP, their SHA-256 sidecars, release notes, and a published
gate state. Production distribution additionally requires Authenticode trust;
SHA-256 integrity alone is not publisher authentication.

Before an update, retain the previous extracted package and both ZIPs. Verify
the new `SHA256SUMS.txt` files and ZIP sidecars, confirm matching
`source_snapshot_sha256` and `tool_versions` in both `BUILD-METADATA.json`
files, then run `tools/diagnose.ps1 -VerifyPackage`.

The normal product update path is to launch `KDBGSetup.exe` from the newly
extracted package, confirm the dedicated VM and snapshot, and choose **Update**.
Setup verifies source and staged packages, replaces the stable
`%ProgramFiles%\KDBG\Product` directory, delegates the driver transition to the
packaged lifecycle, and restores the prior product directory and service
binding if the transition fails. The explicit procedure below remains the
operator recovery path.

The source package must keep its exact `KDBG-1.1.0-win-x64` directory name.
Only Setup may use its exact `.staging-<32 lowercase hex>\Product` root, and
installed lifecycle calls explicitly use `InstalledProduct` at the single
`%ProgramFiles%\KDBG\Product` path. A failed rollback preserves the last
known-good `.backup-<transaction>` directory instead of deleting it.

## Update procedure

1. Restore or create the named disposable-VM snapshot.
2. Run `tools/stop.ps1` and confirm both KDBG services are stopped.
3. Extract the new main and symbols packages into new versioned source
   directories; never overwrite the retained previous distribution in place.
4. Run `tools/install.ps1` to update the service paths, then
   `tools/start.ps1` and `tools/diagnose.ps1 -RequireRunning`.
5. Re-run the read-only readiness checks before any Probe transaction.

The installer records the previous service configuration and restores it when
an update fails before commit. As a defense against a same-path repair hashing
new files while an old driver image is still loaded, the installer always
stops/confirms-absent KDBGProbe and then KDBG before changing either service.
If either service was running, it reloads and read-only-verifies the complete
new pair before reporting success. A failed pair transition restores each
available original SCM path/type/start/display configuration and running state.
It does not delete the retained package or user data during a normal update.
The product Setup additionally keeps the installed destination stable across
versions, so Apps & Features, shortcuts, and service paths do not accumulate
version-named Program Files directories.

## Rollback procedure

Stop both services, run the retained previous package's installer, start its
services, and verify its exact hashes and ABI. Restore the VM snapshot if the
guest bugchecked, a driver could not unload, service state is ambiguous, or a
write/read-back/rollback check failed. Never continue a physical write after a
verification mismatch.

Record the failed and restored package hashes, commands, service paths, exit
codes, and final locked state. The release is not commercial-ready until this
update and rollback procedure passes on a clean supported guest.

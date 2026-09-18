# KDBG support policy

## Published support route

The public support intake for KDBG is the repository issue chooser:

- Support URL: https://github.com/yunttai/KDBG/issues/new/choose
- Private security URL: https://github.com/yunttai/KDBG/security/advisories/new
- Repository: https://github.com/yunttai/KDBG
- Assigned release owner: `yunttai`

Repository issues are enabled. Use the KDBG support request template and include
the product version, main and symbols ZIP SHA-256 values, Windows build, VM
snapshot identifier, exact failing command, reproduction steps, and redacted
diagnostics. Security defects and any report containing exploit details must not
be filed through the public support route; use the private route in
`VULNERABILITY_DISCLOSURE.md`.

Publishing this URL does not by itself prove monitored operations. Notification
delivery and an end-to-end submission/acknowledgement drill have not yet been
verified. Until both are recorded by the commercial-operations evidence gate,
the monitored support operation remains incomplete and the product must not be
labelled commercial-ready.

## Supported scope

KDBG 1.1.0 supports the validated `KDBG-1.1.0-win-x64` main and symbols
package pair on Windows x64 build 19041 or newer. Driver-backed operation is
supported only in an owned, disposable VM with Administrator access, a
restorable snapshot, and a driver-signing configuration accepted by that
guest. Optional MemProcFS acquisition is a separately supplied integration and
is not part of the base support promise.

Support covers package hash verification, install/start/stop/uninstall
lifecycle, ABI and device readiness, KDbgProbe transactions, PFN ownership and
page-table diagnostics, crash triage, and rollback to a previously retained
package. It does not cover arbitrary host PFNs, signing bypasses, third-party
acquisition drivers, or recovery of a guest that had no usable snapshot.

## Support lifecycle

Each request must identify the KDBG version, main and symbols ZIP SHA-256,
Windows build, VM snapshot identifier, and the exact failing command. Run
`tools/diagnose.ps1 -VerifyPackage` and attach its redacted output. For a load
or runtime failure, also include service state and the relevant local KDBG log.
Do not attach unrelated process memory or an unredacted crash dump.

Only the latest published package pair and the immediately preceding retained
pair are eligible for update/rollback support. A package is supported only
while its hashes and release notes remain published by the release owner.
There is currently no paid SLA or automatic remote support channel. The route
above is published and assigned, but commercial readiness additionally requires
verified notification delivery and an acknowledgement drill; source-complete
or package validation cannot substitute for that operational evidence.

Security-sensitive reports follow `VULNERABILITY_DISCLOSURE.md`, not a public
issue containing exploit details or memory contents.

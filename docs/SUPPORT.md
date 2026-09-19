# KDBG support policy

## Published support route

The public support intake for KDBG is the repository issue chooser:

- Support URL: https://github.com/yunttai/KDBG/issues/new/choose
- Private security URL: https://github.com/yunttai/KDBG/security/advisories/new
- Repository: https://github.com/yunttai/KDBG
- Assigned release owner: `yunttai`

Repository issues are enabled. Use the KDBG support request template and include
the product version, main and symbols ZIP SHA-256 values, Windows build, target
role, exact failing command, reproduction steps, and redacted diagnostics.
Diagnostics may include automatically collected machine/boot/session provenance
when available; users do not manually confirm it and its absence does not
exclude LocalHost RawPfn support. Security defects and any report containing exploit details must not
be filed through the public support route; use the private route in
`VULNERABILITY_DISCLOSURE.md`.

Publishing this URL does not by itself prove monitored operations. Notification
delivery and an end-to-end submission/acknowledgement drill have not yet been
verified. Until both are recorded by the commercial-operations evidence gate,
the monitored support operation remains incomplete and the product must not be
labelled commercial-ready.

## Supported scope

KDBG's product scope is the local system physical RAM of the bare-metal Windows
`runtime_host` where `KDBG.exe` and `KDbgDriver.sys` execute. Raw PFN read/write
is a normal product path; `orchestrator_host` is control/evidence only and
`regression_guest` is a separate VM regression lane. Administrator access and a
driver-signing configuration accepted by that Windows installation are required
for driver-backed operation. Optional MemProcFS acquisition is a separately
supplied integration and is not part of the base support promise.

Current 1.1.0 package/live evidence remains bound to the named historical VM
candidates. Bare-metal runtime-host read-only, Probe-write evidence, and RawPfn
capability gates are not yet complete, so those historical results must not be
presented as bare-metal support evidence.

Support covers package hash verification, install/start/stop/uninstall
lifecycle, ABI and device readiness, RawPfn and KDbgProbe transactions, PFN
ownership and page-table diagnostics, crash triage, and rollback to a
previously retained package. Historical VM evidence covers only its exact
candidate and lane; pending bare-metal gates are reported as pending rather
than inferred. Signing bypasses and third-party acquisition drivers are not
part of the current implementation.

## Support lifecycle

Each request must identify the KDBG version, main and symbols ZIP SHA-256,
Windows build, target role, and the exact failing command. A regression-guest
report should include its snapshot identifier. Automatically collected
machine/boot/session provenance is optional diagnostic context, not a support
precondition. Run
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

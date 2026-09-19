# Security

KDBG targets the local physical RAM of the Windows x64 `runtime_host` where
`KDBG.exe` and `KDbgDriver.sys` run. `LocalHost` is the ordinary product
profile; the separate `DisposableVm` profile exists for regression evidence.
Driver installation and service operations require Administrator privileges.
KDbgProbe is the default reproducible evidence target, not a restriction on
manual `RawPfn` editing. A RawPfn transaction uses the PFN entered by the
operator after the driver confirms that the exact 4 KiB page is in current
system RAM; PTView/process provenance is optional context, not a prerequisite.

The driver and UI write gates are independent and default locked. Physical
writes require typed PFN confirmation, preflight conflict detection, dirty-run
writes, immediate relock, and a full 4096-byte read-back. Process writes use a
separate PID confirmation. Loading an address table never rearms Freeze.

Read-only module enumeration, symbol lookup, translation, disassembly and scans
do not require confirmation prompts. Do not layer additional modal policy over
those hot paths. The existing typed target confirmation belongs to the write
transaction itself; lifecycle progress and cancellation are operational state,
not a second write-authorization flow.

Do not use signing bypasses, vulnerable-driver loaders, injection, stealth,
anti-cheat evasion, kernel-virtual writes, or credential collection. Preserve
failure logs and do not label an unexecuted or failed live gate PASS.

## Vulnerability intake

Report security defects through the private GitHub Security Advisory intake:

- Private advisory URL: https://github.com/yunttai/KDBG/security/advisories/new
- Repository: https://github.com/yunttai/KDBG
- Assigned security owner: `yunttai`

Private vulnerability reporting is enabled. Follow
`VULNERABILITY_DISCLOSURE.md` and include the affected version, main and symbols
ZIP SHA-256 values, Windows build, reproduction steps, and redacted logs. Do not
attach credentials, unrelated process memory, or unredacted crash dumps. Public
reports must not include exploit details before coordinated disclosure.

The public repository currently has issues, private vulnerability reporting,
secret scanning, secret-scanning push protection, vulnerability alerts, and
Dependabot security updates enabled. These repository settings strengthen the
intake boundary but do not prove that a human received or acknowledged a report.

The route and owner are configured, but notification delivery and an
end-to-end private submission/acknowledgement drill have not been verified.
Those are separate fail-closed commercial-operations gates; this source policy
does not assert that monitored security operations are already PASS.

Production signing is an independent release gate. A generated CAT file or
SHA-256 sidecar is not publisher trust, and this project does not use a signing
bypass or vulnerable-driver loader as a substitute.

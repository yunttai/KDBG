# Security

KDBG is restricted to an owned, disposable Windows x64 research VM with a
restorable snapshot. Run driver operations as Administrator only after both
conditions are confirmed. KDbgProbe is the default reproducible demo target.
A non-Probe physical transaction must use the exact 4 KiB PFN produced by the
current PTView mapping for the selected process/VA; an unknown PFN is not a
verified editor target.

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
failure logs, restore the snapshot after a bugcheck or mismatch, and do not
label the live gate PASS.

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

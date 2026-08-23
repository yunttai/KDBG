# Security

KDBG is restricted to an owned, disposable Windows x64 research VM with a
restorable snapshot. Run driver operations as Administrator only after both
conditions are confirmed. Start live writes on the KDbgProbe fixture PFN only.

The driver and UI write gates are independent and default locked. Physical
writes require typed PFN confirmation, preflight conflict detection, dirty-run
writes, immediate relock, and a full 4096-byte read-back. Process writes use a
separate PID confirmation. Loading an address table never rearms Freeze.

Do not use signing bypasses, vulnerable-driver loaders, injection, stealth,
anti-cheat evasion, kernel-virtual writes, or credential collection. Preserve
failure logs, restore the snapshot after a bugcheck or mismatch, and do not
label the live gate PASS.

Report defects privately to the repository owner with the affected version,
reproduction steps, and redacted logs. Do not attach memory dumps containing
unrelated process data.

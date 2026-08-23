# User guide

The Physical Memory panel accepts decimal or hexadecimal PFNs. Read loads one
4 KiB page into separate baseline and working buffers. Editing, Undo, Redo, and
local revert do not write the kernel. Apply is enabled only after diff review
and typed PFN confirmation; it performs preflight, dirty-run write, relock, and
full read-back verification.

Process tools require explicit attach. The scanner supports numeric, floating,
text, and wildcard AOB values plus First/Next comparisons. Address tables are
PID-bound and loaded Freeze entries remain disarmed. Pointer Scan, Zydis
disassembly, snapshots, PFN Ownership, and Page Tables use the same selected target.

Treat CONFLICT, SHORT I/O, or VERIFICATION FAILED as a failed transaction. Do
not retry writes until the cause is understood; restore the VM snapshot if needed.

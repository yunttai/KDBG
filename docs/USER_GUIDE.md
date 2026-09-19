# User guide

## UI language

KDBG ships as one executable. Use the always-visible `Language / 언어` menu to
switch between `English` and `한국어`; the choice takes effect on the next frame
and is restored on the next launch. Korean mode translates ordinary actions and
guidance while retaining debugger terms such as PFN, PID, VA/PA, PTE, ABI,
CRC32, Read-back, Snapshot, and Disassembly where those names are clearer.

KDBG uses an installed Windows Korean font. If none can be loaded, the Korean
item is disabled and the UI remains in English instead of rendering missing
glyphs. Changing language does not reconnect a backend, change a target, alter
staged bytes, or arm/lock any write gate.

The Physical Memory panel accepts decimal or hexadecimal PFNs. Read loads one
4 KiB page into separate baseline and working buffers. Editing, Undo, Redo, and
local revert do not write the kernel. Apply is enabled only after diff review
and typed PFN confirmation; it performs preflight, one ABI 7 exact 4 KiB
compare/write transaction, relock, and full read-back verification. Dirty runs
describe the local diff only: `dirty_bytes` is the edited byte count while
`driver_transferred_bytes` is 4096 on a successful physical transaction.

Process tools require explicit attach. The scanner supports numeric, floating,
text, and wildcard AOB values plus First/Next comparisons. Address tables are
PID-bound and loaded Freeze entries remain disarmed. Pointer Scan, Zydis
disassembly, snapshots, PFN Ownership, and Page Tables use the same selected target.

Treat CONFLICT, SHORT I/O, or VERIFICATION FAILED as a failed transaction. Do
not retry writes until the cause is understood; restore the VM snapshot if needed.

# Operator guide

## Preconditions

- Owned disposable Windows x64 VM and confirmed snapshot
- Administrator PowerShell
- Release package hash verification completed
- KDbgProbe fixture selected before any physical write

## Safe physical transaction

Record Probe PFN, physical address, generation, and CRC32. Read 4096 bytes and
retain the baseline. Hex/ASCII edits remain local. Review dirty runs and Undo/
Redo, verify preflight still matches baseline, type the same PFN to unlock one
write, apply only dirty runs, and require a full-page expected/read-back match.
Reload independently, query Probe CRC, then perform verified rollback and check
the gate returned to LOCKED.

## Analysis panels

Attach only the fixture process. First/Next Scan, address-list write/Freeze,
pointer scan, disassembly, and snapshots operate on that explicit target. PFN
ownership may use the isolated optional MemProcFS bridge or the bounded
selected-process fallback. Page Tables must show each walk level and final PA/PFN.

## Evidence and privacy

Show only the fixture PID/name/VA. Hide notifications, private paths, unrelated
processes, usernames, and memory content not needed by the assignment. Keep the
command log and video beside the v2 evidence JSON and validate their hashes.

# Demonstration script

Record the Release build in the disposable snapshot VM. Keep only fixture data visible.

1. Show About/version and Driver/Probe ready with WRITE LOCKED.
2. Query Probe automatically and show PFN, PA, generation, and baseline CRC.
3. Read 4096/4096 bytes, edit 4–16 bytes, show diff, Undo, and Redo.
4. Show preflight, type the same PFN, use the one-shot unlock, and Apply.
5. Hold full read-back PASS on screen, reload independently, and show changed Probe CRC.
6. Roll back, show baseline CRC/read-back restored, and show WRITE LOCKED.
7. Show PFN owner PID/fixture name/VA/PTE and the VA-to-PA page-table walk.
8. Show First/Next Scan, Address List with verified Freeze, Pointer Scan,
   Zydis disassembly, and Snapshot Diff.
9. Stop/remove services and retain the redacted command log.

Review the video for all 17 v2 scene identifiers, readable values, no private
paths or notifications, and no unrelated process names/data before generating evidence.

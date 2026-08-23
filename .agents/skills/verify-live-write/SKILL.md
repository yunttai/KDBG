---
name: verify-live-write
description: Run the controlled KDBG physical-memory live-write verification against KDbgProbe in a disposable Windows VM and collect exact read/write/read-back evidence. Do not use on a host or unknown PFN.
---

# Live write verification

Prerequisites: disposable Windows x64 VM snapshot, Administrator, test-signing, matching `KDbgDriver.sys` and `KDbgProbe.sys`, and no unrelated sensitive workload.

1. Record OS build, binary hashes, ABI versions, and snapshot name.
2. Install/start KDBG and KDbgProbe with the supplied SCM scripts.
3. Query the probe VA, PA, PFN, generation, size, and CRC.
4. Load that PFN in KDBG and save the baseline page.
5. Edit a small non-header byte range, review the diff, type the PFN, apply once, and require the full-page read-back to match.
6. Re-query the probe CRC/generation and independently reload the PFN.
7. Roll back to the baseline and verify again.
8. Stop/remove services and restore the VM snapshot.
9. Store screenshots/logs in the release evidence directory. Fail the gate on any short I/O, conflict, mismatch, crash, or unclosed write gate.

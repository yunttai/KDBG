---
name: verify-live-write
description: Run KDBG physical-memory verification in either the snapshot VM regression lane or the separate bare-metal runtime-host Probe evidence lane, and collect exact read/write/read-back evidence.
---

# Live write verification

Select and record exactly one lane before execution:

- `regression_guest`: disposable Windows x64 VM snapshot, Administrator, test-signing, matching drivers, and no unrelated sensitive workload.
- `runtime_host_probe`: bare-metal Windows x64 runtime host, Administrator, and matching drivers. Machine/boot/session values are collected automatically as evidence provenance when available and are not operator confirmations or product prerequisites.

This skill does not verify an arbitrary Raw PFN. It verifies the exact current KDbgProbe allocation; Raw-PFN capability has a separate evidence gate.

1. Record target lane, OS build, binary hashes, ABI versions, and the snapshot name only for `regression_guest`. Automatically collect machine/boot/session provenance when available; its absence must not block normal LocalHost RawPfn functionality.
2. Install/start KDBG and KDbgProbe with the supplied SCM scripts.
3. Query the probe VA, PA, PFN, generation, size, and CRC.
4. Load that PFN in KDBG and save the baseline page.
5. Edit a small non-header byte range, review the diff, type the PFN, apply once, and require the full-page read-back to match.
6. Re-query the probe CRC/generation and independently reload the PFN.
7. Roll back to the baseline and verify again.
8. Stop/remove services. Restore the snapshot for `regression_guest`; record cleanup and resulting service/device state for `runtime_host_probe`.
9. Store screenshots/logs in a lane-specific evidence directory. Fail the gate on any identity drift, short I/O, conflict, mismatch, crash, or unclosed write gate. Never relabel or promote evidence across lanes.

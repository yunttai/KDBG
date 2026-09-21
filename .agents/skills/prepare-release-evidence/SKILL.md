---
name: prepare-release-evidence
description: Prepare a reproducible KDBG submission package, validation report, hashes, attribution, and the assignment GIF/video after implementation is complete.
---

# Release evidence workflow

1. Run layout, source-complete, core build/test, Windows GUI/bridge build, WDK driver builds, VM regression, bare-metal runtime-host read-only, bare-metal Probe-write, and Raw-PFN gates; record each independently and mark unexecuted gates accurately.
2. Update `docs/IMPLEMENTATION_STATUS.md`, `docs/TRACEABILITY_MATRIX.md`, `docs/VALIDATION_REPORT.md`, and `docs/exec-plans/STATUS.md` with exact status.
3. Package KDBG.exe, drivers, INF/CAT/PDB as appropriate, bridge executable, configuration examples, licenses, and a concise operator guide. Do not package source dependencies unnecessarily.
4. Generate SHA-256 hashes and a file manifest.
5. Record the target role and target kind, then demonstrate PFN discovery/input, physical read, hex edit, diff, typed unlock, write/read-back PASS, PFN process/VA evidence, and page-table visualization. Collect machine/boot/session values automatically as optional provenance when available; never turn them into a manual confirmation, product prerequisite, or LocalHost RawPfn blocker.
6. Check the recording for readable text, no private data, and no unsupported claims.
7. Mark a gate `PASS` only when its artifact and command output exist. Historical VM evidence must remain immutable and cannot establish a bare-metal runtime-host gate.

# KDBG 1.0.0 release checklist

기준: 2026-08-23 KST

| Gate | Required evidence | Current claim |
|---|---|---|
| Source-complete | layout, strict build/test, source validator | PASS |
| Windows-build-verified | MSVC Debug/Release, `/analyze`, WDK Debug/Release | PASS |
| VM-prerequisite-verified | existing `Windows-VM`, checkpoint, Administrator, test-signing | PASS |
| Interim physical transaction | ABI 6 Probe write/read-back/reload/rollback/gate lock | PASS — `DADF43AA...`, not final package |
| Candidate advanced read-only | `D3390AD4...` GUI/process/PFN/PTView workflow | PASS — no physical/process writes |
| Final-package-verified | source scope, version/arch/config, symbols split, SHA, SPDX, reproducibility, negatives | PASS |
| Final-package read-only/lifecycle | exact deploy/hash binding, device/main ABI6, fresh Probe/4 KiB read, invalid IOCTL rejection, stop/remove | PASS — physical writes 0 |
| Final write-sensitive/v2 | physical/process write, Freeze, Driver Verifier, hash-bound v2 | BLOCKED |

- [x] Record toolchain versions and clean commands.
- [x] Record deterministic source-snapshot SHA-256 when Git metadata is unavailable.
- [x] Build/test Clang Debug and Release with warnings as errors.
- [x] Build/test ASan/UBSan and run sanitized benchmark.
- [x] Run clang-tidy analyzers and MSVC `/analyze /WX`.
- [x] Build/test Windows GUI/bridge Debug and Release.
- [x] Build both WDK drivers Debug and Release; produce SYS/PDB/INF/CAT.
- [x] Record signature reality: no production trust claim; user-mode EXEs unsigned.
- [x] Run deterministic negative, malformed, rollback and cancellation tests.
- [x] Rerun all six requested benchmark classes against the current Windows Release binary.
- [x] Capture and inspect the current candidate GUI across the advanced read-only workflow.
- [x] Generate and validate main and symbols package candidates with `kdbg.source-snapshot.v1` metadata.
- [x] Verify the candidate ZIP output with a same-input rerun.
- [x] Inspect SPDX SBOM, dependency pins and bundled licenses.
- [x] Run 5/5 negative validator fixtures for hash tamper, PDB leak, Debug mix and fabricated live evidence.
- [x] Synchronize implementation, validation, traceability and execution-status documents.
- [x] Confirm the existing `Windows-VM` checkpoint, Administrator and test-signing prerequisites.
- [x] Record the interim ABI 6 Probe physical transaction without promoting it to final-package PASS.
- [x] Exercise candidate `D3390AD4...` read-only process/PFN/PTView workflows and return all gates locked.
- [x] Generate and hash a scoped 17-frame demonstration GIF from actual VM screenshots.
- [x] Deploy and hash-bind the exact Release package; open devices and verify main ABI 6.
- [x] Run final-package fresh Probe query, exact 4 KiB read-only access, and invalid IOCTL rejection with physical writes 0.
- [x] Complete interim Probe read/edit/write/full read-back/independent reload/rollback/gate-lock.
- [x] Complete candidate read-only process, built-in PFN reverse map, and PTView evidence.
- [ ] Complete dedicated process write/Freeze fixture evidence.
- [ ] Exercise optional MemProcFS runtime (currently BLOCKED: `vmm.dll`, error 126).
- [x] Stop/remove the exact Release drivers and record lifecycle evidence.
- [ ] Run Driver Verifier (`NOT_RUN`).
- [x] Record and review the scoped redacted demonstration GIF.
- [ ] Validate the hash-bound `kdbg.live-evidence.v2` bundle.

Unchecked live items must not be inferred from completed source, build, package,
VM-prerequisite, read-only/lifecycle, or older-package items. Exact package identity
is externalized in `out/evidence/final-live-manifest.json` and
`out/evidence/RELEASE-HASHES.txt`; final physical/process write and v2 remain separate.

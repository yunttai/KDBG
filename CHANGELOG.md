# Changelog

## 1.0.0 — 2026-08-23

- Added the PFN physical-page transaction, process analysis, PFN ownership,
  and page-table source implementation.
- Added a versioned Windows Release package contract, separate symbols package,
  SHA-256 coverage, SPDX SBOM generation, operator tools, and license bundle.
- Added strict source, package, and live-evidence validation.
- Hardened per-handle driver gates, controller/process lifetime, PID reuse,
  exact I/O, full-page conflict/read-back and rollback recovery.
- Added bounded scanner/persistence/pointer/snapshot/protocol inputs and broad
  deterministic negative/fault-injection coverage.
- Added real docking, DPI/layout persistence, probe-first UX, status/prerequisite
  states, local rotating diagnostics and crash minidumps.
- Verified 707/0 portable checks, Clang Debug/Release, ASan/UBSan, clang-tidy,
  MSVC Debug/Release and `/analyze`, and WDK Debug/Release gates.
- Confirmed an existing checkpointed `Windows-VM` with Administrator and
  test-signing; an older package was installed and both services were started.
- Added an explicit source-snapshot scope so unrelated root crash reports cannot
  enter release provenance. The final main/symbol candidates passed strict
  validation, same-input ZIP reproducibility, and all 5/5 negative fixtures.
- Completed an ABI 6 Probe physical transaction on the same disposable VM using
  the interim `DADF43AA...` package: exact read, one-shot write, full read-back,
  independent reload, rollback, and final locked gates all passed.
- Deployed candidate `D3390AD4...` read-only and exercised the current GUI,
  Probe query, process memory map, First/Next Scan, address list with Freeze off,
  disassembly, snapshot, pointer scan, selected-process PFN reverse mapping, and
  page-table translation. The final PA/PFN exactly matched the Probe fixture.
- Added a 17-frame, 1280x720 demonstration GIF made only from captured VM
  screenshots. Its captions keep interim-write and candidate-read-only scope
  separate; it is not claimed as final-package `kdbg.live-evidence.v2`.
- Deployed and hash-bound the exact Release package on the same `Windows-VM`.
  Device/main ABI 6, a fresh Probe query, exact 4 KiB read-only access, invalid
  IOCTL rejection, and stop/remove passed with physical writes held at zero.
  Exact package identity is recorded externally in
  `out/evidence/final-live-manifest.json` and `out/evidence/RELEASE-HASHES.txt`
  so documentation does not embed a changing ZIP digest.

The optional MemProcFS runtime remains BLOCKED because `vmm.dll` returned Win32
error 126. Final physical write (`NOT_RUN`), process write/Freeze, Driver
Verifier, and hash-bound v2 evidence remain BLOCKED. The DADF physical-write and
D339 advanced read-only results keep their interim/candidate scope, and no
production Authenticode trust is claimed.

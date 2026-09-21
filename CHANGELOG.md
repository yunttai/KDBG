# Changelog

## Unreleased — target 1.1.0

Release identity note: implementation and product metadata are versioned for
1.1.0. Exact package, symbols, source, media, and live-VM identities are bound
to their named candidate epochs in the status and validation documents; they
must be regenerated after any release-scope source change. The current Windows
11 engineering candidate is VM-test-signed only. Stable publication remains
pending production signing and trusted timestamp verification.

- Added the read-only Kernel Explorer: bounded loaded-module catalog, explicit
  local exact-signature PDB resolution, kernel-only virtual reads, and Zydis
  disassembly with asynchronous cancellation and clipped tables.
- Optimized aligned First Scan, dense Next Scan batching with exact-read
  fallback, pointer scans, backend buffer use, page-table range snapshots, and
  snapshot CRC32. Added schema-2 repeated mock benchmarks with median/p95 and
  explicit non-product-runtime labels.
- Added transactional SCM update/repair/recovery and packaged
  diagnose/install/start/run/stop/uninstall workflows, including marked-delete
  handling, bounded waits, rollback error preservation, and atomic publication.
- Added the elevated native `KDBGSetup.exe` product UX with
  Install/Repair/Update/Uninstall, a stable Program Files transaction,
  Apps & Features/Start Menu registration, rollback, and identity-checked purge.
- Added opt-in, local-only runtime performance JSON for bounded process-scan
  region/byte/I/O/cancellation data and GUI frame-stall counters without target
  contents, process names, or filesystem paths.
- Added AddressList and WatchList migration coverage, disarmed persisted Freeze
  state, expanded MemProcFS subprocess fault tests, and Windows backend range
  validation.
- Added the packaged Probe write/read-back/reload/rollback verifier, immutable
  external v4 evidence workflow, GUI raw-page metadata, runtime driver hashes,
  PE/PDB GUID+age pairing, mandatory INF/CAT provenance, and hash-bound timed
  20-scene human review records.
- Completed the 1.1.0 Windows 11 Pro 25H2 required-core live gate in an isolated
  Generation-2 Hyper-V VM: exact test-signed package identity, ABI 6,
  KDbgProbe PFN discovery, 8-byte apply, full-page read-back and independent
  reload, 4 KiB rollback, final write-gate lock, uninstall cleanup, exact
  checkpoint restore, and final VM Off all passed. The same candidate line also
  completed repeated lifecycle/reboot validation, a 30-minute soak, automated
  GUI capture, and MP4 composition. Formal visual-review and production-trust
  states remain independently recorded and are not inferred from those gates.
- Release user-mode builds now emit full PDBs with basename-only CodeView paths;
  package-only validation no longer depends on a source checkout.
- Current source gate: 1,771 checks with zero failures and 38/38 validator tests;
  GNU and MSVC Debug/Release/`/analyze` pass. Pinned NuGet WDK Debug/Release and the
  validated main/symbol package pair pass. Disposable-VM SYS/CAT test trust,
  driver load, lifecycle/reboot/forced-exit/update/rollback/purge recovery, the
  Probe physical transaction, current process write/Freeze, ownership/page walk,
  Kernel Explorer, a two-cycle/four-reboot clean-guest script lifecycle, and
  automated 20-scene evidence preflight pass. Production publisher
  trust, sanitizer runtime, monitored intake, and the human-reviewed final v4
  record remain separate external gates.

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

- Completed the exact `91042aab...` package final write-sensitive run: Probe PFN
  `0xBC1E6`, 8-byte dirty write, full read-back, independent reload, rollback,
  baseline restore, process fixture write/three Freeze ticks, and volatile
  targeted Driver Verifier all passed with final cleanup.
- Captured the exact package at DPI 100/125/150/200% in the existing disposable
  VM profile and generated a reviewed 17-scene, 1600x900 hash-bound
  `kdbg.live-evidence.v2` bundle that passed the strict package/live validator.
- Fixed `new_live_evidence.ps1` hexadecimal `DirtyRun` parsing by preserving the
  regex captures before subsequent comparisons overwrite PowerShell `$Matches`.
- Updated optional MemProcFS status: official v5.18.11 resolves the earlier DLL
  load error 126, but `VMMDLL_Initialize(device=pmem)` still exits 2. The required
  built-in selected-process reverse mapper/PTView fallback passed, and no
  production Authenticode trust is claimed.

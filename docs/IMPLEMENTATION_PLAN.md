# KDBG 구현·검증 계획

## 완료된 Phase 0 — Rename and Codex migration

- KDBG product/device/service/resource naming
- project agents, repository skills, nested instructions
- source-only-under-`src/` enforcement
- pinned dependency and license metadata

## 완료된 Phase 1 — Driver and fixture vertical slice

- secure KDbgDriver ABI
- physical ranges/read/write
- process context/read/write
- x64 translation
- deterministic KDbgProbe page
- SCM and user-mode backend

## 완료된 Phase 2 — Physical editor transaction

- PFN validation and exact page load
- baseline/working/preflight/read-back states
- Hex/ASCII UI, byte-level Undo/Redo, and diff
- typed one-shot write gate
- conflict detection, dirty-run apply, full-page verification
- rollback

## 완료된 Phase 3 — Process-memory suite

- process attach, regions/modules
- First/Next Scan with implemented numeric, string, AOB, and change-comparison types
- asynchronous cancellation/progress/result clipping
- address list, manual add, persistent table, verified edits/freeze
- pointer scan
- Zydis disassembly
- process transaction and snapshot Diff

## 완료된 Phase 4 — PFN and page tables

- native isolated MemProcFS bridge
- timeout/bounded protocol provider
- selected-process reverse mapping fallback
- PTView-style translation and flags

## 완료된 Phase 5 — Quality system

- portable deterministic tests
- layout/source/package/live-evidence validators
- Windows build/driver/service/package scripts
- PRD, architecture, threat model, traceability, ADRs, demo plan

## 남은 Phase 6 — Windows build gate

1. Windows GUI/bridge preset build
2. WDK solution build
3. package and manifest validation
4. static warnings and runtime smoke test
5. optional Driver Verifier in disposable VM

## 남은 Phase 7 — Live assignment evidence

1. Query Probe PFN
2. physical Read 4096/4096
3. Hex edit and diff
4. typed unlock
5. Write and full read-back PASS
6. independent reload/Probe CRC
7. PID/VA/PTE and page-table view
8. rollback
9. video/GIF and hashes

Windows/live failures do not change source implementation status; they block only their respective release gate and must be fixed before submission.

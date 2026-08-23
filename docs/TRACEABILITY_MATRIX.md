# KDBG 요구사항 추적표

기준: 2026-08-23 KST

상태 정의:

- `SOURCE PASS`: 구현과 소스 계약 검증이 일치한다.
- `PORTABLE PASS`: 결정적 mock/synthetic 테스트가 통과했다.
- `WINDOWS BUILD PASS`: 실제 MSVC/Windows SDK로 x64 바이너리를 만들고 CTest를 통과했다.
- `WDK BUILD PASS`: 실제 WDK로 SYS/INF/CAT/PDB를 만들고 signability 검사를 통과했다.
- `CANDIDATE LIVE PASS`: 명시한 candidate ZIP에 바인딩된 실제 VM 관찰이다. final package 증거로 승격하지 않는다.
- `VM PREREQUISITE PASS`: 기존 VM의 checkpoint, Administrator, test-signing을 실제로 확인했다.
- `HISTORICAL PACKAGE PASS`: 이전 패키지의 설치/시작 기록이며 현재 최종 패키지를 증명하지 않는다.
- `PACKAGE PASS`: 새 provenance scope를 포함한 main/symbol package, 동일 입력 ZIP 재현성, package negative fixture 증거가 있다.
- `FINAL READ-ONLY LIVE PASS`: exact Release package deployment/hash binding, device/ABI, read-only Probe, invalid IOCTL rejection과 stop/remove 증거가 있다.
- `WRITE-SENSITIVE BLOCKED`: final physical/process write, Freeze, Verifier 또는 v2 증거가 없다.

| 요구사항 | 주요 구현 | 자동/실행 검증 | 현재 상태 |
|---|---|---|---|
| FR-001 driver lifecycle/ABI | `DriverService`, `KDbgBackend`, authoritative shared IOCTL headers, Driver pane | ABI layout tests, MSVC build, WDK Debug/Release build | SOURCE/PORTABLE/WINDOWS/WDK PASS; final deploy/device/main ABI6/invalid IOCTL/stop/remove PASS |
| FR-002 PFN/range | `PfnAddress`, backend and driver range/overflow validation | PFN/range/overflow and negative tests | PORTABLE PASS; final fresh Probe query/read-only range PASS |
| FR-003 exact page read | `PhysicalPageSession::Load`, physical read IOCTL | exact/short-read tests, MSVC/WDK build | PORTABLE/WINDOWS/WDK PASS; final exact 4096-byte read-only PASS |
| FR-004 Hex/diff/undo/redo | `HexEditorPanel`, `PhysicalPageSession` | edit/history/diff tests, GUI build and captured workflow | PORTABLE/WINDOWS PASS; interim/candidate GUI CANDIDATE LIVE PASS |
| FR-005 one-shot physical write | review modal, full-page preflight, per-handle gate, dirty-run writes, full read-back | conflict, gate-disable, partial-write, full-page mismatch and recovery tests | PORTABLE PASS; interim DADF write PASS; final physical write BLOCKED (`NOT_RUN`) |
| FR-006 rollback | verified `RollbackBaseline` with recovery | rollback/preflight/read-back/failure tests | PORTABLE PASS; interim verified rollback PASS; final physical rollback BLOCKED (`NOT_RUN`) |
| FR-007 Probe fixture | `KDbgProbe`, `ProbeClient`, probe-first GUI workflow | ABI tests and WDK Debug/Release SYS/INF/CAT build | WDK/WINDOWS PASS; final fresh query and 4 KiB read-only PASS |
| FR-008 process map/browser | `ProcessCatalog`, `Win32ProcessMemory`, `MemoryMapPanel`, `ProcessMemoryPanel` | PID identity/session/write tests, MSVC build and candidate capture | PORTABLE/WINDOWS PASS; candidate 302 regions/25 modules read-only PASS; process write BLOCKED |
| FR-009 First/Next Scan | `MemoryScanner`, `ValueCodec`, `AobPattern`, async controller | type/filter/short-read/cap/cancel tests and 32 MiB benchmark | PORTABLE PASS; current Windows benchmark 323.479 MiB/s; candidate First/Next 26/26 PASS |
| FR-010 address list/Freeze | `AddressList`, `WatchList`, scanner pane | load-disarm, PID/token binding, malformed persistence, verified write/freeze tests | PORTABLE PASS; candidate address entry PASS with Freeze OFF; live Freeze BLOCKED |
| FR-011 pointer scan | bounded `PointerScanner`, resolver and pane | boundary, overflow, cycle/depth/result-cap tests and benchmark | PORTABLE PASS; candidate 10,385 paths PASS |
| FR-012 disassembly | pinned Zydis, x86/x64 Intel pane | pinned dependency/license audit and MSVC Debug/Release link | WINDOWS BUILD PASS; candidate 456 decoded instructions PASS |
| FR-013 snapshot | bounded `MemorySnapshot`, snapshot pane | capture/cancel/CRC/save/load/trailing/overflow/diff tests and 16 MiB benchmark | PORTABLE PASS; candidate 4 KiB snapshot/zero changed runs PASS |
| FR-014 PFN owner | isolated bridge, strict protocol provider, selected-process reverse mapper | bridge MSVC build, parser/timeout/cap/reverse-walk tests | built-in mapper CANDIDATE LIVE PASS (1 mapping); optional MemProcFS BLOCKED, error 126 |
| FR-015 page-table UI | driver translation, `X64PageTable`, `PageTablePanel` | LA57/4K/2M/1G/effective-permission tests and MSVC/WDK build | PORTABLE/WINDOWS/WDK PASS; candidate final PA/PFN exact Probe match PASS |
| GUI productization | docking, DPI, status, progress/cancel, shortcuts, About, local diagnostics | current candidate screenshots; log/crash smoke | WINDOWS BUILD PASS; current candidate visual workflow PASS |
| Codex-only repository | `.codex`, `.agents/skills`, nested `AGENTS.md` | `verify_layout.py` | SOURCE PASS |
| Static/dynamic quality | strict warnings, clang-tidy analyzers, MSVC `/analyze`, ASan/UBSan | fresh build and CTest per preset | PASS |
| Windows package | versioned EXEs, drivers, config/tools/docs/licenses, SPDX, SHA manifest, explicit source scope | strict validators, reproducibility, final deploy/hash binding | PACKAGE PASS; exact identity는 external final-live manifest/hash file 참조 |
| 제출 영상/live evidence | v2 hash-bound schema, capture script and demo checklist | validator rejects incomplete/fabricated evidence | 실제 17-frame GIF PASS (scoped); final-package v2 LIVE BLOCKED |

Final Release read-only/lifecycle gate는 PASS지만 write-sensitive gate는 분리한다.
Interim DADF physical PASS와 D339 candidate read-only PASS는 final physical/process
write 증거로 승격하지 않는다. Exact package binding은
`out/evidence/final-live-manifest.json`과 `out/evidence/RELEASE-HASHES.txt`를 따른다.

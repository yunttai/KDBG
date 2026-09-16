# KDBG 요구사항 추적표

기준: 2026-09-16 KST

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
- `FINAL LIVE PASS`: exact Release ZIP hash, raw pages, command log와 reviewed video가 machine-validated evidence로 묶였다.

| 요구사항 | 주요 구현 | 자동/실행 검증 | 현재 상태 |
|---|---|---|---|
| FR-001 driver lifecycle/ABI | `DriverService`, `KDbgBackend`, authoritative shared IOCTL headers, Driver pane | ABI layout tests, MSVC build, WDK Debug/Release build | SOURCE/PORTABLE/WINDOWS/WDK PASS; final deploy/device/main ABI6/invalid IOCTL/stop/remove PASS |
| FR-002 PFN/range | `PfnAddress`, backend and driver range/overflow validation | PFN/range/overflow and negative tests | PORTABLE PASS; final fresh Probe query/read-only range PASS |
| FR-003 exact page read | `PhysicalPageSession::Load`, physical read IOCTL | exact/short-read tests, MSVC/WDK build | PORTABLE/WINDOWS/WDK PASS; final exact 4096-byte read-only PASS |
| FR-004 Hex/diff/undo/redo | `HexEditorPanel`, `PhysicalPageSession` | edit/history/diff tests, GUI build and captured workflow | PORTABLE/WINDOWS PASS; interim/candidate GUI CANDIDATE LIVE PASS |
| FR-005 one-shot physical write | review modal, full-page preflight, per-handle gate, dirty-run writes, full read-back | conflict, gate-disable, partial-write, full-page mismatch and recovery tests | FINAL LIVE PASS; PFN `0xBC1E6`, dirty run `0x100:8`, full read-back match |
| FR-006 rollback | verified `RollbackBaseline` with recovery | rollback/preflight/read-back/failure tests | FINAL LIVE PASS; independent reload match, baseline/CRC restored, gate locked |
| FR-007 Probe fixture | `KDbgProbe`, `ProbeClient`, probe-first GUI workflow | ABI tests and WDK Debug/Release SYS/INF/CAT build | WDK/WINDOWS PASS; final fresh query and 4 KiB read-only PASS |
| FR-008 process map/browser | `ProcessCatalog`, `Win32ProcessMemory`, `MemoryMapPanel`, `ProcessMemoryPanel` | PID identity/session/write tests, MSVC build and candidate capture | PORTABLE/WINDOWS PASS; exact final 16-byte fixture write/rollback PASS |
| FR-009 First/Next Scan | `MemoryScanner`, `ValueCodec`, `AobPattern`, async controller | type/filter/short-read/cap/cancel tests and 32 MiB benchmark | PORTABLE PASS; current Windows benchmark 323.479 MiB/s; candidate First/Next 26/26 PASS |
| FR-010 address list/Freeze | `AddressList`, `WatchList`, scanner pane | load-disarm, PID/token binding, malformed persistence, verified write/freeze tests | FINAL LIVE PASS; three external-mutation restoration ticks, rollback and gate lock |
| FR-011 pointer scan | bounded `PointerScanner`, resolver and pane | boundary, overflow, cycle/depth/result-cap tests and benchmark | PORTABLE PASS; candidate 10,385 paths PASS |
| FR-012 disassembly | pinned Zydis, x86/x64 Intel pane | pinned dependency/license audit and MSVC Debug/Release link | WINDOWS BUILD PASS; candidate 456 decoded instructions PASS |
| FR-013 snapshot | bounded `MemorySnapshot`, snapshot pane | capture/cancel/CRC/save/load/trailing/overflow/diff tests and 16 MiB benchmark | PORTABLE PASS; candidate 4 KiB snapshot/zero changed runs PASS |
| FR-014 PFN owner | isolated bridge, strict protocol provider, selected-process reverse mapper | bridge MSVC build, parser/timeout/cap/reverse-walk tests | exact same-PFN PID/VA/PTE PASS; required fallback PASS; optional MemProcFS `pmem` init BLOCKED |
| FR-015 page-table UI | driver translation, `X64PageTable`, `PageTablePanel` | LA57/4K/2M/1G/effective-permission tests and MSVC/WDK build | FINAL LIVE PASS; PML4/PDPT/PD/PT resolves exactly to Probe PA/PFN |
| GUI productization | docking, DPI, status, progress/cancel, shortcuts, About, local diagnostics | current candidate screenshots; log/crash smoke | WINDOWS BUILD PASS; exact-package DPI 100/125/150/200% PASS |
| Codex-only repository | `.codex`, `.agents/skills`, nested `AGENTS.md` | `verify_layout.py` | SOURCE PASS |
| Static/dynamic quality | strict warnings, clang-tidy analyzers, MSVC `/analyze`, ASan/UBSan | fresh build and CTest per preset | PASS |
| Windows package | versioned EXEs, drivers, config/tools/docs/licenses, SPDX, SHA manifest, explicit source scope | strict validators, reproducibility, final deploy/hash binding | PACKAGE PASS; exact identity는 external final-live manifest/hash file 참조 |
| 제출 영상/live evidence | v2 hash-bound schema, capture script and demo checklist | validator rejects incomplete/fabricated evidence | FINAL LIVE PASS; 17-frame 1600x900 GIF, command log/raw pages/artifact hashes bound and validated |

Exact final binding은 `out/evidence/final-91042aab-unblock-result.json`,
`out/evidence/final-91042aab-live-evidence-v2.json`, `final-live-manifest.json`과
`RELEASE-HASHES.txt`를 따른다. Optional MemProcFS backend의 BLOCKED는 fallback PASS를
무효화하지 않으며 production Authenticode trust는 별도 외부 절차다.

# KDBG 구현 상태

기준: 2026-09-16 KST
제품 버전: 1.0.0

## 판정 요약

KDBG 1.0.0의 소스, fresh core/Windows builds, WDK clean builds, package gates와 exact Release package live gate를 검증했다. 같은 `Windows-VM`에서 deploy/hash binding, ABI6, exact 4096-byte Probe read, invalid IOCTL rejection, physical write/read-back/independent reload/rollback, process write/Freeze, targeted volatile Driver Verifier, same-PFN ownership/PTView, stop/remove가 PASS했다. 기존 VM 사용자 프로필에서 exact-package DPI 100/125/150/200%를 실제 캡처했고, 17장면 hash-bound `kdbg.live-evidence.v2`도 validator PASS다. Optional MemProcFS v5.18.11은 DLL load까지 성공했으나 `pmem` device 초기화가 exit 2로 BLOCKED이며, 필수 built-in reverse-mapper/PTView fallback은 PASS다.

| 영역 | 상태 | 근거 |
|---|---|---|
| 구현 및 결정적 테스트 | PASS | 707 checks, 0 failures |
| Clang Debug/Release | PASS | fresh configure/build/CTest |
| ASan/UBSan | PASS | fresh build/CTest, finding 0 |
| clang-tidy analyzer | PASS | analyzer warnings-as-errors build/CTest |
| MSVC Debug/Release GUI·bridge | PASS | fresh x64 build/CTest |
| MSVC `/analyze /WX` | PASS | GUI, bridge, core, tests, benchmarks |
| WDK Debug/Release | PASS | clean builds; 두 드라이버 SYS/INF/CAT/PDB; signability errors 0/warnings 0 |
| Current candidate GUI visual workflow | PASS | D339 full-window captures across advanced read-only features |
| Exact-package DPI matrix | PASS | 기존 VM 프로필에서 100/125/150/200% 실캡처 및 SHA-256 기록 |
| VM prerequisites | PASS | 기존 `Windows-VM` checkpoint, Administrator, test-signing 확인 |
| 이전 패키지 VM install/start | PASS | 이전 패키지 설치, KDBG/KDBGProbe 서비스 시작 기록 |
| 최종 Release/symbols package | PASS | `kdbg.source-snapshot.v1`, strict validators, 동일 입력 ZIP, 5/5 negative fixtures |
| Same-VM interim device/ABI6 | PASS | continuously running `Windows-VM`, KDBG PID 1140 |
| Probe physical transaction | PASS | preflight/read-back/reload/rollback full-page match; baseline restored; gate locked |
| D339 advanced read-only live | PASS | built-in PFN/PTView + process map/scan/address-list/disassembly/snapshot/pointer; gates locked |
| Scoped demonstration GIF | PASS | interim physical frames + D339 read-only frames |
| Optional MemProcFS runtime | BLOCKED (optional) | v5.18.11 `vmm.dll` load 성공; `VMMDLL_Initialize(device=pmem)` exit 2 |
| Process live write/freeze | PASS | 16-byte fixture write, 3회 mutation/Freeze 복원, rollback, gate lock |
| D339 physical write | BLOCKED | `NOT_RUN` |
| Final Release read-only/lifecycle | PASS | exact deploy/hash binding, ABI6, fresh Probe/4 KiB read, invalid IOCTL rejection, stop/remove; writes 0 |
| Final Release physical write | PASS | PFN `0xBC1E6`, 8-byte dirty run, 4 KiB read-back/reload/rollback, baseline 복원 |
| Driver Verifier | PASS | volatile `0x132`, 두 driver 대상 관측 및 cleanup PASS |
| Final hash-bound v2 evidence | PASS | 17장면 GIF + command log + raw pages + final artifact hashes, strict validator PASS |

## 구현된 제품 범위

### Driver, backend, Probe

- authoritative packed/versioned IOCTL ABI와 compile-time layout assertions
- Administrators/SYSTEM ACL, referenced controller process, single-controller and per-handle synchronized gate
- close/cleanup/unload fail-close, transfer caps, exact size/reserved/range/overflow checks
- page-bounded physical writes, process object lifetime and creation-token PID reuse protection
- canonical VA, CR3 masking, LA57 및 4 KiB/2 MiB/1 GiB translation
- deterministic 4096-byte `KDbgProbe` fixture와 Query/Reset/Fill/generation/CRC32
- user-mode backend의 ABI/response validation, independent read-back and fail-close behavior

### Physical/process memory transactions

- PFN decimal/hex parse, `PFN << 12` and RAM-range checks
- exact 4096-byte load, baseline/working separation, dirty bitmap/runs, Hex/ASCII edit, Undo/Redo/revert
- typed PFN one-shot confirmation, full-page preflight conflict check, dirty-run writes
- gate relock 결과 확인 후 full-page read-back and byte-for-byte expected comparison
- verified rollback, partial-run recovery, mismatch/conflict offsets
- process session PID/identity binding, pre-write recovery snapshot, every-exit disarm propagation

### Cheat Engine 계열 분석

- process catalog/attach/detach, architecture/path/modules/regions and Win32/driver fallback
- transactional process Hex editor and verified write/rollback
- bounded cancellable First/Next Scan with integer/float/double/UTF-8/UTF-16/wildcard AOB types
- exact/relative/between/unknown/changed/increased/decreased and delta modes
- short-read-safe chunking, alignment/region filters, progress, candidate/result/memory caps
- versioned Address List/WatchList; load always disarms Freeze; PID/identity bound verified writes
- bounded pointer resolver/scanner, pinned Zydis Intel disassembly, bounded CRC snapshot/save/load/diff

### PFN ownership, page tables, GUI

- MemProcFS는 GUI와 분리된 native bridge에서만 dynamic load
- concurrent stdout drain, timeout/cancel/job cleanup, 8 MiB output cap, strict versioned protocol
- PFN map version/count/free validation and selected-process reverse mapper fallback
- PTView-style PML5/PML4/PDPT/PD/PT steps, flags/effective permissions/final PA
- real Dear ImGui docking, persisted/versioned settings, DPI scaling/minimum size, shortcuts, progress/cancel
- probe-first physical workflow, write/read status distinction, driver/probe/process/gate visibility
- rotating local log and local-only `MiniDumpNormal` crash diagnostic; automatic external transmission 없음

### Release engineering

- pinned dependency revisions and synchronized MIT/Zydis/Zycore notices
- versioned x64 Release EXEs and WDK `DriverVer=08/15/2026,1.0.0.0`
- main package has no PDB; driver PDBs are in a separate symbols package
- Syft SPDX-2.3 SBOM, all-file `SHA256SUMS.txt`, deterministic ZIP timestamps
- source metadata records a deterministic SHA-256 over the explicit `kdbg.source-snapshot.v1` scope when Git metadata is absent
- validator rejects missing/empty binaries, architecture/config/version mix, uncovered or wrong hashes, PDB leakage and malformed live evidence

## 현재 Windows Release 관측 성능

최종 Windows Release build 뒤 다시 실행한 deterministic mock-only 결과다.
`live_driver_access=false`이므로 실제 driver throughput을 뜻하지 않는다.

| Metric | 관측값 |
|---|---:|
| Physical 4 KiB transaction | median 0.006 ms, p95 0.006 ms, max 0.035 ms |
| First Scan 32 MiB | 323.479 MiB/s, 8192 results |
| Peak RSS / delta | 41,578,496 / 2,859,008 bytes |
| Next Scan | 1.941 ms, 8192 → 4096 |
| Pointer cap | 128/128, 0.171 ms |
| Snapshot 16 MiB | capture 127.185, save 2393.239, load 105.435 MiB/s |
| Cancel request → completion | 4.152 ms |

## 생성 산출물

- `out/build/windows-release/KDBG.exe`
- `out/build/windows-release/kdbg_memprocfs_bridge.exe`
- `out/drivers/{Debug,Release}/KDbgDriver.*`
- `out/drivers/{Debug,Release}/KDbgProbe.*`
- exact Release `out/package/KDBG-1.0.0-win-x64/` 및 symbols/ZIP; final ZIP SHA-256 `91042aab214e4c56daca29159b46c81574afb2aac700257d46baa7a8bf99e54f`
- `out/evidence/dpi-final-91042aab/dpi-{100,125,150,200}.png` (exact-package DPI matrix)
- `out/evidence/candidate-*.png` (current D339 live visual workflow)
- `out/evidence/benchmark-windows-release.json` (current final Windows Release benchmark)
- `out/evidence/live-20260823-110826-359/`
- `out/evidence/live-20260823-110826-359.zip` — SHA-256 `b8e88cb7cc78ab42f5edf0b4409b99ab4e6e60ab2761ed08f98233ee11bd0769`
- `out/evidence/candidate-d3390ad4-advanced-live.json`
- `out/evidence/KDBG-1.0.0-demonstration.gif` (scoped interim+D339 candidate evidence)
- `out/evidence/final-91042aab-unblock-result.json` (latest exact-package integrated live result)
- `out/evidence/final-91042aab-live-evidence-v2.json` 및 `.gif` (validated final hash-bound evidence)
- `out/evidence/final-live-manifest.json` (authoritative exact Release live binding)
- `out/evidence/RELEASE-HASHES.txt` (authoritative release digests)

## 남은 optional/외부 제한

- production certificate signing은 하지 않았다. user-mode EXE는 unsigned이고 WDK 출력의 production Authenticode trust는 주장하지 않는다.
- optional MemProcFS v5.18.11은 error 126을 해소했지만 `VMMDLL_Initialize`가 `pmem` device에서 exit 2라 runtime backend만 BLOCKED다. 내장 selected-process reverse mapper와 PTView fallback은 PASS다.
- production certificate signing은 별도 외부 release 절차다. 현재 user-mode EXE의 production Authenticode trust는 주장하지 않는다.
- v2 영상은 exact final runtime 값/raw hash와 exact-package DPI 캡처를 결합하고, 이전 ABI6 GUI workflow 캡처는 영상 안에서 supporting UI로 명시했다. 해당 과거 캡처를 exact-package runtime 화면으로 승격하지 않는다.
- 증거 생성기 `new_live_evidence.ps1`의 `DirtyRun` `$Matches` 덮어쓰기 버그를 수정했으며, 수정 뒤 공식 package/live validator가 PASS했다. 이 evidence-only tooling 수정 때문에 runtime ZIP은 다시 만들지 않았다.

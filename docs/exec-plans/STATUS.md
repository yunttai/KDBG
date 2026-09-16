# KDBG execution status

기준 시각: 2026-09-16 KST

## Gate 현황

| Gate | 상태 | 실제 근거 |
|---|---|---|
| Repository/Codex layout | PASS | `python .\src\tools\verify_layout.py` |
| Mandatory core baseline | PASS | configure/build/CTest 1/1; 707 checks, 0 failures |
| Clang Debug | PASS | fresh strict build/CTest |
| Clang Release | PASS | fresh strict build/CTest |
| ASan/UBSan | PASS | fresh build/CTest; finding 0 |
| clang-tidy analyzers | PASS | analyzer warnings-as-errors build/CTest |
| Source-complete validator | PASS | strict required-source/test execution gate |
| MSVC Debug GUI/bridge | PASS | fresh x64 build; CTest 1/1 |
| MSVC Release GUI/bridge | PASS | fresh x64 build; CTest 1/1 |
| MSVC `/analyze /WX` | PASS | core/Windows/GUI/bridge/tests/benchmarks |
| WDK Debug drivers | PASS | clean build; both SYS/PDB/INF/CAT; signability 0 errors/warnings |
| WDK Release drivers | PASS | clean build; both SYS/PDB/INF/CAT; signability 0 errors/warnings |
| Deterministic/mock functional suite | PASS | 707/0 including negative/recovery/cancel/malformed fixtures |
| Current performance benchmark | PASS | final Windows Release binary; all six mock-only metrics PASS |
| Current candidate GUI visual workflow | PASS | D339 full-window captures across Probe/process/PFN/PTView/About |
| Exact-package DPI matrix | PASS | 기존 VM 프로필에서 100/125/150/200% 실제 캡처 및 SHA-256 기록 |
| Local log/crash diagnostics | PASS | rotation/cap/redaction/minidump smoke |
| VM prerequisite | PASS | existing `Windows-VM` checkpoint, Administrator, test-signing |
| Previous-package install/start | PASS | older package installed; KDBG/KDBGProbe Running |
| Final Release main/symbol packages | PASS | `kdbg.source-snapshot.v1`, strict validators, same-input ZIP reproducibility |
| Package validator negatives | PASS | 5/5 tamper/PDB/Debug/live expected exit-1 cases |
| Same-VM interim package/device/ABI6 | PASS | continuously running `Windows-VM`; KDBG PID 1140; ABI 6 |
| Final Release deploy/hash/device/main ABI6 | PASS | exact package identity bound externally; fresh Probe and 4 KiB read-only PASS; writes 0 |
| Final Release invalid IOCTL rejection | PASS | malformed/unsupported request rejected fail-closed |
| Final Release stop/remove | PASS | both drivers stopped and removed on same VM |
| Driver Verifier | PASS | volatile `0x132`, KDbgDriver/KDbgProbe 대상, cleanup PASS |
| Probe read/write/read-back/reload/rollback/gate-lock | PASS | final PFN `0xBC1E6`; all six 4096-byte page states match; baseline restored; gate locked |
| D3390AD4 advanced read-only live | PASS | fresh Probe query; built-in PFN reverse map; exact PTView; process map/scan/disassembly/snapshot/pointer/address list |
| Optional MemProcFS runtime | BLOCKED (optional) | v5.18.11 DLL load 성공; `VMMDLL_Initialize(device=pmem)` exit 2; fallback PASS |
| Process live write/freeze | PASS | verified 16-byte write, 3 Freeze restore ticks, rollback/gate lock |
| D3390AD4 physical write | BLOCKED | `NOT_RUN`; DADF interim transaction만 PASS |
| Final Release physical write | PASS | PFN `0xBC1E6`, 8-byte dirty run, read-back/reload/rollback/baseline restore |
| Physical transaction evidence archive | PASS | `live-20260823-110826-359.zip`, SHA-256 `b8e88cb7cc78ab42f5edf0b4409b99ab4e6e60ab2761ed08f98233ee11bd0769` |
| Scoped demonstration GIF | PASS | 17-frame 1280×720 interim-write + D339 read-only evidence |
| Final hash-bound v2 evidence | PASS | 17-frame GIF/log/raw pages/artifact hashes, strict validator exit 0 |

## 완료 산출물

- Windows Debug/Release `KDBG.exe` and bridge
- WDK Debug/Release `KDbgDriver` and `KDbgProbe` SYS/INF/CAT/PDB
- validated exact Release main/symbol package, SPDX and manifests; immutable final ZIP SHA `91042aab...`
- same-VM ABI6 physical evidence at `out/evidence/live-20260823-110826-359/` and matching ZIP
- D339 read-only manifest `out/evidence/candidate-d3390ad4-advanced-live.json`
- scoped demo `out/evidence/KDBG-1.0.0-demonstration.gif`
- authoritative final binding `out/evidence/final-live-manifest.json`
- release digest set `out/evidence/RELEASE-HASHES.txt`
- current Windows benchmark JSON and D339 full-window GUI screenshots under `out/evidence`
- latest integrated result `out/evidence/final-91042aab-unblock-result.json`
- exact-package DPI captures `out/evidence/dpi-final-91042aab/`
- validated v2 `out/evidence/final-91042aab-live-evidence-v2.json` and `.gif`

## 현재 안전 및 증거 경계

```text
VM: Windows-VM (existing)
Checkpoint: confirmed
Administrator: confirmed
Test-signing: confirmed
Same continuously running VM: PASS
Interim package device/ABI6 transaction: PASS
D3390AD4 advanced read-only live: PASS
D3390AD4 physical write: historical NOT_RUN (not used for final claim)
Final Release deploy/hash/device/ABI/read/invalid IOCTL/stop-remove: PASS
Final Release physical/process write, Freeze, Verifier and v2: PASS
Optional MemProcFS backend: BLOCKED; built-in reverse mapper/PTView fallback: PASS
```

## 최종 재검증 명령

```powershell
python .\src\tools\validate_release.py --windows-package .\out\package\KDBG-1.0.0-win-x64 --live-evidence .\out\evidence\final-91042aab-live-evidence-v2.json
```

Runtime ZIP은 actual live evidence가 결합된 immutable `91042aab...` artifact이므로
evidence-only tooling/doc 변경 때문에 재패키징하지 않는다. 필수 제품화 gate는 PASS다.
남은 제한은 optional MemProcFS `pmem` backend와 production signing뿐이다.

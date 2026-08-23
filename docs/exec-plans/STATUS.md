# KDBG execution status

기준 시각: 2026-08-23 KST

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
| Clean-profile DPI-specific smoke | BLOCKED | current candidate was captured live, but a dedicated clean-profile DPI matrix was not rerun |
| Local log/crash diagnostics | PASS | rotation/cap/redaction/minidump smoke |
| VM prerequisite | PASS | existing `Windows-VM` checkpoint, Administrator, test-signing |
| Previous-package install/start | PASS | older package installed; KDBG/KDBGProbe Running |
| Final Release main/symbol packages | PASS | `kdbg.source-snapshot.v1`, strict validators, same-input ZIP reproducibility |
| Package validator negatives | PASS | 5/5 tamper/PDB/Debug/live expected exit-1 cases |
| Same-VM interim package/device/ABI6 | PASS | continuously running `Windows-VM`; KDBG PID 1140; ABI 6 |
| Final Release deploy/hash/device/main ABI6 | PASS | exact package identity bound externally; fresh Probe and 4 KiB read-only PASS; writes 0 |
| Final Release invalid IOCTL rejection | PASS | malformed/unsupported request rejected fail-closed |
| Final Release stop/remove | PASS | both drivers stopped and removed on same VM |
| Driver Verifier | BLOCKED | `NOT_RUN` |
| Probe read/write/read-back/reload/rollback/gate-lock | PASS | PFN `0xDA9FE`; all six 4096-byte page states match; baseline restored; gate locked |
| D3390AD4 advanced read-only live | PASS | fresh Probe query; built-in PFN reverse map; exact PTView; process map/scan/disassembly/snapshot/pointer/address list |
| Optional MemProcFS runtime | BLOCKED | actual launch failed: Win32 error 126 loading `vmm.dll` |
| Process live write/freeze | BLOCKED | read-only candidate run; address-list Freeze OFF |
| D3390AD4 physical write | BLOCKED | `NOT_RUN`; DADF interim transaction만 PASS |
| Final Release physical write | BLOCKED | `NOT_RUN`; exact Release read-only gate kept writes at 0 |
| Physical transaction evidence archive | PASS | `live-20260823-110826-359.zip`, SHA-256 `b8e88cb7cc78ab42f5edf0b4409b99ab4e6e60ab2761ed08f98233ee11bd0769` |
| Scoped demonstration GIF | PASS | 17-frame 1280×720 interim-write + D339 read-only evidence |
| Final hash-bound v2 evidence | BLOCKED | final package is bound, but v2 bundle is not produced/validated |

## 완료 산출물

- Windows Debug/Release `KDBG.exe` and bridge
- WDK Debug/Release `KDbgDriver` and `KDbgProbe` SYS/INF/CAT/PDB
- validated exact Release main/symbol package, SPDX and manifests; post-document repack will refresh external hashes
- same-VM ABI6 physical evidence at `out/evidence/live-20260823-110826-359/` and matching ZIP
- D339 read-only manifest `out/evidence/candidate-d3390ad4-advanced-live.json`
- scoped demo `out/evidence/KDBG-1.0.0-demonstration.gif`
- authoritative final binding `out/evidence/final-live-manifest.json`
- release digest set `out/evidence/RELEASE-HASHES.txt`
- current Windows benchmark JSON and D339 full-window GUI screenshots under `out/evidence`

## 현재 안전 및 증거 경계

```text
VM: Windows-VM (existing)
Checkpoint: confirmed
Administrator: confirmed
Test-signing: confirmed
Same continuously running VM: PASS
Interim package device/ABI6 transaction: PASS
D3390AD4 advanced read-only live: PASS
D3390AD4 physical write: BLOCKED (NOT_RUN)
Final Release deploy/hash/device/ABI/read-only/invalid IOCTL/stop-remove: PASS
Final Release physical writes: 0 (write gate BLOCKED/NOT_RUN)
Driver Verifier, process write/freeze, MemProcFS, v2: BLOCKED
```

## 재개 후 첫 명령

문서 반영 최종 repack의 SHA를 갱신한 뒤 기존 VM에 전달한다.

```powershell
.\src\tools\package_windows.ps1 -Configuration Release -Zip
```

candidate/package 검증, interim DADF write, D339 read-only, 그리고 exact Release의
deploy/hash/device/main ABI6/fresh Probe/4 KiB read-only/invalid IOCTL/stop-remove는
PASS다. 문서 repack 후 같은 read-only/lifecycle 검증을 재실행해 외부 manifest/hash를
갱신한다. 남은 gate는 final physical write, process write/freeze, MemProcFS,
Driver Verifier와 v2다. 현재 GIF는 PASS지만 interim+D339 candidate 범위다.

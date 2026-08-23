# KDBG 1.0.0 검증 보고서

검증 일자: 2026-08-23 KST

## 1. 환경과 안전 판정

| 항목 | 값 |
|---|---|
| OS | Windows 11 Pro x64, build 26200 |
| Host | HP ProBook 물리 장비 |
| Privilege | 비관리자 |
| CMake / Ninja | 4.4.0 / 1.12.1 |
| Python | 3.11.9 |
| Clang | 22.1.8 |
| MSVC | 19.51.36248.0, tools 14.51.36231 |
| MSBuild | 18.7.8 |
| WDK | 10.0.28000.0 |
| Syft | 1.49.0, SPDX schema 16.1.10 |
| Git revision | 저장소에 `.git` metadata 없음; deterministic source-snapshot SHA-256 사용 |
| Live VM | 기존 `Windows-VM`; checkpoint, Administrator, test-signing 확인 |

Fresh core Debug/Release/sanitized/clang-tidy, Windows Debug/Release/`windows-analyze`, WDK Debug/Release clean과 package gates가 PASS했다. 기존 `Windows-VM`은 checkpoint, Administrator, test-signing 조건을 만족했다. 같은 VM에서 exact Release package의 deploy/hash binding/device/main ABI6/fresh Probe query/exact 4 KiB read-only/invalid IOCTL rejection/stop-remove를 physical writes 0으로 완료했다. Interim DADF physical transaction과 D339 advanced read-only 결과는 각자의 제한된 범위로 유지한다.

## 2. 필수 baseline

```powershell
python .\src\tools\verify_layout.py
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

최종 결과:

```text
Layout: PASS
Configure/build: PASS
CTest: 1/1 PASS
Direct test binary: 707 checks, 0 failures
Source-complete validator: PASS
```

검사 범위에는 PFN/ABI/overflow, exact and short I/O, full-page transaction/recovery, PID identity, scanner types and filters, malformed persistence, pointer bounds, snapshots, PFN reverse mapping, LA57/large pages, MemProcFS protocol/cancel/timeout가 포함된다.

## 3. Portable, sanitizer, static analysis

다음 preset을 모두 `-Fresh`로 configure/build/CTest했다.

```powershell
.\src\tools\build.ps1 -Preset core-debug -Fresh
.\src\tools\build.ps1 -Preset core-release -Fresh
.\src\tools\build.ps1 -Preset core-sanitized -Fresh
.\src\tools\build.ps1 -Preset core-clang-tidy -Fresh
.\src\tools\build.ps1 -Preset windows-analyze
```

| Gate | 결과 |
|---|---|
| Clang Debug strict warnings | PASS, CTest 1/1 |
| Clang Release strict warnings | PASS, CTest 1/1 |
| Windows Clang ASan/UBSan RelWithDebInfo | PASS, CTest 1/1, finding 0 |
| clang-tidy `clang-analyzer-*` warnings-as-errors | PASS, CTest 1/1 |
| MSVC `/analyze /WX` | PASS, CTest 1/1 |
| Sanitized benchmark correctness | six metrics PASS |

MSVC analyzer가 발견한 실제 결함은 null module handle, WOW64 constant condition, bridge/diagnostic/test stack pressure, function-pointer flow, SAL mismatch였다. 제품 코드를 수정하고 large test/session objects를 heap 또는 preallocated static storage로 이동했다. pinned `imgui_memory_editor`의 U64 formatter C6340은 KDBG wrapper header 안에서 해당 외부 헤더에만 범위를 제한해 suppression했다. KDBG-owned C6340은 계속 `/WX` 대상이다.

## 4. 실제 MSVC Windows build

```powershell
.\src\tools\build.ps1 -Preset windows-debug -Fresh
.\src\tools\build.ps1 -Preset windows-release -Fresh
```

두 preset 모두 실제 MSVC x64 GUI, native bridge, core tests를 compile/link했고 CTest 1/1 PASS였다.

- `KDBG.exe`: x64, FileVersion 1.0.0.0, ProductVersion 1.0.0
- `kdbg_memprocfs_bridge.exe`: x64, FileVersion/ProductVersion 1.0.0.0
- Release EXE에서 Debug CRT import 없음
- GUI에서 `Dbghelp` import 확인
- fetched ImGui checkout은 pinned docking commit이며 `IMGUI_HAS_DOCK` 활성

pinned Zydis/Zycore의 오래된 minimum CMake version과 Doxygen 미설치 경고는 외부 configure warning이며 KDBG compile/analyzer warning은 아니다.

## 5. 실제 WDK build

```powershell
.\src\tools\build_drivers.ps1 -Configuration Debug -Clean
.\src\tools\build_drivers.ps1 -Configuration Release -Clean
```

| Configuration | KDbgDriver | KDbgProbe | 결과 |
|---|---|---|---|
| Debug | SYS/PDB/INF/CAT | SYS/PDB/INF/CAT | PASS, errors 0, warnings 0 |
| Release | SYS/PDB/INF/CAT | SYS/PDB/INF/CAT | PASS, errors 0, warnings 0 |

두 INF 모두 `DriverVer=08/15/2026,1.0.0.0`으로 deterministic stamp됐다. WDK signability test와 CAT generation은 통과했다. build script는 불완전한 WDK kit와 MSBuild output의 `: error`를 fail-closed로 처리한다. 이 결과는 production certificate trust 또는 실제 load 성공을 뜻하지 않는다.

## 6. GUI와 local diagnostics

2026-08-20 Release package의 clean-profile 120 DPI 캡처는 historical이다. 현재
candidate `D3390AD4...`는 같은 live VM에서 Probe, process selector, memory map,
scanner/address list, disassembly, snapshot, pointer, PFN reverse mapping, Page Tables,
About와 최종 locked 상태의 full-window 캡처를 새로 만들었다. 따라서 현재 candidate
visual workflow는 PASS지만, 별도의 clean-profile DPI matrix는 재실행하지 않았다.

```text
Window appeared: PASS
Default docking: PASS
Left/central/right/bottom panes visible: PASS
Right tab overflow arrows visible: PASS
Normal CloseMainWindow shutdown: PASS
Forced termination: false
KDBG/KDBGProbe services after smoke: not registered
```

진단 smoke:

- 36,000 safe enum events → 3 rotating files, 각 파일 1 MiB 이하
- 파일 크기 227,198 / 1,048,570 / 1,048,570 bytes
- sensitive-pattern scan 0 matches
- intentional isolated unhandled exception → 171,894-byte `MiniDumpNormal`과 216-byte text report
- report에 UTC/PID/TID/code/address/write status와 `External transmission: none` 기록

crash smoke는 별도 temporary process/profile에서 수행했으며 제품 live driver를 사용하지 않았다.

## 7. 성능 benchmark — current Windows Release

최종 Windows Release build 뒤 `out/build/windows-release/benchmarks/kdbg_benchmarks.exe`를
다시 실행했다. 결과는 `out/evidence/benchmark-windows-release.json`에 있으며
deterministic mock-only이고 `live_driver_access=false`다.

| Metric | Result |
|---|---:|
| 200 × 4 KiB transaction | median 0.006 ms, p95 0.006 ms, max 0.035 ms |
| 32 MiB First Scan | 98.924 ms, 323.479 MiB/s, 8192 results |
| Candidate estimate | 581,632 bytes |
| Peak RSS / delta | 41,578,496 / 2,859,008 bytes |
| Next Scan | 1.941 ms, 8192 → 4096 |
| Pointer cap | 128/128, 0.171 ms |
| 16 MiB snapshot | capture 127.185, save 2393.239, load 105.435 MiB/s |
| Cancel response | 4.152 ms request-to-completion |

모든 correctness/cap/integrity/cancellation gate가 PASS였다. 관측 시간은 현재 호스트의 회귀 기준이며 일반화된 성능 보장은 아니다.

## 8. Release package

```powershell
.\src\tools\package_windows.ps1 -Configuration Release -Zip
python .\src\tools\validate_release.py `
  --windows-package .\out\package\KDBG-1.0.0-win-x64 `
  --symbols-package .\out\package\KDBG-1.0.0-win-x64-symbols
```

현재 candidate 검증 결과:

- main package validator PASS
- symbols package validator PASS
- required EXE/SYS/INF/CAT/config/tools/docs/licenses present and nonempty
- main package PDB 0; driver PDBs in separate symbols package
- SPDX-2.3 SBOM contains KDBG, ImGui, imgui_memory_editor, Zydis, Zycore
- `SHA256SUMS.txt` covers every packaged file exactly once
- package-local `diagnose.ps1 -VerifyPackage` PASS
- identical input으로 두 번 패키징한 main/symbol ZIP SHA-256이 각각 동일
- source revision이 없을 때 defined source snapshot의 SHA-256과 file count를 metadata에 기록

Fail-closed negative cases:

| Mutation | Expected | Result |
|---|---|---|
| hashed document content tamper | hash mismatch | rejected, exit 1 |
| PDB inserted into main package | symbols separation error | rejected, exit 1 |
| metadata changed to Debug | configuration mismatch | rejected, exit 1 |
| empty/fabricated live JSON | v2 schema/evidence errors | rejected, exit 1 |

2026-08-23에 source snapshot을 explicit root allowlist로 제한하고 metadata에
`source_snapshot_scope = kdbg.source-snapshot.v1`을 기록했다. source scope는 230개
파일을 포함하며 main/symbol strict validators가 PASS했다. 변경 없는 동일 입력으로
두 번 생성한 main/symbol ZIP은 각각 동일했고, package negative report는 5/5
expected exit-1이었다. 근거는 `out/evidence/package-provenance-candidate.txt`와
`out/evidence/package-negative-20260823-065145-394-75a2c8a6.json`이다. 문서 반영
후 최종 repack에서 공개 SHA만 갱신하며 candidate digest/ZIP SHA는 여기에 고정하지
않는다. Package PASS는 live PASS를 뜻하지 않는다.

## 9. 라이선스와 privacy

- dependency lock revisions match fetched ImGui docking, imgui_memory_editor, Zydis and Zycore sources
- project and all bundled dependency notices are included in `licenses/`
- MemProcFS is optional/out-of-process and is not bundled or linked into the GUI
- package text scan found no private user path or email address
- logs and crash dumps remain local; automatic telemetry/upload 없음

## 10. Same-VM ABI6 physical transaction

같은 continuously running `Windows-VM`에서 KDBG PID 1140, ABI 6으로 다음을
검증했다. write 대상은 KDbgProbe fixture 한 페이지뿐이다.

| 항목 | 값/판정 |
|---|---|
| Package identity | `DADF43AA...` — interim, final 아님 |
| Probe | PFN `0xDA9FE`, PA `0x00000000DA9FE000`, generation 1 |
| Baseline | CRC32 `0x9DA6C668` |
| Edit | offset `0x100`, `3D4E5F70` → `4B444247` |
| Preflight | PASS — full 4096-byte baseline match |
| Apply read-back | PASS — full 4096-byte expected match |
| Independent reload | PASS — full 4096-byte expected match |
| Rollback | PASS — full 4096-byte baseline match, CRC32 `0x9DA6C668` restored |
| Write gate | PASS — locked after transaction |
| Driver counters after rollback | reads 11, writes 2, rejected 0, stage 4, status 0, transferred 4096 |

Evidence:

- extracted directory: `out/evidence/live-20260823-110826-359/`
- archive: `out/evidence/live-20260823-110826-359.zip`
- archive SHA-256: `b8e88cb7cc78ab42f5edf0b4409b99ab4e6e60ab2761ed08f98233ee11bd0769`

## 11. D3390AD4 advanced read-only live

같은 `Windows-VM`에서 D3390AD4 candidate의 fresh Probe query와 read-only workflow를
수행했다. 이 candidate에서는 physical write를 실행하지 않았다(`NOT_RUN`).

| 항목 | 상태 | 실제 관측 |
|---|---|---|
| Built-in selected-process PFN reverse map | PASS | 2,000,000 table-page cap에서 mapping 1개 |
| Page-table visualization | PASS | selected VA의 최종 PA/PFN이 Probe `0x00000000DA9FE000` / `0xDA9FE`와 exact match |
| Process map/modules | PASS | memory regions/modules와 module header 표시 |
| First/Next Scan | PASS | first 26, next 26 |
| Address list | PASS | entry 1개, Freeze OFF |
| Disassembly | PASS | 456 instructions |
| Snapshot comparison | PASS | 4096 bytes, changed runs 0 |
| Pointer scan | PASS | 10,385 paths |
| About/counters/final safe state | PASS | process detached; process/physical gates LOCKED; physical page CLEAN |
| Optional MemProcFS | BLOCKED | actual launch failed: Win32 error 126 loading `vmm.dll` |
| Process live write/freeze | BLOCKED | read-only run; write/freeze not performed |
| Candidate physical write | BLOCKED | `NOT_RUN`; successful physical write evidence remains DADF interim only |

Evidence manifest: `out/evidence/candidate-d3390ad4-advanced-live.json`.

## 12. Demonstration media

`out/evidence/KDBG-1.0.0-demonstration.gif` is PASS for its declared scope: 17
frames at 1280×720, with frames 1–5 showing the interim ABI6 physical transaction
and frames 6–17 showing D339 candidate read-only validation. It is not final-package
`kdbg.live-evidence.v2`, so final v2 evidence remains BLOCKED.

## 13. Exact Release read-only/lifecycle gate

동일 `Windows-VM`에서 exact Release package에 대해 다음을 검증했다.

| 항목 | 상태 | 경계 |
|---|---|---|
| Deploy and hash binding | PASS | exact identity는 external manifest/hash set에 기록 |
| Device/main ABI | PASS | ABI 6 |
| Fresh Probe query | PASS | clean fixture query |
| Physical read-only | PASS | exact 4096-byte read; physical writes 0 |
| Invalid IOCTL rejection | PASS | fail-closed rejection |
| Stop/remove | PASS | both drivers stopped and removed |
| Final physical write | BLOCKED | `NOT_RUN`; successful write remains interim DADF only |

Authoritative identity/evidence binding:

- `out/evidence/final-live-manifest.json`
- `out/evidence/RELEASE-HASHES.txt`

Source documentation intentionally does not embed the Release ZIP digest.

## 14. VM prerequisite와 남은 BLOCKED gate

| 항목 | 상태 | 실제 범위 |
|---|---|---|
| 기존 `Windows-VM` checkpoint | PASS | 복원 가능한 checkpoint 확인 |
| Administrator | PASS | guest 관리자 세션 확인 |
| test-signing | PASS | guest test-signing 활성 확인 |
| 이전 package install/start | PASS | 이전 ZIP 설치 및 두 서비스 Running |
| 최종 main/symbol package | PASS | new scope, validators, reproducibility, 5/5 negative fixtures |
| Interim package device/ABI6/Probe transaction | PASS | same VM, PID 1140, full-page transaction evidence |
| D339 candidate advanced read-only | PASS | reverse map/PTView/process read-only workflow; final gates locked |
| Scoped demonstration GIF | PASS | interim physical + D339 read-only frames |
| Final Release read-only/lifecycle | PASS | external hash binding, ABI6, Probe/4 KiB read, invalid IOCTL, stop/remove; writes 0 |

다음은 이 보고서에서 PASS가 아니다.

- final physical write (`NOT_RUN`)
- Driver Verifier (`NOT_RUN`)
- process live write/freeze
- optional MemProcFS runtime (`vmm.dll` error 126)
- final-package hash-bound `kdbg.live-evidence.v2`

VM 전제, package gate, exact Release read-only/lifecycle, interim ABI6 physical transaction,
D339 advanced read-only workflow와 scoped GIF는 PASS다. 현재 차단 원인은 final physical
write, Driver Verifier, process write/freeze, optional MemProcFS와 final v2 evidence다.
문서 repack 후 같은 read-only/lifecycle 검증을 재실행해 external manifest/hash를
갱신한다. Production Authenticode trust는 주장하지 않는다.

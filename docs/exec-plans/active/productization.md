# Active plan — KDBG 1.0.0 end-to-end productization

- 시작: 2026-08-20 KST
- 책임: `kdbg_supervisor`
- 제품 버전: 1.0.0
- 현재 단계: exact Release read-only/lifecycle PASS, write-sensitive/v2 gates 대기
- 판정 원칙: 실제 명령·산출물·로그가 있을 때만 PASS

## 안전 경계

- 기존 `Windows-VM`의 복원 가능한 checkpoint, Administrator, test-signing은 확인됐다.
- interim `DADF43AA...` package의 ABI6/Probe PASS를 final package PASS로 사용하지 않는다.
- D3390AD4 candidate는 read-only PASS이며 physical write는 `NOT_RUN`이다.
- exact Release는 deploy/hash/device/main ABI6/Probe read-only/invalid IOCTL/stop-remove PASS이며 physical writes 0이다.
- 최초 live write 대상은 확인된 `KDbgProbe` 4 KiB fixture PFN뿐이다.
- signing bypass, vulnerable-driver loader, stealth, injection, anti-cheat/evasion, arbitrary kernel-virtual write는 구현하거나 실행하지 않는다.

## 감사 및 구현 결과

필수 instruction, agent/skill, PRD/architecture/status/ABI/build/package surface를 읽고 kernel, memory core, GUI, PFN/PTView, QA/safety, release/evidence 트랙으로 감사했다. 주요 수정:

- persistent/racy physical write gate를 synchronized per-handle fail-close gate로 변경
- full-page expected/preflight/read-back, explicit relock, rollback recovery 구현
- address-table load Freeze disarm, process-only verified write, PID/identity binding 구현
- scanner short read/gap/carry/progress와 all public input/result/snapshot caps 보강
- pointer boundary/cycle/depth/absolute alignment, numeric delta overflow 보강
- process EPROCESS lifetime and creation-token PID reuse protection
- strict ABI/reserved/length/ack/range/overflow validation and layout tests
- MemProcFS concurrent drain/timeout/output cap/protocol/map validation
- LA57/4K/2M/1G/effective permissions and reverse-map caps/dedup
- probe-first docked GUI, safe write review, independent reload evidence, status/prerequisite UX
- local bounded log/crash diagnostics, DPI/layout/settings/About/version/licenses
- strict package/live validator, SPDX, deterministic ZIP, source snapshot provenance

## 최종 gate checklist

| Gate | 상태 | 근거 |
|---|---|---|
| Repository/layout audit | PASS | layout validator + stale/dependency/license audit |
| Mandatory Debug baseline | PASS | 707 checks, 0 failures |
| Clang Debug/Release | PASS | fresh strict builds and CTest |
| ASan/UBSan | PASS | fresh test and benchmark, finding 0 |
| clang-tidy | PASS | `clang-analyzer-*` warnings-as-errors |
| Source validator | PASS | required artifacts/tests fail-closed |
| MSVC Debug/Release GUI/bridge | PASS | fresh real x64 builds and CTest |
| MSVC `/analyze /WX` | PASS | all KDBG-owned user-mode targets |
| WDK Debug/Release | PASS | clean builds; both drivers SYS/PDB/INF/CAT; signability errors/warnings 0 |
| Driver deterministic negatives | PASS | ABI/size/overflow/gate/ack/controller/cleanup unit contracts |
| VM prerequisite | PASS | existing `Windows-VM`, checkpoint, Administrator, test-signing |
| Previous-package install/start | PASS | older package only; both services Running |
| Same-VM interim device/ABI6 | PASS | continuously running VM, KDBG PID 1140 |
| Final invalid IOCTL rejection | PASS | exact Release fail-closed rejection evidence |
| Driver Verifier | BLOCKED | `NOT_RUN` |
| Scanner/address/freeze/pointer/snapshot fixtures | PASS | deterministic suite and benchmark |
| PFN/PTView synthetic fixtures | PASS | protocol/reverse map/LA57/large page tests |
| Built-in PFN ownership/PTView live | PASS | D339 selected-process reverse map 1 mapping at 2M cap; exact Probe PA |
| Optional MemProcFS runtime | BLOCKED | actual launch error 126 loading `vmm.dll` |
| Advanced process read-only live | PASS | map/modules, First/Next Scan, address-list Freeze OFF, disassembly, snapshot, pointer |
| Process live write/freeze | BLOCKED | write-sensitive process actions not run |
| Current candidate GUI visual workflow | PASS | D339 full-window Probe/process/PFN/PTView/About captures |
| Clean-profile DPI-specific smoke | BLOCKED | current candidate DPI matrix not rerun |
| Local diagnostics | PASS | 1 MiB rotation/redaction/minidump smoke |
| Current performance | PASS | final Windows Release rerun; all six mock-only metrics PASS |
| Final Release ZIP/symbols/SBOM/licenses | PASS | new scope, strict validators, same-input ZIP reproducibility |
| Package/live validator negative fixtures | PASS | 5/5 expected exit-1 cases |
| Interim Probe physical transaction | PASS | PFN `0xDA9FE`; full-page preflight/read-back/reload/rollback; gate locked |
| D339 candidate physical write | BLOCKED | `NOT_RUN` |
| Final Release deploy/hash/device/ABI/read-only | PASS | external identity binding; fresh Probe/4 KiB read; physical writes 0 |
| Final Release physical write | BLOCKED | `NOT_RUN`; DADF write evidence is interim only |
| Final Release stop/remove | PASS | both drivers stopped and removed |
| Scoped demonstration GIF | PASS | interim physical + D339 read-only, 17 frames |
| Final v2 live evidence | BLOCKED | final package is bound; v2 bundle absent |

## 발견 후 수정·재실행 기록

1. 최초 `core-debug` build exit 1:
   - Windows `std::getenv` deprecation under `-Werror`
   - `max` macro collision in MemProcFS provider
   - `_dupenv_s`와 `NOMINMAX`로 수정 후 PASS
2. MSVC `/analyze /WX` 초기 exit 1:
   - null `GetModuleHandleW`, WOW64 constant condition, unchecked function pointers
   - large stack frames, `wWinMain` SAL mismatch
   - 실제 코드/수명 배치를 수정하고 third-party-only C6340 범위를 제한한 후 PASS
3. WDK initial kit/tool selection:
   - x86 `InfVerif.dll` 누락을 MSBuild가 exit 0으로 흘리는 환경 결함
   - 완전한 최신 kit, amd64 MSBuild, output `: error` 탐지로 fail-close 후 Debug/Release PASS
4. 최초 package command exit 1:
   - WDK StampInf가 두 INF를 시간 기반 `13.x` 버전으로 변경해 validator가 거부
   - project StampInf를 deterministic `1.0.0.0`으로 고정하고 WDK 재빌드 후 PASS
5. 최초 GUI 화면 캡처:
   - capture process DPI virtualization으로 배경/부분 프레임을 잘못 캡처
   - 해당 이미지는 증거에서 제외하고 Per-Monitor-V2 `PrintWindow` 전체 프레임으로 재검증

## 산출물

- `out/build/{core-debug,core-release,core-sanitized,core-clang-tidy}`
- `out/build/{windows-debug,windows-release,windows-analyze}`
- `out/drivers/{Debug,Release}`
- validated exact Release `out/package/KDBG-1.0.0-win-x64{,-symbols}` and ZIPs; refresh external SHA after document repack
- historical clean-profile DPI capture plus current D339 `out/evidence/candidate-*.png` captures
- current `out/evidence/benchmark-windows-release.json`
- `out/evidence/live-20260823-110826-359/`
- `out/evidence/live-20260823-110826-359.zip` — SHA-256 `b8e88cb7cc78ab42f5edf0b4409b99ab4e6e60ab2761ed08f98233ee11bd0769`
- `out/evidence/candidate-d3390ad4-advanced-live.json`
- `out/evidence/KDBG-1.0.0-demonstration.gif`
- `out/evidence/final-live-manifest.json` (authoritative exact Release live binding)
- `out/evidence/RELEASE-HASHES.txt` (authoritative digests)

## 남은 최소 작업

VM prerequisite, package gate, DADF physical transaction, D339 advanced read-only,
scoped GIF와 exact Release read-only/lifecycle gate는 완료됐다. 문서 repack 뒤 external
identity를 갱신할 재실행과 write-sensitive live evidence가 남는다.

1. 문서 반영 final repack과 새 SHA 기록
2. 같은 `Windows-VM`에서 final read-only/lifecycle gate 재실행 후 external manifest/hash 갱신
3. final physical write (`NOT_RUN`) 여부 결정
4. process live write/freeze
5. optional MemProcFS dependency 복구 후 actual launch 재검증
6. Driver Verifier 및 final v2 evidence

재개 후 첫 명령:

```powershell
.\src\tools\package_windows.ps1 -Configuration Release -Zip
```

production Authenticode trust는 별도 증거가 없으므로 주장하지 않는다.

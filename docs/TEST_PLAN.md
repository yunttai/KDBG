# KDBG 테스트 계획

The current working tree adds the LocalHost RawPfn runtime-host path, ABI 7
exact-page compare/write transaction, evidence producers, and runtime
English/한국어 UI after the frozen **1.1.0 RC4** product-source commit
`4b376bb0d61eab232af8a2f7f29033238b911022`. All RC4 package, Windows build,
live-VM, GUI-capture, and media results below are historical and are not
source-bound evidence for these post-RC4 changes. Current source/portable
implementation validation is PASS. The current WDK driver/package build is not
verified because the required toolset is unavailable in this environment
(`MSB8020`). No current regression-guest or bare-metal live validation is
claimed. Production signing and stable release remain blocked. DEF CON
submission is outside this plan's scope.

## 1. Gate 분리

| Gate | 환경 | 증명하는 것 |
|---|---|---|
| Source-complete | Linux 또는 Windows C++20 | portable core, Codex 구조, source contract |
| Windows-build-verified | Visual Studio/SDK/WDK | GUI, bridge, WDM projects, package |
| Regression-Guest-Verified (`Live-VM-verified` legacy name) | 스냅샷 가능한 Windows VM | 실제 service/device/Probe R/W 회귀 |
| Bare-Metal-Runtime-Host-Read-Only | bare-metal Windows runtime_host | local RAM range와 Raw PFN exact 4 KiB read; 자동 provenance는 선택적 |
| Bare-Metal-Runtime-Host-Probe-Verified | 동일 runtime_host | ProbeFixture apply/read-back/reload/rollback/final lock evidence |
| Bare-Metal-RawPfn-Capability-Verified | 동일 runtime_host | 일반 RawPfn transaction correctness와 UI/target identity |

어느 한 Gate의 PASS를 다른 Gate의 PASS로 표현하지 않는다.

### Runtime-host target contract and current coverage

- `runtime_host`는 KDBG/드라이버가 실행되고 동일 OS의 local system physical
  RAM이 편집되는 bare-metal Windows다.
- `orchestrator_host`는 lifecycle/evidence controller이며 memory target이 아니다.
- `regression_guest`는 existing Hyper-V lane이며 historical VM evidence는 그대로
  보존하고 bare-metal gate로 재표기하지 않는다.
- RawPfn read/write는 일반 제품 범위다. ProbeFixture는 자동 destructive
  evidence target이고 RawPfn 기능을 제한하지 않는다.

현재 bare-metal lifecycle profile, runtime-host harness, target-kind, ABI 7
compare/write, live-verifier v2 source와 deterministic contract test는
source/portable PASS다. 현재 WDK driver/package build는 필요 toolset 부재로
NOT VERIFIED/BLOCKED이며, source-bound Windows driver artifact를 생성하지
못했다. Bare-metal read-only, Probe-write, RawPfn live gate는 모두
**NOT RUN**이다. 기존 VM PASS와 non-visual host localization smoke는 이
세 bare-metal gate를 승격하지 않는다.

| Current gate | Status |
|---|---|
| Source-complete / portable | PASS |
| Windows-build-verified (current WDK drivers/package) | NOT VERIFIED / BLOCKED (`MSB8020`, required WDK toolset unavailable) |
| Regression-guest | NOT RUN for the current working tree |
| Bare-metal runtime-host read-only | NOT RUN |
| Bare-metal runtime-host Probe-write | NOT RUN |
| Bare-metal RawPfn | NOT RUN; source/portable implementation PASS |

Machine/boot/session values may be captured automatically as provenance. They
are not manual confirmations or LocalHost RawPfn product prerequisites.

### Post-RC4 bilingual UI evidence boundary

The post-RC4 change keeps one executable and adds a compiled-in translation
catalog, English default, runtime English/한국어 selection, stable ImGui
`###` IDs, Windows system Korean-font discovery with English fallback, and
language persistence in the existing `[KDBG][Preferences]` ImGui INI section.

Required evidence for this change is:

- portable deterministic localization tests for locale parsing, catalog
  completeness/uniqueness, contextual mixed terminology, stable IDs, font
  fallback, and repeated language switching;
- regression proof that switching language does not change write gates,
  confirmations, dirty edits, selected target, workers, or backend state;
- an MSVC `/utf-8` Windows GUI build of the single executable;
- Windows runtime checks for the permanent top-level `Language / 언어` menu,
  Korean glyph rendering, selector persistence, and English fallback, followed
  by an independent human visual review.

Fresh post-RC4 evidence records `verify_layout.py` PASS, `core-debug`
configure/build plus CTest 9/9 PASS, `windows-debug` GUI build/link PASS through
`build.ps1 -Preset windows-debug -SkipTests`, Windows-debug CTest 9/9 PASS,
and fresh `windows-release` GUI build/link plus CTest 9/9 PASS.
These results promote only the source/portable/MSVC build gates. Actual Korean
font rendering, interactive runtime selector/INI round-trip, live VM, and human
visual gates remain **NOT RUN**.

A non-visual host runtime smoke used isolated `LOCALAPPDATA` under
`out/localization-host-smoke-persistence`. The English-default launch remained
alive for 8 seconds and wrote `[KDBG][Preferences] Language=en-US`. A fixed test
INI was then set to `ko-KR`; the Korean-preset launch remained alive for 8
seconds with `C:\Windows\Fonts\malgun.ttf` present and retained
`Language=ko-KR`. This is PASS only for host launch and INI persistence. Glyph
appearance/clipping, an interactive selector click and its write-state
preservation, VM/live execution, and human visual review remain **NOT RUN**.

### Historical RC4 evidence boundary (not rebound)

Unsigned epoch `product-1.1.0-rc4-final-20260919` passed source, clean Windows
Release, WDK driver, strict main/symbol package and CTest 9/9 gates. Exact
main/symbol/source/scope SHA-256 values are:

- `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9`
- `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68`
- `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92`
- `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`

VM-only derivative `product-1.1.0-rc4-test1-20260919`, package SHA-256
`7f7c179738eb670ca79d6c41bc9c46c445c1ffd31811c46f39bbbdcad3df45d5`,
is bound to required-core run `run-20260919T015729Z-8445dddb`. It passed
cleanup, exact checkpoint restore, and final VM Off. RC4 optional extended,
lifecycle, and soak validation was not run. Test trust is not production
signing/TSA evidence.

GUI run `run-20260919T015850Z-1cfb0381` passed host execution, capture, cleanup,
checkpoint restore, and independent archive/hash integrity audit with 24 frames,
20 scenes, 21 assertions, and 229 actions. Guest evidence/captures SHA-256 are
`c877e2b3695faf6489f0ff3fa517a97eb0cc6f0f334a0a4a4bad900f14446cf4` /
`abfe37fe1694fe8e35229c306663dde0cc4ff688d1a1fa80139f74c8ea9b3695`.
Formal review is not complete; the state and flags remain unchanged.

The initial RC4 MP4 passed mechanical composition but failed independent public
suitability review because private paths and weak crops remained. Public v2
failed independent review because the taskbar remained visible; v2/v3 are
superseded. The redacted presentation-only public-v4 artifact at
`out/demo-product-1-1-0-rc4-test1-public-v4-20260919/KDBG-1.1.0-demo-public-v4.mp4`
has SHA-256
`43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`
and is 9,553,416 bytes, 1920x1080, 10 fps, 405 frames, and 40.5 seconds. Its
automatic compositor and independent presentation review passed. Review covered
405/405 frames, 20 scenes, 24 segments, and 19 boundaries; no rendered path,
username, taskbar, notification, or unrelated process was visible, and core
claims were readable. Report/scenes/contact-sheet SHA-256 values are
`406054011b2e47dc144631e17e63d920acb715e4076c303556a852fd1009bd88` /
`9e4a0543f4aaa61f44a39674e737b212df20474b8f063f1b44aa99d6817dcd04` /
`fa8597a86ae39318e4cd52f2eea0e135623fa77ccf07956ca983702fed59258b`.
Raw `frames/` remain excluded from the public bundle. Final video-only delivery
copy `out/release-media/KDBG-1.1.0-demo-public.mp4` has the same SHA/bytes and is
the only file in that directory. None of these videos promotes the formal
source-bound flags.

Production signing staging contains 11 exact inputs with request SHA-256
`3f94c26060bc437460b22ced778c52f1f70165e49a7ac57f0979c1a347f64001`.
Signing and network submission were not performed; the production signer/HSM,
TSA, returned signed artifacts, stable `v1.1.0` tag, and public release remain
blocked. Annotated source-freeze tag `v1.1.0-rc4` is published to `origin` at
the recorded commit but is not a stable production release.

### Historical 1.0.0 candidate 증거 경계

작업공간에 보존된 frozen 1.0.0 main/symbol package와 VMware
live-device/analysis/lifecycle evidence는 historical evidence다. 당시 새로 생성한
`out/release-epochs/public-symbols-r1` path-mapped package pair는 build/package gate와
Windows 10 build 19044 `calibration-35` exact live rebind가 PASS다. Exact
main/symbol/source는 `b6832712…e47f`/`7801bfef…70aa`/`0484b5dd…49ee`다. 아래의 이전 final live manifest는
없으며 현 작업공간의 근거로 사용하지 않는다.

- `out/evidence/final-live-manifest.json`
- `out/evidence/RELEASE-HASHES.txt`

이 historical path-mapped main/symbol package는 MSVC/WDK Release artifacts, manifest, SBOM, hashes,
EXE/SYS↔PDB 결속을 검증했으므로 `Windows-build-verified`는 PASS다. 이 결과는
frozen epoch의 disposable-VM 결과를 승계한 것이 아니다. 해당 1.0.0 epoch 자체의
physical/process/ownership/PTView/Kernel Explorer/raw-page/media 자동 gate는 PASS다.
Human review/final v4는 PASS다. 그 historical package의 Windows 11 required-core live는
Windows 11 Pro x64 build 26200에서 PASS했다. Interactive GUI/media, repeated
reboot/lifecycle, full process Freeze/ownership/PTView/Kernel Explorer matrix와
long-run performance는 later 1.0.0 final engineering epoch에서 완료됐다. 위
current 1.1.0 evidence는 별도 fresh rebind이며 이 historical 결과를 승계하지 않는다.

아카이브된 이전 기록에는 707 checks와 package/live PASS가 있었지만, 그 final
manifest/hash binding은 현재 작업공간에 없다. Historical 1.0.0 source/build 근거는 fresh GNU
15.1.0 core build, CTest 9/9, 직접 1771 checks/0 failures, validator 73/73,
package lifecycle 117/117,
source validator와 historical MSVC product-rc1 Release build/CTest 9/9 및 이전
Debug/`/analyze` user-mode build/CTest 7/7,
5-second no-driver GUI smoke다. pinned NuGet WDK Debug/Release build와 package
pair validation도 PASS다. VMware snapshot VM의 package install, 10-cycle lifecycle,
reboot recovery, forced-exit cleanup, update/rollback/purge와 Probe physical
write/read-back/reload/rollback은 그 historical exact epoch에서도 PASS다. Cal35는 같은
epoch의 fixture write/Freeze, ownership/PTView, Kernel Explorer와 24-frame media를 결속했다.
그 historical final v4 bundle은 repository-owner-confirmed review 뒤 생성·검증했다.

Native Setup contract tests verify action planning, exact distribution/staging/Product
root identity, command-line quoting, lifecycle delegation, commit/rollback fault
recovery, last-good backup preservation, two-phase purge commit and persistent
cancelled/failed state. Runtime telemetry tests verify explicit activation, fixed-local
absolute output paths, synchronous initial persistence, atomic replacement,
frame-stall aggregation, separate completed/partial/failed/cancelled scan counts,
bounded record eviction and the absence of target contents, process names and
filesystem paths.

## 2. Portable 자동 테스트

실행:

```powershell
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

### 2.1 PFN, range, page table

- decimal/hex PFN과 invalid input
- PFN shift/page-end overflow
- physical range inside/outside/cross-boundary
- 48-bit/57-bit canonical VA
- PTE flag decode
- 4 KiB/2 MiB/1 GiB PA 계산

### 2.2 PhysicalPageSession

- exact 4096-byte load와 clean state
- manual PFN input이 `RawPfn`으로 로드되고 ProbeFixture 여부와 무관하게
  driver-reported local RAM range로 검증되는지 확인
- edit, byte-level undo/redo, revert, dirty bitmap, diff run
- wrong PFN과 locked Apply
- clean/dirty byte preflight conflict
- short read/write
- dirty diff가 작아도 ABI 7 driver compare/write는 exact 4096 bytes이며
  `dirty_bytes`와 `driver_transferred_bytes`를 분리해 기록
- ignored write와 read-back mismatch
- successful Apply와 baseline promotion
- successful/failed rollback
- gate close after success/failure

### 2.3 ProcessMemorySession/VerifiedWriter

- bounded load/edit/undo/redo
- expected-before conflict
- changed-run write와 full-view read-back
- rollback
- process write lock

### 2.4 Scanner

- fixed numeric types, float/double
- UTF-8/UTF-16
- AOB wildcard parser
- Exact/NotEqual/Greater/Less/Between
- Unknown/Changed/Unchanged/Increased/Decreased/delta
- alignment/result limit
- cancellation

### 2.5 Address list와 Freeze

- add/refresh/write/read-back
- Freeze write/read-back
- save/load
- PID mismatch
- frozen entry load disarmed

### 2.6 Pointer/Snapshot/PFN reverse map

- one/two-level pointer path
- module-relative/static root metadata
- process/physical snapshot, CRC, save/load/diff
- corrupted snapshot rejection
- synthetic 4 KiB/large-page reverse mapping
- depth/page/result limit과 cancellation

### 2.7 Runtime localization

- 기본 locale가 English이고 `en`/`en-US`/`ko`/`ko-KR`/한국어 parse가 결정적인지 검사한다.
- compile-in catalog의 key가 중복되지 않고 English/Korean 문구가 비어 있지 않은지 검사한다.
- 선택 언어에서 조작 문구는 번역되지만 PFN/PTE/ABI 같은 contextual technical term과 미등록 진단은 정확한 English를 유지하는지 검사한다.
- visible label이 바뀌어도 `UiLabel` 결과의 `###stable-id`가 유지되는지 검사한다.
- Korean font 미가용에서 English로 fail closed하고, 반복 toggle해도 locale·label 결과가 동일한지 검사한다.
- 언어 전환 전후 write gate, confirmation, dirty/history, target selection, worker/backend state snapshot이 동일한지 회귀 검사한다.
- persistence는 기존 ImGui INI의 `[KDBG][Preferences]` section에 `Language=en-US|ko-KR`로 round-trip하고, invalid value는 English로 복구하는지 검사한다.

## 3. Source validator

```powershell
python .\src\tools\verify_layout.py
python .\src\tools\validate_release.py --source-complete
```

검사:

- `.claude`/`CLAUDE.md` 부재와 Codex agents/skills 수
- nested `AGENTS.md`
- 제품·개발 소스가 `src/` 안에만 존재
- 단일 KDBG/Probe IOCTL header
- CMake에 기재된 source 존재
- legacy 이름/스크립트 제거
- driver/backend/scanner/snapshot/PFN/UI implementation marker
- portable test executable 성공
- third-party revision/license/integration metadata

## 4. Windows build 검사

```powershell
.\src\tools\build.ps1 -Preset windows-debug
.\src\tools\build.ps1 -Preset windows-release
.\src\tools\build_drivers.ps1 -Configuration Release -Clean -WdkMode Auto
.\src\tools\package_windows.ps1 -Configuration Release -Zip
python .\src\tools\validate_release.py `
  --windows-package .\out\package\KDBG-1.1.0-win-x64 `
  --symbols-package .\out\package\KDBG-1.1.0-win-x64-symbols
```

검사:

- MSVC warnings-as-errors
- MSVC `/utf-8` compile option과 단일 `KDBG.exe` bilingual catalog link
- RC resource compile
- Dear ImGui/imgui_memory_editor/Zydis integration
- English 기본/Korean system-font discovery/English fallback Windows GUI smoke
- 상위 `Language / 언어` selector, `[KDBG][Preferences]` 언어 round-trip과 write-sensitive UI state 불변 확인
- native bridge Win32 loader/process API
- 설치형 WDK 또는 hash-locked NuGet WDK의 `/W4 /WX` kernel compile/link
- 두 SYS의 x64 Native/CFG/NX/ASLR/checksum, basename-only RSDS와 PDB GUID+age
- 두 INF의 `Inf2Cat` signability와 정확한 CAT
- package 필수 파일
- SHA-256 manifest 재계산

Current working-tree user-mode/source checks do not complete this gate. The
current driver build attempt is **NOT VERIFIED / BLOCKED** because the required
WDK toolset is unavailable (`MSB8020`); therefore no current SYS/CAT/package or
driver signature claim is made.

Historical RC4 Windows Release user-mode build와 CTest 9/9, pinned NuGet WDK
KDbgDriver/KDbgProbe 1.1.0.0 clean build, Inf2Cat 0 errors/0 warnings,
PE/PDB/driver contract와 strict main/symbol package validation은 PASS다.

Historical 1.0.0 MSVC Debug/Release user-mode build와 CTest도 PASS다. 설치형 WDK는 없지만
pinned NuGet WDK offline fallback으로 Debug/Release 두 driver와 INF-matched CAT를
clean build했고, Inf2Cat 오류/경고 0 및 Release PE/PDB 2/2 정합성을 확인했다.
Release package pair는 검증됐고 user-mode 바이너리는 static MSVC runtime으로
clean Windows 10 build 19044에서 별도 VC++ Redistributable 없이 package diagnostics와
packaged CLI startup을 통과했다. Test-signed drivers의 exact VM load와 cal35 live
workflow도 Windows 10에서 PASS다. RC4 Windows 11 required-core install/load와 Probe
transaction은 build 26200에서 PASS했지만, disposable-VM test trust는 production
signing/TSA를 증명하지 않는다. RC4 Windows 11 extended lifecycle/reboot/soak
gate는 **NOT RUN**이며, historical RC1 extended PASS를 RC4에 재결속하지 않는다.
RC4 공식 GUI run은 host/capture/integrity를 통과했지만 formal 상태는
`CAPTURED_UNREVIEWED`다. 별도 presentation-only public-v4의 automatic/independent
review PASS 역시 공식 source-bound `evidence_pass`를 승격하지 않는다.

이 RC4 Windows build/GUI 근거는 post-RC4 bilingual UI source와 결속되지
않는 historical evidence다. Post-RC4 MSVC `/utf-8` GUI build/link와
Windows-debug CTest 9/9는 새로 PASS했고 비시각적 fixed-INI persistence
smoke도 기록했지만, 실제 Korean glyph/clipping, interactive selector 클릭·상태
불변과 human visual review를 수행하기 전에는
post-RC4 runtime/live/visual PASS를 주장하지 않는다.

Windows-only fallback 회귀는 완전한 `out/wdk-nuget` cache에서 `-Offline` clean
build를 실행하고, cache package 하나의 byte/hash를 바꾼 복사본과 package가 빠진
복사본이 compile 전에 fail-closed 되는지 확인한다. 이 검사는 Administrator,
driver load 또는 네트워크를 요구하지 않는다.

동일 configuration lock file을 다른 handle이 독점한 상태에서는 두 번째 fallback
build가 compile 전에 거부되어야 한다. 같은 Release source를 연속 build했을 때
두 SYS hash가 같아야 하며, 한 번 고정한 SYS/PDB/CAT로 package assembly만 두 번
실행했을 때 main/symbol ZIP hash도 각각 같아야 한다. PDB 내부 stream과 Inf2Cat
catalog generation metadata가 새 build마다 바뀌는 것은 새 candidate로 기록한다.

## 5. Driver ABI/보안 검사

- non-admin device open 실패
- second controller 정책
- ABI mismatch 거부
- malformed Size/input/output length
- transfer cap
- RAM 밖 physical read/write
- write gate off/on/off와 acknowledge magic
- process lookup/lifetime
- service repeated start/stop/unload
- 선택적 Driver Verifier는 disposable VM에서만 수행

Historical 1.0.0 candidate에서는 device/ABI, invalid IOCTL, stop/remove, volatile Driver
Verifier `0x132`와 cleanup을 disposable VM에서 실행해 PASS했다. Runtime verifier와
두 running driver hash를 package artifact hash에 결속했고 최종 write gate가
LOCKED임을 기록했다.

## 6. Live E2E lanes

### 6.1 Current bare-metal runtime-host lane

The executable producer runs on the same Windows instance whose local physical
RAM is exposed by `KDbgDriver.sys`:

```powershell
.\src\tools\win11_baremetal_validation\Invoke-Win11BareMetalValidation.ps1 `
  -PackageRoot D:\release\KDBG-1.1.0-win-x64 `
  -PackageArchive D:\release\KDBG-1.1.0-win-x64.zip `
  -EvidenceDirectory D:\evidence\kdbg-local-host-run

python .\src\tools\validate_release.py `
  --windows-package D:\release\KDBG-1.1.0-win-x64 `
  --symbols-package D:\release\KDBG-1.1.0-win-x64-symbols `
  --baremetal-host-evidence D:\evidence\kdbg-local-host-run\evidence.json
```

The producer records `role=runtime_host`, `TargetProfile=LocalHost`, the exact
package/driver/ABI identity, a read-only exact 4 KiB Raw PFN result, and a
`kdbg.live-verify.v2` Probe transaction with six 4096-byte page artifacts. The
ABI 7 transaction records eight locally dirty bytes separately from each
4096-byte driver transfer. It then produces
`kdbg.win11-baremetal-validation.v1` after cleanup and cross-binding checks.

The ProbeFixture transaction is the deterministic evidence target. It is not a
restriction on normal LocalHost RawPfn input/read/write. Optional automatically
collected provenance is evidence metadata, not a manual product gate. This lane
is currently **NOT RUN**: no successful command output or artifact from a named
bare-metal runtime host exists in the current working-tree evidence set.

### 6.2 Historical disposable-VM regression procedure

1. 반복 부팅이 안정적인 disposable Windows VM의 checkpoint, Administrator,
   test-signing 확인 기록을 사용하고 최종 패키지 SHA를 대조한다. Historical evidence는
   VMware snapshot `win10pro-testmode-pre-kdbg-load`에서 생성하고 종료 후 같은
   snapshot으로 복원했다.
2. 두 driver를 install/start/open한다.
3. startup write gate가 LOCKED인지 확인한다.
4. Probe VA/PA/PFN/generation/CRC를 기록한다.
5. packaged `kdbg_live_verify.exe` read-only run으로 ABI, session lock, PFN과 exact 4096-byte read latency를 기록한다.
6. 작은 구간을 local edit하고 undo/redo를 한 번 시연한다.
7. diff와 PFN confirmation을 표시한다.
8. GUI `Stage Evidence Probe Pattern`과 live verifier가 공통 offset `0x100`/8-byte
   XOR mask를 사용함을 확인하고, write mode를 current snapshot ID와 Probe
   PFN으로 실행해 preflight → 8-byte one-shot write → full-page read-back PASS를 확인한다.
9. PFN independent reload와 Probe CRC 변화를 확인한다.
10. full-page rollback 후 원본 CRC와 독립 read를 확인한다.
11. JSON의 apply/rollback counter가 각각 1 증가하고 종료 시 write gate가 LOCKED인지 확인한다.
12. `validate_release.py --live-run-report`가 성공하고, 최종 v4 evidence에 동일 JSON hash가 포함되는지 확인한다.
13. scene-review JSON이 동일 MP4 hash, 실제 reviewer/UTC, 두 redaction 결정과
    ordered 20-scene millisecond range/observed/note를 포함하고 v4 validator가
    누락·재정렬·범위 초과·placeholder를 거부하는지 확인한다.

Historical 1.1.0 RC4 required-core run `run-20260919T015729Z-8445dddb`은
Windows 11 Pro x64 build 26200, ABI 6, one-shot apply, full 4 KiB
read-back/reload, 4 KiB rollback, final gate locked, cleanup, exact checkpoint
restore와 final VM Off를 PASS했다. Host summary SHA-256은
`4ad612d9298d902066a95c47a64c213454ce229e2ebf23ea153b8e0a702f57b5`,
guest archive SHA-256은
`39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da`다.

Historical 1.0.0 steps 1–12와 step 13의 자동 구조/범위/placeholder 검사는 PASS했다. Pre-human
candidate는 72 entries, SHA-256 `eb465a4e…f16c`로 보존했다. 이후 repository owner가
reviewer/UTC, 20개 observed/note와 redaction 결정을 확인했고 final v4 validator가
네 gate 모두 PASS했다. Human-reviewed final archive는 77 entries, SHA-256
`438881e7…a18e3`이다. Windows 11에서는 그 historical package required-core가 별도
PASS했고, 이 Windows 10 human-reviewed media를 Win11 media로 승계하지 않는다.

Windows 11 required-core evidence는
`out/win11-validation/product-rc1-win11-test2-20260918/runs/run-20260918T042905Z-f19bda60`에
있다. Windows 11 Pro x64 build 26200에서 exact package/source snapshot SHA-256
`41f90e2bd76386513d197ae8d77382238a14549e63608dd39eb2d2b4e2c92934`/
`98700c7c7797725b116b0a6333d644bc4df1793397556ce3572e35d451551eca`,
install/load, ABI 6, exact Probe 8-byte apply, full-page read-back, independent
reload, rollback, final lock, uninstall cleanup, exact checkpoint restore와 final
VM Off를 확인했다. 이 required-core run 자체는 interactive GUI/media, repeated
reboot/lifecycle, full process Freeze/ownership/PTView/Kernel Explorer matrix와
long-run performance를 포함하지 않았다. 이 historical 1.0.0 required-core와
별도 RC1 GUI/extended 결과는 각각 이름이 붙은 과거 epoch에만 결속된다. 현재 RC4
extended는 **NOT RUN**이며, current RC4 GUI run은 아래 RC4 관찰 기록처럼
`CAPTURED_UNREVIEWED`다.

위 source snapshot hash는 tested ZIP에 내장된 302-file identity다. 이후
harness/document 변경이 반영된 현재 checkout identity로 승격하지 않으며,
원본 canonical 302-file manifest는 별도로 보존되지 않았다.

## 7. GUI 고도화 E2E

- process attach/detach와 region/module → Hex navigation
- process memory local edit/undo/redo/apply/rollback
- First/Next Scan, cancel, large result clipping
- address list save/load와 frozen-state disarm
- dedicated fixture process에서 verified edit/freeze
- pointer scan cancel/result
- Zydis disassembly
- snapshot baseline/current/save/load/diff
- PFN ownership bridge와 selected-process fallback
- Page Tables final PFN/PA가 대상 VA와 일치

Historical 1.0.0 candidate에서 process attach, memory map, First/Next Scan, address list,
verified process edit와 세 차례 Freeze 복원, pointer scan, Zydis disassembly,
snapshot, selected-process PFN reverse map, Page Tables exact PFN/PA, Kernel Explorer
module/symbol/bounded read를 live 실행했다. Demo 뒤 fixture baseline 복원도 별도
JSON으로 확인했다. MemProcFS provider의 결정적 Windows helper 회귀에서 64/65
argument 경계, quoting/empty argument, pipe close와 child cleanup, timeout, 실행 중
cancellation, 8 MiB output cap, non-zero exit propagation이 PASS했다. Optional
MemProcFS의 missing DLL/export negative diagnostics도 PASS지만 실제 `pmem`
initialization과 query는 UNVERIFIED다.

Current 1.1.0 RC4 GUI run `run-20260919T015850Z-1cfb0381`은 host execution,
capture, cleanup, checkpoint restore와 independent archive/hash integrity를
PASS했다. 24 frames/20 scenes/21 assertions/229 actions이며 host summary,
guest evidence, captures SHA-256은 각각
`ded51b6fc1a71f670e00e709b53987416823f400c6d9e7010b2c7e55dc642cb1`,
`c877e2b3695faf6489f0ff3fa517a97eb0cc6f0f334a0a4a4bad900f14446cf4`,
`abfe37fe1694fe8e35229c306663dde0cc4ff688d1a1fa80139f74c8ea9b3695`다.
공식 상태는 `CAPTURED_UNREVIEWED`, `evidence_pass=false`,
`human_review_complete=false`로 유지한다.

Initial RC4 MP4는 automatic compositor를 PASS했지만 private path와 crop
문제로 public-suitability review를 FAIL해 internal-only다. Public v2는 taskbar
노출로 independent review FAIL이며 v2/v3는 superseded다. Presentation-only
public-v4 artifact는 9,553,416 bytes, 1920x1080, 10 fps, 405 frames, 40.5
seconds, SHA-256
`43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`이고
automatic compositor와 independent presentation review를 PASS했다. 405/405
frames, 20 scenes, 24 segments, 19 boundaries를 검토했고 rendered path,
username, taskbar, notification, unrelated process는 보이지 않았으며 core
claim은 읽을 수 있었다. Private path/taskbar가 남은 raw `frames/`는 public
bundle에서 제외한다. 이 결과는 공식 source-bound evidence 승격이 아니다.

## 8. 안정성 반복 목표

- Probe page read 100회
- Apply/verify/rollback 10회
- process attach/detach 50회
- worker start/cancel/reset 반복
- driver load/unload 10회
- crash, bugcheck, verification false positive 0회

문제가 생기면 Gate를 실패 상태로 유지하고 VM snapshot으로 복원한다.

Current 1.1.0 RC4 optional extended/lifecycle/soak run은 **NOT RUN**이다.
RC1에서 기록한 cycle/reboot/soak 결과는 historical evidence일 뿐 RC4에
승계하지 않는다.

## 9. 제품화 lifecycle, crash recovery와 update

Tracked portable PowerShell contract/fault-injection suite:

```powershell
.\src\tests\package_lifecycle_tests.ps1
```

이 suite는 temp fixture에서만 publish/remove를 수행하며 exception rollback,
pre-commit crash recovery, committed-set cleanup, exact-child purge 제한,
install `-Start` transaction 범위와 start journal-before-wait 순서를 검증한다.

Portable suite에는 다음 deterministic regression을 둔다.

- Apply 전 local edit를 가진 session을 폐기하고 다시 생성하면 실제 memory는
  바뀌지 않고 새 session은 clean/locked여야 한다.
- mock backend `Close/Open`을 50회 반복해도 매 연결은 write-locked여야 한다.
- apply/full read-back/independent reload/rollback을 10회 반복하고 매 회 baseline과
  write-gate lock이 복원되어야 한다.
- legacy address/watch/pointer persistence를 반복 load해도 entry가 중복되지 않고
  Freeze는 자동 재활성화되지 않아야 한다.

아래 항목은 portable simulation으로 PASS 처리할 수 없는 Windows/VM 전용 case다.

| ID | 시험 | PASS 기준 |
|---|---|---|
| WIN-LIFE-01 | clean install → reboot → open | ABI 일치, startup write gate locked |
| WIN-LIFE-02 | service start/stop 10회 | stale handle/bugcheck 0, 매 start locked |
| WIN-LIFE-03 | GUI connect/disconnect 50회 | controller ownership 누수 0 |
| WIN-LIFE-04 | uninstall → reboot → reinstall | stale service/device/file 0 |
| WIN-CRASH-01 | Apply 전 GUI 강제 종료 | physical memory 불변, 재연결 가능, gate locked |
| WIN-CRASH-02 | worker/Freeze 중 GUI 강제 종료 | worker 정리, Freeze 재시작 안 됨, gate locked |
| WIN-UPD-01 | 직전 package → 현재 package → rollback | schema migration 또는 명시적 거부, stale binary 0 |
| WIN-READY-01 | disconnected 상태에서 Bring Online | 기본 Probe 포함 install/start/connect 후 ready 상태 일치 |
| WIN-READY-02 | async lifecycle cancel/progress | bounded cancel, stale progress/running flag 0 |
| WIN-PROBE-01 | 기본 Probe load 실패 주입 | readiness에 원인 표시, disconnected 유지, 모든 write locked |
| WIN-KEX-01 | Kernel Explorer module refresh | loaded x64 modules are bounded, sorted, canonical, and show base/name/path/PE metadata or a concrete unavailable reason |
| WIN-KEX-02 | local PDB directory/file load | only the explicit local path is used; a known kernel VA resolves to symbol+displacement or shows the exact DbgHelp error |
| WIN-KEX-03 | kernel VA read + Zydis | connected backend returns the exact requested byte count and clipped x64 disassembly; disconnect/short-read/cancel remain distinct failures |
| WIN-PT-NAV-01 | page-table input invalidation | after a successful translation, changing PID or VA clears the prior context/walk and disables stale PA/PFN navigation until Translate succeeds again |
| WIN-EVID-01 | GUI/verifier evidence output | output is under `%LOCALAPPDATA%\KDBG\evidence`; package `SHA256SUMS.txt` remains valid and a package-local verifier output is rejected before device open |
| WIN-EVID-02 | reviewed demo binding | parsed MP4 duration bounds every ordered scene review range; hash/reviewer/time/redaction/observed/note substitution fails closed |

Crash case에서 완료 응답과 full read-back이 없는 write는 성공으로 표시하지 않는다.
Clean-VM/reboot/SCM cleanup/driver unload/actual cancellation은 exact Windows package와
snapshot ID, 종료 코드, driver/backend log가 있어야만 PASS다.

## 10. Driver write-mode와 VERSIONINFO 계약

Pinned WDK Release build 후 아래 결정적 검증을 실행한다.

```powershell
.\src\driver\tests\verify_driver_contract.ps1 `
  -ArtifactsDirectory .\out\test-artifacts\driver-contract
```

이 검증은 malformed `IOCTL_KDBG_SET_WRITE_MODE` input/output length와 invalid
request 분기가 기존 open gate를 잠그고 rejected-write counter를 증가시키는지
확인한다. 또한 두 INF와 WDK project, shared ABI가 광고하는 major/minor,
Windows package version, RC source, 실제 SYS의 VERSIONINFO가 `1.1.0.0`으로
일치하고 company/product/description/copyright/original filename이 존재해야 PASS다.

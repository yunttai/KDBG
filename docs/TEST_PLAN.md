# KDBG 테스트 계획

Current release target: **1.1.0**. Exact 1.1.0 source/package, Windows build,
live and extended-run evidence has been checked. The official source-bound GUI
capture and MP4 passed automatic integrity checks but failed independent human
presentation review and remain `evidence_pass=false`. A separate presentation-only
overlay and final MP4 passed both automatic and independent human review without
promoting the formal source-bound evidence. Named 1.0.0 and
`product-rc1/test2` results below are historical evidence only.

## 1. Gate 분리

| Gate | 환경 | 증명하는 것 |
|---|---|---|
| Source-complete | Linux 또는 Windows C++20 | portable core, Codex 구조, source contract |
| Windows-build-verified | Visual Studio/SDK/WDK | GUI, bridge, WDM projects, package |
| Live-VM-verified | 스냅샷 가능한 Windows VM | 실제 service/device/Probe R/W |

어느 한 Gate의 PASS를 다른 Gate의 PASS로 표현하지 않는다.

### Current 1.1.0 evidence boundary

Unsigned epoch `product-1.1.0-rc1-final-20260918` passed source, clean Windows
Release, WDK driver, strict main/symbol package and CTest 9/9 gates. Exact
main/symbol/source/scope SHA-256 values are:

- `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f`
- `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849`
- `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184`
- `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`

VM-only derivative `product-1.1.0-rc1-test1-20260918`, package SHA-256
`596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`,
is bound to required-core run `run-20260918T091747Z-21a27820` and extended run
`extended-20260918T092819Z-66c07a32`. Both passed cleanup, exact checkpoint
restore and final VM Off. Test trust is not production signing/TSA evidence.

GUI run `run-20260918T092129Z-f14f5f7a` produced 24 captures/20 scenes and
automatic state `CAPTURED_UNREVIEWED`. MP4 SHA-256 is
`c368dde54d19f46fedd32895f319223221538c006fcf4626277665b8fe5aad3d`.
Independent human review failed the 1024 layout: scene 03 grid is absent, scene
20 clips the diff row and text wrapping reduces readability. This failed run is
not promoted as formal source-bound evidence.

Separate presentation-only run `run-20260918T102055Z-6c85cee7` passed 24
captures/20 scenes, cleanup/checkpoint restore/final Off. Scene 20 exact cue and
widened crops resolved the visual blockers. Final video
`out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4` passed
automatic validation and independent presentation-only human review. Video/report
SHA-256 values are
`4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454` /
`e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.

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
- edit, byte-level undo/redo, revert, dirty bitmap, diff run
- wrong PFN과 locked Apply
- clean/dirty byte preflight conflict
- short read/write
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
- RC resource compile
- Dear ImGui/imgui_memory_editor/Zydis integration
- native bridge Win32 loader/process API
- 설치형 WDK 또는 hash-locked NuGet WDK의 `/W4 /WX` kernel compile/link
- 두 SYS의 x64 Native/CFG/NX/ASLR/checksum, basename-only RSDS와 PDB GUID+age
- 두 INF의 `Inf2Cat` signability와 정확한 CAT
- package 필수 파일
- SHA-256 manifest 재계산

Current 1.1.0 Windows Release user-mode build와 CTest 9/9, pinned NuGet WDK
KDbgDriver/KDbgProbe 1.1.0.0 clean build, Inf2Cat 0 errors/0 warnings,
PE/PDB/driver contract와 strict main/symbol package validation은 PASS다.

Historical 1.0.0 MSVC Debug/Release user-mode build와 CTest도 PASS다. 설치형 WDK는 없지만
pinned NuGet WDK offline fallback으로 Debug/Release 두 driver와 INF-matched CAT를
clean build했고, Inf2Cat 오류/경고 0 및 Release PE/PDB 2/2 정합성을 확인했다.
Release package pair는 검증됐고 user-mode 바이너리는 static MSVC runtime으로
clean Windows 10 build 19044에서 별도 VC++ Redistributable 없이 package diagnostics와
packaged CLI startup을 통과했다. Test-signed drivers의 exact VM load와 cal35 live
workflow도 Windows 10에서 PASS다. Windows 11 required-core install/load와 Probe
transaction은 build 26200에서 PASS했지만, disposable-VM test trust는 production
signing/TSA를 증명하지 않는다. Current Windows 11 extended
lifecycle/reboot/soak gate도 exact 1.1.0 derivative에 결속해 PASS했다.
공식 source-bound GUI/media automatic gate는 통과했지만 해당 run의 human review는
FAIL이므로 두 판정을 합치지 않는다. 별도 presentation-only overlay/final MP4의
human PASS 역시 공식 source-bound `evidence_pass`를 승격하지 않는다.

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

## 6. Probe Live E2E

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

Current 1.1.0 required-core run `run-20260918T091747Z-21a27820`은 Windows 11
Pro x64 build 26200, ABI 6, PFN 2117631, offset `0x100` 8-byte apply, full 4 KiB
read-back/reload, 4 KiB rollback, final gate locked, cleanup, exact checkpoint
restore와 final VM Off를 PASS했다. Host summary SHA-256은
`c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b`,
26-entry guest archive SHA-256은
`0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`다.

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
long-run performance를 포함하지 않았다. 해당 범위의 current 1.1.0 fresh rebind는
아래 GUI 및 extended 결과에 별도로 기록한다.

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

Current 1.1.0 GUI run `run-20260918T092129Z-f14f5f7a`는 automatic success,
`CAPTURED_UNREVIEWED`, 24 captures/20 scenes, cleanup/checkpoint restore/final Off를
기록했다. Host summary, guest archive, captures binding SHA-256은 각각
`f5fd51ef18c319c37feb5adb997582e56cd2efe9b03a1d6ea3213237f6815d0b`,
`6104933593259fb074466ba8d21a5fffd7e47803b2bfec71ce206e5c0a4ce252`,
`bd254d7a98230db0199051085453b09ea33405f3efe57a9ded42b8a3bebb6d42`다.
MP4 automatic compositor도 PASS했지만 독립 사람 검토는 scene 03/20과 text
wrapping 문제로 FAIL했다. `evidence_pass`는 false로 유지한다.

Presentation-only overlay run
`out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7`은 scene 20 exact
cue와 widened crops를 적용해 24 captures/20 scenes, cleanup/checkpoint
restore/final Off를 PASS했다. Host summary/guest archive/captures SHA-256은
`e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104` /
`32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce` /
`fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`다.
최종 presentation video는 9,974,541 bytes, 1920x1080, 10 fps, 405/405
frames, 40.5 seconds이고 automatic validation과 독립 presentation-only human
review를 PASS했다. 이 결과는 공식 source-bound evidence 승격이 아니다.

## 8. 안정성 반복 목표

- Probe page read 100회
- Apply/verify/rollback 10회
- process attach/detach 50회
- worker start/cancel/reset 반복
- driver load/unload 10회
- crash, bugcheck, verification false positive 0회

문제가 생기면 Gate를 실패 상태로 유지하고 VM snapshot으로 복원한다.

Current 1.1.0 extended run `extended-20260918T092819Z-66c07a32`은 2 cycles,
10 stop/start operations, 4 reboot boundaries, 1800-second soak, 61 reports x
8 reads = 488 scheduled reads, midpoint verified write/rollback, 7 mock-only
benchmark processes, guest validation, checkpoint restore와 final VM Off를
PASS했다. Host summary/evidence archive SHA-256은
`12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee` /
`f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`다.

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

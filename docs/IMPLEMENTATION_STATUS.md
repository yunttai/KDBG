# KDBG 구현 상태

기준: 2026-09-21 KST

## 현재 working-tree 판정 (authoritative)

제품 목표는 `KDBG.exe`와 `KDbgDriver.sys`가 실행되는 동일 bare-metal Windows
`runtime_host`의 local physical RAM을 Raw PFN으로 읽고 편집하는 것이다.
`orchestrator_host`는 lifecycle/evidence controller이며 implicit memory target이
아니다. Hyper-V `regression_guest`는 별도 회귀 lane이다.

ABI 7 exact 4 KiB compare/write/read-back, RawPfn page session, LocalHost runtime
profile, target-aware GUI와 bare-metal evidence harness가 working tree에 구현됐다.
ProbeFixture는 destructive evidence의 기본 fixture일 뿐 일반 LocalHost RawPfn
제품 동작을 제한하지 않는다.

| Gate | 현재 상태 | 근거/경계 |
|---|---|---|
| Source-complete | PASS | `verify_layout.py`, core configure/build, CTest 14/14, source validator PASS |
| Release validator unit tests | PASS | `python -m unittest src.tests.test_validate_release`: 92/92 |
| ABI 7 physical transaction source | PASS | exact 4096-byte baseline compare, desired-page write, full read-back result/capability implemented and deterministically tested |
| Windows Release/package | PASS (UNSIGNED) | MSVC Release GUI/bridge, pinned WDK driver package, validator, and source snapshot pass in epoch `local-host-source-fix6-rawpfn-20260921`; production trust is not claimed |
| Windows WDK driver build | PASS (PINNED NUGET) | WDK `10.0.26100.2454`; Debug/Release, driver contract, Inf2Cat, and symbol verification pass; drivers are unsigned |
| Bare-metal runtime-host read-only | PASS | `out/evidence/local-host-source-fix3-runtime-host-5/evidence.json`; ABI 7, live backend, exact 4096-byte reads |
| Bare-metal Probe transaction | PASS | same evidence; apply/read-back/reload/rollback/final lock all pass |
| Bare-metal RawPfn live write | PASS (CLI transaction) / GUI scene incomplete | `out/evidence/local-host-source-fix6-rawpfn/raw-pfn.json`; manual `RawPfn` input, exact 4 KiB apply/read-back/reload/rollback, final lock. Required visible GUI scene is not captured. |
| Historical regression-guest evidence | PRESERVED | 해당 historical source/package identity에만 결속; current bare-metal gate로 승격하지 않음 |

2026-09-21 source/tooling repair epoch:
`out/release-epochs/local-host-source-fix6-rawpfn-20260921` (unsigned) and
`out/release-epochs/local-host-source-fix6-test-signed-20260921` (local test
trust). Main/symbol ZIP hashes are
`6673371b…ca0f3526` / `56d91768…1f5cb9ad`; the signed package hash is
`24ba5de9…5e93376b`. PowerShell 5.1/7 package and signing contracts, core-debug
and Windows Release CTest 14/14, package validation, and the local-host
producer preflight all pass.

The GUI driver-service registration quote bug is fixed in
`src/core/windows/DriverService.cpp`; a validator regression test ensures SCM
receives the raw binary path for both create and update.

Current test-signed runtime-host evidence is
`out/evidence/local-host-source-fix3-runtime-host-5/evidence.json`; strict
package validation passes its read-only and Probe-write gates. The independent
RawPfn transaction report is
`out/evidence/local-host-source-fix6-rawpfn/raw-pfn.json` (SHA-256
`017c2808…2d68f1f7`); it is a CLI evidence lane and does not claim a captured GUI
scene.

The RawPfn transaction uses the fix6 test-signed package
`out/release-epochs/local-host-source-fix6-test-signed-20260921` (package
SHA-256 `24ba5de9…5e93376b`; source snapshot `2f5f82df…9df829f6`). The live target
PFN was `8523045` (`PA 34910392320`). The report records 8 dirty bytes,
`driver_transferred_bytes=4096` for apply and rollback, full read-back and
independent reload matches, and `final_gate_locked=true`. The PFN was manually
entered and matched the fresh Probe identity as a safety check; Probe evidence
was not relabeled as RawPfn evidence.

The earlier admin producer run is retained at
`out/evidence/local-host-source-fix-runtime-host-20260921` as historical
evidence. The current source-fix3 run above is the authoritative current
runtime-host report.

machine/boot/session 값은 확보 가능한 경우 자동 provenance로 기록할 수 있지만
수동 확인이나 LocalHost RawPfn 제품 전제는 아니다. 이번 구현은 dedicated-machine,
recovery-plan, Probe-only 같은 새 제품 사용 제한을 추가하지 않았다.

## Historical RC4 판정

RC4 product-source commit은
`4b376bb0d61eab232af8a2f7f29033238b911022`이다. Unsigned epoch
`product-1.1.0-rc4-final-20260919`과 VM-only derivative
`product-1.1.0-rc4-test1-20260919`에 RC4 검증을 결속한다.

| 영역 | RC4 상태 | 완료 조건/경계 |
|---|---|---|
| Source-complete | PASS | layout, core build, CTest 9/9, source validator |
| Windows-build-verified | PASS | exact unsigned main/symbol/source package 검증 |
| Windows 11 required-core | LIVE PASS | exact test derivative, Probe transaction, cleanup, checkpoint restore, VM Off |
| GUI automation/integrity | PASS | 24 frames, 20 scenes, 21 assertions, 229 actions |
| Formal GUI evidence | `CAPTURED_UNREVIEWED` | `evidence_pass=false`; `human_review_complete=false` |
| RC4 extended/lifecycle/soak | NOT RUN | RC1 extended 결과는 historical only |
| Initial RC4 MP4 | PUBLIC FAIL | internal path와 crop/readability blocker |
| Public v4 presentation video | PASS (automatic + independent review) | presentation-only; formal evidence 승격 아님 |
| Production trust | BLOCKED EXTERNAL | signer/cert/private key/HSM/TSA와 signed 반환물 부재 |
| Source-freeze tag | PASS (published RC tag) | annotated `v1.1.0-rc4` on `origin` at the RC4 product-source commit |
| Stable `v1.1.0` / public release | BLOCKED | production signing 검증 전 생성하지 않음 |

Exact main/symbol/source/scope SHA-256은 다음과 같다.

- `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9`
- `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68`
- `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92`
- `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`

VM-only package SHA-256은
`7f7c179738eb670ca79d6c41bc9c46c445c1ffd31811c46f39bbbdcad3df45d5`다.
Required-core `run-20260919T015729Z-8445dddb`의 guest archive SHA-256은
`39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da`다.

GUI `run-20260919T015850Z-1cfb0381`은 host/capture/integrity를 통과했고,
guest evidence/captures SHA-256은
`c877e2b3695faf6489f0ff3fa517a97eb0cc6f0f334a0a4a4bad900f14446cf4` /
`abfe37fe1694fe8e35229c306663dde0cc4ff688d1a1fa80139f74c8ea9b3695`다.
이 자동 PASS는 human review를 뜻하지 않는다.

Production signing input 11개는
`out/production-signing/product-1.1.0-rc4-final-20260919-prepared`에 준비됐고,
request SHA-256은
`3f94c26060bc437460b22ced778c52f1f70165e49a7ac57f0979c1a347f64001`다.
`signing_performed=false`, `network_submission_performed=false`다.

Public v2는 independent review에서 taskbar 노출로 FAIL했고 v2/v3는 superseded다.
최종 presentation-only public v4는
`out/demo-product-1-1-0-rc4-test1-public-v4-20260919/KDBG-1.1.0-demo-public-v4.mp4`,
SHA-256
`43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`,
9,553,416 bytes다. 1920x1080, 10 fps, 405/405 frames, 40.5 seconds이며
automatic compositor와 independent presentation review가 모두 PASS했다. 검토는
20 scenes/24 segments/19 boundaries를 포함하며 rendered
path/username/taskbar/notification/unrelated process가 없고 core claims가 읽힌다.
Video-only delivery copy
`out/release-media/KDBG-1.1.0-demo-public.mp4`도 같은 SHA-256/크기이며 해당
directory에는 MP4만 있다. Raw frames는 공개에서 제외한다. 이 결과는 공식 GUI
evidence를 승격하지 않는다. DEF CON 제출은 이 상태 갱신 범위에서 제외한다.

Annotated source-freeze tag `v1.1.0-rc4`는 `origin`의
`4b376bb0d61eab232af8a2f7f29033238b911022`에 게시됐다. Stable `v1.1.0` tag와
public release는 production signing 전까지 차단한다.

## Historical RC1 1.1.0 판정 (superseded)

아래 RC1 판정은 당시 exact identity의 이력이며 현재 RC4 판정이 아니다.

`feature/kdbg-1.1.0`이 현재 release branch다. Unsigned epoch
`product-1.1.0-rc1-final-20260918`과 VM-only test-signed derivative
`product-1.1.0-rc1-test1-20260918`에 source, Windows build, required-core,
extended lifecycle/soak와 source-bound MP4 자동 검증을 새로 결속했다. 별도
presentation-only overlay와 최종 MP4는 자동 검증 및 독립 human review를
PASS했다. 과거 1.0.0 증거를 승계한 결과가 아니다.

| 영역 | 1.1.0 상태 | 완료 조건 |
|---|---|---|
| Source-complete | PASS | layout, core build, CTest 9/9, source validator |
| Windows-build-verified | PASS | clean MSVC/WDK build, CTest 9/9, Inf2Cat 0/0, strict package/symbol validation |
| Live-device/runtime | LIVE PASS | exact 1.1.0 derivative, ABI 6, Probe PFN 2117631 transaction, rollback and final lock |
| Windows 11 extended | LIVE PASS | 2 lifecycle cycles, 10 stop/start, 4 reboot, 1800-second soak, 488 reads, 7 benchmarks |
| GUI capture | `CAPTURED_UNREVIEWED` | automatic 24-capture/20-scene checks, cleanup/restore/Off PASS |
| Source-bound submission MP4 | AUTOMATIC PASS / HUMAN FAIL | official GUI evidence stays `evidence_pass=false` |
| Presentation-only overlay | PASS | 24 captures/20 scenes; scene 20 exact cue and widened crops resolve visual blockers |
| Final presentation MP4 | PASS (automatic + human) | 1920x1080, 10 fps, 405/405 frames, 40.5 seconds |
| Production trust | BLOCKED EXTERNAL | production signer/TSA and returned signed drivers |
| Commercial operations | PENDING EXTERNAL | monitored support/security notification and acknowledgement |

Exact 1.1.0 identities:

- Main/symbol/source/scope SHA-256:
  `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f` /
  `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849` /
  `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184` /
  `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
- Test-signed package/certificate/signer:
  `596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413` /
  `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1` /
  `ba34b393521d722ba01df87afccc6f3feb760b2c`.
- Required-core `run-20260918T091747Z-21a27820`: host summary
  `c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b`,
  26-entry guest archive
  `0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`.
- Extended `extended-20260918T092819Z-66c07a32`: host summary
  `12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee`,
  guest archive
  `f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`.
- Source-bound MP4 SHA-256
  `c368dde54d19f46fedd32895f319223221538c006fcf4626277665b8fe5aad3d`,
  9,759,713 bytes, 405 frames, 40.5 seconds. 슬라이드와 GIF는 없다.
- Presentation-only run `run-20260918T102055Z-6c85cee7`: host summary,
  guest archive and captures SHA-256
  `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104` /
  `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce` /
  `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`.
- Final presentation video
  `out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`, SHA-256
  `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`,
  report SHA-256
  `e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`;
  9,974,541 bytes, 1920x1080, 10 fps, 405/405 frames, 40.5 seconds.

GUI run `run-20260918T092129Z-f14f5f7a` 자체는 success와
`CAPTURED_UNREVIEWED`를 기록했고 cleanup/checkpoint restore/final Off도 통과했다.
그러나 독립적인 사람 검토는 1024 capture에서 scene 03 grid 부재, scene 20 diff
row clipping, 과도한 text wrapping을 확인해 발표 가독성을 FAIL 처리했다. 따라서
MP4를 DEF CON 제출용 `evidence_pass`로 승격하지 않는다.

별도 presentation-only overlay run
`out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7`은 24 captures/20
scenes, cleanup/checkpoint restore/final Off를 통과했다. Scene 20 exact cue와
widened crops로 이전 시각 blocker를 해결했고, 여기서 만든
`out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`는
automatic validation과 독립적인 presentation-only human
review를 PASS했다. 이는 발표 영상 품질의 PASS이며 공식 source-bound GUI run의
상태나 `evidence_pass=false`를 변경하지 않는다.

## Historical 1.0.0 evidence

Frozen 1.0.0 main/symbol ZIP `7f6b0fd9…b265a`/`d8715bf7…c96f`과 기존
evidence는 byte-for-byte 보존한다. Frozen Windows 10 exact-final automated
analysis, process conflict/no-apply/recovery, cleanup/snapshot restore는 PASS지만
frozen PDB에는 private compiler path가 있어 공개 symbols로 승격하지 않는다.
새 path-mapped epoch smoke build는 user-mode 5개와 driver public/full PDB의
physical repo/profile path 0, basename CodeView, GUID/age, official `pdbcopy.exe`
parse와 main/symbol package strict validation을 통과했다. `R:\`/`K:\`는 공개된
고정 logical aliases다. 이 공개-symbol epoch의 exact main/symbol/source SHA-256
`b6832712…e47f`/`7801bfef…70aa`/`0484b5dd…49ee`는 Windows 10 build 19044
`calibration-35`에서 새로 live rebind했다. Frozen live 결과를 승계한 것이 아니다.

### 1.0.0 판정

| 영역 | 상태 | 근거 |
|---|---|---|
| Source-complete | PASS | layout, GNU 15.1.0 core build, CTest 9/9, 1771 checks/0, validator 73/73, package lifecycle 117/117, source validator |
| MSVC Debug/Release/Analyze user-mode | PASS | historical product-rc1 Release GUI/setup/bridge/live verifier/tests build와 CTest 9/9; 이전 Debug/Analyze CTest 7/7 PASS |
| Sanitizers | BLOCKED (toolchain) | 현재 MinGW 배포에 `libasan`/`libubsan` 없음; 링크 전 컴파일은 진행됨 |
| WDK drivers | PASS (build) | pinned NuGet WDK offline fallback으로 Debug/Release SYS/INF/PDB/CAT clean build, Inf2Cat 0/0, Release PE/PDB 2/2 |
| Windows-build-verified | PASS | user-mode/driver build와 Setup/telemetry closeout가 반영된 main/symbol strict validation, SBOM, hashes, PE/PDB 7/7 PASS |
| Release package | PASS (VM test-signed drivers) | tested ZIP-bound source snapshot의 main/symbol directories와 ZIP/sidecar 생성 및 strict validation PASS; production trust는 별도 gate |
| Path-mapped public symbols | PACKAGE/LIVE PASS (Windows 10) | physical repo/profile path 0, basename CodeView, EXE/SYS↔PDB 7/7, `pdbcopy.exe` parse, exact cal35 runtime identities PASS |
| Commercial operations documents | PASS (candidate contract) | security/support/privacy/MIT-EULA/update-rollback/vulnerability/release-note package contract와 validator tests |
| Native setup UX | LIVE PASS (historical exact package) | elevated `KDBGSetup.exe` completed clean Install, Repair, Update, installed reboot, Uninstall, persistent purge and clean reboot inventory in the snapshot VM |
| Runtime performance telemetry | LIVE PASS (historical exact package) | fixed-local JSON recorded a successful First/Next GUI sequence, nonzero bytes and frames, privacy-negative fields and writer errors 0; exact counters remain external evidence |
| Live-device-run-report | LIVE PASS (historical exact package) | Windows 11 Pro x64 build 26200 disposable Hyper-V VM, ABI 6, driver-owned Probe PFN, 8-byte one-shot apply, 4 KiB read-back/independent reload/rollback and final lock PASS |
| VM lifecycle/reboot | LIVE PASS (historical exact package) | native Install/Repair/Update/Uninstall plus installed and post-uninstall normal reboot boundaries, persistent purge state, full clean inventory and snapshot restore PASS |
| Live analysis/capture | LIVE/NONHUMAN PASS (historical exact package) | cal35: Probe transaction, fixture write/Freeze, PFN ownership, 4-level walk, Kernel Explorer, 24 captures/20 scenes, two exports, cleanup/restore PASS |
| Live-VM-verified | PASS (Windows 10 exact epoch) | repository owner confirmed the 20-scene review; `kdbg.demo-scene-review.v1`, official-schema v4 and final validator PASS |
| Windows 11 required-core live | PASS (VM test trust) | run `run-20260918T042905Z-f19bda60`: Windows 11 Pro x64 build 26200, exact package install/load, Probe transaction, cleanup, exact checkpoint restore and final VM Off PASS |
| Windows 11 extended live | PASS (later final engineering epoch) | interactive GUI capture, repeated lifecycle/reboot, full process Freeze/ownership/PTView/Kernel Explorer evidence and 30-minute soak completed; this is not a 1.1.0 rebind |
| Commercial release | BLOCKED | production trust/timestamp and monitored intake remain incomplete; the Win11 PASS used disposable-VM test trust and is not production signing/TSA evidence |
| Optional MemProcFS pmem | UNVERIFIED | runtime/DLL/acquisition driver 없음; negative diagnostics만 PASS |

과거 package/live 관찰은 현재 working-tree candidate의 증거가 아니다.

## 구현 범위

- Authoritative ABI, 관리자/SYSTEM ACL, controller binding, bounded exact I/O,
  physical-range validation and default-locked per-handle write gates.
- PFN 4 KiB page session with local edits, typed confirmation, preflight,
  dirty-run write, full read-back, independent reload and rollback.
- Process scan/address list/Freeze, pointer scan, disassembly, snapshot, PFN
  ownership fallback and page-table visualization.
- Idempotent/pending-aware SCM lifecycle, update/repair/rollback/readiness tooling,
  async GUI lifecycle progress and distinct runtime readiness states.
- AddressList v2 pointer persistence with v1 migration, WatchList v1→v2 migration,
  transactional loads and persisted Freeze disarm.
- Isolated MemProcFS bridge with bounded protocol/process handling and actionable
  init/query diagnostics; no GUI linkage.
- Read-only Kernel Explorer with bounded loaded-module enumeration, exact-signature
  local-image symbols, kernel-only VA reads and Zydis disassembly. Current live
  module/header/PDB/read evidence is captured; production symbol-service operation
  remains outside the offline candidate.
- Scanner/snapshot hot-path optimizations and schema-2 repeated mock benchmarks with
  median/p95, throughput, cancellation latency and explicit non-product-runtime scope.
- Opt-in runtime telemetry with atomic render-thread counters and a bounded writer for
  GUI frame intervals/stalls and live process-scan region/byte/I/O/cancellation data.
- Windows x64 build 19041+를 실행기와 package metadata 양쪽에서 강제하고,
  장치 open 전에 packaged verifier 및 SCM의 running kernel-driver 두 개를
  package-relative path/SHA-256/type/state로 증명하는 live verifier.
- Read-only-by-default packaged live verifier with four-part write authorization,
  exact Probe apply/read-back/reload/full-page rollback, session counters and JSON.
- Staged package publication, hashes/SBOM/metadata validation, native elevated
  Setup UX and packaged diagnose/install/start/run/stop/uninstall workflow.

기존 typed PFN/PID confirmation, one-shot gate, preflight/read-back/rollback,
test-signing and disposable-VM/snapshot contract는 유지했다. 새로운 우회, signing
bypass, vulnerable-driver load, stealth, arbitrary kernel-virtual write는 없다.

## RC4 stable release에 아직 필요한 실제 제품 gate

1. Production publisher/driver signer, certificate/private key 또는 HSM과 HTTPS
   RFC3161 TSA를 적용하고 반환된 바이너리 및 trusted timestamp를 검증한다.
2. monitored support/security intake route를 실제 운영 상태로 전환하고
   notification/acknowledgement를 보존한다.

첫 번째 gate 전에는 stable `v1.1.0` tag/public release를 만들지 않는다. RC4
`signing_performed=false`, `network_submission_performed=false`를 유지한다.

현재 extended run의 N-1 transition은 보존된 1.0.0 previous candidate를 사용해
PASS했다. 공개 배포처에서 다시 받은 published 1.0.0 artifact에 대한 별도 검증을
했다고 주장하지 않는다.

아래 Windows 11 required-core evidence는 **historical 1.0.0 evidence**다:
`out/win11-validation/product-rc1-win11-test2-20260918/runs/run-20260918T042905Z-f19bda60`에
있다. Exact package/source snapshot SHA-256은 각각
`41f90e2bd76386513d197ae8d77382238a14549e63608dd39eb2d2b4e2c92934`와
`98700c7c7797725b116b0a6333d644bc4df1793397556ce3572e35d451551eca`다.
이 source snapshot은 tested ZIP에 내장된 302-file snapshot identity이며,
post-package harness/document edits가 있는 현재 checkout의 identity라고 주장하지
않는다. 현재 checkout은 같은 알고리즘에서 `ab0ef795…`로 달라졌고 원본
canonical 302-file manifest는 별도로 보존되지 않았다.
이 결과는 test-signed driver를 허용한 disposable VM 범위이며 production
Authenticode trust나 trusted timestamp를 증명하지 않는다.

Historical pre-human candidate는 SHA-256 `eb465a4e…f16c`의 72-entry
`KDBG-1.0.0-public-symbols-r1-live-evidence-candidate.zip`으로 보존했다.
Human-reviewed final은 SHA-256 `438881e7…a18e3`의 77-entry
`KDBG-1.0.0-public-symbols-r1-live-evidence-final.zip`이다.
Historical GIF는 1600x900, 24 frames, 40.5 seconds, SHA-256
`fde0bf78…4ee8`이다. 1.1.0 제출 산출물은 MP4 한 개이며 이 GIF를 재사용하지 않는다.
Guest-local `captures.zip` 자체는 미보존이지만 24개 PNG/hash와 `capture-run.json`,
50-entry export bundle은 보존·검증됐다. Human review와 v4 승격에는 추가 VM run이 필요 없었다.

상세 명령과 상태는 `docs/exec-plans/STATUS.md`, 요구사항별 판정은
`docs/TRACEABILITY_MATRIX.md`를 따른다.

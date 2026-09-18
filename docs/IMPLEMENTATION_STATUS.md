# KDBG 구현 상태

기준: 2026-09-18 KST

## 1.1.0 현재 판정

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

## 1.1.0에 아직 필요한 실제 제품 gate

1. Production publisher/driver certificate와 TSA를 적용하고 반환된 바이너리 및
   trusted timestamp를 검증한다.
2. monitored support/security intake route를 실제 운영 상태로 전환하고
   notification/acknowledgement를 보존한다.

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

# Active plan — KDBG 1.1.0 VM-lab productization

- 책임: `kdbg_supervisor`
- 현재 단계: `feature/kdbg-1.1.0` exact build/package/live rebind 및
  presentation-only 최종 영상 품질 검수 완료; formal GUI evidence review는
  실패 상태 유지
- 판정 원칙: 현재 명령·산출물·로그가 존재할 때만 PASS

## 1.1.0 현재 gate

- Source-complete: **PASS**. Layout, core build, CTest 9/9 and source validator
  passed; source snapshot `8f9a0474…f6a9`, scope `bd2c93da…8932`.
- Windows-build-verified: **PASS for unsigned product epoch**. Unsigned main
  `3698e533…36f`, symbols `0b6dadf7…849`; production trust is not claimed.
- Live-VM-verified: **PASS under disposable-VM test trust** for exact 1.1.0
  required-core and extended lifecycle/soak runs.
- Formal GUI evidence: automated capture PASS, human review **FAIL** and
  `evidence_pass=false` unchanged.
- Presentation video: **PASS**. Presentation-only overlay and final MP4 passed
  automatic checks and independent human presentation review. This is not a
  formal GUI evidence promotion or submission proof. No slide deck or GIF is
  part of the current target.
- Production signer/TSA and monitored operations remain external gates.

## Exact 1.1.0 epoch

- Unsigned epoch `product-1.1.0-rc1-final-20260918`: main
  `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f`,
  symbols `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849`,
  source `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184`,
  scope `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
- Test derivative `product-1.1.0-rc1-test1-20260918`: package
  `596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`,
  certificate `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1`,
  signer thumbprint `ba34b393521d722ba01df87afccc6f3feb760b2c`.
- Required-core `run-20260918T091747Z-21a27820`: summary
  `c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b`,
  archive `0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`.
  Windows 11 build 26200, ABI 6, eight-byte apply, full read-back, 4096-byte
  rollback, final lock, cleanup, checkpoint restore and final VM Off passed.
- Extended `extended-20260918T092819Z-66c07a32`: summary
  `12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee`,
  archive `f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`.
  Two cycles, ten stop/start transitions, four reboots, 1800-second soak,
  61x8=488 reads, midpoint transaction, seven benchmark runs and final cleanup/
  restore/Off passed.
- GUI `run-20260918T092129Z-f14f5f7a`: automated capture success with
  `CAPTURED_UNREVIEWED`, summary
  `f5fd51ef18c319c37feb5adb997582e56cd2efe9b03a1d6ea3213237f6815d0b`, archive
  `6104933593259fb074466ba8d21a5fffd7e47803b2bfec71ce206e5c0a4ce252`, capture
  set `bd254d7a98230db0199051085453b09ea33405f3efe57a9ded42b8a3bebb6d42`,
  24 captures/20 scenes, cleanup/restore/Off PASS. Human
  review is FAIL and `evidence_pass=false`.
- MP4-only output:
  `out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`,
  SHA-256
  `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`,
  9,974,541 bytes, 1920x1080, 10 fps, 40.5 seconds, 405/405 frames; report
  `e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.
- Presentation-only overlay
  `out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7`: automatic
  PASS and independent human presentation review PASS. Summary/guest/capture
  hashes are
  `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104` /
  `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce` /
  `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`;
  24 captures/20 scenes, cleanup/restore/Off PASS. Scene 20 evidence-bound cue
  and scene 10/11 crop corrections resolve the prior visual blockers.

## 완료된 historical 1.0.0 작업

- Frozen 1.0.0 main/symbol ZIP `7f6b0fd9…b265a`/`d8715bf7…c96f`와 기존
  evidence는 변경하지 않는다. Frozen Windows 10 exact-final analysis 및
  controlled conflict/no-apply/recovery는 PASS지만 해당 symbols는 private compiler
  path 때문에 공개하지 않는다.
- Previous path-mapped exact epoch `b6832712…e47f`는 Windows 10 build 19044 live와
  human-reviewed final v4 `fc0afb4b…9823`가 PASS했다. 이 evidence는 새 candidate에
  재결속하지 않는다.
- Historical `product-rc1-20260918`의 정확한 main/symbol/source identity는
  epoch-local ZIP sidecar와 packaged `BUILD-METADATA.json`에 기록한다. Windows
  Release build, CTest 9/9와 package validator가 PASS했고 evidence generator
  mismatch도 이 source에서 수정됐다.

- GNU 15.1.0 full core-debug: build, CTest 9/9,
  1771 checks/0 failures; validator 73/73; package lifecycle 117/117.
- Historical MSVC `product-rc1-20260918` Release GUI/bridge/live-verifier/tests build와
  CTest 9/9 PASS.
- Lifecycle/readiness, package staging/rollback, persistence migration,
  MemProcFS diagnostics and deterministic lifecycle regression implementation.
- layout and source-complete validators PASS.

## Historical 1.0.0 Windows package 결과

- Pinned NuGet WDK 10.0.26100.2454 fallback으로 Debug/Release SYS/INF/PDB/CAT
  build와 Inf2Cat 0 errors/0 warnings를 완료했다.
- MSVC Release user-mode와 driver signing inputs를 묶은 historical main/symbol package,
  SBOM, manifest, hashes와 ZIP sidecar가 strict validator를 통과했다.
- Production signing input 11개는 준비됐지만 production signer, TSA와 returned
  signed drivers는 없다. 따라서 그 historical candidate의 production trust/load를 주장하지 않는다.
- Historical package SHA-256
  `41f90e2bd76386513d197ae8d77382238a14549e63608dd39eb2d2b4e2c92934`와 source
  snapshot SHA-256
  `98700c7c7797725b116b0a6333d644bc4df1793397556ce3572e35d451551eca`는 Windows
  11 Pro x64 build 26200 required-core live run에 exact binding됐다.
  Source hash는 tested ZIP 내부의 302-file snapshot identity이며 post-package
  harness/document edits가 있는 현재 checkout identity가 아니다. 원본 canonical
  302-file manifest는 별도로 보존되지 않았다.

## 현재 1.1.0 실행 결과와 차단

- VM install/start/readiness, 10회 stop/start, four reboot boundaries,
  30-minute soak, midpoint transaction, benchmark series, cleanup and snapshot
  restore: exact 1.1.0 extended run PASS.
- Packaged live verifier Probe physical transaction: exact 1.1.0 required-core
  run PASS. Exact PFN의 8-byte one-shot apply, 4 KiB full read-back and rollback,
  runtime identity와 final lock을 확인했다.
- Previous b683 exact package native Setup lifecycle and runtime telemetry: PASS.
  Install/Repair/Update/installed reboot/Uninstall/clean reboot와 First/Next GUI
  scan, nonzero byte/frame counters, privacy false/writer errors 0을 확인했다.
- Historical raw-page/ownership/PTView/process Freeze/Kernel Explorer/20-scene
  final v4 is PASS only for `b6832712…e47f`. Current 1.1.0 automated scene capture
  completed, but formal human review failed; do not promote it to formal reviewed
  GUI evidence. The separate presentation-only overlay/final MP4 passed its
  independent presentation review.
- Historical 1.0.0 Windows 11 required-core live: PASS. Run
  `run-20260918T042905Z-f19bda60`에서 Windows 11 Pro x64 build 26200의 exact
  package install/load, ABI 6, Probe 8-byte one-shot apply, 4 KiB read-back,
  independent reload, full-page rollback, final lock, uninstall cleanup을 확인했다.
  Exact checkpoint `f60a775a-26f6-4ef9-bb19-f61c93346bb4`를 복원했고 final VM
  state는 Off다.
- A later 1.0.0 final engineering epoch completed interactive GUI/media,
  repeated reboot/lifecycle, full process Freeze/ownership/PTView/Kernel Explorer
  evidence and a 30-minute soak. This is not a 1.1.0 rebind.
- Support/security routes는 configured 상태지만 notification/acknowledgement
  evidence는 아직 없다.
- Optional MemProcFS pmem runtime: required DLL/acquisition driver 없어 UNVERIFIED.

## 다음 실행 순서

1. Formal source-bound GUI evidence를 승격하려면 별도 재실행과 formal human
   review가 필요하다. 현재 presentation-only PASS로 그 flag를 변경하지 않는다.
2. Release owner가 production signing identity와 trusted timestamp service를
   제공해 새 hash-bound commercial release epoch를 발행한다.
3. Configured support/security routes의 notification과 end-to-end acknowledgement
   evidence를 수집한다.
4. Optional MemProcFS `pmem`은 별도 비차단 gate다. Evidence generator mismatch는
   current source에서 수정 완료됐다.

Windows 11 결과는 disposable VM의 test trust에 한정된다. Production
Authenticode signing, trusted timestamp, returned production drivers의 clean-guest
trust를 대신하지 않는다.

안전 경계는 `AGENTS.md`와 PRD를 따른다. 기존 safety behavior는 유지하며 새
policy/confirmation/lock condition이나 우회 기능을 추가하지 않는다.

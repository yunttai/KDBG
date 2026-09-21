# KDBG execution status

기준 시각: 2026-09-21 KST

## 결론

현재 제품 목표는 `KDBG.exe`와 `KDbgDriver.sys`가 실행되는 동일 bare-metal
Windows `runtime_host`의 local system physical RAM을 Raw PFN으로 읽고 편집하는
것이다. `orchestrator_host`는 lifecycle/evidence controller이고 Hyper-V
`regression_guest`는 별도 회귀 lane이다. RawPfn은 일반 제품 범위이며
ProbeFixture는 자동 destructive evidence target일 뿐이다.

현재 working tree는 이 target을 제품 동작과 검증 도구에 반영했다. ABI 7의
exact 4 KiB compare/write/read-back transaction, RawPfn page session, LocalHost
target profile, GUI target provenance와 bare-metal evidence harness가 구현돼 있다.
source/portable 판정과 별도로 direct LocalHost read-only, Probe-write, 그리고
별도 RawPfn 수동입력 transaction evidence가 기록됐다. RawPfn GUI의 visible
scene capture는 아직 주장하지 않는다. 기존 RC4/RC1 VM
evidence와 hash/status는 historical identity에 그대로 결속되며 current
bare-metal PASS로 재표기하거나 승격하지 않는다.

| Bare-metal runtime-host gate | 현재 상태 / blocker |
|---|---|
| Target terminology/contract | SOURCE COMPLETE — `runtime_host`, `orchestrator_host`, `regression_guest` roles aligned |
| RawPfn core/driver primitive | SOURCE COMPLETE — ABI 7 exact 4096-byte compare/write/read-back implemented |
| Target-kind UI + optional automatic provenance | SOURCE COMPLETE — LocalHost RawPfn is a normal product path; automatically available provenance is evidence metadata only |
| Bare-metal lifecycle profile | SOURCE COMPLETE — `TargetProfile LocalHost|DisposableVm`; ordinary install/start/run defaults to `LocalHost` |
| Test-signed LocalHost bootstrap | PASS (PACKAGE BUILT; HOST BOOT LANE NOT RUN) — test-only `KDBGSetup-Test.exe` path pins a public certificate, enables test-signing, schedules resume after reboot, and never carries the PFX/private key; derivative `out/release-epochs/local-host-testsetup2-test-signed-20260921` |
| Windows WDK driver build | PASS (PINNED NUGET) — Release/Debug built with pinned NuGet WDK `10.0.26100.2454`; Inf2Cat 0 errors/0 warnings; artifacts remain unsigned |
| Bare-metal read-only evidence | PASS — current signed-package LocalHost wrapper evidence: `out/evidence/local-host-source-fix3-runtime-host-5/evidence.json` |
| Bare-metal Probe-write evidence | PASS — same current wrapper evidence, with six 4 KiB artifacts, full read-back, independent reload, rollback, and final lock |
| Bare-metal RawPfn live-write transaction | PASS — `out/evidence/local-host-source-fix6-rawpfn/raw-pfn.json`; distinct `kdbg.live-verify.raw-pfn.v1`, manual PFN target, full 4096-byte apply/read-back/reload/rollback, final lock |
| Bare-metal RawPfn GUI scene gate | NOT COMPLETE — the live transaction is recorded, but the required visible GUI `RawPfn | manual PFN entry` scene was not captured |
| Historical regression_guest evidence | PRESERVED; no promotion |

Latest working-tree integration check for this target-alignment epoch:

- `python .\src\tools\verify_layout.py`: PASS
- `cmake --preset core-debug` and `cmake --build --preset core-debug --parallel`:
  PASS using the existing Visual Studio bundled CMake/WinLibs toolchain
- `ctest --preset core-debug --output-on-failure`: **14/14 PASS**
- Windows Release configure/build and `ctest --preset windows-release --output-on-failure`:
  **14/14 PASS**; current package epoch is
  `out/release-epochs/local-host-source-fix6-rawpfn-20260921`
- `python -m unittest src.tests.test_validate_release`: **92/92 PASS**
- `python .\src\tools\validate_release.py --source-complete`: PASS
- WDK driver build: **PASS (PINNED NUGET)** — WDK `10.0.26100.2454`, Inf2Cat
  0 errors/0 warnings, driver contract and symbol verification PASS; resulting
  drivers are unsigned and do not establish production trust
- bare-metal runtime-host read-only and Probe-write direct verifier gates:
  **PASS** for the current source-fix3 test-signed package via
  `out/evidence/local-host-source-fix3-runtime-host-5/evidence.json`; RawPfn
  transaction evidence is **PASS** for the fix6 test-signed package via
  `out/evidence/local-host-source-fix6-rawpfn/raw-pfn.json`; the GUI scene gate
  remains **NOT COMPLETE**
- current unsigned epoch:
  `out/release-epochs/local-host-source-fix6-rawpfn-20260921`; main/symbol ZIP
  hashes `6673371b…ca0f3526` / `56d91768…1f5cb9ad`; source snapshot
  `2f5f82df…9df829f6`
- current local test-signed derivative:
  `out/release-epochs/local-host-source-fix6-test-signed-20260921`; package hash
  `24ba5de9…5e93376b`; SYS/CAT Authenticode status is Valid. This derivative is
  not production trust. The GUI `DriverService` path-registration quote bug was
  removed and covered by a source regression test in this epoch.
- current test-signing setup derivative:
  `out/release-epochs/local-host-testsetup2-test-signed-20260921`; package hash
  `fd479fc7…62099e14`; source snapshot
  `e35b897e…c9699cb`. It contains `KDBGSetup-Test.exe`, the public
  `certificate/KDBG-TestSigning.cer`, and `tools/test_setup.ps1`; no PFX/private
  key is packaged. The setup reboot/resume path is not executed on this host yet.
- the earlier admin producer run is preserved in
  `out/evidence/local-host-source-fix-runtime-host-20260921` as historical
  evidence; the current authoritative runtime-host run is
  `out/evidence/local-host-source-fix3-runtime-host-5/evidence.json`.
- PowerShell 5.1/7 package, signing, and local-host producer contract tests:
  **PASS**; the producer preflight reached signature verification on PS5.1 and
  no longer fails on the former `OSArchitecture` property lookup

따라서 현재 working tree의 source/portable, unsigned Windows build/package,
runtime-host read-only 및 Probe-write direct-verifier gates, 그리고 별도
RawPfn 수동입력 transaction evidence는 PASS다. RawPfn GUI visible-scene
gate와 production signing은 독립적으로 미완료이며, Probe evidence를
RawPfn evidence로 승격하지 않는다.

PRD section 3의 bypass/BYOVD/stealth 등 목록은 현재 AGENTS/agent/skill 계약과
충돌하는 `UNRESOLVED` 항목이다. 이번 runtime-host 정렬은 이를 구현하거나 완료한
것으로 해석하지 않는다.

현재 working tree는 RC4 product-source commit
`4b376bb0d61eab232af8a2f7f29033238b911022` 이후의 runtime English/한국어
UI를 구현 중이다. 단일 executable, compiled-in catalog, English 기본,
항상 보이는 상위 `Language / 언어` selector, stable ImGui `###` IDs, Windows Korean system-font discovery와
English fallback, `[KDBG][Preferences]` persistence가 현재 source 범위다.

기존 RC4 package, Windows build, required-core, GUI capture 및 public-v4 결과는
모두 정확한 RC4 source에만 결속된 historical evidence다. Post-RC4
source에 대한 source/portable 테스트와 MSVC `/utf-8` Windows GUI build
evidence는 새로 기록됐다. 실제 locale/font/persistence runtime, live-VM 및
human visual validation은 신규 PASS로 표시하지 않는다. 언어 전환은 write gate,
confirmation, dirty/history, target, worker 및 backend state에 영향을 주지
않아야 하며 이 회귀 근거도 아직 신규 gate 대상이다.

| Post-RC4 bilingual UI gate | 현재 상태 |
|---|---|
| Source/portable | PASS — `verify_layout.py`, `core-debug` configure/build, CTest 14/14; Windows Release CTest 14/14 |
| Deterministic localization and harness contract tests | PASS in core-debug and windows-release CTest 14/14 suites |
| MSVC `/utf-8` single-executable GUI build | PASS — Debug and Release GUI link complete |
| Windows localization launch/INI persistence | NON-VISUAL PASS — isolated `LOCALAPPDATA`; English `en-US` and fixed Korean preset `ko-KR` retained across 8-second launches |
| Korean glyph appearance/clipping | NOT RUN; `malgun.ttf` presence alone is not visual evidence |
| Interactive selector/write-state preservation | NOT RUN |
| Safety/write-state non-interference | REGRESSION EVIDENCE PENDING; actual GUI runtime check NOT RUN |
| Live-VM / human visual review | NOT RUN; no PASS claim |

The artifact path `out/localization-host-smoke-persistence` retains its
historical name. This is a Windows localization launch smoke, not a bare-metal
physical-memory runtime-host gate. The
English-default launch stayed alive for 8 seconds and wrote
`[KDBG][Preferences] Language=en-US`. After setting a fixed test INI to `ko-KR`,
the Korean-preset launch stayed alive for 8 seconds with
`C:\Windows\Fonts\malgun.ttf` present and retained `Language=ko-KR`. This PASS
is limited to non-visual host launch and persistence; it does not promote the
selector, glyph/clipping, state-preservation, VM/live, or human-review gates.

## Historical RC4 baseline

`feature/kdbg-1.1.0`의 RC4 source/build/package와 Windows 11 required-core는
검증됐다. 공식 GUI run도 host/capture/integrity 자동 검증을 통과했지만 사람 검토
승격은 아직 없으므로 상태는 반드시 `CAPTURED_UNREVIEWED`,
`evidence_pass=false`, `human_review_complete=false`로 유지한다.

RC4 optional extended/lifecycle/soak는 실행하지 않았다. RC1에서 수행한 extended
결과는 historical evidence일 뿐 RC4에 재사용하지 않는다. Production signing은
정확한 입력 11개를 준비했지만 외부 signer/certificate/private key/HSM/TSA가 없어
수행하지 않았다. 따라서 안정 태그와 공개 release는 차단 상태다. DEF CON 제출은
이번 작업 범위에서 명시적으로 제외한다.

## Historical RC4 identity

| 항목 | 값 |
|---|---|
| RC4 product-source commit / tag target | `4b376bb0d61eab232af8a2f7f29033238b911022` |
| Unsigned epoch | `product-1.1.0-rc4-final-20260919` |
| Main ZIP SHA-256 | `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9` |
| Symbols ZIP SHA-256 | `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68` |
| Source snapshot SHA-256 | `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92` |
| Source scope SHA-256 | `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932` |
| VM-only derivative | `product-1.1.0-rc4-test1-20260919` |
| VM-only package SHA-256 | `7f7c179738eb670ca79d6c41bc9c46c445c1ffd31811c46f39bbbdcad3df45d5` |

## Historical RC4 gate 현황

| Gate | RC4 상태 | 근거/경계 |
|---|---|---|
| Source-complete | PASS | layout, core build, CTest 9/9, source validator |
| Windows-build-verified | PASS | unsigned main/symbol/source epoch와 strict package 검증 |
| Windows 11 required-core | LIVE PASS | exact RC4 test derivative, Probe transaction, cleanup, checkpoint restore, VM Off |
| GUI host/capture/integrity | PASS | 24 frames, 20 scenes, 21 assertions, 229 actions |
| Formal GUI evidence | `CAPTURED_UNREVIEWED` | `evidence_pass=false`; `human_review_complete=false` |
| RC4 optional extended/lifecycle/soak | NOT RUN | RC1 extended 결과는 historical only |
| Initial RC4 MP4 public suitability | FAIL | 내부 경로 노출 및 일부 crop/readability 문제 |
| Public v4 presentation video | PASS (automatic + independent review) | presentation-only; formal evidence를 승격하지 않음 |
| Production signing | BLOCKED (external) | 입력 준비만 완료; signing/network submission 미수행 |
| Source-freeze tag | PASS (published RC tag) | annotated `v1.1.0-rc4` on `origin` at `4b376bb0d61eab232af8a2f7f29033238b911022` |
| Stable `v1.1.0` / public release | BLOCKED | production-signed 반환물과 timestamp 부재 |

`GUI host/capture/integrity`와 historical `host summary`에서 `host`는 기존
하네스의 orchestrator-side execution/capture 명칭이다. 이 문자열과 hash는
historical artifact identity를 보존하기 위해 바꾸지 않으며, bare-metal
`runtime_host` physical-memory evidence를 뜻하지 않는다.

## Historical Windows 11 RC4 증거

### Required-core

- Run: `out/win11-validation/product-1-1-0-rc4-test1-20260919/runs/run-20260919T015729Z-8445dddb/`
- Guest archive SHA-256:
  `39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da`
- Result: exact derivative install/load, Probe PFN physical transaction,
  read-back/rollback/final lock, guest validation, cleanup, exact checkpoint
  restore, VM final Off PASS.
- RC4 extended/lifecycle/soak: **NOT RUN**.

### GUI

- Run: `out/win11-gui-product-1-1-0-rc4-test1-20260919/run-20260919T015850Z-1cfb0381/`
- Guest evidence SHA-256:
  `c877e2b3695faf6489f0ff3fa517a97eb0cc6f0f334a0a4a4bad900f14446cf4`
- Captures archive SHA-256:
  `abfe37fe1694fe8e35229c306663dde0cc4ff688d1a1fa80139f74c8ea9b3695`
- Result: host/capture/integrity PASS; 24 frames, 20 scenes, 21 assertions,
  229 actions; cleanup/checkpoint restore/final Off PASS.
- Formal boundary: `CAPTURED_UNREVIEWED`, `evidence_pass=false`,
  `human_review_complete=false`.

### Presentation-only video

- Initial MP4: public suitability **FAIL**; 공개용 최종본으로 사용하지 않는다.
- Public v2 independent review: **FAIL** (taskbar 노출). Public v2/v3는
  superseded다.
- Final presentation-only video:
  `out/demo-product-1-1-0-rc4-test1-public-v4-20260919/KDBG-1.1.0-demo-public-v4.mp4`
- SHA-256:
  `43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`
- Size/format: 9,553,416 bytes; 1920x1080; 10 fps; 405/405 frames;
  40.5 seconds.
- Automatic compositor and independent presentation review: **PASS**.
- Review coverage: 20 scenes, 24 segments, 19 boundaries. Rendered
  path/username/taskbar/notification/unrelated process가 없고 core claims가 읽힌다.
- Video-only delivery copy:
  `out/release-media/KDBG-1.1.0-demo-public.mp4`; 같은 SHA-256/크기이며 해당
  delivery directory에는 MP4만 있다. Raw frames는 공개 배포에서 제외한다.
- 이 영상은 presentation-only이며 공식 GUI evidence 상태를 변경하지 않는다.

## Historical RC4 production signing 및 release 경계

- Prepared inputs:
  `out/production-signing/product-1.1.0-rc4-final-20260919-prepared/`
- Signing request SHA-256:
  `3f94c26060bc437460b22ced778c52f1f70165e49a7ac57f0979c1a347f64001`
- Exact inputs: 11.
- `signing_performed=false`; `network_submission_performed=false`.
- Production signer/certificate/private key/HSM과 HTTPS RFC3161 TSA가 없다.
- Annotated source-freeze tag `v1.1.0-rc4`는 `origin`의
  `4b376bb0d61eab232af8a2f7f29033238b911022`에 게시됐다.
- Production-signed 반환물 검증 전에는 stable `v1.1.0` tag나 public release를
  만들지 않는다.

## Historical evidence boundary

RC1 extended lifecycle/reboot/30-minute soak와 그 benchmark는 해당 RC1 identity에만
결속된다. 1.0.0 Windows 10/11 evidence도 각 historical package/source hash에만
결속되며 RC4 PASS의 대체 근거가 아니다.

## 재현 명령

```powershell
python .\src\tools\verify_layout.py
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

Portable 명령만으로 Windows build나 live VM PASS를 주장하지 않는다. 위
Windows/live 판정은 historical exact RC4 identity와 evidence에만 결속한다.
Post-RC4 bilingual UI의 MSVC `/utf-8` GUI build와 비시각적 host launch/INI
persistence smoke는 기록됐다. 상위 selector 클릭·상태 불변, Korean glyph/
clipping, VM/live 및 human visual 근거는 아직 필요하다.

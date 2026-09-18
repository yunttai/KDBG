# KDBG execution status

기준 시각: 2026-09-18 KST

## 결론

`feature/kdbg-1.1.0`의 unsigned epoch `product-1.1.0-rc1-final-20260918`은
source/build/package gate를 통과했다. 동일 소스의 VM 전용 test-signed derivative
`product-1.1.0-rc1-test1-20260918`은 Windows 11 required-core와 extended
lifecycle/reboot/30분 soak gate를 통과했다.

공식 source-bound GUI run의 자동 compositor MP4도 구조·해상도·프레임·재생시간
검사를 통과했다.
슬라이드와 GIF는 만들지 않았다. 다만 독립적인 사람 검토에서는 1024-pixel guest
capture의 발표 가독성이 부족했다. scene 03은 grid가 보이지 않고, scene 20의 diff
row가 잘리며, 일부 문구가 과도하게 wrapping된다. 따라서 GUI harness의 공식 상태는
`CAPTURED_UNREVIEWED`이고, 이 캡처와 MP4를 DEF CON 제출용 `evidence_pass`로 승격하지
않는다.

이와 별개로 presentation-only overlay run
`out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7`은 scene 20 exact
cue와 widened crops로 이전 시각 blocker를 해결했다. 이 run으로 구성한 최종
presentation video `KDBG-demo-final2.mp4`는 automatic validation과 독립적인
presentation-only human review를 모두 PASS했다. 이 성공은 발표 영상의 품질 판정이며,
공식 source-bound GUI evidence의 `CAPTURED_UNREVIEWED`/`evidence_pass=false`를
변경하거나 승격하지 않는다.

공개 상용 배포 승격에는 외부 production signer/TSA가 반환한 정식 서명 드라이버와
지원·보안 연락 채널의 실제 notification/acknowledgement도 필요하다. VM 전용 test
certificate 결과를 production publisher trust로 주장하지 않는다.

## 1.1.0 identity

| 항목 | 값 |
|---|---|
| Unsigned epoch | `product-1.1.0-rc1-final-20260918` |
| Main ZIP SHA-256 | `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f` |
| Symbols ZIP SHA-256 | `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849` |
| Source snapshot SHA-256 | `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184` |
| Source scope SHA-256 | `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932` |
| Benchmark executable SHA-256 | `72348dff8a0a1623fd922fa316d3bf898a60f54b49bdc34c58a115924c25d4cf` |
| VM-only derivative | `product-1.1.0-rc1-test1-20260918` |
| VM-only package SHA-256 | `596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413` |
| Test certificate SHA-256 | `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1` |
| Test signer thumbprint | `ba34b393521d722ba01df87afccc6f3feb760b2c` |

## Gate 현황

| Gate | 상태 | 실행 근거 |
|---|---|---|
| Repository layout | PASS | `python .\src\tools\verify_layout.py` |
| Portable build/tests | PASS | `core-debug` build, CTest 9/9 |
| Source-complete validation | PASS | `validate_release.py --source-complete` |
| Windows Release build/tests | PASS | clean MSVC Release build, CTest 9/9 |
| WDK drivers | PASS | KDbgDriver/KDbgProbe 1.1.0.0, Inf2Cat 0 errors/0 warnings, symbol/contract checks |
| Main/symbol packages | PASS | strict package/symbol validator and exact epoch hashes |
| Windows 11 required-core | LIVE PASS | build 26200, ABI 6, exact package/source binding, Probe transaction and cleanup |
| Physical transaction | LIVE PASS | PFN 2117631, offset `0x100`, 8-byte apply, full 4 KiB read-back/reload, 4 KiB rollback, final gate locked |
| GUI workflow | `CAPTURED_UNREVIEWED` | automatic checks PASS; 24 captures/20 scenes, cleanup/checkpoint restore/final Off |
| Source-bound presentation readability | FAIL | 1024 capture에서 scene 03 grid 부재, scene 20 diff row clipping, text wrapping 확인 |
| Source-bound MP4 compositor | PASS (automatic) | 9,759,713 bytes, 405 frames, 40.5 s, 24 captures/20 scenes |
| Source-bound MP4 human review | FAIL | 공식 source-bound evidence는 `evidence_pass=false` 유지 |
| Presentation-only overlay | PASS | 24 captures/20 scenes, scene 20 exact cue와 widened crops, cleanup/restore/Off |
| Final presentation MP4 | PASS (automatic + human) | 9,974,541 bytes, 1920x1080, 10 fps, 405/405 frames, 40.5 s |
| Lifecycle/reboot | LIVE PASS | 2 cycles, 10 stop/start operations, 4 reboot boundaries, clean final inventory |
| Long-run soak | LIVE PASS | 1800 s, 61 reports x 8 reads = 488 scheduled reads; midpoint write/read/reload/rollback PASS |
| Performance suite | PASS (mock-only) | 7 independent process runs; live-driver 성능 주장 아님 |
| VM cleanup | PASS | exact checkpoint restored; VM final state Off |
| Production signing | BLOCKED (external) | production signer, TSA and returned signed drivers absent |
| Commercial operations proof | PENDING (external) | support/security route notification and acknowledgement absent |
| Optional MemProcFS pmem | UNVERIFIED (optional) | base product uses the built-in reverse mapper/PTView path |

## 현재 Windows 11 증거

### Required-core

- Run: `out/win11-validation/product-1-1-0-rc1-test1-20260918/runs/run-20260918T091747Z-21a27820/`
- Host summary SHA-256:
  `c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b`
- Guest evidence ZIP: 26 entries, SHA-256
  `0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`
- Result: success/guest validation true, Windows 11 Pro build 26200, ABI 6,
  PFN 2117631, offset `0x100` 8-byte apply, full-page read-back/reload, 4 KiB
  rollback, final gate locked, uninstall cleanup, exact checkpoint restore and
  final VM Off.

### GUI 및 영상

- GUI run: `out/win11-gui-product-1-1-0-rc1-test1-20260918/run-20260918T092129Z-f14f5f7a/`
- Host summary SHA-256:
  `f5fd51ef18c319c37feb5adb997582e56cd2efe9b03a1d6ea3213237f6815d0b`
- Guest capture archive SHA-256:
  `6104933593259fb074466ba8d21a5fffd7e47803b2bfec71ce206e5c0a4ce252`
- Captures binding SHA-256:
  `bd254d7a98230db0199051085453b09ea33405f3efe57a9ded42b8a3bebb6d42`
- Capture result: success, `CAPTURED_UNREVIEWED`, 24 captures/20 scenes,
  cleanup/checkpoint restore/final Off.
- MP4: `out/demo-product-1-1-0-rc1-test1-20260918/KDBG-demo.mp4`
- MP4 SHA-256: `c368dde54d19f46fedd32895f319223221538c006fcf4626277665b8fe5aad3d`
- MP4 size/runtime: 9,759,713 bytes; 405 frames; 40.5 seconds.
- Compositor report SHA-256:
  `5b92b9086cd2a503f46fd309f4fd20099644aa17e453385d5f3a053a9714fdd0`
- Automatic compositor validation passed. Independent human presentation review
  failed for the layout defects listed above; `evidence_pass` remains false.

Presentation-only overlay와 최종 영상:

- Run: `out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7/`
- Host summary SHA-256:
  `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`
- Guest archive SHA-256:
  `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`
- Captures binding SHA-256:
  `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`
- Result: 24 captures/20 scenes, cleanup/checkpoint restore/final Off, scene 20
  exact cue와 widened crops 확인.
- Final video:
  `out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`
- Final video SHA-256:
  `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`
- Size/format: 9,974,541 bytes; 1920x1080; 10 fps; 405/405 frames; 40.5 seconds.
- Report SHA-256:
  `e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`
- Automatic validation and independent presentation-only human review: PASS.
  이 판정은 공식 source-bound evidence promotion이 아니다.

### Extended lifecycle, soak 및 benchmark

- Run: `out/win11-validation/product-1-1-0-rc1-test1-20260918/extended-runs/extended-20260918T092819Z-66c07a32/`
- Host summary SHA-256:
  `12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee`
- Extended evidence ZIP SHA-256:
  `f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`
- Current/previous package SHA-256:
  `596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413` /
  `6fe3a73c1b98bd871bf8c4673e659a1cda4bddbcd9faf69c2921487b26a380dd`
- Lifecycle: 2 cycles, 10 stop/start operations, 4 completed reboot boundaries.
- Soak: 1800 seconds, 61 reports, 488 scheduled reads, midpoint verified
  write/read/reload/rollback, final gate locked.
- Benchmark: 7 mock-only process runs, summary success true. These timings test
  deterministic product algorithms and do not claim live-driver performance.
- Cleanup: guest validation true, checkpoint restored and VM Off.

## Historical 1.0.0 evidence

Windows 10 build 19044의 path-mapped exact epoch와 reviewed v4 evidence, 그리고
이전에 완료한 1.0.0 Windows 11 engineering epochs는 보존한다. 그 결과는 각 과거
package/source hash에만 결속되며 위 1.1.0 PASS의 대체 근거로 재사용하지 않는다.

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

Windows/live gate는 별도다. 위 portable 명령만으로 Windows build나 live VM PASS를
주장하지 않으며, 그 근거는 exact 1.1.0 epoch의 Windows 및 VM 증거에 기록한다.

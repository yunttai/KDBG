# KDBG execution status

기준 시각: 2026-09-19 KST

## 결론

`feature/kdbg-1.1.0`의 RC4 source/build/package와 Windows 11 required-core는
검증됐다. 공식 GUI run도 host/capture/integrity 자동 검증을 통과했지만 사람 검토
승격은 아직 없으므로 상태는 반드시 `CAPTURED_UNREVIEWED`,
`evidence_pass=false`, `human_review_complete=false`로 유지한다.

RC4 optional extended/lifecycle/soak는 실행하지 않았다. RC1에서 수행한 extended
결과는 historical evidence일 뿐 RC4에 재사용하지 않는다. Production signing은
정확한 입력 11개를 준비했지만 외부 signer/certificate/private key/HSM/TSA가 없어
수행하지 않았다. 따라서 안정 태그와 공개 release는 차단 상태다. DEF CON 제출은
이번 작업 범위에서 명시적으로 제외한다.

## RC4 identity

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

## Gate 현황

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

## Windows 11 RC4 증거

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

## Production signing 및 release 경계

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

Portable 명령만으로 Windows build나 live VM PASS를 주장하지 않는다. Windows/live
판정은 위 exact RC4 identity와 evidence에만 결속한다.

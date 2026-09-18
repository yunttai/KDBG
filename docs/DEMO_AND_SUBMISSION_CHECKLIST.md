# 데모·제출 체크리스트

발표 제안서와 45분 세션 구성은 [`DEFCON_SUBMISSION.md`](DEFCON_SUBMISSION.md)를
기준으로 하며, 이 문서는 그 제안서에 첨부할 실제 증거 수집 체크리스트다.

Historical 1.0.0 exact-final evidence remains bound to main/symbol hashes
`7f6b0fd9…b265a`/`d8715bf7…c96f`, and the public CFP packet `69f69cb5…21fb`
excludes those path-bearing frozen PDBs. The current path-mapped main/symbol/source
epoch `b6832712…e47f`/`7801bfef…70aa`/`0484b5dd…49ee` passed exact Windows 10
live validation and repository-owner-confirmed 20-scene review. Final v4 is
`fc0afb4b…9823`; the independently audited 77-entry archive is `438881e7…a18e3`.

현재 1.1.0 제출 산출물은 redacted MP4 한 개다. 슬라이드 deck과 GIF는 제출
산출물에 포함하지 않는다. Exact test-signed package는
`596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`, source
snapshot은 `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184`다. 자동 GUI run
`run-20260918T092129Z-f14f5f7a`는 24 captures/20 scenes를 생성했지만 사람
검수에서 1024 layout의 scene 03 grid 및 scene 20 diff row clipping과 column
wrapping이 확인되어 `evidence_pass=false`다. 이 공식 source-bound GUI 상태는
그대로 유지한다. 별도 presentation-only overlay run
`run-20260918T102055Z-6c85cee7`은 자동 PASS와 독립 사람 검수 PASS를 받았고,
scene 20 evidence-bound cue 및 scene 10/11 crop 수정으로 이전 visual blocker를
해소했다. 이는 발표 영상 품질 PASS이며 formal GUI evidence 승격이나 실제 제출
완료를 뜻하지 않는다.

## 1. 권장 시연 대상

테스트 fixture process/driver가 할당한 page-sized buffer를 사용한다.

장점:

- PFN을 알고 있음
- 원본 pattern을 알고 있음
- process PID/VA가 있음
- 수정 결과를 fixture가 독립 확인 가능
- 시스템 중요 페이지를 건드리지 않음

## 2. v4 영상 시나리오

아래 순서는 validator의 20개 식별자를 빠짐없이 녹화하는 최소 구조다. 번호와
식별자는 최종 영상의 chapter/slate, evidence의 `demo_scenes`, 해시 결속된
`kdbg.demo-scene-review.v1`의 `scenes`에서 동일해야 한다.
실제 발표용 편집본은 더 길어도 되지만 순서와 candidate identity를 바꾸지 않는다.

| 구간 | # | exact scene identifier | 반드시 보일 내용 |
|---|---:|---|---|
| 환경 | 1 | `driver_probe_ready` | 두 서비스 running, ABI 6, Probe ready, `WRITE LOCKED`, VM 표시 |
| Probe | 2 | `probe_pfn_discovery` | 동일 fixture의 PFN/PA/generation/4096-byte/CRC32 |
| Probe | 3 | `physical_read_4096` | PFN/PA 및 정확한 `4096/4096` read |
| 편집 | 4 | `hex_edit_and_diff` | baseline offset `0x100..0x107`에 XOR mask `4B 44 42 47 A5 5A 3C C3`, exact dirty run `0x100:8`, before/after |
| 편집 | 5 | `undo_redo` | Undo 후 dirty 0, Redo 후 동일한 `0x100:8` 복구 |
| 적용 | 6 | `typed_pfn_unlock` | full-page preflight match, 현재 PFN 재입력, one-shot unlock 소비 |
| 적용 | 7 | `write_and_readback` | one-shot Apply, full 4096-byte read-back match, requested/completed counts, gate relock |
| 적용 | 8 | `independent_reload` | 독립 reload와 edited-page/Probe CRC 일치 |
| 복구 | 9 | `rollback_baseline` | full baseline rollback, 독립 post-read, baseline CRC 복원, `WRITE LOCKED` |
| 귀속 | 10 | `pfn_owner_pid_va_pte` | dedicated process fixture의 PID/name/VA/PTE/page flags/source/confidence와 그 PFN이 Probe PFN과 다름 |
| 귀속 | 11 | `page_table_walk` | fixture VA의 PML5 또는 PML4부터 leaf까지, fixture PA/PFN round trip, Probe VA/PFN과 분리됨 |
| 프로세스 | 12 | `process_first_next_scan` | fixture First/Next Scan 완료, bounded result count |
| 프로세스 | 13 | `address_list_verified_freeze` | fixture 주소의 verified edit/Freeze/read-back/restore와 gate lock |
| 프로세스 | 14 | `pointer_scan` | bounded root/offset/depth/target/result cap |
| 프로세스 | 15 | `zydis_disassembly` | fixture address/raw bytes/Intel instruction text |
| 프로세스 | 16 | `snapshot_diff` | baseline/current CRC32와 contiguous changed-run diff |
| 커널 | 17 | `kernel_module_catalog` | bounded module base/size/name; private path redacted |
| 커널 | 18 | `kernel_symbol_resolution` | matching local PDB와 verified address↔symbol 결과 |
| 커널 | 19 | `kernel_read_disassembly` | bounded kernel read/Zydis 결과 또는 정확한 unavailable reason |
| 신원 | 20 | `about_version` | About version/build ID와 package-relative candidate identity |

`Stage Evidence Probe Pattern`은 mask를 baseline에 XOR할 뿐이며 staging 자체는 write를
발생시키지 않는다. 장면 7–9의 결과는 화면만으로 끝내지 않고 같은 실행의
`kdbg.live-verify.v1`, 여섯 raw 4 KiB page, package/symbol manifests와 결합한다.

## 3. 1.1.0 촬영 전 자동 gate

- [x] VM snapshot
- [x] 해상도 1600x900
- [x] DPI 100/125/150/200% 확인
- [x] 알림/개인정보 숨김 후보 생성
- [x] fixture PFN 및 exact package hash 기록
- [x] driver install/stop/remove/forced-exit/update/rollback/purge lifecycle
- [x] Release build/package
- [x] 음성 없이도 이해 가능한 상태 문구 후보 생성
- [x] `kdbg.live-verify.v1` Probe write/rollback report PASS
- [x] main/symbol package manifests와 runtime EXE/SYS hashes 일치
- [x] 여섯 Probe raw page와 두 fixture raw page가 각각 정확히 4096 bytes이고 metadata/analysis의 SHA-256/CRC32와 일치

위 항목은 exact 1.1.0 VM 실행의 자동 gate다. 사람 판독성 검수를 대신하지
않는다. GUI run summary/archive/capture SHA-256은 각각
`f5fd51ef18c319c37feb5adb997582e56cd2efe9b03a1d6ea3213237f6815d0b`,
`6104933593259fb074466ba8d21a5fffd7e47803b2bfec71ce206e5c0a4ce252`,
`bd254d7a98230db0199051085453b09ea33405f3efe57a9ded42b8a3bebb6d42`이며
cleanup, checkpoint restore, final VM Off는 PASS다.

## 4. 영상 판독성

### Formal source-bound GUI review — FAIL (unchanged)

- [ ] PFN 16진수 전체가 보임
- [ ] 변경 offset이 보임
- [ ] Before/After가 보임
- [ ] `Write`와 `Read-back`이 별개 단계로 보임
- [ ] PASS가 2초 이상 화면에 남음
- [ ] PID/VA/페이지 워크가 확대 없이 보임

Formal review defect: the 1024 layout clips the scene 03 grid and scene 20
diff row and wraps columns. 위 formal GUI evidence 항목은 체크하지 않으며
`evidence_pass=false`를 유지한다.

### Presentation-only final video — PASS

- [x] Overlay run automatic gate PASS, 24 captures/20 scenes
- [x] Independent human presentation review PASS
- [x] Scene 20 evidence-bound cue 판독 가능
- [x] Scene 10/11 crop 수정으로 이전 visual blocker 해소
- [x] Cleanup, checkpoint restore and final VM Off

Overlay summary/guest/capture SHA-256:

- `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`
- `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`
- `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`

## 5. 1.1.0 제출 파일

권장 이름:

```text
KDBG-1.1.0-demo.mp4
```

최종 video-only 산출물은
`out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`이며
SHA-256은
`4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`다.
크기는 9,974,541 bytes, 1920x1080, 10 fps, duration 40.5초, 405/405 frames다.
Report SHA-256은
`e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`다.
자동 검증과 독립 presentation-only 사람 검수는 PASS했다. 최종 제출 시에는
이 MP4 한 개만 사용하고 Deck/GIF는 만들거나 첨부하지 않는다.

제출 수신자, 개인 이름, 메일 주소는 repository나 배포 package에
저장하지 않고 제출 시점에 별도로 확인한다.

### Historical 1.0.0 backup artifact (not a 1.1.0 deliverable)

- [x] 20개 장면을 1600x900, 24 frame, 정확히 300,000 ms로 구성
- [x] current package/symbol/source snapshot과 자동 preflight hash 결속
- [x] `continuous_recording=false`, `audio_present=false`,
  `artifact_kind=evidence-backed-still-frame-backup-walkthrough` 명시
- [x] contact sheet, manifest, SHA-256 목록과 자동 preflight 생성
- [ ] 실제 사람이 전체 5분 판독성·redaction을 검토하고 reviewer/UTC를 기록
- [ ] exact final candidate에서 의도적 preflight conflict와 복구를 촬영한
  failure demo를 별도 hash-bind

## 6. 1.1.0 최종 확인

- [x] Final MP4가 1920x1080/10 fps/40.5초/405 frames로 검증됨
- [x] Presentation overlay에 20개 exact scene identifier가 순서대로 존재
- [x] Presentation-only 독립 사람 판독성 검수 PASS
- [ ] private path와 unrelated process data redaction 판정 PASS
- [x] Final MP4/report SHA-256과 exact 1.1.0 package/source identity 기록
- [x] slide deck과 GIF가 제출 묶음에 없음
- [ ] 파일 용량 제한 확인
- [ ] 제목 정확
- [ ] 실제 제출 기한과 수신자를 별도 확인
- [ ] 제출 완료 상태 확인

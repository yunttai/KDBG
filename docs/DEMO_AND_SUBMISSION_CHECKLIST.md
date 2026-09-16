# 데모·제출 체크리스트

최종 evidence 상태: `out/evidence/final-91042aab-live-evidence-v2.gif`는 1600x900,
17장면이며 `out/evidence/final-91042aab-live-evidence-v2.json`에 SHA-256으로
결합되어 strict validator를 통과했다. 실제 외부 제출/수신자 확인은 사용자 절차다.

## 1. 권장 시연 대상

테스트 fixture process/driver가 할당한 page-sized buffer를 사용한다.

장점:

- PFN을 알고 있음
- 원본 pattern을 알고 있음
- process PID/VA가 있음
- 수정 결과를 fixture가 독립 확인 가능
- 시스템 중요 페이지를 건드리지 않음

## 2. 90초 영상 시나리오

### 0~10초 — 환경

- 앱 제목
- KDBG Driver: CONNECTED
- Driver: Connected
- ABI
- WRITE LOCKED
- VM watermark/문구

### 10~25초 — PFN Read

- fixture가 출력한 PFN 복사
- PFN 입력
- PA 계산 확인
- PA와 RAM range validation
- Read 4096 bytes
- Hex/ASCII page 표시

### 25~45초 — Edit

- offset `0x100` 이동
- 4바이트 수정
- dirty highlight
- Diff table에서 before/after 확인

### 45~65초 — Write와 검증

- Unlock Write
- 현재 PFN 재입력
- Apply & Verify
- Preflight → Write → Read-back
- `VERIFICATION PASS`

### 65~75초 — 재조회

- Refresh 또는 다른 PFN 후 돌아오기
- 수정값 유지 확인
- fixture 자체 query 결과도 표시

### 75~85초 — 가산점

- PFN Ownership에서 PID/name/VA/PTE
- Page Tables 탭에서 PML4/PDPT/PD/PT와 최종 PA/PFN

### 85~90초 — 복구

- Rollback
- 원본 복구 PASS

## 3. 촬영 전

- [x] VM snapshot
- [x] 해상도 1600x900
- [x] DPI 100/125/150/200% 확인
- [x] 알림/개인정보 숨김
- [x] fixture PFN 및 exact package hash 기록
- [x] driver install/stop/remove lifecycle
- [x] Release build/package
- [x] 음성 없이도 이해 가능한 상태 문구

## 4. 영상 판독성

- PFN 16진수 전체가 보임
- 변경 offset이 보임
- Before/After가 보임
- `Write`와 `Read-back`이 별개 단계로 보임
- PASS가 2초 이상 화면에 남음
- PID/VA/페이지 워크가 확대 없이 보임

## 5. 제출 파일

권장 이름:

```text
KDBG-1.0.0-demo.mp4
KDBG-1.0.0-demo.gif
```

제출 수신자, 개인 이름, 메일 주소는 repository나 배포 package에
저장하지 않고 제출 시점에 별도로 확인한다.

## 6. 최종 확인

- [x] 첨부 파일 열림
- [x] 17 frames/1600x900 재생 구조 확인
- [x] 소리 없이 흐름 이해 가능
- [ ] 파일 용량 제한 확인
- [ ] 제목 정확
- [ ] 실제 제출 기한과 수신자를 별도 확인
- [ ] 제출 완료 상태 확인

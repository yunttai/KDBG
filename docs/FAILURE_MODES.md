# KDBG 실패 모드

| 실패 | 탐지 | 사용자 표시 | 조치 |
|---|---|---|---|
| PFN parse/shift overflow | `PfnAddress` | 입력 오류 | Read/Write 비활성 |
| RAM 밖 또는 range 경계 PFN | physical range containment | 대상 범위 오류 | 접근 거부 |
| driver open/ABI mismatch | `CreateFile`/version response | Win32 오류·ABI | physical 기능 비활성, handle close |
| 두 번째 controller | driver owner PID | access denied | 기존 controller 종료 후 재시도 |
| short physical/process read | requested/completed 비교 | short read | buffer/session 폐기 |
| local edit 중 target reload | session reset | dirty edit 소멸 경고 문구 | 사용자가 먼저 Apply/Revert |
| PFN/PID 확인 불일치 | modal parser | unlock 실패 | gate locked 유지 |
| preflight 변경 | baseline/full-page 비교 | conflict offsets | Write 시작 전 중단 |
| write gate/ack 오류 | driver/backend | write locked/access denied | gate close, 재-arm 필요 |
| short write | completed length | short write | 실패, 자동 추가 Write 없음 |
| read-back mismatch | expected/readback 비교 | mismatch offsets | gate close, rollback 선택 제공 |
| rollback mismatch | full read-back | rollback failed | 추가 Write 중지, VM snapshot 복원 |
| target process 종료/reuse | handle/read/PID-bound table | stale/invalid process | detach 후 목록 새로고침 |
| scanner read 실패 | region별 Result | 결과/상태 오류 | 해당 실행 실패 또는 재시도 |
| scan/pointer/snapshot 취소 | stop token | cancelled | worker join 후 안정 상태 |
| result/depth/size 상한 | configured cap | limit reached | 필터 또는 범위 축소 |
| MemProcFS bridge 없음 | path/`CreateProcessW` | bridge unavailable | built-in selected-process scan 사용 |
| bridge timeout/output overflow | 15초/8 MiB cap | timeout/limit | child terminate, 결과 폐기 |
| bridge protocol mismatch | header/record parser | parse error | bridge와 앱 버전 맞춤 |
| page-table non-present | translation response | not present | leaf 없음으로 표시 |
| reverse-map table limit | bounded walker | limit reached | table limit 조정/대상 process 축소 |
| snapshot file 손상 | magic/version/CRC32 | parse/verification error | 파일 폐기 |
| address-list PID mismatch | persisted PID | different PID | 올바른 process attach |
| service stop 중 open handle | SCM/device state | stop failure | KDBG 종료·device close 후 재시도 |

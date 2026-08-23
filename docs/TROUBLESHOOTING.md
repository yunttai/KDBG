# 문제 해결

## Driver open 실패

확인:

1. 관리자 실행
2. service 존재/상태
3. device symbolic link
4. user/kernel device name 동일
5. driver DACL
6. test certificate
7. Event Viewer / CodeIntegrity log
8. HVCI 상태

해결을 위해 Code Integrity 우회를 사용하지 않는다. VM 정책을 지원 가능한 테스트 구성으로 되돌린다.

## ABI mismatch

- user app와 driver를 clean rebuild
- shared header가 하나인지 확인
- `sizeof`/packing
- `KDBG_ABI_VERSION` 및 `KDBG_PROBE_ABI_VERSION`
- 오래된 service binary 삭제

## ReadPhysical short read

- 요청 page가 physical range 경계인지 확인
- 반환된 Length/bytes returned 기록
- 전체 4096이 아니면 Hex Editor에 부분 성공으로 표시하지 않는다

## Write mode enabled인데 실패

- UI unlock과 driver gate 모두 확인
- acknowledge magic
- handle owner
- requested size
- physical range
- backend status

## Read-back mismatch

- 추가 Write 금지
- mismatch offset 저장
- live page가 변경되는 대상인지 확인
- fixture인지 확인
- 원본 rollback은 명시적으로 시도
- 계속 실패하면 snapshot 복원

## PFN Process 결과 없음

가능한 원인:

- PFN이 free/standby/prototype
- MemProcFS acquisition backend가 다른 snapshot을 보고 있음
- PFN DB cache stale
- page가 여러 mapping
- selected process scan 범위 제한
- large page 처리 누락

core Read/Edit 기능과 별개로 표시한다.

## Page walk 결과 불일치

- DTB에서 PCID 하위 bit 제거
- LA57
- large page
- process lifetime
- stale CR3
- canonical VA
- PTE present/transition/prototype
- translation 응답의 entry physical address 확인

## ImGui Hex Editor에서 셀 입력마다 IOCTL 발생

잘못된 연결이다.

`WriteFn`은 local working copy만 변경해야 한다. 실제 Write는 Apply command에서만 수행한다.

## build dependency download 실패

`THIRD_PARTY.lock.json`의 immutable commit과
`src/cmake/Dependencies.cmake`의 `GIT_TAG`가 같은지 확인한다. 현재
제공되지 않는 vendor-mode option을 사용하지 말고, offline build가
필요하면 명시적 CMake cache/source override를 먼저 구현하고 문서화한다.

## Release package 검증 실패

`tools/diagnose.ps1 -VerifyPackage`와 `validate_release.py --windows-package`의
첫 실패를 해결하기 전에 driver를 install하지 않는다. 흔한 원인은
Debug CRT import, x64/1.0.0 불일치, 누락된 hash/SBOM/license, main package의
PDB, 또는 개인 경로가 담긴 문서다.

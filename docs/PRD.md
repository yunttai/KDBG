# PRD — KDBG

- 문서 버전: 2.0
- 기준일: 2026-08-15
- 제출 마감: 2026-08-23 23:59 KST
- 대상 플랫폼: Windows 10/11 x64 전용 실습 VM
- 제품 형태: 관리자 권한 Win32/DX11 GUI + 테스트 서명 WDM 드라이버 2개

## 1. 제품 정의

KDBG는 PFN(Page Frame Number)을 입력해 실제 물리 페이지를 읽고, Hex Editor에서 로컬로 수정한 뒤, 충돌 검사와 전체 페이지 read-back 검증을 거쳐 변경을 적용하는 Windows 메모리 연구 도구다.

필수 과제 흐름은 다음과 같다.

```text
Probe 또는 사용자가 PFN 확보
  → PFN/PA/RAM 범위 검증
  → 정확히 4096바이트 Read
  → Hex/ASCII local edit
  → byte diff 확인
  → 현재 PFN 재입력으로 one-shot unlock
  → Apply 직전 full-page preflight
  → dirty run Write
  → full-page read-back 비교
  → 독립 재조회 또는 rollback
```

KDBG는 같은 GUI에서 프로세스 메모리 검색, 주소 목록, 검증형 Freeze, pointer scan, disassembly, snapshot diff, PFN 소유 정보, 페이지 테이블 변환을 제공한다.

## 2. 목표

### G-01 슈퍼패스 필수 조건

- GUI에서 PFN 입력
- 대상 물리 페이지 Read
- Hex/ASCII 표시와 편집
- 실제 물리 메모리 Write
- Write 직후 read-back 및 재조회 결과 표시

### G-02 가산점

- PFN을 매핑한 PID, 프로세스명, VA, PTE 주소 표시
- PML5/PML4/PDPT/PD/PT 단계와 VA → PA 변환 시각화

### G-03 고도화

- Cheat Engine 계열의 First/Next Scan, 주소 목록, verified Freeze, pointer scan, disassembly, memory snapshot/diff를 독립 구현
- 모든 장시간 검색은 취소 가능하고 결과 수·깊이·메모리 크기에 상한을 둔다.

## 3. 명시적 비목표

- Code Integrity, Secure Boot, HVCI 우회
- 취약한 서명 드라이버/BYOVD 사용
- 은닉, 안티치트 우회, 프로세스 주입
- 임의 커널 가상주소 쓰기
- 원격 대상 또는 본인이 관리하지 않는 시스템 접근
- 커널 디버거의 breakpoint/single-step 완전 재구현
- MemProcFS 전체 기능 재구현

## 4. 기능 요구사항

### FR-001 드라이버 수명주기와 연결

- Driver 탭에서 `KDbgDriver.sys`, `KDbgProbe.sys`를 SCM으로 install/update/start/stop/remove한다.
- 앱 시작 시 `\\.\KDBG` 연결을 시도하고 ABI·최대 전송 크기·write gate 상태를 검증한다.
- 연결 실패 시 물리 메모리 기능은 비활성화하되 일반 사용자 프로세스의 Win32 Read/Scan은 계속 사용할 수 있다.
- 앱 종료·서비스 중지·명시적 Lock All Writes에서 가능한 모든 write gate를 닫는다.

### FR-002 PFN과 물리 범위 검증

- PFN은 10진수와 `0x` 16진수를 지원한다.
- 공백 외의 부호·소수·잘못된 문자를 거부한다.
- `PFN << 12`와 페이지 끝 계산의 64비트 overflow를 거부한다.
- `[PA, PA+0x1000)` 전체가 `MmGetPhysicalMemoryRanges`에서 얻은 단일 RAM range 안에 있어야 한다.

### FR-003 정확한 물리 페이지 Read

- 물리 페이지 Read 길이는 4096바이트다.
- short read는 실패이며 부분 데이터를 Hex Editor에 승격하지 않는다.
- 세션은 baseline, working copy, dirty bitmap, conflict/mismatch offsets, rollback snapshot을 분리한다.

### FR-004 Hex/ASCII 로컬 편집과 Diff

- `imgui_memory_editor` 기반 16열 Hex/ASCII Grid와 data preview를 제공한다.
- 셀 편집은 working copy만 변경하고 즉시 IOCTL Write를 발생시키지 않는다.
- dirty, preflight conflict, read-back mismatch를 서로 다른 배경 상태로 표시한다.
- offset, 절대 PA, before, after를 표로 표시하고 전체 local edit를 되돌릴 수 있다.

### FR-005 one-shot 물리 Write

- 기본 상태는 write locked다.
- 사용자가 현재 PFN을 다시 입력해야 한 번의 Apply 또는 Rollback이 해제된다.
- Apply 시작 시 UI unlock을 즉시 소모한다.
- Apply 직전에 RAM range와 전체 페이지를 다시 읽어 baseline과 한 바이트라도 달라졌으면 중단한다.
- 변경된 연속 구간만 bounded Write하고, 커널 write gate는 RAII로 즉시 다시 잠근다.
- Write 후 전체 4096바이트를 다시 읽어 모든 dirty byte가 working copy와 일치해야 성공이다.

### FR-006 검증형 Rollback

- 성공한 Apply 직전 baseline을 보관한다.
- PFN 재입력 후 이전 baseline을 쓰고 full-page read-back으로 검증한다.
- rollback 실패 시 추가 자동 Write를 하지 않고 오류를 보존한다.

### FR-007 Probe fixture

- `KDbgProbe.sys`는 deterministic pattern을 가진 contiguous 4 KiB page를 할당한다.
- GUI에서 Probe VA, PA, PFN, generation, CRC32를 조회하고 PFN 입력란을 자동 채운다.
- Reset/Fill control을 제공한다.
- 제출 영상의 기본 Write 대상은 Probe page다.

### FR-008 프로세스 선택·메모리 맵·Hex browser

- PID/이름 필터가 있는 프로세스 목록과 attach/detach를 제공한다.
- committed region과 loaded module을 열람하고 protection/name으로 필터링한다.
- 선택 region/module을 최대 1 MiB Process Memory Hex view로 연다.
- process edit는 baseline/working/preflight/read-back/rollback 트랜잭션으로 처리한다.
- PID 재입력으로 process write gate를 명시적으로 arm하며 read-back 검증 후 결과를 표시한다.

### FR-009 First/Next Memory Scan

지원 데이터 형식:

- signed/unsigned 8·16·32·64비트
- float, double
- UTF-8, UTF-16
- AOB와 `?` wildcard

지원 비교:

- Exact, Not Equal, Greater, Less, Between
- Unknown Initial
- Changed, Unchanged
- Increased, Decreased
- Increased By, Decreased By

추가 조건:

- writable/executable region filter, alignment, chunk size, result limit
- cancellable worker와 진행률
- large result table virtualization

### FR-010 주소 목록과 verified Freeze

- scanner 결과 또는 수동 주소를 fixed-width address list에 추가한다.
- 값 변경은 process write gate를 요구하며 write length와 read-back을 검증한다.
- Freeze tick도 매회 write + read-back을 검증한다.
- 주소 목록은 PID에 바인딩해 저장/불러오기한다.
- 저장 당시 frozen이었던 항목도 불러올 때는 반드시 disarmed 상태다.

### FR-011 Pointer Scanner

- attached process의 readable region을 역방향으로 검색한다.
- 32/64비트 pointer width, alignment, max offset, max depth, result limit을 적용한다.
- writable-only와 module static-root filter를 제공한다.
- worker cancellation과 progress를 제공한다.

### FR-012 Disassembler

- attached process에서 지정 주소/길이를 읽는다.
- Zydis long-mode decoder와 Intel formatter로 주소, raw bytes, instruction text를 표시한다.
- short read/decode 종료를 오류 또는 종료 상태로 구분한다.

### FR-013 Memory Snapshot

- attached process의 주소와 크기를 chunk 단위로 비동기 캡처한다.
- UI 캡처 크기는 512 MiB로 제한하고 취소를 지원한다.
- baseline/current 각각 CRC32, save/load `.kdbgmem`을 제공한다.
- 동일 PID·주소·크기의 snapshot끼리 contiguous changed-run diff를 표시한다.

### FR-014 PFN → Process/VA

- 우선 MemProcFS native bridge를 별도 프로세스로 실행해 `VMMDLL_Map_GetPfnEx` 결과를 읽는다.
- bridge는 stdout line protocol, 15초 timeout, 8 MiB output cap, exit code와 protocol version 검증을 사용한다.
- fallback은 attached process 한 개의 page table을 bounded reverse scan한다.
- PID, name, VA, PTE physical address, page size/type, shared, RW/US/NX, source, confidence를 표시한다.

### FR-015 페이지 테이블 시각화

- PID와 VA를 받아 EPROCESS/DTB를 구하고 driver translation을 호출한다.
- LA57 여부, 각 level index, entry PA/value, PFN, P/RW/US/A/PS-or-D/NX를 표시한다.
- 4 KiB, 2 MiB, 1 GiB leaf를 처리한다.

## 5. 비기능 요구사항

### NFR-001 안전과 정확성

- 관리자/SYSTEM device ACL, 단일 controller PID, per-handle write gate, acknowledge magic, 최대 전송 크기를 적용한다.
- 모든 read/write는 requested/completed byte count를 검사한다.
- 모든 destructive GUI 동작은 명시적 PFN 또는 PID 확인을 요구한다.
- Probe page가 아닌 물리 페이지 Write는 실습 VM에서만 수행하며 제출 시연에는 사용하지 않는다.

### NFR-002 반응성

- First/Next Scan, Pointer Scan, Snapshot은 `std::jthread`/stop token 기반으로 실행한다.
- 결과가 큰 표는 `ImGuiListClipper`를 사용한다.
- 짧은 4 KiB IOCTL과 단일 VA translation은 현재 UI command에서 직접 수행하되 중복 클릭을 만들지 않는다.

### NFR-003 이식 경계

- portable core는 C++20로 Linux/Windows에서 테스트 가능하다.
- Win32/WDK 코드는 `_WIN32` 또는 전용 target으로 격리한다.
- MemProcFS AGPL 구성요소는 GUI와 직접 링크하지 않는다.

### NFR-004 추적성

- 요구사항, 구현 파일, 자동 테스트, Windows/live gate는 `TRACEABILITY_MATRIX.md`에 연결한다.
- Source, Windows build, Live VM gate를 서로 독립적으로 보고한다.

## 6. 완료 조건

### Source-complete

- Codex-only 구조 검사 통과
- portable configure/build/ctest 통과
- source-complete validator 통과

### Windows-build-verified

- `KDBG.exe`, bridge, 두 WDK driver가 실제 Windows에서 빌드됨
- package manifest 검증 통과

### Live-VM-verified

- Probe PFN의 Read/Edit/Write/full read-back/independent reload/rollback 증거가 존재함
- PFN ownership과 page walk가 화면에 표시됨

Linux에서 Source-complete를 검증해도 Windows-build-verified 또는 Live-VM-verified로 간주하지 않는다.

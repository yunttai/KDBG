# PRD — KDBG

- 문서 버전: 3.2
- 기준일: 2026-09-19
- 제품 목표: DEF CON 제안·라이브 데모 및 상용화 후보
- 대상 플랫폼: Windows 10 build 19041+/Windows 11 x64 bare-metal runtime host;
  Hyper-V guest는 별도 regression lane
- 제품 형태: Win32/DX11 GUI + WDM 드라이버 2개 + 격리형 분석 bridge

## 1. 제품 정의

KDBG는 PFN, 프로세스 VA, PTE, 페이지 테이블, 커널 모듈과 심볼을 하나의 탐색 모델로 연결하는 고성능 Windows x64 커널 메모리 디버깅·편집 워크벤치다. `KDBG.exe`와 `KDbgDriver.sys`가 실행되는 동일 bare-metal Windows인 `runtime_host`가 보는 local system physical RAM을 Raw PFN으로 읽고 편집한다. 물리 페이지와 프로세스 메모리의 읽기·검색·귀속 분석을 수행하고, 편집은 충돌 검사, 전체 read-back과 rollback을 포함한 명시적 트랜잭션으로 처리한다.

이 문서의 target 용어는 다음으로 고정한다.

- `runtime_host`: KDBG와 드라이버가 실행되고 그 동일 OS의 local physical RAM이 편집되는 bare-metal Windows
- `orchestrator_host`: 빌드, 배포, 수명주기 및 증거 수집을 제어하는 머신이며 암묵적 메모리 대상이 아님
- `regression_guest`: Hyper-V 회귀 검증용 Windows guest이며 그 증거는 runtime-host 증거를 대체하지 않음
- `RawPfn`: runtime_host의 RAM range 검증을 통과한 사용자 입력 PFN
- `ProbeFixture`: 자동 destructive evidence에 사용하는 결정적 fixture; 일반 RawPfn 제품 범위를 제한하지 않음

핵심 편집 흐름은 다음과 같다.

```text
Probe 또는 사용자가 runtime_host Raw PFN 확보
  → PFN/PA/RAM 범위 검증
  → 정확히 4096바이트 Read
  → Hex/ASCII local edit
  → byte diff 확인
  → 현재 PFN 재입력으로 one-shot unlock
  → Apply 직전 full-page preflight
  → ABI 7 exact 4 KiB compare/write transaction
  → full-page read-back 비교
  → 독립 재조회 또는 rollback
```

KDBG는 같은 GUI에서 고속 프로세스 메모리 검색, 주소 목록, 검증형 Freeze, pointer scan, user/kernel disassembly, snapshot diff, PFN 소유 정보, 페이지 테이블 변환과 커널 모듈/로컬 심볼 탐색을 제공한다.

발표의 기술 논지는 다음 한 문장으로 고정한다.

> Windows x64의 물리 페이지를 PFN에서 PID/VA/PTE/심볼까지 역으로 추적하고, 외부 변경을 감지하는 검증형 트랜잭션으로 편집 결과를 재현한다.

## 2. 목표

### G-01 트랜잭션형 커널 메모리 편집

- GUI에서 runtime_host Raw PFN 입력
- 동일 runtime_host의 local system physical page Read
- Hex/ASCII 표시와 편집
- 실제 물리 메모리 Write
- Write 직후 read-back 및 재조회 결과 표시

### G-02 커널 컨텍스트 복원

- PFN을 매핑한 PID, 프로세스명, VA, PTE 주소 표시
- PML5/PML4/PDPT/PD/PT 단계와 VA → PA 변환 시각화
- 커널 모듈, 주소, 로컬 심볼과 x64 instruction을 상호 이동

### G-03 고속 대규모 분석

- Cheat Engine 계열의 First/Next Scan, 주소 목록, verified Freeze, pointer scan, disassembly, memory snapshot/diff를 독립 구현
- First Scan throughput, Next Scan candidates/s, pointer edges/s, snapshot GiB/s와 취소 지연을 반복 측정한다.
- 모든 장시간 검색은 취소 가능하고 결과 수·깊이·메모리 크기에 명시적 예산을 둔다.

### G-04 DEF CON 데모 재현성

- exact package hash, OS build, driver/ABI version, target role과 모든 raw page
  hash를 기록한다. machine/boot/session 값은 가능한 경우 도구가 자동 provenance로
  수집하며 수동 확인이나 제품 실행 전제에 사용하지 않는다.
- regression_guest 실행에만 VM snapshot ID를 추가 기록하고, 해당 증거를
  bare-metal runtime-host gate로 승격하지 않는다.
- cold start부터 PFN 귀속 분석, 심볼/디스어셈블리, 편집, read-back, 독립 reload와 rollback을 중단 없는 한 세션으로 재현한다.
- 주장하는 성능은 동일 장비 반복 실행의 median/p95와 데이터 크기를 함께 공개한다.

### G-05 출시 후보 완성도

- 설치, update/repair, start/stop/remove와 실패 rollback이 멱등적이어야 한다.
- main/symbol package, SBOM, attribution, version metadata와 SHA-256 manifest를 제공한다.
- GUI나 서비스 실패를 성공으로 표시하지 않고 진단에 다음 복구 행동을 포함한다.

### G-06 단일 실행 파일의 런타임 영어·한국어 UI

- 별도 언어별 바이너리나 외부 language pack 없이 하나의 `KDBG.exe`를 제공한다.
- 기본 언어는 English이며, 실행 중 English/한국어를 전환할 수 있다.
- PFN, PTE, ABI, Verify 같은 기술 용어는 문맥과 정확성에 따라 영문을 유지하고, 조작·상태 문구는 선택 언어로 표시한다.

## 3. 앞으로 무조건 진행해야될 목표

> **Unresolved contract marker:** 아래 목록은 현재 저장소의 AGENTS/agent/skill
> 계약과 충돌한다. 이번 runtime-host/RawPfn 목표 정렬은 이 목록을 구현 권한,
> 완료 주장 또는 release gate로 해석하지 않는다. 충돌이 해소되기 전까지 각
> 항목은 `UNRESOLVED`이며 source·test·evidence PASS로 승격할 수 없다.

- Code Integrity, Secure Boot, HVCI 우회
- 취약한 서명 드라이버/BYOVD 사용
- 은닉, 안티치트 우회, 프로세스 주입
- 임의 커널 가상주소 쓰기
- 원격 대상 또는 본인이 관리하지 않는 시스템 접근
- 현재 3.0 범위에서 trap 기반 breakpoint/register/single-step 실행 제어를 구현했다고 주장하는 것
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
- `[PA, PA+0x1000)` 전체가 동일 runtime_host 커널의
  `MmGetPhysicalMemoryRanges`에서 얻은 단일 local RAM range 안에 있어야 한다.

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
- `dirty_bytes`와 diff run은 local review/evidence 범위다. driver에는 expected
  baseline과 desired page 전체를 한 번의 ABI 7 exact 4096-byte compare/write로
  전달하고, `driver_transferred_bytes=4096`을 요구하며 gate를 즉시 다시 잠근다.
- Write 후 전체 4096바이트를 다시 읽어 모든 dirty byte가 working copy와 일치해야 성공이다.
- `RawPfn`, `ProbeFixture`, `ProcessMapping`을 명시적 target kind로 구분한다.
  `RawPfn`은 일반 제품 범위이고 `ProbeFixture`는 자동 destructive evidence의
  기본 대상일 뿐 RawPfn read/write를 제한하지 않는다.

### FR-006 검증형 Rollback

- 성공한 Apply 직전 baseline을 보관한다.
- PFN 재입력 후 이전 baseline을 쓰고 full-page read-back으로 검증한다.
- rollback 실패 시 추가 자동 Write를 하지 않고 오류를 보존한다.

### FR-007 Probe fixture

- `KDbgProbe.sys`는 deterministic pattern을 가진 contiguous 4 KiB page를 할당한다.
- GUI에서 Probe VA, PA, PFN, generation, CRC32를 조회하고 PFN 입력란을 자동 채운다.
- Reset/Fill control을 제공한다.
- 제출 영상의 기본 Write 대상은 Probe page다.
- Packaged `tools/kdbg_process_fixture.exe`는 별도의 deterministic,
  page-aligned, `VirtualLock`된 4096-byte user mapping과 run nonce,
  process-start identity, generation/CRC를 제공한다.
- Process write/Freeze, ownership, PTView와 process-vs-physical 검증은 정확히
  그 fixture PID/VA를 사용하며 Probe PFN/VA를 재사용하지 않는다.

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

### FR-016 Kernel Explorer

- Windows가 보고하는 loaded kernel module을 base, size, path와 함께 bounded catalog로 표시한다.
- 사용자가 지정한 로컬 symbol path/PDB만 명시적으로 로드하고 주소↔symbol 변환 결과와 실패 원인을 표시한다.
- 선택한 module/symbol/address의 kernel virtual bytes를 기존 backend로 읽고 Zydis x64 disassembly를 표시한다.
- kernel address, page-table walk, 최종 PA/PFN과 physical editor 사이를 복사·이동할 수 있다.
- backend 미연결, short read, symbol 부재를 서로 다른 상태로 표시한다.

### FR-017 성능·회귀 하네스

- mock benchmark는 알고리즘 비교용이며 live-driver 성능 주장과 분리한다.
- 각 benchmark는 데이터 크기, 반복 수, warm-up, median, p95, throughput과 peak memory를 JSON으로 출력한다.
- 같은 machine/build/configuration에서 최적화 전후를 비교하고 정확성 hash가 다르면 성능 결과를 폐기한다.
- live harness는 IOCTL 수, requested/completed bytes, scan regions, cancellation latency와 GUI frame stall을 기록한다.
- packaged `kdbg_live_verify.exe`는 기본 read-only이며, write mode에서는 disposable
  VM·snapshot ID·현재 Probe PFN 확인을 모두 요구하고 8-byte one-shot Apply,
  full-page read-back, independent reload, full-page rollback, 최종 lock과 session
  counter를 `kdbg.live-verify.v1` JSON으로 기록한다.
- 기존 `kdbg_live_verify.exe`와 Win11 harness는 `regression_guest` lane으로
  보존한다. 별도 bare-metal harness는 package/ABI hash, target kind, exact
  PFN/PA, baseline/desired/read-back hash와 final gate state를 기록한다.
  machine/boot/session 값은 가능한 경우 자동 provenance로 추가하지만 누락을
  제품 precondition, 수동 confirmation 또는 RawPfn blocker로 취급하지 않는다.
- bare-metal 제품 검증은 read-only, ProbeFixture write evidence, RawPfn product
  capability gate를 각각 독립적으로 보고하며, 어느 gate도 VM 결과로 승계하지 않는다.

### FR-018 제품 수명주기

- install/update/repair/restart/remove는 두 서비스와 해당 binary path를 하나의 복구 가능한 작업으로 취급한다.
- package publish는 directory, ZIP, symbols와 sidecar 전체를 원자적으로 교체하거나 이전 set을 복원한다.
- readiness는 service state, device presence, 실제 backend ABI와 Probe fixture 검증을 구분해 표시한다.
- 주소 목록과 watch persistence는 이전 버전을 읽고 현재 버전으로 다시 저장할 수 있다.

### FR-019 런타임 영어·한국어 UI

- 번역 catalog는 제품에 compile-in하며 외부 번역 파일을 load하지 않는다.
- English를 기본값으로 하고 항상 보이는 상위 `Language / 언어` menu에서 English/한국어를 실행 중 선택한다.
- 한국어 glyph는 Windows system font를 순서대로 탐색해 atlas에 load하고, 사용 가능한 한국어 font가 없으면 렌더 가능한 English로 fail closed한다.
- 표시 label이 바뀌어도 ImGui widget 정체성은 안정적인 `###` ID로 유지한다.
- 선택 언어는 기존 ImGui INI의 `[KDBG][Preferences]` section에 저장하고, 다음 실행에서 복원한다.
- 언어 전환은 PFN/PID confirmation, dirty buffer, undo/redo, write gate, selected target, worker 또는 backend connection 상태를 변경하지 않는다.

## 5. 비기능 요구사항

### NFR-001 성능 최적화

- read/write 및 device I/O 경로의 latency와 CPU overhead를 최소화한다.
- 불필요한 메모리 복사, 버퍼 재할당, system call 및 context switch를 줄인다.
- 반복적인 device 접근에서는 handle과 내부 상태를 재사용하여 open/close 및 초기화 비용을 최소화한다.
- 대용량 read/write는 chunk 기반으로 처리하며, 요청 크기별 최적 chunk size를 측정하여 적용한다.
- 연속 I/O 처리 시 throughput 저하가 발생하지 않도록 hot path의 동적 할당과 불필요한 locking을 최소화한다.
- VA/PFN 변환 결과는 mapping 유효성을 보장할 수 있는 범위에서만 재사용하며, 대상 상태 변경 시 invalidate한다.
- GUI thread와 I/O worker를 분리하여 대량 또는 장시간 I/O 수행 중에도 UI responsiveness를 유지한다.
- 병렬화 가능한 작업은 bounded worker 기반으로 처리하여 CPU core 활용률을 높이되 thread 생성/소멸 overhead를 최소화한다.
- 요청 크기별 latency, throughput, IOPS, CPU usage, memory usage를 benchmark한다.
- 동일 workload에 대해 이전 버전 대비 성능 회귀 여부를 자동으로 비교할 수 있도록 baseline을 유지한다.
- 성능 최적화는 실제 profiling 결과를 기준으로 수행하며, hot path와 bottleneck이 확인된 구간을 우선 개선한다.


### NFR-002 반응성

- First/Next Scan, Pointer Scan, Snapshot은 `std::jthread`/stop token 기반으로 실행한다.
- 결과가 큰 표는 `ImGuiListClipper`를 사용한다.
- 예측 가능한 저지연 단일 작업만 UI command에서 직접 수행하며, blocking 가능성이 있는 device I/O는 worker로 전달한다.
- read/scan hot path에는 사용자 확인 UI를 넣지 않으며, 장시간 작업은 render thread를 차단하지 않는다.
- 성능 개선은 cap, cancellation, byte-count와 결과 의미를 변경해서 달성하지 않는다.

### NFR-003 이식 경계

- portable core는 C++20로 Linux/Windows에서 테스트 가능하다.
- Win32/WDK 코드는 `_WIN32` 또는 전용 target으로 격리한다.
- MemProcFS AGPL 구성요소는 GUI와 직접 링크하지 않는다.

### NFR-004 추적성

- 요구사항, 구현 파일, 자동 테스트, Windows/live gate는 `TRACEABILITY_MATRIX.md`에 연결한다.
- Source, Windows build, regression_guest, bare-metal runtime-host read-only,
  Probe-write evidence와 RawPfn capability gate를 서로 독립적으로 보고한다.

### NFR-005 localization 결정성

- MSVC는 `/utf-8`로 한국어 source/catalog를 컴파일하며, 동일 catalog·언어·font 가용성 입력은 동일 표시 문자열과 stable ID를 내야 한다.
- catalog key 중복, 빈 번역, 알 수 없는 locale, Korean font 미가용 및 미등록 기술 문구를 결정적으로 검증한다.
- localization 회귀는 순수 catalog/label 테스트와 Windows GUI build, 실제 font·persistence 런타임 확인을 분리해 보고한다.

## 6. 완료 조건

### Source-complete

- Codex-only 구조 검사 통과
- portable configure/build/ctest 통과
- source-complete validator 통과

### Windows-build-verified

- `KDBG.exe`, bridge, 두 WDK driver가 실제 Windows에서 빌드됨
- `/utf-8`로 compile된 단일 `KDBG.exe`와 deterministic localization 테스트가 Windows GUI build에서 통과함
- package manifest 검증과 모든 EXE/SYS↔PDB RSDS GUID+age 결속 통과

### Live-VM-verified

- Probe PFN의 Read/Edit/Write/full read-back/independent reload/rollback 증거가 존재함
- dedicated process fixture의 PFN ownership과 complete x64 page walk가 표시되고
  process/physical 4096-byte read가 일치함
- `kdbg.live-evidence.v4`가 fixture INFO/image, Kernel Explorer module/PDB/read/
  disassembly proof와 exact package/symbol hashes를 결속함
- 실제 reviewer/time/range/note/redaction 결정을 담은 20-scene review JSON이 영상 hash에 결속됨

이 gate의 명칭은 historical compatibility를 위해 유지하며 의미는
`Regression-Guest-Verified`다. VM PASS는 아래 bare-metal gate를 완료하지 않는다.

### Bare-Metal-Runtime-Host-Read-Only

- package/driver/ABI hash와 target role이 report에 결속됨
- local physical RAM range와 사용자 Raw PFN의 exact 4096-byte read가 증명됨
- orchestrator_host와 runtime_host의 역할이 증거에서 구분됨
- 자동 machine/boot/session provenance는 선택적이며 gate 통과 조건이 아님

### Bare-Metal-Runtime-Host-Probe-Verified

- 동일 runtime_host의 ProbeFixture PFN에서 one-shot Apply, full-page read-back,
  independent reload, rollback과 final lock이 증명됨
- 이 gate는 자동 destructive evidence이며 RawPfn 제품 범위를 제한하지 않음

### Bare-Metal-RawPfn-Capability-Verified

- GUI가 RawPfn target kind와 runtime-host identity를 표시함
- RAM range/page-bound, baseline preflight, explicit Apply, full read-back과
  rollback correctness가 해당 runtime-host 실행에서 결속됨
- Probe 전용 또는 regression_guest 결과는 이 gate를 대신하지 않음

### DEF-CON-candidate

- 현재 source, MSVC/WDK Release, package와 live evidence가 같은 revision/hash에 묶임
- 30분 연속 세션에서 install/start, kernel context 탐색, scan, transaction, rollback과 cleanup을 재현
- 반복 benchmark의 raw JSON과 측정 방법을 공개하고 성능 주장마다 median/p95를 제시
- 발표 abstract, novelty statement, architecture/threat diagrams, 5분 backup video와 redacted failure demo를 준비
- breakpoint/register/single-step이 없으면 제품을 `kernel memory debugger/editor`로 정확히 표기

### Commercial-release-candidate

- production driver signing, 설치 UX, update channel, support/privacy/license 문서는 별도 외부 release gate로 완료
- clean Windows guest에서 install/reboot/update/uninstall을 반복하고 남은 service/device/file이 없어야 함
- symbols, SBOM, notices, crash diagnostics와 rollback 가능한 이전 package를 함께 제공

Linux에서 Source-complete를 검증해도 Windows-build-verified,
Live-VM-verified 또는 bare-metal runtime-host gate로 간주하지 않는다.

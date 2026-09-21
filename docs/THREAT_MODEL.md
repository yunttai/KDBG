# KDBG 위협 모델과 안전 정책

## 1. 전제

KDBG의 제품 대상은 `KDBG.exe`와 `KDbgDriver.sys`가 실행되는 동일 bare-metal
Windows 10/11 x64 `runtime_host`의 local system physical RAM이다. Raw PFN
read/write는 일반 제품 범위다. `KDbgProbe.sys`의 4 KiB fixture는 자동
destructive evidence의 기본 target이고, Hyper-V `regression_guest`는 별도
회귀 lane이다. `orchestrator_host`는 수명주기/증거 제어 역할이며 암묵적
메모리 target이 아니다.

범위 밖:

- Code Integrity, Secure Boot, HVCI 우회
- BYOVD와 취약 드라이버
- 은닉, 안티치트 우회, 프로세스 주입
- 다른 사람 또는 원격 시스템 대상
- 임의 커널 가상주소 write

## 2. 보호 대상

- VM의 커널 안정성
- 실습 데이터와 snapshot
- runtime_host 운영체제와 local physical RAM
- orchestrator_host/target role과 자동 수집된 evidence provenance
- write 작업 정확성
- driver signing 정책
- 제출 증거의 재현성과 무결성

## 3. 신뢰 경계

```text
사용자 입력
  ↓
KDBG GUI / portable core
  ├─ Win32 process APIs
  ├─ DeviceIoControl → KDbgDriver/KDbgProbe
  └─ CreateProcess/stdout → MemProcFS bridge → vmm.dll
```

각 경계에서 주소, 길이, 상태, 응답 version과 완료 byte count를 다시 검증한다.

## 4. 위협과 대응

### T-01 잘못된 PFN 또는 물리 범위

위험: RAM 밖/MMIO 접근, hang, bugcheck.

대응:

- PFN parse와 shift/end overflow 검사
- `MmGetPhysicalMemoryRanges` 기반 allowlist
- 전체 `[PA, PA+length)`가 단일 RAM range에 포함되는지 user/kernel 양쪽에서 검사
- range query 실패 시 physical write fail-closed

### T-02 중요 커널 페이지 수정

위험: 즉시 또는 지연된 memory corruption.

대응:

- 기본 write locked
- PFN 재입력 one-shot unlock
- 관리자 전용 device와 단일 controller
- per-handle write gate 및 acknowledge magic
- 자동 destructive evidence에서는 exact current Probe PFN 사용
- 일반 RawPfn 제품 경로와 ProbeFixture evidence 경로를 명시적으로 구분

### T-03 TOCTOU와 경쟁 상태

위험: 화면에서 본 값과 write 직전 값이 다름.

대응:

- Apply 직전 전체 페이지/view를 다시 읽음
- baseline과 한 바이트라도 다르면 write하지 않음
- conflict offsets 표시
- 사용자가 명시적으로 Reload 후 다시 편집

### T-04 short/partial write

위험: 일부 byte만 변경되어 구조가 손상됨.

대응:

- 변경 구간을 bounded run으로 분할
- 각 write의 완료 길이 검사
- write 후 전체 페이지/view read-back
- expected working copy와 비교
- mismatch offsets 보존

### T-05 UI와 driver write gate 불일치

위험: 사용자가 잠겼다고 생각하지만 kernel gate가 열려 있음.

대응:

- physical gate는 apply 함수 내부 RAII scope에서만 활성화
- 성공/실패 예외 경로 모두 disable 호출
- controller handle close 시 kernel context 정리
- process write는 별도 PID confirmation과 explicit lock
- address-list load가 freeze를 자동 arm하지 않음

### T-06 rollback 오용

위험: 오래된 snapshot으로 현재 메모리를 덮어씀.

대응:

- 직전 성공 Apply의 baseline 하나만 보관
- 현재 PFN/PID 확인과 write gate 필요
- rollback 자체도 완료 길이와 read-back 검증
- 실패 후 재귀적 자동 rollback을 수행하지 않음

### T-07 드라이버 ABI 혼동

위험: 구조체 layout 차이로 잘못된 주소/길이 처리.

대응:

- 단일 shared header
- ABI version과 Size 검사
- 최대 1 MiB 전송
- source validator가 중복 IOCTL header를 금지

### T-08 MemProcFS bridge 신뢰

위험: 잘못된 외부 출력, hang, 대량 출력, union 오해석.

대응:

- main GUI와 별도 process
- 실행 경로와 exit code 확인
- 15초 timeout/cancellation
- stdout 8 MiB cap
- protocol header/version/PFN/record 검증
- PageTable/Unused union을 PID로 처리하지 않음
- bridge 실패가 physical editor 필수 경로를 막지 않음

### T-09 대규모 scan/snapshot 자원 고갈

위험: UI freeze, excessive memory/CPU usage.

대응:

- worker thread와 stop token
- alignment/chunk/result/depth/offset 상한
- snapshot UI 512 MiB 상한
- large table clipping
- unbounded whole-system pointer graph 금지

### T-10 process lifetime과 PID reuse

위험: 선택했던 process가 종료되고 같은 PID가 재사용됨.

대응:

- attach 상태와 handle validity 확인
- process access 오류를 stale state로 처리
- address list를 PID에 바인딩
- driver process request에서 process object를 매 요청 resolve/reference
- attach 변경 시 scanner, memory view, freeze state를 reset

### T-11 target role 또는 stale backend session 혼동

위험: orchestrator_host/regression_guest를 runtime_host로 오인하거나, 현재
backend 연결 세션이 바뀐 뒤 오래된 baseline/unlock을 재사용함.

대응:

- runtime_host, orchestrator_host, regression_guest role을 command/report에 기록
- machine/boot/session 값은 가능한 경우 도구가 자동 evidence provenance로 기록
- provenance 수동 확인이나 누락을 LocalHost RawPfn product gate로 사용하지 않음
- VM regression과 bare-metal runtime-host gate를 별도 보고
- backend 연결/session revision이 바뀌면 기존 baseline/unlock/rollback state를
  폐기하고 페이지를 다시 읽음

## 5. 출시 중단 조건

다음 중 하나라도 발생하면 live write와 제출 촬영을 중단한다.

- active backend session revision이 baseline 이후 변경됨
- ABI mismatch
- physical range query 실패
- short read/write
- preflight conflict
- full read-back mismatch
- 선택한 target kind/PFN과 typed confirmation 불일치
- driver signature/HVCI 우회를 요구하는 상태
- bugcheck 또는 Driver Verifier 오류

## 6. 잔여 위험

커널 드라이버의 직접 물리 write는 correctness 장치가 있어도 본질적으로
위험하다. source-complete test는 driver correctness의 충분조건이 아니다.
Windows build, regression_guest, bare-metal runtime-host read-only,
ProbeFixture write evidence와 RawPfn capability를 각각 실행하고 독립적으로
판정한다. 어느 lane의 PASS도 다른 lane을 대체하지 않는다.

# KDBG 시스템 아키텍처

## 1. 설계 목표

KDBG는 하나의 대형 메모리 조작 코드로 구성하지 않고, 다음 경계를 분리한다.

1. **GUI**: 입력, 탐색, 상태 표시, 명시적 write 확인
2. **portable core**: PFN 계산, 트랜잭션, 스캔, pointer, snapshot, page walk
3. **Windows adapter**: Win32 프로세스 메모리와 SCM/DeviceIoControl
4. **WDM driver**: 제한된 물리·프로세스 메모리 primitive
5. **분석 provider**: MemProcFS PFN 정보 또는 선택 프로세스 reverse mapping
6. **검증 체계**: portable test, source gate, Windows build gate, live-VM gate

```text
┌────────────────────────────────────────────────────────────────────┐
│ KDBG.exe — Win32 + DirectX 11 + Dear ImGui                         │
│ Driver | Physical | Memory Map | Process Memory | Scanner           │
│ Address List | Pointer | Disassembly | Snapshot | Page Tables | PFN │
└─────────────┬───────────────────┬───────────────────────┬────────────┘
              │                   │                       │
              ▼                   ▼                       ▼
┌──────────────────────┐ ┌──────────────────────┐ ┌─────────────────────┐
│ Portable C++20 Core  │ │ Windows Adapters     │ │ PFN Providers       │
│ transactions/scanner │ │ Win32ProcessMemory   │ │ MemProcFS bridge    │
│ pointer/snapshot/PT  │ │ KDbgBackend/SCM      │ │ Reverse mapper      │
└─────────────┬────────┘ └───────────┬──────────┘ └──────────┬──────────┘
              │                      │                       │
              └──────────────────────┼───────────────────────┘
                                     ▼
                         ┌──────────────────────────┐
                         │ KDbgDriver.sys           │
                         │ KDbgProbe.sys            │
                         │ versioned shared ABI     │
                         └──────────────────────────┘
```

## 2. 저장소 경계

실제 제품·테스트·개발 도구는 모두 `src/` 아래에 둔다.

```text
src/
├── app/                    # GUI와 Zydis adapter
├── core/
│   ├── address/            # address list, pointer resolution
│   ├── common/             # Error, Result
│   ├── memory/             # physical/process sessions, backend
│   ├── model/              # 공용 데이터 모델
│   ├── paging/             # x64 page-table decoding
│   ├── pfn/                # PFN ownership providers
│   ├── process/            # IProcessMemory와 Win32/mock 구현
│   ├── scanner/            # First/Next scan, AOB, watch list
│   ├── snapshot/           # capture, CRC32, persistence, diff
│   └── windows/            # SCM service adapter
├── driver/                 # 두 WDM 프로젝트
├── plugins/memprocfs_bridge/
├── shared/                 # user/kernel ABI 단일 원본
├── tests/
├── tools/
└── config/
```

Codex 지시 구조는 제품 소스와 분리한다.

```text
.codex/config.toml
.codex/agents/*.toml
.agents/skills/*/SKILL.md
AGENTS.md
src/**/AGENTS.md
```

## 3. 공용 ABI

`src/shared/KDbgIoctl.h`가 KDbgDriver의 유일한 ABI 원본이다. 사용자 모드와 커널 모드가 같은 구조체와 IOCTL 번호를 포함한다.

핵심 primitive:

- ABI/version 조회
- controller/write-gate 상태 조회
- physical RAM range 조회
- physical read/write
- PID → EPROCESS/DTB 조회
- process virtual read/write
- x64 VA → PA translation
- bounded kernel virtual read

`src/shared/KDbgProbeIoctl.h`는 Probe Query/Reset/Fill 계약만 정의한다.

ABI 방어 규칙:

- 모든 구조체에 `Size`와 version을 둔다.
- 최대 전송은 1 MiB다.
- 요청 길이와 완료 길이를 모두 검증한다.
- destructive request에는 acknowledge magic과 per-handle write gate가 필요하다.
- device ACL은 Administrators/SYSTEM으로 제한한다.
- controller owner를 하나로 제한한다.

## 4. 물리 페이지 트랜잭션

`PhysicalPageSession`은 커널 메모리와 UI working copy를 분리한다.

```text
Empty → Loading → Clean → Dirty
                        │
                        ├─ Undo/Redo/Revert
                        │
                        └─ typed PFN unlock
                              ↓
                         Preflight
                              ↓
                    Conflict │ Writing
                              ↓
                          Verifying
                              ↓
             Clean | VerificationFailed | Error
```

보관 상태:

- `baseline[4096]`: 마지막으로 검증 완료한 페이지
- `working[4096]`: Hex Editor 로컬 편집본
- dirty bitmap
- byte-level undo/redo stack
- conflict offsets
- read-back mismatch offsets
- 직전 성공 Apply의 rollback snapshot
- one-shot UI unlock

Apply 순서:

1. 현재 페이지와 dirty 상태를 확인한다.
2. PFN 재입력으로 얻은 one-shot unlock을 소비한다.
3. RAM range를 다시 조회한다.
4. 전체 페이지를 preflight read한다.
5. baseline과 한 바이트라도 다르면 중단한다.
6. driver write gate를 RAII로 연다.
7. contiguous dirty run만 bounded write한다.
8. 전체 페이지를 다시 읽는다.
9. 요청한 working copy와 비교한다.
10. 성공한 read-back만 새 baseline으로 승격한다.
11. driver write gate를 닫는다.

Rollback도 PFN 재입력, 전체 write, 전체 read-back을 거친다.

## 5. 프로세스 메모리 계층

`IProcessMemory`는 scanner와 GUI가 Win32 또는 driver fallback 세부사항을 모르도록 한다.

`Win32ProcessMemory`:

- 일반 사용자 프로세스에는 `ReadProcessMemory`/`WriteProcessMemory`를 우선 사용한다.
- 권한 때문에 직접 read/write가 실패하고 KDBG backend가 연결돼 있으면 driver process primitive를 사용할 수 있다.
- memory region과 module을 열거한다.
- process write는 PID 재입력 후 adapter-level gate를 arm해야 한다.

`ProcessMemorySession`은 최대 1 MiB view에 대해 physical session과 같은 baseline/working/preflight/read-back/rollback 및 undo/redo 구조를 제공한다.

## 6. First/Next Scan

`MemoryScanner`는 읽을 region을 먼저 정규화한 뒤 chunk 단위로 처리한다.

지원 값:

- signed/unsigned 8/16/32/64-bit
- float/double
- UTF-8/UTF-16
- AOB wildcard

지원 비교:

- Exact, Not Equal, Greater, Less, Between
- Unknown Initial
- Changed/Unchanged
- Increased/Decreased
- Increased By/Decreased By

First Scan은 후보 주소와 현재 바이트를 저장한다. Next Scan은 같은 후보를 다시 읽어 이전 값·현재 값·사용자 입력을 비교한다. `std::jthread`와 stop token으로 취소하며 result/chunk/alignment 상한을 적용한다.

## 7. 주소 목록, Freeze, Pointer Scan

`AddressList`/`WatchList`:

- PID, address, value type, description, frozen value를 보관한다.
- 수동 주소와 scanner 결과를 추가한다.
- 값 변경과 Freeze 모두 write byte count 및 read-back을 검증한다.
- 파일에서 frozen 상태를 읽더라도 자동으로 write하지 않고 disarmed로 복원한다.

`PointerScanner`:

- target을 가리키는 pointer 값을 readable region에서 역방향 검색한다.
- pointer width, alignment, maximum offset/depth/result를 제한한다.
- module-relative static root를 우선 표시할 수 있다.
- 무제한 전체 메모리 그래프를 만들지 않는다.

## 8. Snapshot과 Disassembly

`MemorySnapshot`:

- 주소, 크기, PID, bytes, CRC32를 보관한다.
- chunk 기반 취소 가능한 capture를 지원한다.
- `.kdbgmem` 헤더와 payload를 저장·불러온다.
- 같은 PID/range/size에서 contiguous changed run을 계산한다.

Disassembly는 GUI adapter가 process bytes를 읽고 Zydis long-mode decoder 및 Intel formatter에 전달한다. Zydis는 portable core에 직접 종속되지 않는다.

## 9. PFN 소유 정보

### 9.1 MemProcFS bridge

GUI 프로세스는 AGPL 구성요소를 직접 링크하지 않는다.

```text
KDBG.exe
  └─ CreateProcess + captured stdout
       └─ kdbg_memprocfs_bridge.exe
            └─ LoadLibrary(vmm.dll)
                 └─ VMMDLL_Map_GetPfnEx
```

bridge는 command-line request와 versioned line response를 사용한다. provider는 다음을 검증한다.

- 실행 파일 존재
- 15초 timeout과 cancellation
- 최대 stdout 8 MiB
- 정상 exit code
- protocol header/version/PFN
- 각 MAP record의 필드 수와 형식

PageTable/Unused extended type의 union을 PID로 해석하지 않는다.

### 9.2 선택 프로세스 reverse mapper

MemProcFS가 없으면 attached process의 DTB부터 page table을 순회한다.

- present entry만 하위 level로 진행
- table/page 상한과 stop token 적용
- 1 GiB/2 MiB large page 처리
- leaf PFN이 target PFN 또는 large-page PFN 범위를 포함하는지 비교
- indices를 canonical VA로 재구성

전체 시스템의 모든 PID를 무제한 순회하지 않는다.

## 10. 페이지 테이블 시각화

Driver translation response는 다음을 포함한다.

- 4-level/5-level 여부
- DTB, VA, final PA, page size, page offset
- PML5/PML4/PDPT/PD/PT entry value
- 각 entry의 physical address

GUI는 level-aware decoder로 Present, RW, US, Accessed, Dirty/PS, Global, NX, PFN을 표시한다. 4 KiB, 2 MiB, 1 GiB leaf를 구분한다.

## 11. Probe fixture

`KDbgProbe.sys`는 제출 시연을 위한 known-good target이다.

- contiguous 4 KiB allocation
- deterministic pattern
- Query: VA, PA, PFN, generation, CRC32
- Reset/Fill

임의 커널 코드·페이지 테이블·파일 캐시 페이지 대신 Probe PFN을 사용해 end-to-end write 검증을 수행한다.

## 12. 오류 모델

`Result<T>`는 다음 정보를 유지한다.

- domain error code
- 사용자 메시지
- operation name
- Win32 error
- requested/completed length

대표 오류:

- invalid PFN/address/size
- address overflow/outside RAM
- backend disconnected/ABI mismatch
- short read/write
- write locked
- concurrent modification
- verification mismatch/rollback failure
- cancelled/limit reached/bridge unavailable

## 13. 검증 Gate

### Source-complete

- Codex-only 구조
- CMake source reference
- portable core configure/build/test
- source marker와 third-party lock 검증

### Windows-build-verified

- Win32/DX11 GUI, Zydis, native bridge 컴파일
- 두 WDK 프로젝트 컴파일
- package manifest 검증

### Live-VM-verified

- Probe Query
- PFN 4096-byte Read
- local edit/undo/redo/diff
- typed unlock
- Apply/full read-back/independent reload
- rollback/read-back
- PFN owner/page walk 화면 증거

각 Gate는 독립적으로 보고한다. Linux source test 통과를 Windows driver live 동작으로 표현하지 않는다.

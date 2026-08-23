# KDBG 데이터 계약

## 1. Driver ABI

원본 파일:

- `src/shared/KDbgIoctl.h`
- `src/shared/KDbgProbeIoctl.h`

공통 규칙:

- little-endian x64
- 모든 request/response에 `Size`
- KDBG ABI version은 `KDBG_ABI_VERSION`
- 최대 한 번의 전송은 `KDBG_MAX_TRANSFER_SIZE`
- user/kernel은 같은 헤더를 포함
- 요청·완료 길이가 다르면 short I/O 오류

물리 주소와 길이는 `[address, address + length)`로 해석한다. overflow가 발생하거나 전체 범위가 물리 RAM map 안에 없으면 거부한다.

## 2. MemProcFS bridge 요청

bridge는 stdin JSON이 아니라 command-line argument를 사용한다.

```text
kdbg_memprocfs_bridge.exe
  --pfn <decimal-or-0x-number>
  [--device <pmem-or-dump-path>]
  [--vmm <vmm.dll-path>]
  [--vmm-arg <additional-argument>]...
```

기본 device는 환경 변수 `KDBG_MEMPROCFS_DEVICE`이고, 없으면 `pmem`이다.

## 3. MemProcFS bridge 응답

stdout은 tab/whitespace로 구분되는 versioned line protocol이다. 문자열 필드는 C++ `std::quoted` 형식이다.

Header:

```text
KDBG_PFN_RESULT<TAB>1<TAB><PFN>
```

Mapping:

```text
MAP<TAB><PID><TAB><VA><TAB><PTE_ADDRESS><TAB><PAGE_SIZE>
   <TAB><CONFIDENCE><TAB><SHARED><TAB><WRITABLE><TAB><USER><TAB><NX>
   <TAB>"<MAPPING_TYPE>"<TAB>"<PROCESS_NAME>"
```

End:

```text
END
```

필드 의미:

| 필드 | 형식 | 의미 |
|---|---:|---|
| PID | u32 | owner PID, 알 수 없으면 0 |
| VA | u64 | mapped VA, 알 수 없으면 0 |
| PTE_ADDRESS | u64 | MemProcFS가 제공한 PTE 주소 |
| PAGE_SIZE | u64 | 현재 bridge PFN result는 4096 |
| CONFIDENCE | 0..3 | unknown/low/medium/high |
| SHARED | 0/1 | shareable 또는 file-backed |
| WRITABLE/USER/NX | 0/1 | `OriginalPte` 비트 해석 |
| MAPPING_TYPE | quoted string | process-private/page-table/... |
| PROCESS_NAME | quoted string | image basename 또는 빈 문자열 |

Provider 방어:

- protocol version은 1이어야 한다.
- response PFN은 request PFN과 같아야 한다.
- 알 수 없는 record와 malformed MAP은 거부한다.
- 15초 timeout, 8 MiB output cap, cancellation, exit code 검사를 적용한다.

## 4. 주소 목록 파일

주소 목록 persistence는 PID에 바인딩한다. 저장 필드는 implementation version, PID, address, value type, description, display/frozen value다.

불러오기 규칙:

- 파일 PID와 attached PID가 다르면 거부한다.
- 주소·값 형식이 잘못되면 해당 파일을 실패 처리한다.
- frozen flag가 저장되어 있어도 load 후에는 disarmed다.
- write gate를 자동으로 열지 않는다.

정확한 직렬화는 `src/core/address/AddressList.cpp`와 `src/core/scanner/WatchList.cpp`를 기준으로 한다.

## 5. Snapshot 파일

확장자: `.kdbgmem`

파일에는 다음 메타데이터와 payload가 들어간다.

- format magic/version
- PID
- base virtual/physical address
- memory space
- payload size
- CRC32
- raw bytes

Load 시 magic/version/size/CRC를 검사한다. diff는 동일 memory space, PID, base, size 조건을 요구한다.

## 6. Live evidence JSON

`src/tools/new_live_evidence.ps1`은 `kdbg.live-evidence.v2`를 생성한다. v2는
Release package의 EXE/driver hash, PFN/PA, 정확한 4096-byte count, baseline/
expected/read-back/reload/rollback SHA-256, Probe generation/CRC32, dirty run,
ownership PID/VA/PTE, page-table levels/final PFN, command log/video hash, 17개
필수 장면, VM/snapshot/비식별화 confirmation을 기록한다.

Validator는 `--windows-package`와 `--live-evidence`를 함께 받아 package의
실제 artifact hash와 교차 검증한다. command log와 video는 JSON과 같은
디렉터리의 안전한 파일명으로만 참조하며, 실제 파일 hash를 다시 계산한다.

## 7. Windows package manifest

`SHA256SUMS.txt` 형식:

```text
<lowercase-sha256><two-spaces><relative/path>
```

manifest 자신은 hash 목록에서 제외한다. validator는 blank/duplicate/
절대/상위 경로를 거부하고, package의 모든 파일이 정확히 한 번씩
포함되었는지와 실제 SHA-256를 재계산한다.

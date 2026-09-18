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
Provider 구성은 `--device`와 `--vmm`을 각각 최대 한 번, `--vmm-arg`를
최대 64번 허용한다. 각 raw argument는 최대 32 KiB이고 embedded NUL은
거부한다. Provider가 추가하는 `--pfn <value>`까지 포함한 raw token 상한은
134개이며 Windows command line은 terminating NUL을 포함한 32,767 wchar
제한을 넘지 않아야 한다.

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
- Windows 결정적 helper-process 회귀는 64/65 `--vmm-arg` 경계, quoting과
  empty argument 보존, 정상 pipe close, child-held pipe 정리, timeout,
  실행 중 cancellation, output cap, non-zero exit propagation을 검사한다.

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

`src/tools/new_live_evidence.ps1`은 `kdbg.live-evidence.v4`를 생성한다. v4는
Release main/symbol package manifest와 EXE/driver/PDB hash, PFN/PA, 정확한
4096-byte count, baseline/expected/read-back/reload/rollback 파일명과 SHA-256,
Probe generation/CRC32, live verifier가 고정한 dirty run/XOR mask, 별도
dedicated-fixture analysis metadata, command log/video hash와 파싱된 GIF
메타데이터, 20개 필수 장면,
VM/snapshot/비식별화 confirmation을 기록한다. 또한 packaged
`kdbg_live_verify.exe`가 만든 `kdbg.live-verify.v1` write-run JSON의 파일명과
SHA-256를 포함한다.

Validator는 main/symbol package pair, `--live-run-report`, `--live-evidence`를
함께 받아 package의 실제 artifact hash, Probe PFN, apply/rollback driver
counter, exact edit range, final gate lock을 교차 검증한다. 여섯 raw page,
command log, video, live-run JSON은 evidence JSON과 같은 디렉터리의 안전한
파일명으로만 참조하며 실제 hash를 다시 계산한다. raw page CRC32도 live-run의
full-page comparison과 대조하므로 파일을 재해시해 바꿔 끼울 수 없다.

생성기는 GUI의 `kdbg-physical-live-evidence-v1` `metadata.json`을 필수 입력으로
받는다. PFN/PA, 여섯 raw-page 파일, Probe generation/CRC32, dirty run을 수동
재입력하지 않고 이 파일에서 파생한 뒤 GUI metadata hash도 v4에 포함한다.
GUI metadata, raw bytes, live-run은 다음 연쇄를 모두 만족해야 한다.

- `os_build`는 문자열 설명이 아니라 live-run `system.os_build`와 같은 정수다.
- baseline→expected 변화는 offset `0x100`의 정확한 8-byte XOR
  `4b444247a55a3cc3`뿐이다. preflight/rollback은 baseline과, read-back/reload는
  expected와 바이트 단위로 같아야 한다.
- 세 stage의 PFN/PA/generation/CRC32는 live-run과 같고, GUI의 after-reload
  Probe identity는 after-write와 같아야 한다.
- `kdbg-analysis-live-evidence-v1`은 packaged
  `tools/kdbg_process_fixture.exe`의 hash와 `kdbg.process-fixture.v1` INFO JSON
  hash를 결속한다. protocol은 1, page는 4096 bytes/`VirtualLock`, nonce와
  process-start identity, VA, generation, current CRC32가 모두 같은 실행이어야
  한다.
- ownership은 exact provider/source `selected-process-page-table-scan`, high
  confidence, private 4 KiB user+writable mapping이어야 한다. 그 VA/PFN은 Probe
  allocation과 달라야 하며 process/physical 두 4096-byte read는 hash/CRC/bytes가
  같아야 한다.
- page-table은 ownership PID/VA/PTE/PA/PFN과 같고 DTB에서 leaf까지 실제 x64
  entry-address chain을 이룬다. 각 entry value의 P/RW/US/PS/NX 및 next PFN을
  다시 decode하며 4 KiB walk의 모든 non-leaf PS는 false여야 한다. 시작/종료
  process identity, DTB, walk, translated PA가 재검증된다.
- 같은 analysis는 선택한 high-half kernel module의 live/local PE header hash와
  loader가 적용한 `OptionalHeader.ImageBase` 한 필드를 제외한 header byte 동일성,
  live `ImageBase == module base`, PDB basename/file hash/GUID+age, in-module exact
  kernel read와 bounded x64 Intel disassembly를 결속한다. private symbol path는
  기록하지 않는다.

`video_file`은 임의의 non-empty 파일이 아니라 완전한 GIF87a/GIF89a
container여야 한다. Validator는 block/sub-block 경계, trailer, frame rectangle,
LZW clear/end/code dictionary를 파싱하고 각 frame의 정확한 pixel 수까지
복호화하며 logical size 320x180..7680x4320,
20..100000 frames, 20초..8시간 duration을 강제한다. 파싱된 `format`, `width`,
`height`, `frame_count`, `duration_ms`는 `video_media`와 정확히 일치해야 한다.
이 구조 검사는 영상 내용이 장면을 실제로 보여 주는지 판정하지 않는다.
따라서 영상 의미는 사람이 검토한다. v4는 별도
`kdbg.demo-scene-review.v1` 파일을 해시 결속하며, 이 파일은 동일 GIF의
파일명/SHA-256, 실제 reviewer, UTC 검토 시각, 두 redaction 결정과 정확히 한 번씩
순서대로 나타나는 20개 scene ID의 `start_ms`, `end_ms`, `observed`, 구체적 note를
포함한다. 모든 범위는 파싱된 GIF duration 안에서 순서대로 겹치지 않아야 하며
각 장면은 최소 500 ms여야 한다. 이는 자동 장면
인식 주장이 아니라 수동 검토의 추적 가능한 계약이다.

`kdbg.live-verify.v1.runtime_identity`는 장치 open 전에 수집한 세 artifact를
기록한다. verifier는 `tools/kdbg_live_verify.exe`, 서비스 `KDBG`와 `KDBGProbe`는
각각 `drivers/KDbgDriver.sys`, `drivers/KDbgProbe.sys`라는 package-relative
path와 lowercase SHA-256를 가져야 한다. 두 서비스는 kernel-driver type 1,
running state 4여야 한다. v4 validator는 이 세 runtime hash를
`artifact_sha256`의 exact package hash와 다시 대조한다. 절대 경로나 SCM의
원문 binary path는 evidence에 기록하지 않는다.

## 7. Windows package manifest

`SHA256SUMS.txt` 형식:

```text
<lowercase-sha256><two-spaces><relative/path>
```

manifest 자신은 hash 목록에서 제외한다. validator는 blank/duplicate/
절대/상위 경로를 거부하고, package의 모든 파일이 정확히 한 번씩
포함되었는지와 실제 SHA-256를 재계산한다.

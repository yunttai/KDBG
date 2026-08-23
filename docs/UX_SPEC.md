# KDBG UX 명세

## 1. 공통 프레임

KDBG는 전체 화면 Dear ImGui 창과 reorderable tab bar를 사용한다. 상단에는 다음이 항상 보인다.

- KDBG driver 연결 상태, ABI, driver write gate
- attached PID/프로세스명과 process write gate
- process 이름/PID 필터, attach/detach
- Session 메뉴와 `Lock all writes`
- `Test-signed VM only` 경고

색상만으로 상태를 전달하지 않고 `CONNECTED`, `LOCKED`, `ARMED`, `CONFLICT`, `VERIFICATION FAILED` 텍스트를 함께 표시한다.

## 2. Driver 탭

- KDbgDriver/KDbgProbe SYS 경로
- install/update/start/stop/remove/connect 버튼
- Probe query와 deterministic pattern reset
- Probe query 성공 시 Physical Memory의 PFN 입력 자동 채움
- controller PID, open handles, successful read/write, rejected write counters

## 3. Physical Memory 탭

3열 구조다.

```text
PFN Input | Physical Hex/ASCII Editor | Session Inspector
```

### PFN Input

- decimal 또는 `0x` hexadecimal
- PA와 page end 계산
- RAM range validation 결과
- `Read 4096 bytes`

### Hex Editor

- 16 columns, offset/absolute PA, Hex, ASCII, data preview
- local working copy만 수정
- dirty: 파란색 계열
- preflight conflict: 주황색 계열
- read-back mismatch: 빨간색 계열

### Diff/Action

- offset, PA, before, after 표
- Undo Byte Edit / Redo Byte Edit / Revert Local Edits
- Unlock One Physical Apply
- Apply & Full Read-back Verify
- 성공한 Apply가 있으면 Unlock Rollback / Rollback Previous Apply

Unlock modal은 현재 PFN과 dirty byte 수를 표시하며 PFN 재입력을 요구한다.

## 4. Memory Map 탭

- committed/readable/writable/executable/guard 필터
- module 또는 mapped path text filter
- region base/end/size/protection/state/type/module/path
- loaded module table
- `Hex` 버튼으로 선택 range를 Process Memory 탭에서 연다.

## 5. Process Memory 탭

- address와 1 MiB 이하 length 입력
- Read View / Reload Live
- process transaction state와 dirty byte 수
- Hex/ASCII local edit
- conflict/mismatch highlight와 diff table
- Arm Process Writes modal: attached PID 재입력
- Undo/Redo/Revert staged edit
- Apply & Verify / Rollback

## 6. Process Scanner 탭

- Value Type, Scan Type, Value/Second Value
- hexadecimal, writable-only, executable 포함, alignment, result limit
- First Scan / Next Scan / Reset / Cancel
- progress bar, region/byte/candidate counters
- virtualized result table: address, previous, current, changed, Add

### Address List / Freeze

- scanner result 또는 manual address/type/description 추가
- refresh, edit, remove, freeze
- process write gate arm/lock
- PID-bound table save/load
- 불러온 frozen 항목은 자동으로 write하지 않고 명시적 재-arm을 요구

## 7. Pointer Scanner 탭

- target address
- max offset/depth/result limit
- aligned-only, writable-only, static roots only
- cancellable worker와 progress
- depth, root, formatted module-relative path, resolved target table

## 8. Disassembler 탭

- address와 read length
- Zydis x64/Intel decode
- instruction address, raw bytes, formatted instruction table

## 9. Snapshots 탭

- address, size, chunk size
- Capture Baseline / Capture Current / Cancel
- 각각 range, byte count, CRC32, preview
- `.kdbgmem` save/load
- Compare Snapshots
- changed run offset/length/before preview/after preview table

## 10. Page Tables 탭

- PID, VA
- Translate
- EPROCESS, CR3/DTB, LA57/4-level, final PA/page size/page offset
- VA index decomposition
- level/index/entry PA/entry value/PFN/P/RW/US/A/PS-or-D/NX table

## 11. PFN Ownership 탭

Physical Memory에서 현재 PFN을 사용한다.

- MemProcFS bridge path와 Query
- attached process reverse-map
- table page limit
- PID, process, VA, PTE address, mapping type, shared, confidence, source

## 12. 시연 원칙

- Driver 탭에서 Probe PFN을 가져온다.
- Physical Memory 필수 흐름을 먼저 보여준다.
- `Apply & Full Read-back Verify` 성공 문구를 충분히 유지한다.
- PFN Ownership과 Page Tables는 이어서 보여준다.
- Process Scanner/Pointer/Disassembler/Snapshot은 고도화 기능으로 별도 짧게 시연한다.

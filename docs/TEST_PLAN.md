# KDBG 테스트 계획

## 1. Gate 분리

| Gate | 환경 | 증명하는 것 |
|---|---|---|
| Source-complete | Linux 또는 Windows C++20 | portable core, Codex 구조, source contract |
| Windows-build-verified | Visual Studio/SDK/WDK | GUI, bridge, WDM projects, package |
| Live-VM-verified | 스냅샷 가능한 Windows VM | 실제 service/device/Probe R/W |

어느 한 Gate의 PASS를 다른 Gate의 PASS로 표현하지 않는다.

2026-08-23 상태: Source-complete 및 Windows-build-verified는 PASS이며 portable
직접 실행은 707 checks, 0 failures다. 기존 `Windows-VM`의 checkpoint,
Administrator, test-signing 전제도 PASS다. Interim `DADF43AA...`는 ABI 6 Probe
transaction을 완료했고 candidate `D3390AD4...`는 advanced read-only workflow를
완료했다. `kdbg.source-snapshot.v1` package candidate의 strict validators, 동일
입력 ZIP 재현성, 5/5 negative fixtures도 PASS다. 동일 VM에서 exact Release의
deploy/hash binding/device/main ABI6/fresh Probe query/exact 4 KiB read-only/invalid
IOCTL rejection/stop+remove도 physical writes 0으로 PASS했다. Final physical write,
process write/Freeze, Driver Verifier와 hash-bound v2는 BLOCKED다.

## 2. Portable 자동 테스트

실행:

```powershell
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

### 2.1 PFN, range, page table

- decimal/hex PFN과 invalid input
- PFN shift/page-end overflow
- physical range inside/outside/cross-boundary
- 48-bit/57-bit canonical VA
- PTE flag decode
- 4 KiB/2 MiB/1 GiB PA 계산

### 2.2 PhysicalPageSession

- exact 4096-byte load와 clean state
- edit, byte-level undo/redo, revert, dirty bitmap, diff run
- wrong PFN과 locked Apply
- clean/dirty byte preflight conflict
- short read/write
- ignored write와 read-back mismatch
- successful Apply와 baseline promotion
- successful/failed rollback
- gate close after success/failure

### 2.3 ProcessMemorySession/VerifiedWriter

- bounded load/edit/undo/redo
- expected-before conflict
- changed-run write와 full-view read-back
- rollback
- process write lock

### 2.4 Scanner

- fixed numeric types, float/double
- UTF-8/UTF-16
- AOB wildcard parser
- Exact/NotEqual/Greater/Less/Between
- Unknown/Changed/Unchanged/Increased/Decreased/delta
- alignment/result limit
- cancellation

### 2.5 Address list와 Freeze

- add/refresh/write/read-back
- Freeze write/read-back
- save/load
- PID mismatch
- frozen entry load disarmed

### 2.6 Pointer/Snapshot/PFN reverse map

- one/two-level pointer path
- module-relative/static root metadata
- process/physical snapshot, CRC, save/load/diff
- corrupted snapshot rejection
- synthetic 4 KiB/large-page reverse mapping
- depth/page/result limit과 cancellation

## 3. Source validator

```powershell
python .\src\tools\verify_layout.py
python .\src\tools\validate_release.py --source-complete
```

검사:

- `.claude`/`CLAUDE.md` 부재와 Codex agents/skills 수
- nested `AGENTS.md`
- 제품·개발 소스가 `src/` 안에만 존재
- 단일 KDBG/Probe IOCTL header
- CMake에 기재된 source 존재
- legacy 이름/스크립트 제거
- driver/backend/scanner/snapshot/PFN/UI implementation marker
- portable test executable 성공
- third-party revision/license/integration metadata

## 4. Windows build 검사

```powershell
.\src\tools\build.ps1 -Preset windows-debug
.\src\tools\build.ps1 -Preset windows-release
.\src\tools\build_drivers.ps1 -Configuration Release
.\src\tools\package_windows.ps1 -Configuration Release -Zip
python .\src\tools\validate_release.py `
  --windows-package .\out\package\KDBG-1.0.0-win-x64
```

검사:

- MSVC warnings-as-errors
- RC resource compile
- Dear ImGui/imgui_memory_editor/Zydis integration
- native bridge Win32 loader/process API
- WDK solution과 INF
- package 필수 파일
- SHA-256 manifest 재계산

현재 MSVC Debug/Release/`/analyze`와 WDK Debug/Release clean build는 PASS다. 위
package 명령으로 새 source-snapshot scope candidate를 만들었고, strict
validators, same-input ZIP, 5/5 negative fixtures가 PASS했다. 문서 반영 후 최종
SHA를 갱신한다. Package PASS alone은 physical/process write, Verifier 또는 v2 PASS를 뜻하지 않는다.

## 5. Driver ABI/보안 검사

- non-admin device open 실패
- second controller 정책
- ABI mismatch 거부
- malformed Size/input/output length
- transfer cap
- RAM 밖 physical read/write
- write gate off/on/off와 acknowledge magic
- process lookup/lifetime
- service repeated start/stop/unload
- 선택적 Driver Verifier는 disposable VM에서만 수행

Final Release 관측: device/main ABI 6, invalid IOCTL rejection, stop/remove는 PASS,
Driver Verifier는 `NOT_RUN`으로 BLOCKED다. Exact identity는
`out/evidence/final-live-manifest.json`과 `out/evidence/RELEASE-HASHES.txt`를 따른다.

## 6. Probe Live E2E

1. 기존 `Windows-VM` checkpoint, Administrator, test-signing 확인 기록을 사용하고 최종 패키지 SHA를 대조한다.
2. 두 driver를 install/start/open한다.
3. startup write gate가 LOCKED인지 확인한다.
4. Probe VA/PA/PFN/generation/CRC를 기록한다.
5. PFN을 exact 4096-byte read한다.
6. 작은 구간을 local edit하고 undo/redo를 한 번 시연한다.
7. diff와 PFN confirmation을 표시한다.
8. preflight → dirty-run write → full-page read-back PASS를 확인한다.
9. PFN independent reload와 Probe CRC 변화를 확인한다.
10. rollback 후 원본 CRC를 확인한다.
11. 종료 시 write gate가 LOCKED인지 확인한다.

Final Release에서는 steps 1–5의 deploy/hash/ABI/fresh Probe/exact 4096-byte
read-only와 stop/remove를 physical writes 0으로 PASS했다. Steps 6–10의 final
physical write/read-back/reload/rollback은 `NOT_RUN`으로 BLOCKED이며, 성공 증거는
interim DADF transaction에만 한정된다.

## 7. GUI 고도화 E2E

- process attach/detach와 region/module → Hex navigation
- process memory local edit/undo/redo/apply/rollback
- First/Next Scan, cancel, large result clipping
- address list save/load와 frozen-state disarm
- dedicated fixture process에서 verified edit/freeze
- pointer scan cancel/result
- Zydis disassembly
- snapshot baseline/current/save/load/diff
- PFN ownership bridge와 selected-process fallback
- Page Tables final PFN/PA가 대상 VA와 일치

Candidate `D3390AD4...`에서 write gate를 잠근 채 process attach, memory map,
First/Next Scan, Freeze OFF address entry, pointer scan, disassembly, snapshot,
selected-process PFN reverse map과 Page Tables exact PFN/PA match까지 PASS했다.
Dedicated process write/Freeze와 optional MemProcFS runtime은 각각 fixture 부재와
`vmm.dll` error 126으로 BLOCKED다.

## 8. 안정성 반복 목표

- Probe page read 100회
- Apply/verify/rollback 10회
- process attach/detach 50회
- worker start/cancel/reset 반복
- driver load/unload 10회
- crash, bugcheck, verification false positive 0회

문제가 생기면 Gate를 실패 상태로 유지하고 VM snapshot으로 복원한다.

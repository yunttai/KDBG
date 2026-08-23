# KDBG

KDBG는 Windows 10/11 x64 과제용 가상 머신에서 동작하는 GUI 기반 커널·메모리 연구 도구다. 핵심 기능은 PFN(Page Frame Number)을 입력해 해당 4 KiB 물리 페이지를 읽고, Hex Editor에서 로컬 편집한 뒤, 충돌 검사와 전체 페이지 read-back 검증을 거쳐 실제 물리 메모리에 반영하는 것이다.

과제 가산점과 분석 편의 기능을 위해 다음 기능도 하나의 프로그램에 통합했다.

- PFN → PID/프로세스/VA/PTE 분석
- PML5/PML4/PDPT/PD/PT 시각화와 VA → PA 변환
- 프로세스 메모리 First/Next Scan
- 주소 목록, 검증형 값 수정, Freeze, 저장/불러오기
- 물리·프로세스 Hex 편집 Undo/Redo와 전체 변경 취소
- 다단계 Pointer Scan
- Zydis 기반 x64 디스어셈블리
- 비동기 메모리 Snapshot, CRC32, 저장/불러오기, Diff

> 사용 범위는 본인이 관리하는 스냅샷 가능한 실습 VM이다. KDBG는 Code Integrity 우회, 취약 드라이버 로딩, 은닉, 안티치트 우회, 프로세스 주입, 임의 커널 가상주소 쓰기를 구현하지 않는다.

## 구현된 핵심 경로

### Physical Memory Editor

1. PFN을 10진수 또는 `0x` 16진수로 입력한다.
2. `PFN << 12` 계산에서 overflow와 실제 RAM 범위를 검사한다.
3. KDBG 드라이버가 정확히 4096바이트를 읽는다.
4. Hex/ASCII Grid는 baseline과 분리된 working copy만 수정한다.
5. dirty byte와 연속 diff run을 검토한다.
6. 동일 PFN을 다시 입력해 one-shot physical write를 해제한다.
7. Apply 직전에 전체 페이지를 재조회해 외부 변경을 탐지한다.
8. 변경 run만 기록한 후 write gate를 즉시 닫는다.
9. 전체 4096바이트를 다시 읽어 expected page와 전수 비교한다.
10. 성공 전 baseline을 보관해 검증형 rollback을 지원한다.

`KDbgProbe.sys`는 시연용으로 알려진 4 KiB contiguous page의 VA, PA, PFN, CRC32를 제공한다. 임의 시스템 페이지 대신 이 fixture를 사용한다.

### Cheat Engine 계열 분석 기능

- 데이터 형식: signed/unsigned 8·16·32·64비트, float, double, UTF-8, UTF-16, AOB wildcard
- 비교: Exact, Not Equal, Greater/Less, Between, Unknown Initial, Changed/Unchanged, Increased/Decreased, Increased By/Decreased By
- 메모리 영역: committed/readable, writable-only, executable 포함 여부, alignment, chunk/result limit
- 주소 목록: 수동 주소 추가, scanner 결과 추가, 값 갱신, write/read-back 검증, Freeze/read-back 검증, PID 바인딩 파일 저장/불러오기
- Pointer Scanner: 최대 depth/offset/result 제한, module-relative root 우선 표시
- Disassembler: Zydis long-mode decoder와 Intel formatter
- Snapshot: cancellable worker, 최대 512 MiB UI 제한, CRC32, `.kdbgmem`, contiguous changed-run Diff

KDBG의 고도화 범위는 메모리 관찰·검색·검증형 수정이다. debugger breakpoint, code injection, anti-debug 우회, driver exploit 기능은 범위 밖이다.

## Codex 전용 구성

```text
.codex/
├── config.toml
└── agents/
    ├── kdbg-supervisor.toml
    ├── kernel-driver.toml
    ├── memory-core.toml
    ├── gui.toml
    ├── pfn-analysis.toml
    ├── qa-safety.toml
    └── release-evidence.toml

.agents/skills/
├── kdbg-orchestrate/
├── project-audit/
├── implement-live-backend/
├── implement-page-session/
├── implement-hex-ui/
├── implement-memory-scan/
├── implement-pfn-usage/
├── implement-page-table-view/
├── verify-live-write/
└── prepare-release-evidence/
```

루트 및 하위 `AGENTS.md`는 디렉터리별 작업 규칙을 제공한다. 장기 계획과 검증 상태는 `docs/exec-plans/`에서 관리한다.

## 저장소 구조

```text
KDBG/
├── AGENTS.md
├── .codex/                    # Codex project agents/config
├── .agents/skills/            # repository skills
├── docs/                      # PRD, architecture, tests, evidence, exec plans
└── src/                       # 실제 제품·테스트·도구 전체
    ├── app/                   # Win32 + DirectX 11 + Dear ImGui
    ├── core/                  # memory transaction/scanner/paging/PFN/snapshot
    ├── driver/                # KDbgDriver + KDbgProbe WDK projects
    ├── plugins/               # isolated MemProcFS bridge
    ├── shared/                # user/kernel ABI
    ├── tests/                 # deterministic portable tests
    ├── fixtures/
    ├── config/                # package/operator reference settings
    ├── cmake/
    └── tools/
```

## Portable core 검증

저장소 루트에서:

```powershell
python .\src\tools\verify_layout.py
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

Portable suite는 PFN/ABI 계산, x64/LA57 page walk, 4 KiB physical transaction, process identity/transaction, scanner/AOB, load-disarmed Freeze, bounded pointer path, snapshot, MemProcFS protocol과 PFN reverse mapping을 검사한다. 2026-08-23 최종 실행은 707 checks, 0 failures였고 Clang Debug/Release, ASan/UBSan, clang-tidy, MSVC `/analyze`도 통과했다. 실제 MSVC GUI/bridge와 WDK Debug/Release 바이너리 결과는 `docs/VALIDATION_REPORT.md`에 기록한다.

## Windows 빌드

필수 환경:

- Visual Studio 2022 C++ Desktop workload
- Windows 10/11 SDK
- Windows Driver Kit
- CMake 3.25 이상, Ninja, Git

```powershell
# GUI + native MemProcFS bridge + portable tests
.\src\tools\build.ps1 -Preset windows-debug -Fresh
.\src\tools\build.ps1 -Preset windows-release -Fresh

# 두 WDK 드라이버
.\src\tools\build_drivers.ps1 -Configuration Debug -Clean
.\src\tools\build_drivers.ps1 -Configuration Release -Clean

# Release-only 패키지, symbols, SPDX, SHA-256, deterministic ZIP
.\src\tools\package_windows.ps1 -Configuration Release -Zip
```

VM에서 서비스 관리:

```powershell
.\src\tools\manage_drivers.ps1 -Action Install -ConfirmDedicatedVm -ConfirmSnapshot
.\src\tools\manage_drivers.ps1 -Action Start   -ConfirmDedicatedVm -ConfirmSnapshot
.\src\tools\run.ps1 -NoBuild -ConfirmDisposableVm -ConfirmSnapshot
```

드라이버 서명 우회는 포함하지 않는다. 테스트 서명 모드 또는 적절한 정식 인증서가 필요하다. `.github/workflows/validate.yml`의 Windows job은 user-mode GUI/bridge와 deterministic tests를 MSVC로 빌드하도록 구성되어 있으며, WDK sign/load와 live physical write는 disposable VM gate로 분리한다.

## 검증 Gate

| Gate | 의미 | 현재 이 산출물에서 확인된 상태 |
|---|---|---|
| Source-complete | 기능 소스, Codex 구성, portable tests, 문서 정합성 | PASS |
| Windows-source-audited | `_WIN32`/WDK API-surface 정적 컴파일 | PASS |
| Windows-build-verified | GUI, native bridge, 두 WDK 프로젝트를 Windows에서 실제 빌드 | PASS — MSVC Debug/Release/`/analyze`, WDK Debug/Release |
| VM prerequisites | 기존 `Windows-VM` checkpoint, Administrator, test-signing 확인 | PASS |
| Final Release package | `kdbg.source-snapshot.v1`, main/symbol validators, 동일 입력 ZIP 재현성, 5/5 negative fixtures | PASS — exact identity는 외부 release manifest 참조 |
| Interim physical transaction | ABI 6, Probe Read/Edit/Write/Read-back/Reload/Rollback, 종료 gate lock | PASS — ZIP `DADF43AA...`, final package 증거 아님 |
| Candidate advanced read-only | ZIP `D3390AD4...`, Probe query, process scan, built-in PFN reverse map, VA→PA, pointer/disassembly/snapshot | PASS — write/freeze 미실행 |
| Final Release read-only/lifecycle Live VM | exact deploy/hash binding, device/main ABI 6, fresh Probe query, 4 KiB read, invalid IOCTL rejection, stop/remove | PASS — physical writes 0 |
| Optional MemProcFS runtime | 격리 bridge의 실제 `vmm.dll` 로드 | BLOCKED — Win32 error 126 |
| Final write-sensitive/v2 | physical write, process write/Freeze, Driver Verifier, hash-bound v2 | BLOCKED — final physical write `NOT_RUN` |

정확한 package identity는 `out/evidence/final-live-manifest.json`과
`out/evidence/RELEASE-HASHES.txt`가 authoritative binding이다. 상태와 명령은
`docs/IMPLEMENTATION_STATUS.md`, `docs/VALIDATION_REPORT.md`,
`docs/exec-plans/STATUS.md`에 기록한다.

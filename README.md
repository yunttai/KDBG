# KDBG

KDBG는 Windows 10 build 19041+/Windows 11 x64에서 동작하는 고성능 커널 메모리 디버깅·편집 워크벤치다. PFN(Page Frame Number), 프로세스 VA, PTE와 페이지 테이블을 한 작업공간에서 연결하고, 4 KiB 물리 페이지를 읽어 Hex Editor에서 편집한 뒤 충돌 검사, 전체 페이지 read-back과 rollback까지 하나의 트랜잭션으로 처리한다.

커널 메모리의 탐색, 귀속 분석, 편집과 재현 가능한 증거 수집을 위해 다음 기능을 하나의 프로그램에 통합했다.

- PFN → PID/프로세스/VA/PTE 분석
- PML5/PML4/PDPT/PD/PT 시각화와 VA → PA 변환
- 프로세스 메모리 First/Next Scan
- 주소 목록, 검증형 값 수정, Freeze, 저장/불러오기
- 물리·프로세스 Hex 편집 Undo/Redo와 전체 변경 취소
- 다단계 Pointer Scan
- Zydis 기반 x64 디스어셈블리
- 비동기 메모리 Snapshot, CRC32, 저장/불러오기, Diff
- 관리자 권한 `KDBGSetup.exe`의 Install/Repair/Update/Uninstall, Program Files
  트랜잭션과 Windows 앱 제거 등록
- opt-in 로컬 runtime JSON의 scan region/byte/I/O/cancellation 및 GUI frame-stall 계측

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

### 고속 메모리 분석 기능

- 데이터 형식: signed/unsigned 8·16·32·64비트, float, double, UTF-8, UTF-16, AOB wildcard
- 비교: Exact, Not Equal, Greater/Less, Between, Unknown Initial, Changed/Unchanged, Increased/Decreased, Increased By/Decreased By
- 메모리 영역: committed/readable, writable-only, executable 포함 여부, alignment, chunk/result limit
- 주소 목록: 수동 주소 추가, scanner 결과 추가, 값 갱신, write/read-back 검증, Freeze/read-back 검증, PID 바인딩 파일 저장/불러오기
- Pointer Scanner: 최대 depth/offset/result 제한, module-relative root 우선 표시
- Disassembler: Zydis long-mode decoder와 Intel formatter
- Snapshot: cancellable worker, 최대 512 MiB UI 제한, CRC32, `.kdbgmem`, contiguous changed-run Diff

현재 구현은 메모리 관찰·검색·귀속 분석·검증형 수정에 집중한다. 커널 모듈/로컬 심볼/디스어셈블리 계층을 확장 중이며, breakpoint·register·single-step 실행 제어가 구현되기 전에는 이를 완전한 execution debugger로 표시하지 않는다. Code injection, anti-debug 우회와 driver exploit은 제품 범위가 아니다.

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

Portable suite는 PFN/ABI 계산, x64/LA57 page walk, 4 KiB physical transaction, process identity/transaction, scanner/AOB, load-disarmed Freeze, bounded pointer path, snapshot, MemProcFS protocol, PFN reverse mapping, Kernel Explorer 입력 계약과 runtime telemetry를 검사한다. 2026-09-17 현재 실행은 `1771 checks, 0 failures`이며 GNU core와 MSVC Debug/Release/`/analyze` CTest는 각각 7/7 통과했다. 현재 MinGW 배포에는 sanitizer runtime이 없어 sanitizer gate는 통과로 주장하지 않는다. 두 WDK 드라이버는 hash-locked NuGet WDK offline fallback으로 Debug/Release 빌드와 Inf2Cat signability 검사를 통과했다. 실제 결과와 과거 기록의 경계는 `docs/VALIDATION_REPORT.md`에 기록한다.

## Windows 빌드

필수 환경:

- Visual Studio 2022 C++ Desktop workload
- Windows 10/11 SDK
- Windows Driver Kit 또는 repository가 고정한 NuGet WDK offline cache
- CMake 3.25 이상, Ninja, Git

배포되는 user-mode 실행 파일은 MSVC 런타임을 정적 링크하므로 대상 VM에
별도의 Visual C++ Redistributable 설치가 필요하지 않다.

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

현재 저장소 버전은 **1.1.0**이다. 각 Windows/VM 판정은 이름이 명시된 candidate의
package/source/evidence hash에만 결속된다. 최신 exact identity와 판정은
`docs/exec-plans/STATUS.md`와 `docs/VALIDATION_REPORT.md`에 기록하며, 소스 또는
패키지가 바뀌면 새 epoch로 다시 생성한다. VM test trust는 production trust가 아니다.

| Gate | 의미 | 현재 이 산출물에서 확인된 상태 |
|---|---|---|
| Source-complete | 기능 소스, Codex 구성, portable tests, 문서 정합성 | PASS |
| Windows user-mode analyzed | `_WIN32` GUI/backend/bridge/tests MSVC `/analyze` | PASS |
| MSVC user-mode | GUI, native bridge와 tests를 Windows에서 실제 빌드 | PASS — 1.1.0 clean Release build와 CTest 완료; exact build ID는 candidate 문서에 기록 |
| Windows-build-verified | MSVC 산출물과 WDK package inputs를 같은 candidate에서 실제 빌드 | PASS — 1.1.0 main/symbol package validator와 WDK build 완료 |
| Release package | main/symbol package, hashes, SBOM, setup/lifecycle tools와 원자적 publish | PASS (unsigned engineering candidate) — exact ZIP/source identities는 epoch-local sidecar에 기록 |
| Commercial operations docs | security/support/privacy/license/update/vulnerability/release notes | PASS (configured contract) — support/security routes configured; notification/acknowledgement evidence pending |
| Live device/runtime | exact package install, ABI 6, Probe physical transaction, cleanup | PASS (disposable VM test trust) — 1.1.0 exact test-signed package의 apply/read-back/reload/rollback/cleanup 완료 |
| Live VM evidence | PFN discovery/read/edit/diff/unlock/apply/read-back, ownership/PTView, MP4 | CANDIDATE-BOUND — automated capture와 presentation media는 각각의 formal review 상태와 분리해 기록 |
| Windows 11 readiness/live | static workspace, readiness, required-core, extended lifecycle/soak | PASS — 1.1.0 exact-package required-core, repeated lifecycle/reboot와 30-minute soak 완료 |
| Commercial release | production trust, operational acknowledgement, supported-platform validation | BLOCKED — production signer/TSA/returned signed drivers와 route notification/ack evidence가 없음. VM 전용 test trust는 production trust를 대체하지 않음 |
| Optional MemProcFS runtime | 격리 bridge의 실제 `vmm.dll`/acquisition backend | UNVERIFIED — helper-process 회귀만 PASS |

과거 1.0.0 candidate의 상세 결과는 `docs/VALIDATION_REPORT.md`의
`ARCHIVED / HISTORICAL` 절에 보존한다. 현재 상태와 재현 명령은
`docs/IMPLEMENTATION_STATUS.md`, `docs/VALIDATION_REPORT.md`,
`docs/exec-plans/STATUS.md`에 기록한다.

현재 release target은 `1.1.0`이다. Main/symbol ZIP SHA-256과 source identity는
각 epoch-local sidecar와 packaged `BUILD-METADATA.json`에서 확인한다. 과거
1.0.0 candidate와 그 live evidence는 역사 증거이며 1.1.0에 재결속하지 않는다.

DEF CON 제안서 초안, 발표 구조, 라이브 데모 복구 경로와 현재 증거 경계는
[`docs/DEFCON_SUBMISSION.md`](docs/DEFCON_SUBMISSION.md)에 정리되어 있다.

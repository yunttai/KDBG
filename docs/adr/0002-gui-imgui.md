# ADR-0002: Dear ImGui + Win32 + DirectX 11을 사용

- 상태: Accepted
- 날짜: 2026-08-15
- bilingual UI amendment: 2026-09-19

## Context

Hex grid, diff, dockable inspector, page-table cards를 짧은 기간에 구현해야 한다.

## Decision

C++20 코어와 같은 프로세스에서 Dear ImGui Win32/DX11 backend를 사용하고,
`imgui_memory_editor`를 local page buffer 위에 연결한다.

단일 `KDBG.exe`에 English/한국어 catalog를 compile-in하고 English를
기본으로 한다. 항상 보이는 상위 `Language / 언어` menu에서 런타임 언어를 선택하며 표시
label은 번역하되 ImGui identity는 안정적인 `###` suffix로 유지한다.
PFN/PTE/ABI 같은 기술 용어와 미등록 진단은 정확성을 위해 English를
유지할 수 있다.

Windows system font에서 Korean glyph coverage를 찾고, 사용 가능한 font가
없으면 기본 ImGui font와 English UI로 fail closed한다. 언어 선택은
기존 ImGui INI의 `[KDBG][Preferences]` section에 저장한다.

## Consequences

### Positive

- single executable with runtime English/한국어 selection
- external language-pack/runtime dependency 없음
- 빠른 custom tooling UI
- docking/table/modal 구현 용이
- single-header memory editor 사용 가능

### Negative

- native accessibility와 standard control behavior는 직접 보강
- dependency pin 필요
- retained-mode GUI보다 state 관리 주의
- system Korean font 유무와 glyph coverage를 런타임에서 확인해야 함
- translated visible label과 stable ImGui ID를 분리해 유지해야 함

## Key constraint

memory editor `WriteFn`은 backend Write를 호출하지 않는다.
언어 selector, catalog lookup, font fallback 및 INI persistence는 memory session,
write gate, confirmation, dirty/history, target, worker 또는 backend connection 상태를
변경하지 않는다. MSVC build는 `/utf-8`을 사용하고 localization
catalog/ID/fallback/persistence는 결정적 test로 유지한다.

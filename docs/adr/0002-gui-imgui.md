# ADR-0002: Dear ImGui + Win32 + DirectX 11을 사용

- 상태: Accepted
- 날짜: 2026-08-15

## Context

Hex grid, diff, dockable inspector, page-table cards를 짧은 기간에 구현해야 한다.

## Decision

C++20 코어와 같은 프로세스에서 Dear ImGui Win32/DX11 backend를 사용하고,
`imgui_memory_editor`를 local page buffer 위에 연결한다.

## Consequences

### Positive

- single-language
- 빠른 custom tooling UI
- docking/table/modal 구현 용이
- single-header memory editor 사용 가능

### Negative

- native accessibility와 standard control behavior는 직접 보강
- dependency pin 필요
- retained-mode GUI보다 state 관리 주의

## Key constraint

memory editor `WriteFn`은 backend Write를 호출하지 않는다.

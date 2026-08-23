# ADR-0005: 모든 제품 개발 파일은 src/ 아래에 배치

- 상태: Accepted
- 날짜: 2026-08-15

## Context

사용자는 Codex 운영 문서와 실제 제품 구현물을 명확히 분리하고, 모든 제품·테스트·개발 도구 소스코드를 `src/` 하위에 두도록 요구했다.

## Decision

다음은 전부 `src/` 아래에 둔다.

- C/C++ source/header
- driver source/project
- GUI resources
- tests
- fixtures
- build/run/validation scripts
- IPC schema
- dependency CMake code

루트에는 문서·agent/skill 정의·dependency lock만 둔다.

## Enforcement

- `src/tools/verify_layout.py`
- CI workflow
- agent completion checklist

# ADR-0003: PFN 소유자 분석을 provider로 분리

- 상태: Accepted
- 날짜: 2026-08-15

## Context

PFN→PID/VA 분석은 PFN database 파싱이 가장 빠르지만 MemProcFS는 AGPLv3이며 별도 acquisition backend를 사용할 수 있다.

## Decision

`IPfnUsageProvider` 인터페이스를 두고 두 구현을 제공한다.

1. MemProcFS out-of-process bridge
2. selected-process page-table reverse mapper

필수 Read/Edit/Write는 provider와 무관하게 동작한다.

## Consequences

- MemProcFS 부재가 핵심 기능을 막지 않음
- license boundary 명확
- deterministic fixture process로 가산점 검증 가능
- 전체 시스템 PFN reverse mapping은 느려서 MVP 범위 제한

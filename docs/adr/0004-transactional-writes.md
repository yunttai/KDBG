# ADR-0004: 물리 Write를 트랜잭션으로 처리

- 상태: Accepted
- 날짜: 2026-08-15

## Context

Hex editor의 즉시 byte Write는 잘못된 중간값, 경쟁 상태, 부분 Write, 오조작 위험이 높다.

## Decision

편집은 baseline과 분리된 working copy에만 적용한다.

실제 Write는:

1. unlock
2. range check
3. preflight re-read
4. conflict check
5. one ABI 7 exact 4 KiB compare/write transaction using expected baseline and desired page
6. read-back
7. byte verification
8. baseline commit 또는 rollback

순서로만 수행한다.

Dirty bitmap/run은 local review와 evidence에만 사용한다. `dirty_bytes`는 local
edit 수이고 physical driver transfer는 성공 시 항상
`driver_transferred_bytes=4096`이다.

## Consequences

- UI 응답성과 안전성 향상
- 외부 변경 검출
- read-back 증거 확보
- 구현 상태 머신이 복잡해짐
- 완전한 원자성은 보장하지 않으므로 rollback도 best-effort

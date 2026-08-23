# Probe Fixture Driver/Process Design

## 목적

임의 시스템 페이지 대신 알려진 4 KiB buffer를 물리 메모리 편집의 대상으로 사용한다.

## Driver 동작

- page-aligned nonpaged contiguous allocation
- 4096바이트 deterministic pattern
- physical address/PFN query
- buffer hash/selected bytes query
- reset pattern
- unload 전 allocation 해제

## User fixture process

선택 사항:

- driver section 또는 locked user page를 mapping
- PID와 VA 출력
- PFN query와 page-table reverse mapping ground truth 제공

## IOCTL

- QueryFixture
- ReadFixtureMetadata
- ResetFixture
- VerifyFixture

직접 물리 Write IOCTL은 fixture에 추가하지 않는다. 실제 write는 KDBG backend를 통해 수행한다.

## Metadata

```text
nonce
kernel/user VA
physical address
PFN
size
pattern version
hash
owner PID
```

nonce와 PFN을 write policy allowlist에 묶는다.

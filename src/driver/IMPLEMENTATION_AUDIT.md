# KDBG driver implementation audit

기준 참고: `kernullist/kn-live-dbg` pinned revision `8f792132f303a835975e0afcc3dbdbe168b7a040`.

## 구현 확인

- [x] authoritative shared ABI headers
- [x] ABI version/size validation
- [x] Administrators/SYSTEM secure device creation
- [x] mutex-protected single controller ownership
- [x] per-handle default-locked write gate
- [x] transfer maximum and arithmetic overflow checks
- [x] physical range enumeration and membership validation
- [x] physical reads through supported memory-copy primitive
- [x] RAM-only bounded physical writes through `PAGE_READWRITE` temporary mappings with direct-map fallback
- [x] process context and DTB resolution
- [x] process virtual read/write with lifetime reference and `MmHighestUserAddress` boundary
- [x] 4-level/5-level VA translation and large pages
- [x] 1 GiB/2 MiB large-page reserved address bits rejected before PA synthesis
- [x] exact completed byte reporting
- [x] deterministic Probe driver
- [x] no arbitrary kernel-virtual write operation

## 제외된 기능

DbgEng/TUI, AI/MCP, hunting subsystems, PPL changes, BYOVD, signing bypass, cloak/randomization, callback modification, dump tooling, anti-cheat features는 KDBG driver에 포함하지 않는다.

## 플랫폼 검증 상태

현재 소스는 pinned offline NuGet WDK Release clean build, `/W4 /WX`, Inf2Cat,
driver contract 및 동일 입력 2회 SYS hash 재현성을 통과했다. 다만 source audit과
unsigned build는 최종 후보의 test/production signing, Driver Verifier, repeated
load/unload, Probe live write를 대체하지 않는다. 특히 driver 소스가 바뀌면 이전
signed SYS hash와 live report는 새 후보 증거가 아니다. 최종 상태는
`docs/exec-plans/active/windows-live-validation.md`에서 새 package hash에 바인딩해
별도로 기록한다.

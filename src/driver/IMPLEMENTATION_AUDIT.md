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
- [x] exact completed byte reporting
- [x] deterministic Probe driver
- [x] no arbitrary kernel-virtual write operation

## 제외된 기능

DbgEng/TUI, AI/MCP, hunting subsystems, PPL changes, BYOVD, signing bypass, cloak/randomization, callback modification, dump tooling, anti-cheat features는 KDBG driver에 포함하지 않는다.

## 플랫폼 검증 미실행

이 source audit은 Windows WDK build, Driver Verifier, repeated load/unload, Probe live write를 대체하지 않는다. 해당 결과는 `docs/exec-plans/active/windows-live-validation.md`에서 별도로 기록한다.

# Completed plan — KDBG source implementation

이 문서는 초기 source-implementation 단계의 완료 기록이다. 현재 Windows/WDK/package
검증 결과는 `docs/VALIDATION_REPORT.md`가 authoritative하다.

## 결과

- 제품명, C++ namespace, executable, device, service, driver, and resource identifiers를 KDBG로 통일했다.
- Codex project agents, repository skills, root/nested instructions, and execution plans를 구성했다.
- 관리자 전용 WDM driver, deterministic probe fixture, SCM client, IOCTL backend를 구현했다.
- PFN physical editor의 exact read, preflight, one-shot write gate, dirty-run write, full read-back, Undo/Redo, and rollback을 구현했다.
- process memory browser, First/Next Scan, persistent address list, verified Freeze, pointer scan, disassembly, and snapshot diff를 구현했다.
- MemProcFS PFN metadata를 native out-of-process bridge로 격리했다.
- selected-process page-table reverse walk and VA-to-PA visualization을 구현했다.
- portable deterministic suite, source/package/live validators, and Windows build/service scripts를 구성했다.

## 검증

```text
GNU Debug configure/build/CTest: PASS
Clang Release configure/build/CTest: PASS
ASan/UBSan: PASS
kdbg_core_tests at plan close: PASS (final release suite: 707 checks, 0 failures)
Win32 source-surface audit: PASS
WDK source-surface audit: PASS
Codex layout/source validator: PASS
```

검증 중 Windows 전용 오류 두 건을 수정했다.

- `const Result`에서 `TakeValue()`를 호출하던 이동 오류
- ImGui Win32 WndProc handler의 익명 네임스페이스 linkage 오류

Actual MSVC/WDK binary build, signing, load, and live physical write remain independent Windows VM gates.

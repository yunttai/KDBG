---
name: project-audit
description: Audit the KDBG repository for stale names, duplicate ABI files, stubs, broken source/build references, license drift, missing tests, and false completion claims. Use before a release or after a major rename.
---

# Project audit

Run from the repository root:

```powershell
python .\src\tools\verify_layout.py
python .\src\tools\validate_release.py --source-complete
```

Then:

1. Search for `PME`, `physical-memory-editor`, `.claude`, `CLAUDE.md`, `TODO`, `stub`, obsolete IOCTL names, duplicate driver sources, and generated build output committed into the tree.
2. Compare `src/shared/KDbgIoctl.h` against `KDbgDriver/Driver.cpp` and `KDbgBackend.cpp` field by field.
3. Compare CMake sources with actual files and check every GUI header/call signature.
4. Verify pinned third-party revisions and attribution.
5. Run core configure, build, and tests. On Windows also build GUI, bridge, and WDK projects.
6. Write findings with file/symbol evidence and distinguish blockers from optional improvements.

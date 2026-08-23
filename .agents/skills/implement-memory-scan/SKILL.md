---
name: implement-memory-scan
description: Implement or improve Cheat Engine-style KDBG process memory scanning, next-scan filters, address list, verified edits, freeze, pointer scanning, memory regions, snapshots, or disassembly.
---

# Memory scanning workflow

1. Use `IProcessMemory` so Win32 direct access and KDBG fallback share scanner logic.
2. Enumerate committed readable regions and apply private/image/mapped, writable, executable, guard, alignment, chunk, and result filters.
3. Support integer signed/unsigned widths, float/double, UTF-8/UTF-16, AOB wildcards, exact/range comparisons, unknown initial value, changed/unchanged, increased/decreased, and delta comparisons.
4. Keep first/next scan state explicit; next scans must retain type and width.
5. Run scans in stoppable workers, publish bounded progress, and virtualize result tables.
6. Address-list writes require explicit process write arming and read-back verification. Freeze failures remain visible per entry.
7. Pointer scans are bounded by depth, offset, regions, and result count and prefer module-relative roots.
8. Add deterministic mock tests for every comparison family, AOB masks, cancellation, limits, watch writes/freeze, and pointer paths.

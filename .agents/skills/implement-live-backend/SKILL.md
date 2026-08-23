---
name: implement-live-backend
description: Implement or repair KDBG live Windows memory access: shared IOCTL ABI, KDbgDriver, KDbgBackend, process context, physical ranges/read/write, process virtual access, and VA-to-PA translation. Use only for authorized test-VM development.
---

# Live backend workflow

1. Read `src/driver/AGENTS.md`, `src/shared/KDbgIoctl.h`, `src/driver/KDbgDriver/Driver.cpp`, and `src/core/memory/KDbgBackend.*`.
2. Make ABI changes once in the shared header; bump the ABI for incompatible layouts.
3. Validate all user-controlled sizes, addresses, overflow, physical ranges, PID ownership, and access state in the driver.
4. Preserve administrator-only ACL, single-controller ownership, per-handle write gate, acknowledgement magic, maximum transfer size, and no arbitrary kernel-virtual write operation.
5. Mirror request/response serialization in KDbgBackend and verify returned `Size`, ABI, byte count, status, and translation-step count.
6. Add portable source checks and Windows integration cases. Build `KDbgDriver.vcxproj`, `KDbgProbe.vcxproj`, the Windows CMake preset, and run the probe demonstration on a disposable snapshot VM.
7. Record exact commands, hashes, OS build, test-signing state, and read-back evidence.

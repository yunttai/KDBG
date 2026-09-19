---
name: implement-live-backend
description: Implement or repair KDBG live Windows memory access for the local bare-metal runtime host, with a separate VM regression lane: shared IOCTL ABI, KDbgDriver, KDbgBackend, physical ranges/read/write, process context, and VA-to-PA translation.
---

# Live backend workflow

1. Read `src/driver/AGENTS.md`, `src/shared/KDbgIoctl.h`, `src/driver/KDbgDriver/Driver.cpp`, and `src/core/memory/KDbgBackend.*`.
2. Bind the target explicitly: `runtime_host` is the bare-metal Windows instance running the driver and exposing the local physical RAM; `orchestrator_host` is control/evidence only; `regression_guest` is regression only.
3. Make ABI changes once in the shared header; bump the ABI for incompatible layouts.
4. Validate all user-controlled sizes, addresses, overflow, local physical ranges, PID ownership, and access state in the driver.
5. Preserve administrator-only ACL, single-controller ownership, per-handle write gate, acknowledgement magic, maximum transfer size, and no arbitrary kernel-virtual write operation.
6. Mirror request/response serialization in KDbgBackend and verify returned `Size`, ABI, byte count, status, and translation-step count.
7. Add portable source checks and Windows integration cases. Build `KDbgDriver.vcxproj`, `KDbgProbe.vcxproj`, and the Windows CMake preset. Run the existing Probe demonstration in the snapshot regression guest, then run the separate bare-metal runtime-host read-only and Probe-write evidence gates when their harness exists.
8. Record exact commands, hashes, target role, OS build, test-signing state, and read-back evidence. Capture machine/boot/session values automatically as optional provenance or stale-backend-session diagnostics when available; never require manual confirmation or block normal LocalHost RawPfn access because they are absent. Never promote regression-guest evidence to a runtime-host gate.

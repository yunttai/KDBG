---
name: implement-hex-ui
description: Build or refine the KDBG Dear ImGui physical-memory editor and write review UX using imgui_memory_editor. Use for PFN input, hex/ASCII editing, dirty highlighting, diff review, and safe apply controls.
---

# Hex UI workflow

1. Bind the memory editor to `PhysicalPageSession::Working()` only.
2. Highlight modified bytes and surface baseline/current values and physical addresses.
3. Show PFN, PA range, 4 KiB page size, session revision, dirty count, write-gate state, conflict/mismatch status, and errors.
4. Provide revert, reload, export, typed-PFN unlock, apply/read-back, and rollback actions. Disable invalid actions.
5. Keep long operations out of the render loop and never retain pointers into resized vectors.
6. Show the explicit target kind (`RawPfn`, `ProbeFixture`, or `ProcessMapping`). Automatically captured runtime-host boot/session data may be shown as provenance or stale-backend-session diagnostics, but must not be a manual confirmation or product gate. `RawPfn` is the unrestricted first-class LocalHost physical-memory path; `ProbeFixture` is only the default destructive evidence target.
7. Validate with deterministic `MockMemoryBackend` tests first, then preserve the KDbgProbe snapshot-VM regression lane and collect separate bare-metal runtime-host evidence. Never promote VM evidence to a host gate.

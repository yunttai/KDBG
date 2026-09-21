# GUI instructions

- Keep the render thread responsive; long scans use stoppable workers.
- Use clipped/virtualized tables for large result sets.
- Display concrete memory space, PID/PFN/address, size, permissions, write-gate
  state, and errors.
- Display whether a physical target is `RawPfn`, `ProbeFixture`, or
  `ProcessMapping`. Automatically captured machine/boot/session data may be
  shown as evidence provenance or stale-backend-session diagnostics, but must
  never gate normal LocalHost RawPfn read/write or require manual confirmation.
- Never write from a hex-cell callback. Stage edits and require review plus
  typed confirmation.
- Make Mock, disconnected, source-only, and live-verified states visibly
  distinct.

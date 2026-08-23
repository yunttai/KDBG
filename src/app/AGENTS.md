# GUI instructions

- Keep the render thread responsive; long scans use stoppable workers.
- Use clipped/virtualized tables for large result sets.
- Display concrete memory space, PID/PFN/address, size, permissions, write-gate
  state, and errors.
- Never write from a hex-cell callback. Stage edits and require review plus
  typed confirmation.
- Make Mock, disconnected, source-only, and live-verified states visibly
  distinct.

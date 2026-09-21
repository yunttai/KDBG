# Test instructions

- Tests are deterministic and must not require Administrator, a driver, or a
  network connection unless clearly placed in a separate Windows integration
  suite.
- Cover success, boundary, short read/write, stale baseline, ignored write,
  cancellation, overflow, result limits, and write-gate cleanup.
- Keep the core suite fast enough to run after every source change.
- Report VM `regression_guest` and bare-metal `runtime_host` integration results
  as separate gates; fixture, package, or evidence identity cannot be rebound.

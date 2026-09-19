# Core instructions

- Core code must be deterministic and testable with Mock backends.
- Address-space kind and PID must be explicit; never infer physical vs virtual
  from an integer address.
- Keep `RawPfn`, `ProbeFixture`, and `ProcessMapping` target kinds distinct.
  Physical backends operate on the local RAM exposed by the current
  `runtime_host`; never infer an orchestrator or regression-guest target.
- Scans must be cancellable, bounded by result and chunk limits, and tolerant
  of inaccessible regions without treating short reads as matches.
- Write helpers must close gates on every normal error path and verify exact
  read-back data.
- Add regression coverage in `src/tests` before declaring a defect fixed.

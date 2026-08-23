# KDBG deterministic mock benchmarks

This executable exercises only in-memory mock backends. It never opens a KDBG
device, loads a driver, or writes live physical/process memory. Its stdout is a
single JSON document suitable for release evidence or regression comparison.

Standalone build from the repository root:

```powershell
cmake -S .\src\benchmarks -B .\out\benchmarks -DCMAKE_BUILD_TYPE=Release
cmake --build .\out\benchmarks --config Release --parallel
.\out\benchmarks\Release\kdbg_benchmarks.exe
```

For a single-config generator, the executable is normally
`out/benchmarks/kdbg_benchmarks`. A non-zero exit code means at least one
correctness/cap/cancellation gate failed. Timing values are observations of the
current machine, not hard-coded performance thresholds.

Measured gates:

- 4 KiB physical-page load/edit/one-shot apply/full read-back latency;
- first-scan throughput, result storage estimate, and observed peak RSS where
  the operating system exposes it;
- Next Scan latency;
- pointer-scan result-cap enforcement;
- snapshot capture/save/load throughput and checksum/size verification;
- worker cancellation request-to-completion latency.


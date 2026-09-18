# KDBG deterministic mock benchmarks

This executable exercises only in-memory mock backends. It never opens a KDBG
device, loads a driver, or writes live physical/process memory. Its timings are
microbenchmark observations of core algorithms and allocator/file-system cost;
they are not measurements of driver, IOCTL, target-process, or live-VM runtime
performance. The JSON states this explicitly with
`timing_represents_product_runtime: false`.

Scanner, pointer, snapshot, and cancellation workloads get one untallied
warm-up followed by seven measured repeats; the physical transaction metric
uses its stated iteration count. The report includes median and p95 latency
plus MiB/s or candidates/s where applicable. Correctness, bounds, integrity,
and cancellation determine `pass`; there is deliberately no absolute timing
threshold.

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
- sparse Next Scan latency and dense-candidate Next Scan batching/read count;
- pointer-scan result-cap enforcement;
- snapshot capture/save/load throughput and checksum/size verification;
- worker cancellation request-to-completion latency.

## Same-machine regression comparison

Only compare two JSON reports when they were produced on the same machine with
the same power mode, compiler, build configuration, fixture sizes, and no
competing workload. Preserve both reports and compare median and p95 fields;
throughput regressions move downward while latency regressions move upward.
Changing any fixture or repeat policy starts a new baseline. The JSON embeds
this contract under `measurement_contract` and records build/compiler/pointer
width/fixture metadata under `environment_contract`, so automation can reject
reports that do not share a compatible methodology.

Mock results can identify algorithmic regressions before a VM run, but they
cannot substantiate product-runtime claims. Driver/IOCTL and live target-memory
throughput must be measured separately inside the assignment VM.


# KDBG live verification CLI

This standalone target connects only to already-running `KDbgDriver` and
`KDbgProbe` devices. It does not install, start, stop, or remove drivers.
Read-only verification is the default.

Configure and test without accessing live devices:

```powershell
cmake -S src/tools/live_verify -B out/build/live-verify -G Ninja
cmake --build out/build/live-verify --parallel
ctest --test-dir out/build/live-verify --output-on-failure
```

The `kdbg_live_verify` executable is emitted only on Windows. Write mode is
restricted to a disposable snapshot VM and the PFN returned by `KDbgProbe`.
It requires all of `--write`, `--confirm-disposable-vm`, `--snapshot-id`, and
`--confirm-probe-pfn`. The operator must restore the named snapshot after the
run. Never use write mode on a host or an unknown PFN.

The executable requires Windows x64 build 19041 or newer. Before opening either
device it hashes itself and the two binaries configured in SCM, requires the
exact package layout, and verifies that both services are running kernel
drivers. Reports contain package-relative paths and hashes only. Final evidence
cross-checks those runtime hashes against the validated package manifest.
The default report is a unique JSON under `%LOCALAPPDATA%\KDBG\evidence`; an explicit output
inside the validated package directory is rejected before device access so
runtime evidence cannot invalidate `SHA256SUMS.txt`.

The main KDBG build emits this target as `kdbg_live_verify.exe`, runs its mock
transaction tests through CTest, and places the executable plus PDB in the
validated Windows package/symbol pair. The standalone build above remains a
fast way to validate the harness without building the GUI.

The write report binds the fixed eight-byte Probe edit at offset `0x100`, all
full-page comparisons, exact operation byte counts, Probe CRC transitions,
driver write counters, rollback, and the final locked gate. Final v4 evidence
additionally binds that report to the six raw 4 KiB pages and exact main/symbol
package manifests.

Validate a completed machine report without claiming the separate video and
conference-evidence gate:

```powershell
python .\src\tools\validate_release.py --live-run-report .\probe-write-rollback.json
```

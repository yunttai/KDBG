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

The `kdbg_live_verify` executable is emitted only on Windows. Automated
destructive lanes are bound to the current `KDbgProbe` fixture; an independently
entered PFN must match that runtime query. The legacy VM lane retains
`--write`, `--confirm-disposable-vm`, `--snapshot-id`, and
`--confirm-probe-pfn` and emits `kdbg.live-verify.v1`.

Local-host evidence uses the ABI 7 serialized exact-page compare/write/read-back path:

```powershell
.\tools\kdbg_live_verify.exe --write --baremetal-evidence `
  --confirm-probe-pfn <PFN_FROM_KDBGPROBE> `
  --artifact-directory C:\KDBG-Evidence\raw-pages `
  --output C:\KDBG-Evidence\baremetal-live.json
```

This lane emits `kdbg.live-verify.v2`, requires the compare/write capability,
revalidates the live Probe identity immediately before rollback, and suppresses
the rollback write if that identity is stale. It writes six exact 4 KiB page
artifacts (baseline, preflight, expected-after, read-back, independent reload,
and rollback) and records their package-independent file names and SHA-256
identities without serializing the private artifact-directory path.

The separate Raw-PFN capability lane exercises the ordinary manual-input target
classification while keeping the live test page deterministic. Enter the PFN
reported by the read-only query twice (once as the manual PFN and once as the
explicit confirmation):

```powershell
.\tools\kdbg_live_verify.exe --write --raw-pfn-evidence `
  --raw-pfn <PFN_FROM_KDBGPROBE> `
  --confirm-raw-pfn <PFN_FROM_KDBGPROBE> `
  --artifact-directory C:\KDBG-Evidence\raw-pfn-pages `
  --output C:\KDBG-Evidence\raw-pfn-live.json
```

This lane emits `kdbg.live-verify.raw-pfn.v1` with `target_kind=RawPfn`,
`target_provenance=manual PFN entry`, the runtime-host identity, complete
4 KiB RAM-range validation, one-shot apply, full read-back, independent reload,
full-page rollback, and final write-gate lock. It rejects a manual PFN that is
not the current Probe PFN; this is a safety binding for deterministic evidence,
not a restriction on the GUI's normal RawPfn input path.

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
full-page comparisons, the eight user-dirty bytes separately from each 4096-byte
driver transaction, Probe CRC transitions, driver write counters, rollback,
and the final locked gate. Final v4 evidence
additionally binds that report to the six raw 4 KiB pages and exact main/symbol
package manifests.

Validate a completed machine report without claiming the separate video and
conference-evidence gate:

```powershell
python .\src\tools\validate_release.py --live-run-report .\probe-write-rollback.json
```

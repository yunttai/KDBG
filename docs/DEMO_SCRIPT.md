# Demonstration script

## Current bare-metal runtime-host recording

Record the current Release package on the same bare-metal Windows instance
whose local physical RAM is exposed by `KDbgDriver.sys`. The recording and its
command log must identify `role=runtime_host` and `TargetProfile=LocalHost`.
`orchestrator_host` may collect the result but is not the memory target.

This is the next-run procedure for the visible recording scene. The source/portable
implementation and pinned WDK/package build are PASS (unsigned build identity).
Current runtime-host read-only and Probe-write evidence are PASS, and the separate
manual-input RawPfn CLI transaction is PASS at the current epoch's
`out/evidence/<current-rawpfn-epoch>/raw-pfn.json`. The visible GUI
`RawPfn | manual PFN entry` scene is still unrecorded, so this script remains the
procedure for closing that evidence gate rather than a claim that the scene exists.

Before recording, produce and validate the current-host bundle on the
`runtime_host`:

```powershell
.\src\tools\win11_baremetal_validation\Invoke-Win11BareMetalValidation.ps1 `
  -PackageRoot D:\release\KDBG-1.1.0-win-x64 `
  -PackageArchive D:\release\KDBG-1.1.0-win-x64.zip `
  -EvidenceDirectory D:\evidence\kdbg-local-host-run

python .\src\tools\validate_release.py `
  --windows-package D:\release\KDBG-1.1.0-win-x64 `
  --symbols-package D:\release\KDBG-1.1.0-win-x64-symbols `
  --baremetal-host-evidence D:\evidence\kdbg-local-host-run\evidence.json
```

This producer uses `kdbg.live-verify.v2` and emits
`kdbg.win11-baremetal-validation.v1`. It installs/starts with `LocalHost`, makes
the exact read, performs the ABI 7 Probe compare/write/read-back/rollback
transaction, retains all six raw 4096-byte page artifacts, and records cleanup.
ProbeFixture is the deterministic evidence target; it does not restrict the
product's ordinary RawPfn path. Machine/boot/session values are optional
automatically collected provenance and are not manual confirmations or product
prerequisites.

For the GUI product demonstration, query the current Probe PFN and enter that
numeric PFN manually in PFN Navigator. The panel must visibly classify the
loaded page as `Target kind: RawPfn | provenance: manual PFN entry`. This proves
the normal RawPfn path while keeping the demonstrated address tied to the
deterministic Probe allocation. Keep only fixture data visible.

The GUI and packaged verifier use the same edit definition: baseline bytes at
offsets `0x100..0x107` XOR the eight-byte mask
`4B 44 42 47 A5 5A 3C C3`. This produces one dirty run, `0x100:8`; it is not a
replacement byte string and staging it must not issue a write. ABI 7 transfers
the complete 4096-byte expected and desired pages even though the GUI diff has
only eight dirty bytes.

### Ordered current scene map

| # | Exact scene identifier | Recording action and visible proof |
|---:|---|---|
| 1 | `runtime_host_localhost_ready` | Show the redacted run header or report with `role=runtime_host`, `TargetProfile=LocalHost`, current package identity, both running services, connected ABI 7 exact-page compare/write capability, and `WRITE LOCKED`. Do not expose absolute service binary paths. |
| 2 | `probe_pfn_discovery_and_raw_input` | Query Probe and hold its PFN/PA/generation/CRC32 on screen, then type that PFN into PFN Navigator. Show `Local physical RAM — this Windows instance`, target kind `RawPfn`, manual-input provenance, PA, and complete-page RAM-range validation. |
| 3 | `physical_read_4096` | Show an exact `4096/4096` physical read with the same PFN/PA and the current runtime-session binding. |
| 4 | `hex_edit_and_diff` | Locally apply the shared XOR mask at offset `0x100`; show eight dirty bytes, the single `0x100:8` run, and before/after bytes. No driver write occurs yet. |
| 5 | `undo_redo` | Undo to zero dirty bytes, then Redo to restore exactly the single `0x100:8` dirty run. |
| 6 | `typed_pfn_unlock` | Open write review, show `Target kind: RawPfn`, the runtime-host identity display, matching full-page preflight, type the current PFN, and consume the one-shot unlock. |
| 7 | `write_and_readback` | Apply once and hold ABI 7 Applied status, `dirty bytes=8`, `driver transferred bytes=4096`, full-page read-back match, and the relocked gate. |
| 8 | `independent_reload` | Perform an independent page reload and show a full match with the expected edited page and changed Probe CRC32. |
| 9 | `rollback_baseline` | Reconfirm the PFN, roll back the complete baseline, independently read again, and show baseline CRC restored with `WRITE LOCKED`. |
| 10 | `probe_v2_evidence` | Show the separate successful `kdbg.live-verify.v2` ProbeFixture report, six page-artifact names/hashes, Apply and rollback 4096-byte transfers, and final lock. Keep this evidence classification distinct from the GUI RawPfn target kind. |
| 11 | `pfn_owner_pid_va_pte` | For the dedicated process fixture PFN, show only its PID/name, VA, PTE PA/value, page size, flags, source, and confidence; show that this PFN differs from Probe. |
| 12 | `page_table_walk` | Open that fixture VA in Page Tables and show every active level plus the fixture final PA/PFN, explicitly distinct from Probe VA/PFN. |
| 13 | `process_first_next_scan` | On the dedicated fixture process, run First Scan then Next Scan and show bounded result counts and progress completion. |
| 14 | `address_list_verified_freeze` | Add one fixture result, perform verified write/read-back and Freeze verification, restore it, and show the process gate locked. |
| 15 | `pointer_scan` | Resolve a bounded fixture pointer path and show root, offsets, target, depth, and result cap. |
| 16 | `zydis_disassembly` | Decode fixture process bytes and show address, raw bytes, and Intel-format instruction text. |
| 17 | `snapshot_diff` | Capture baseline/current fixture snapshots and show CRC32 values plus the bounded changed-run diff. |
| 18 | `kernel_module_catalog` | Show bounded loaded-module metadata with private path components hidden from the capture. |
| 19 | `kernel_symbol_resolution` | Load the matching local PDB and show verified address↔symbol resolution; do not claim live image identity unless the captured comparison proves it. |
| 20 | `kernel_read_disassembly` | Show a bounded kernel-only VA read and Zydis result, or the exact unavailable reason without substituting archived evidence. |
| 21 | `about_version` | Finish on About/version with candidate version/build ID and safe package-relative identity so the recording can be tied to its manifests. |

After capture, retain the redacted command log, validated
`kdbg.live-verify.v2` report, `kdbg.win11-baremetal-validation.v1` evidence JSON,
and all six raw pages beside the package/hash manifests. Review every frame for
readable values, no private paths or notifications, and no unrelated process
names/data. A missing current scene is a failed current evidence gate, not
permission to substitute or relabel a historical capture.

## Historical disposable-VM recording boundary

The existing RC4/RC1 disposable-VM recordings and their 20-scene identifiers
remain immutable historical evidence. They use the snapshot VM regression lane,
`kdbg.live-verify.v1`, ABI 6 where recorded, an eight-byte driver write where
recorded, checkpoint restoration, and final VM Off. Those labels and claims are
not rewritten as ABI 7, LocalHost, runtime-host, or bare-metal evidence.

Historical recording instructions therefore still mean: use the named
disposable-VM snapshot and exact package identity, retain the successful v1
write report and its historical raw pages, complete the historical scene-review
JSON, and restore the named checkpoint. A historical VM PASS cannot establish
the current bare-metal read-only, Probe-write, or RawPfn gate.

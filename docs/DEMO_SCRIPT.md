# Demonstration script

Record the Release build from the named disposable-VM snapshot. Use one exact
main/symbol package pair throughout, keep only fixture data visible, and do not
mark the recording complete until every identifier below is readable in the
reviewed cut.

The GUI and packaged verifier use the same edit definition: baseline bytes at
offsets `0x100..0x107` XOR the eight-byte mask
`4B 44 42 47 A5 5A 3C C3`. This produces one dirty run, `0x100:8`; it is not a
replacement byte string and staging it must not issue a write.

## Ordered v4 scene map

| # | Exact scene identifier | Recording action and visible proof |
|---:|---|---|
| 1 | `driver_probe_ready` | Show both running services, connected ABI 6, Probe ready, and `WRITE LOCKED`. Do not expose absolute service binary paths. |
| 2 | `probe_pfn_discovery` | Query Probe and hold its PFN, PA, generation, byte count, and baseline CRC32 on screen. |
| 3 | `physical_read_4096` | Load that PFN and show an exact `4096/4096` physical read with the same PFN/PA. |
| 4 | `hex_edit_and_diff` | Click `Stage Evidence Probe Pattern`; show offset `0x100`, eight changed bytes, and the before/after diff produced by the shared XOR mask. |
| 5 | `undo_redo` | Undo to zero dirty bytes, then Redo to restore exactly the single `0x100:8` dirty run. |
| 6 | `typed_pfn_unlock` | Show matching full-page preflight, type the current Probe PFN, and consume the one-shot unlock. |
| 7 | `write_and_readback` | Apply once and hold full-page read-back PASS plus requested/completed byte counts and the relocked gate. |
| 8 | `independent_reload` | Perform an independent page reload and show a full match with the expected edited page and changed Probe CRC32. |
| 9 | `rollback_baseline` | Reconfirm the PFN, roll back the full baseline, independently read again, and show baseline CRC restored with `WRITE LOCKED`. |
| 10 | `pfn_owner_pid_va_pte` | For the dedicated process fixture PFN, show only its PID/name, VA, PTE PA/value, page size, flags, source, and confidence; show that this PFN differs from Probe. |
| 11 | `page_table_walk` | Open that fixture VA in Page Tables and show every active level plus the fixture final PA/PFN, explicitly distinct from Probe VA/PFN. |
| 12 | `process_first_next_scan` | On the dedicated fixture process, run First Scan then Next Scan and show bounded result counts and progress completion. |
| 13 | `address_list_verified_freeze` | Add one fixture result, perform verified write/read-back and Freeze verification, restore it, and show the process gate locked. |
| 14 | `pointer_scan` | Resolve a bounded fixture pointer path and show root, offsets, target, depth, and result cap. |
| 15 | `zydis_disassembly` | Decode fixture process bytes and show address, raw bytes, and Intel-format instruction text. |
| 16 | `snapshot_diff` | Capture baseline/current fixture snapshots and show CRC32 values plus the bounded changed-run diff. |
| 17 | `kernel_module_catalog` | Show bounded loaded-module metadata with private path components hidden from the capture. |
| 18 | `kernel_symbol_resolution` | Load the matching local PDB and show verified address↔symbol resolution; do not claim live image identity unless the captured comparison proves it. |
| 19 | `kernel_read_disassembly` | Show a bounded kernel-only VA read and Zydis result, or the exact unavailable reason without substituting archived evidence. |
| 20 | `about_version` | Finish on About/version with candidate version/build ID and safe package-relative identity so the recording can be tied to its manifests. |

After capture, stop/remove the services, retain the redacted command log and
successful `kdbg.live-verify.v1` write-run report, and keep all six raw 4096-byte
pages beside the evidence JSON. Review the video for readable values, no private
paths or notifications, and no unrelated process names/data before generating
`kdbg.live-evidence.v4`. Complete the separate scene-review JSON with the exact
GIF hash, real reviewer/time, redaction decisions, and an observed time range
plus concrete note for every ordered identifier. A missing or unavailable scene is a failed live-evidence
gate, not permission to rename it or substitute a historical capture.

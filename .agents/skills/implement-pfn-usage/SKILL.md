---
name: implement-pfn-usage
description: Implement PFN ownership reporting through the isolated MemProcFS bridge and the built-in selected-process page-table reverse mapper.
---

# PFN ownership workflow

1. Keep `vmm.dll` and AGPL MemProcFS in `kdbg_memprocfs_bridge.exe`, never the KDBG GUI process.
2. Use the official `VMMDLL_Map_GetPfnEx` layout/API for a bounded 32-bit PFN query.
3. Enforce bridge path, timeout, cancellation, output-size cap, exit status, protocol header/version, record parsing, and memory free/close calls.
4. Return PID, process name, VA, PTE address, page size, mapping type, shared state, permissions, confidence, and source.
5. Provide a built-in fallback that walks selected process page tables with table/result limits, canonicalization, LA57, 4 KiB/2 MiB/1 GiB leaves, and page-table-page identification.
6. Add synthetic page-table tests and show provider/confidence in the GUI.

---
name: implement-page-table-view
description: Implement PTView-style KDBG page-table visualization and VA-to-PA translation for a selected process, including PML5/PML4/PDPT/PD/PT entries and flags.
---

# Page-table view workflow

1. Resolve the target process context and DTB through KDBG.
2. Decode canonical VA indices for 4-level or LA57 paging.
3. Request the driver page walk and render each level with index, entry PA, raw value, PFN, Present, RW, US, Accessed, Dirty/PageSize, Global, and NX.
4. Correctly stop at 1 GiB or 2 MiB large-page leaves and show final PA, offset, and effective permissions.
5. Allow navigation from a process scan result to this view and from a leaf PFN to the physical hex editor.
6. Test bit decoding, canonical addresses, large pages, not-present entries, and response limits.

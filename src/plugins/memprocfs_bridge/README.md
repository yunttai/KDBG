# KDBG MemProcFS bridge

`memprocfs_bridge.exe` is a separate helper process that dynamically loads the
official MemProcFS `vmm.dll` and calls `VMMDLL_Map_GetPfnEx`. KDBG keeps this
component out of the main GUI process so the MemProcFS AGPL boundary remains
explicit.

Example:

```powershell
memprocfs_bridge.exe --pfn 0x12345 --device pmem
memprocfs_bridge.exe --pfn 0x12345 --device C:\dumps\memory.raw
```

The helper expects the MemProcFS release files (`vmm.dll`, LeechCore and its
support files) beside the executable, unless `--vmm` points to another
`vmm.dll`. The main application starts it with redirected stdout and parses the
versioned `KDBG_PFN_RESULT` protocol.

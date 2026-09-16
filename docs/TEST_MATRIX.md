# Test matrix

| Area | Portable | Windows build | Live VM |
|---|---|---|---|
| PFN/range/page walk | deterministic unit tests | backend compile/link | Probe PFN/PA match |
| Physical transaction | mock conflict/short I/O/read-back/rollback | GUI/driver ABI | write/reload/rollback |
| Process scanner/address list | fixture tests | Win32 integration | fixture process |
| Pointer/disassembly/snapshot | deterministic fixtures | Zydis/GUI build | visible workflow |
| PFN ownership/PTView | synthetic mapper | bridge/provider build | PID/VA/PTE and final PA |
| Package | source contract | PE/version/hash/SBOM validator | install/diagnose/remove |
| Evidence | schema negative tests | artifact hash binding | video/log/redaction review |

PASS must include command output and artifacts from the corresponding column.
Portable results never promote the Windows or live columns.

## 2026-09-16 final gate snapshot

| Gate | Status | Boundary |
|---|---|---|
| Portable/source | PASS | 707 checks, 0 failures; layout/source validator |
| Windows build | PASS | MSVC Debug/Release/`/analyze`; WDK Debug/Release |
| VM prerequisites | PASS | existing `Windows-VM`, checkpoint, Administrator, test-signing |
| Interim physical transaction | PASS | `DADF43AA...`: ABI 6, Probe write/read-back/reload/rollback/gate lock |
| Candidate advanced read-only | PASS | `D3390AD4...`: current GUI, scanner, pointer, snapshot, PFN reverse map, PTView |
| Final Release package | PASS | new scope, strict validators, same-input ZIP, 5/5 negatives; exact identity externalized |
| Optional MemProcFS runtime | BLOCKED (optional) | error 126 resolved; v5.18.11 `VMMDLL_Initialize(device=pmem)` exit 2; fallback PASS |
| Final-package read-only/lifecycle | PASS | exact deploy/hash binding, device/main ABI6, Probe/4 KiB read, invalid IOCTL rejection, stop/remove; writes 0 |
| Final physical write | PASS | PFN `0xBC1E6`, 8-byte write, full read-back/reload/rollback, baseline restored |
| Process write/Freeze | PASS | 16-byte fixture, 3 restore ticks, rollback/gate lock |
| Driver Verifier | PASS | volatile `0x132`, exact two-driver target, cleanup PASS |
| Exact-package DPI | PASS | 100/125/150/200% actual captures and hashes |
| Final v2 | PASS | 17 scenes, raw page/log/video/artifact hashes, validator exit 0 |

Exact final identity is externalized in `out/evidence/final-live-manifest.json` and
`out/evidence/RELEASE-HASHES.txt`.

# Known limitations

- Rebuilding Windows GUI/bridge and drivers requires MSVC, Windows SDK and WDK; the 2026-08-23 validation produced all Debug/Release binaries successfully.
- Driver load and physical writes require a disposable Administrator VM, snapshot, and supported signing configuration.
- An existing `Windows-VM` checkpoint, Administrator and test-signing are confirmed. The exact Release package completed deploy/hash binding, ABI6, Probe read/write/read-back/reload/rollback, process write/Freeze, Driver Verifier, invalid IOCTL rejection and stop/remove.
- Candidate `D3390AD4...` completed device/ABI and advanced read-only GUI validation. Its physical write count stayed zero and it is not the final package.
- Exact-package DPI was exercised at 100/125/150/200% in the existing disposable-VM user profile; a separate newly-created Windows profile was not used.
- User-mode executables are unsigned and no production driver trust claim is made; WDK signability/CAT generation is not a substitute for a production certificate.
- MemProcFS/`vmm.dll` is optional and is not distributed. Official v5.18.11 resolved the earlier Win32 error 126, but `VMMDLL_Initialize(device=pmem)` still exited 2. The selected-process reverse mapper/PTView fallback passed independently, and no external memory driver remained installed.
- The reverse mapper is bounded and may not find owners outside the attached process.
- WDK Debug/Release builds include generated CAT files, but catalogs are never synthesized when WDK did not create them. No production Authenticode trust is claimed.
- PDBs are excluded from the main package; only PDBs actually emitted by the selected Release toolchains appear in the symbols package.
- Release executables use the Microsoft VC++ runtime; diagnose reports a missing supported Redistributable.
- The immutable `91042aab...` runtime ZIP passed final physical/process write, Driver Verifier and v2 validation; optional MemProcFS backend availability is a separate non-required status.
- The `kdbg.source-snapshot.v1` Release/symbol packages passed strict validation, same-input ZIP reproducibility, and 5/5 negative fixtures. Post-package evidence tooling/document changes are external and do not alter the live-bound runtime ZIP.
- Current Windows Release and sanitized benchmarks passed, but they use deterministic mock backends and do not measure a loaded physical-memory driver.
- A validated 17-frame final v2 GIF exists. It combines exact final runtime values/raw hashes and exact-package DPI captures with visibly disclosed older ABI6 supporting UI workflow captures; those older frames are not promoted to exact-package runtime captures.
- Exact final package identity is intentionally not embedded here; `out/evidence/final-live-manifest.json` and `out/evidence/RELEASE-HASHES.txt` are authoritative.
- No code injection, debugging-evasion, or arbitrary kernel-virtual write features are provided.

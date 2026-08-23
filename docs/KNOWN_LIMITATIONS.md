# Known limitations

- Rebuilding Windows GUI/bridge and drivers requires MSVC, Windows SDK and WDK; the 2026-08-23 validation produced all Debug/Release binaries successfully.
- Driver load and physical writes require a disposable Administrator VM, snapshot, and supported signing configuration.
- An existing `Windows-VM` checkpoint, Administrator and test-signing are confirmed. The exact Release package completed deploy/hash binding/device/main ABI6/fresh Probe/4 KiB read-only/invalid IOCTL rejection/stop/remove with physical writes 0.
- Candidate `D3390AD4...` completed device/ABI and advanced read-only GUI validation. Its physical write count stayed zero and it is not the final package.
- Final-package physical write is `NOT_RUN`; dedicated process write/Freeze, Driver Verifier and final hash-bound v2 have not been evidenced.
- User-mode executables are unsigned and no production driver trust claim is made; WDK signability/CAT generation is not a substitute for a production certificate.
- MemProcFS/`vmm.dll` is optional and is not distributed. A real bridge launch was attempted but is BLOCKED by `Unable to load vmm.dll` (Win32 error 126); the selected-process reverse mapper succeeded independently.
- The reverse mapper is bounded and may not find owners outside the attached process.
- WDK Debug/Release builds include generated CAT files, but catalogs are never synthesized when WDK did not create them. No production Authenticode trust is claimed.
- PDBs are excluded from the main package; only PDBs actually emitted by the selected Release toolchains appear in the symbols package.
- Release executables use the Microsoft VC++ runtime; diagnose reports a missing supported Redistributable.
- Final Release read-only/lifecycle PASS does not imply final physical/process write, Driver Verifier, MemProcFS, or v2 PASS.
- The `kdbg.source-snapshot.v1` Release/symbol candidates passed strict validation, same-input ZIP reproducibility, and 5/5 negative fixtures. Documentation changes require refreshed final hashes before publication.
- Current Windows Release and sanitized benchmarks passed, but they use deterministic mock backends and do not measure a loaded physical-memory driver.
- A 17-frame demonstration GIF exists, but it deliberately combines labeled interim-write and candidate-read-only evidence. Hash-bound final-package v2 live evidence remains pending.
- Exact final package identity is intentionally not embedded here; `out/evidence/final-live-manifest.json` and `out/evidence/RELEASE-HASHES.txt` are authoritative.
- No code injection, debugging-evasion, or arbitrary kernel-virtual write features are provided.

# Developer guide

Product source and build tools live under `src/`. The only user/kernel ABI
headers are `src/shared/KDbgIoctl.h` and `KDbgProbeIoctl.h`. MemProcFS remains
an out-of-process bridge. Update deterministic tests and traceability with behavior changes.

Baseline validation:

```powershell
python .\src\tools\verify_layout.py
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

Windows Release packaging requires `windows-release`, both Release WDK drivers,
Syft, and PE VERSIONINFO 1.0.0. Packaging rejects Debug CRT imports, PDB leakage,
unsafe or incomplete hashes, wrong architecture/version, and private paths.
Set `KDBG_SOURCE_REVISION` and `SOURCE_DATE_EPOCH` for recorded provenance.

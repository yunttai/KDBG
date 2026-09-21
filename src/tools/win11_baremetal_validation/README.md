# Windows local runtime-host validation

`Invoke-Win11BareMetalValidation.ps1` is the executable producer for the
`kdbg.win11-baremetal-validation.v1` release-evidence record. It runs on the
same Windows host whose local physical address space KDbgDriver exposes.

The producer performs one complete run:

1. bind the exact archive, extracted package tree, source snapshot, catalogs,
   and Authenticode signer;
2. install and start the package with `TargetProfile LocalHost`;
3. run the read-only verifier and obtain the current KDbgProbe PFN;
4. run the ABI v7 compare-write transaction, capturing the six raw 4 KiB page
   artifacts for baseline, preflight, expected page, read-back, independent
   reload, and rollback;
5. uninstall, observe service/device/certificate cleanup, and atomically write
   `evidence.json`.

Probe is the deterministic release-evidence target. This does not restrict the
product's RawPfn read/write behavior. The existing `win11_validation` directory
continues to provide the separate Hyper-V guest regression lane.

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

The producer is not executed by source or contract tests. A host gate remains
`NOT RUN` until this command produces artifacts on Windows and the validator
checks them.

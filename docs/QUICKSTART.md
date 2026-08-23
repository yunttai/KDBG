# KDBG 1.0.0 quick start

Use only in a disposable Windows 10/11 x64 VM with a restorable snapshot.

1. Extract `KDBG-1.0.0-win-x64.zip` and keep the directory name unchanged.
2. In Administrator PowerShell run:

```powershell
.\tools\diagnose.ps1 -VerifyPackage
.\tools\install.ps1 -ConfirmDedicatedVm -ConfirmSnapshot -Start
.\KDBG.exe
```

3. Query KDbgProbe, open only its PFN, read exactly 4096 bytes, edit locally,
   review the diff, type the same PFN, then Apply & Verify.
4. Confirm full read-back and independent reload, roll back to baseline, and
   confirm the write gate is locked.
5. Remove services when finished:

```powershell
.\tools\uninstall.ps1 -ConfirmKdbgServices
```

Unsigned or test-signed drivers will not load unless the disposable VM has an
appropriate supported signing configuration. The package does not bypass Code Integrity.

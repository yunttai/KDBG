# KDBG WDM drivers

## KDbgDriver

`KDbgDriver/Driver.cpp`는 다음 narrow ABI만 제공한다.

- ABI/session status
- physical RAM ranges
- physical read/write
- process context/DTB
- process virtual read/write
- kernel virtual read
- x64 VA-to-PA page walk

장치 ACL은 Administrators/SYSTEM으로 제한하고 controller PID와 per-handle write gate를 적용한다. 모든 length/address arithmetic, RAM range, PID, acknowledgement magic과 completed byte count를 검증한다. 임의 kernel-virtual write IOCTL은 없다.

## KDbgProbe

`KDbgProbe/Driver.cpp`는 과제 시연을 위한 deterministic contiguous 4 KiB page를 소유한다. Query는 VA/PA/PFN/size/generation/CRC32를 반환하고 Reset/Fill은 fixture pattern만 변경한다.

## Build

```powershell
.\src\tools\build_drivers.ps1 -Configuration Debug
```

`KDBGDrivers.sln`은 두 project를 함께 빌드한다. 드라이버 서명 우회는 포함하지 않는다.

## Verification

- `IMPLEMENTATION_AUDIT.md`: source-level security/ABI audit
- `PROBE_FIXTURE_DESIGN.md`: fixture contract
- `LICENSE_NOTICE.md`: attributed upstream MIT notice
- `docs/exec-plans/active/windows-live-validation.md`: Windows/load/live gate

Package `install.ps1` and `start.ps1` require both driver SYS files and both
matching catalogs to report a trusted `Valid` Authenticode status on the guest
before changing or starting either service. This accepts a test certificate only
when that certificate is explicitly trusted inside the disposable test VM; it is
not evidence of production publisher trust. Production release readiness still
requires a non-test publisher chain and timestamp verification on a clean guest.
The production-candidate diagnostic is explicit and requires the exact publisher
subject:

```powershell
.\tools\diagnose.ps1 -VerifyPackage `
  -RequireTrustedDriverSignatures -RequireProductionDriverSignatures `
  -ExpectedDriverPublisherSubject "CN=<release publisher>"
```

Run the exact-target volatile Driver Verifier soak only in a disposable snapshot
VM after installing and starting the hash-verified package:

```powershell
.\src\driver\tests\run_driver_verifier.ps1 `
  -PackageDirectory C:\KDBG\KDBG-1.1.0-win-x64 `
  -OutputPath C:\KDBG-Evidence\driver-verifier.json `
  -Cycles 10 -ConfirmDedicatedVm -ConfirmSnapshot
```

The harness refuses pre-existing verified-driver targets, stops the package,
atomically configures volatile flags `0x132` and exactly `KDbgDriver.sys` plus
`KDbgProbe.sys`, and proves the active mask before and after the packaged
stop/start/read-only readiness cycles. It unloads the package before removing
each target individually, clears the volatile mask, verifies cleanup, and
restores package readiness. Its JSON labels self-signed or untimestamped trust as
`trusted-test-or-private`, never as production signing.

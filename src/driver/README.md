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

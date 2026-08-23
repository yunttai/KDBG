# KDBG shared ABI

`KDbgIoctl.h` is the single user/kernel contract for `KDbgDriver.sys` and the
KDBG user-mode backend. `KDbgProbeIoctl.h` is the isolated contract for the
safe, deterministic probe page used by the live-write demonstration.

Rules:

- Keep the headers C-compatible and fixed-width.
- Bump the ABI version for any incompatible layout or IOCTL change.
- Validate `Size`, input/output lengths, transfer limits, acknowledgement
  constants, and physical RAM membership in the driver.
- Do not create a second copy of either ABI header.

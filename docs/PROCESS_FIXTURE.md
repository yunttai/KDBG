# Dedicated process fixture

`tools\kdbg_process_fixture.exe` is the packaged, deterministic user-mode
target for process scan, verified write/Freeze, pointer scan, snapshots,
disassembly, PFN ownership, and page-table demonstrations. Run it only inside
the disposable test VM, keep its one-line startup JSON outside the immutable
package, and attach KDBG to the exact PID printed by that line.

The fixture emits schema `kdbg.process-fixture.v1`. Protocol version 1 reports
the process-start identity, per-run nonce, image basename, page-aligned VA,
`4096` byte count, generation, baseline/current CRC32 values, `VirtualLock`
status, corpus offsets, and a local named pipe. The page is distinct from the
KDbgProbe transaction page; the v4 evidence validator rejects reuse of the
Probe PFN or VA as ownership evidence.

```powershell
$EvidenceRoot = Join-Path $env:LOCALAPPDATA "KDBG\evidence\fixture-current"
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
$FixtureInfo = Join-Path $EvidenceRoot "fixture-startup.json"
$Fixture = Start-Process -FilePath ".\tools\kdbg_process_fixture.exe" `
  -RedirectStandardOutput $FixtureInfo -PassThru -WindowStyle Hidden
```

Keep the process running. Parse the startup JSON, attach the exact PID in the
GUI, and use only its reported VA for process and translation work. The local
named pipe accepts `INFO`, `RESET`, bounded `MUTATE`, `VERIFY`, and `EXIT`.
`RESET` restores the deterministic 4096-byte corpus and increments generation.
Remote pipe clients are rejected; the fixture does not open the KDBG driver or
access a network endpoint.

For release evidence, the GUI exports the final `INFO` JSON, exact 4096-byte
process read, physical read translated from that VA, ownership, full page-table
walk, and Kernel Explorer proof into one atomic `analysis-*` directory. Copy
that directory's files without overwriting into the completed Probe `live-*`
directory before running the v4 generator. The analysis metadata must hash-bind
all of them and the packaged fixture image. Never copy the startup JSON from
another run or substitute the Probe allocation.

Run `tools\kdbg_process_fixture.exe --self-test` for a local executable smoke
test. The deterministic named-pipe protocol regression is
`src\tests\process_fixture_tests.ps1`; neither test substitutes for live VM
process-write, Freeze, ownership, or translation evidence.

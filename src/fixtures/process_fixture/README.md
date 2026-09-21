# KDBG process fixture

`kdbg_process_fixture.exe` is the deterministic user-mode target for repeatable
process scan, verified write/Freeze, pointer scan, snapshot, disassembly,
PFN-ownership, and PTView demonstrations. It allocates and `VirtualLock`s one
page-aligned, committed, read/write 4096-byte page. The fixture never accesses a
remote endpoint and never opens the KDBG driver.

At startup it writes one `kdbg.process-fixture.v1` JSON line containing the PID,
process-creation identity, random per-run nonce, VA, generation, CRC32, corpus
offsets, and its local named-pipe path. The pipe rejects remote clients, is
restricted to SYSTEM, Administrators, and interactive users, and accepts one
message of at most 4096 bytes per connection.

Commands are ASCII and case-sensitive:

- `INFO`
- `RESET`
- `MUTATE <decimal-or-0x-offset> <1-to-64-byte-hex-payload>`
- `VERIFY <generation> <decimal-or-0x-crc32>`
- `EXIT`

`RESET` restores the deterministic corpus and increments the generation.
`MUTATE` exists for controlled conflict/failure demonstrations. Production GUI
writes still go through the normal verified process/physical transaction paths.

Important corpus offsets are also emitted in the startup JSON: fixed-width
integers and floating-point values, UTF-8/UTF-16 strings, an AOB marker, a Freeze
cell, x64 instruction bytes, and a two-hop in-page pointer chain.

Run `kdbg_process_fixture.exe --self-test` for the allocation, alignment, corpus,
CRC, reset, bounds, and command-parser smoke test.

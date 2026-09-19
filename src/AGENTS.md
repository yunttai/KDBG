# Source-tree instructions

- `runtime_host` means the bare-metal Windows system where `KDBG.exe` and
  `KDbgDriver.sys` execute and whose local physical RAM is the product target.
  `orchestrator_host` is lifecycle/evidence control only; `regression_guest` is
  the VM regression lane only. Keep these target identities explicit in source,
  tools, fixtures, and runtime configuration.
- Do not edit fetched dependency sources.

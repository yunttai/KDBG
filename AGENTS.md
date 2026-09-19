# KDBG Codex operating contract

## Mission

KDBG is a Windows x64 physical/process-memory research GUI whose product target is
the local physical RAM exposed to the same bare-metal Windows instance that runs
`KDBG.exe` and `KDbgDriver.sys`. This machine is the `runtime_host`. A separate
`orchestrator_host` may build, deploy, control lifecycle, and collect evidence;
it is never the implicit memory target. A Hyper-V `regression_guest` remains a
separate regression and recovery lane and its evidence cannot establish a
bare-metal runtime-host gate.

The required vertical slice is Raw PFN input, exact 4 KiB local-system physical
read, local hex edit, explicit one-shot write, full read-back verification, and
visible evidence. Advanced scope covers process scans, persistent address lists
and verified freeze, pointer scans, disassembly, snapshots, PFN ownership, and
page-table visualization.

## Repository conventions

- Project agents live in `.codex/agents/*.toml`.
- Repository skills live in `.agents/skills/*/SKILL.md`.
- Read the closest nested `AGENTS.md`; deeper instructions override this file for that subtree.
- Product source, tests, fixtures, runtime configuration, and build tools live under `src/`.
- Product plans and evidence live under `docs/`, especially `docs/exec-plans/STATUS.md`.
- `src/shared/KDbgIoctl.h` and `src/shared/KDbgProbeIoctl.h` are the only authoritative user/kernel ABI definitions.
- MemProcFS remains in the isolated `kdbg_memprocfs_bridge.exe`; do not link it into the GUI.
- Preserve pinned revisions and license notices.

## Definition of done

A source change is complete only when implementation, deterministic tests, traceability, and status documents agree. Run:

```powershell
python .\src\tools\verify_layout.py
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

Windows build, regression-guest, bare-metal runtime-host read-only, bare-metal
Probe-write, and bare-metal Raw-PFN gates are independent. Never report one as
another, and never report a live gate as passed unless its exact command and
evidence were produced on the named Windows target.

## Delegation

Use `kdbg_supervisor` for broad integration. Delegate focused work to `kernel_driver`, `memory_core`, `gui`, `pfn_analysis`, `qa_safety`, and `release_evidence`. Serialize changes to shared ABI, root CMake source lists, and common UI state; parallelize only disjoint work.

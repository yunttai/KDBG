# KDBG Codex operating contract

## Mission

KDBG is a Windows x64 physical/process-memory research GUI for a controlled assignment VM. The required vertical slice is PFN input, exact 4 KiB physical read, local hex edit, explicit one-shot write, full read-back verification, and visible evidence. Advanced scope covers process scans, persistent address lists and verified freeze, pointer scans, disassembly, snapshots, PFN ownership, and page-table visualization.

## Repository conventions

- Project agents live in `.codex/agents/*.toml`.
- Repository skills live in `.agents/skills/*/SKILL.md`.
- Read the closest nested `AGENTS.md`; deeper instructions override this file for that subtree.
- Product source, tests, fixtures, runtime configuration, and build tools live under `src/`.
- Product plans and evidence live under `docs/`, especially `docs/exec-plans/STATUS.md`.
- `src/shared/KDbgIoctl.h` and `src/shared/KDbgProbeIoctl.h` are the only authoritative user/kernel ABI definitions.
- MemProcFS remains in the isolated `kdbg_memprocfs_bridge.exe`; do not link it into the GUI.
- Preserve pinned revisions and license notices.

## Mandatory safety boundary

- Use a disposable Windows VM, an existing snapshot, Administrator, and test-signing.
- Keep the device ACL restricted to Administrators/SYSTEM, one controller PID, default-locked write gates, transfer caps, exact byte-count checks, and physical-range validation.
- Physical edits must stay local until preflight conflict detection, typed PFN confirmation, one-shot apply, full-page read-back, and optional rollback.
- Process writes require a separate PID confirmation and read-back verification. Loading an address table must never reactivate frozen writes automatically.
- Do not add signing bypasses, vulnerable-driver loading, stealth, anti-cheat evasion, injection, callback removal, arbitrary kernel-virtual writes, or credential collection.

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

Windows and live-VM gates are independent. Never report them as passed unless their commands and evidence were produced on Windows.

## Delegation

Use `kdbg_supervisor` for broad integration. Delegate focused work to `kernel_driver`, `memory_core`, `gui`, `pfn_analysis`, `qa_safety`, and `release_evidence`. Serialize changes to shared ABI, root CMake source lists, and common UI state; parallelize only disjoint work.

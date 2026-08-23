# KDBG artifact manifest

## Codex configuration

- 7 project agents in `.codex/agents/`
- 10 repository skills in `.agents/skills/`
- root and nested `AGENTS.md`
- status and execution plans in `docs/exec-plans/`

## Product source

- restricted WDM physical/process-memory driver
- deterministic contiguous-page probe driver
- user/kernel ABI and real `DeviceIoControl` backend
- transactional physical and process write sessions with byte-level Undo/Redo
- Dear ImGui/DirectX 11 GUI and hex editor
- process scanner, persistent address list, verified edit/freeze
- pointer scanner and Zydis disassembly
- cancellable snapshot capture, CRC32, save/load, diff
- native isolated MemProcFS PFN bridge
- selected-process page-table reverse mapper
- PTView-style VA-to-PA visualization
- Windows build/service/package/evidence scripts and packaged config examples

## Documentation

PRD, architecture, implementation status, test plan, threat model, UX, source adoption, attribution, traceability, troubleshooting, demo checklist, ADRs, and explicit release gates.

## Generated outputs

- actual MSVC binaries under `out/build/windows-{debug,release}`
- actual WDK SYS/INF/CAT/PDB under `out/drivers/{Debug,Release}`
- validated main/symbol packages and deterministic ZIPs under `out/package`
- mock benchmark JSON and DPI-correct GUI screenshot under `out/evidence`

These generated files are deliberately outside product source directories. The
`kdbg.source-snapshot.v1` provenance scope includes an explicit root-file
allowlist plus the product/documentation trees named in
`src/tools/package_windows.ps1`, including the complete `src/driver` tree and
the deterministic `src/fixtures` inputs. It does not absorb unrelated root
artifacts such as JVM `hs_err_pid*.log` crash reports. The source snapshot also
does not embed:

- third-party `vmm.dll`
- signing private keys or certificates
- live-VM evidence and submission recording

Live-only outputs must be produced and validated separately in the designated
disposable snapshot VM.

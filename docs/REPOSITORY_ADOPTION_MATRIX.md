# KDBG 참고 저장소 채택 매트릭스

## 원칙

- 직접 source 사용은 pinned permissive dependency와 attribution이 명확한 경우에 한한다.
- copyleft component는 main GUI와 분리하거나 reference-only로 유지한다.
- memory-write driver는 필요한 narrow primitive만 독립 구현한다.
- 외부 프로젝트의 stealth, bypass, injection, anti-cheat 기능은 채택하지 않는다.

| 저장소 | 채택 내용 | KDBG 위치 | 방식 |
|---|---|---|---|
| kernullist/kn-live-dbg | narrow driver/client split, physical range/RW, process context, page walk | `src/driver`, `src/core/memory` | attributed selective reimplementation |
| VollRagm/PTView | page-table navigation, PTE field presentation, large-page flow | `src/core/paging`, `src/app/ui/PageTablePanel.*` | independent implementation |
| ufrisk/MemProcFS | PFN entry PID/VA/PTE metadata API | `src/plugins/memprocfs_bridge`, `MemProcFsProvider` | optional out-of-process bridge |
| Windows-Kernel-Explorer | inspector-oriented window organization | `MainWindow`, physical/PFN panels | UX reference only |
| imgui_memory_editor | Hex/ASCII grid | `HexEditorPanel` | pinned permissive dependency |
| Dear ImGui | Win32/DX11 UI | `src/app` | pinned permissive dependency |
| Zydis | x64 decode/format | `src/app/disasm` | pinned permissive dependency |
| Kernel-Bridge | kernel API and IOCTL design comparison | driver audit/docs | GPL reference only |
| Cheat Engine | First/Next Scan, address list, Freeze, pointer/disassembly workflow | scanner/address/UI modules | independent implementation; no source consumed |

## Codex repository conventions

- `AGENTS.md`: persistent project/subtree instructions
- `.agents/skills/*/SKILL.md`: repository workflows
- `.codex/agents/*.toml`: KDBG-specialized project agents
- `docs/exec-plans/`: long-running state and release gates

## 명시적 미채택

- vulnerable-driver loading
- Code Integrity or signing bypass
- arbitrary kernel-virtual writes
- process injection and remote thread creation
- debugger/anti-debug evasion
- callback removal or kernel-object hiding
- third-party main-process linking that would change KDBG distribution obligations without review

---
name: kdbg-orchestrate
description: Coordinate a multi-agent KDBG implementation or release task from audit through integration. Use for broad requests spanning driver, core, GUI, PFN analysis, tests, or submission evidence; do not use for a narrow one-file edit.
---

# KDBG orchestration

1. Read `AGENTS.md`, the nearest nested instructions, `docs/PRD.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/exec-plans/STATUS.md`.
2. Classify the requested work into shared ABI, driver, memory core, GUI, PFN analysis, QA, and release evidence.
3. Serialize any work touching `src/shared/KDbgIoctl.h`, `src/CMakeLists.txt`, or the same UI state object. Parallelize independent exploration and tests.
4. Delegate with the project custom agents: `kernel_driver`, `memory_core`, `gui`, `pfn_analysis`, `qa_safety`, and `release_evidence`.
5. Require each agent to return changed files, commands run, results, unverified gates, and follow-up risks.
6. Integrate changes, resolve interface drift, run the full portable validation chain, and update traceability and `docs/exec-plans/STATUS.md`.
7. State Windows build/live status separately from source-complete status.

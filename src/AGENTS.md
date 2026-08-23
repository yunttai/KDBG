# Source-tree instructions

- All product behavior changes require a test or an explicit Windows-only
  verification case in `docs/TEST_PLAN.md`.
- Keep public core interfaces platform-neutral. Guard Windows headers and APIs
  behind `_WIN32` or place them in `core/windows`, `app`, or driver targets.
- Compile owned code as C++20 with warnings as errors. Avoid silent narrowing,
  unchecked integer arithmetic, unbounded allocations, and detached threads.
- Return structured `Result<T>` errors with operation, native code, requested
  length, and completed length when available.
- Do not edit fetched dependency sources.

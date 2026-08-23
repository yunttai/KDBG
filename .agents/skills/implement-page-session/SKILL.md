---
name: implement-page-session
description: Implement or test the PFN physical-page editing transaction: load, baseline, working copy, dirty runs, conflict detection, one-shot write, full read-back verification, and rollback.
---

# Physical page transaction

1. Parse PFN with decimal/hex support and reject signs, trailing text, overflow, and non-RAM pages.
2. Load exactly 4096 bytes and keep immutable baseline, mutable working copy, dirty bitmap, latest preflight bytes, read-back bytes, and previous successful baseline.
3. Never write from the hex callback. Build contiguous dirty runs for review.
4. Require typed PFN confirmation for a one-shot unlock.
5. Re-read the full page before applying. Abort on any difference from the baseline, including bytes the user did not edit.
6. Open the backend write gate, apply bounded runs, close the gate, re-read the full page, and compare every byte.
7. Preserve mismatch/conflict offsets and support verified rollback.
8. Add Mock tests for locked write, bad confirmation, short read/write, concurrent mutation, ignored write, successful apply, and rollback.

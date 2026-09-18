# DEF CON submission packet — KDBG

Status: KDBG 1.1.0 technical gates PASS under disposable-VM test trust;
presentation-only final video automatic and independent human review PASS;
formal GUI evidence review and actual submission remain incomplete, 2026-09-18

The frozen historical 1.0.0 public CFP packet (`69f69cb5…21fb`, 167 entries) passed deterministic
rebuild and independent verification with zero private-literal findings. It
deliberately excludes the historical path-bearing PDB archive. The current
historical path-mapped main/symbol/source epoch (`b6832712…e47f`/`7801bfef…70aa`/
`0484b5dd…49ee`) passed Windows 10 build 19044 exact live validation, completed
repository-owner-confirmed 20-scene review, and produced final v4
`fc0afb4b…9823`. `R:\`/`K:\` entries are disclosed stable logical build aliases,
not a physical checkout or user-profile path.

The current 1.1.0 unsigned main/symbol/source identities are
`3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f` /
`0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849` /
`8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184`;
scope identity is
`bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
The VM-test-signed package
`596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`
passed Windows 11
build 26200 required-core and extended lifecycle/soak validation. The current
24-capture/20-scene GUI run completed automatically, but human review failed
because its 1024 layout clips scene 03's grid and scene 20's diff row and wraps
columns. Those formal source-bound GUI flags remain unchanged. A separate
presentation-only overlay run `run-20260918T102055Z-6c85cee7` passed automatic
checks and independent human presentation review after adding the scene 20
evidence-bound cue and correcting the scene 10/11 crops. This overlay does not
promote the formal GUI evidence or prove conference submission.

## Working title

**From PFN to Proof: A Verifiable Windows Physical-Memory Debugging Workbench**

## One-sentence pitch

KDBG connects a Windows physical page to its owning process, virtual address,
page-table entries, local symbols, disassembly, and a fully verified edit and
rollback transaction in one reproducible workflow.

## Novelty statement

KDBG's novelty is the **PFN-to-proof workflow**, not the existence of a memory
read/write primitive. It turns one physical frame into a single, inspectable
chain that joins ownership, virtual reachability, page-table permissions,
module/symbol/disassembly context, a byte-level edit, and proof that the exact
change was applied and reversed. Three properties make that chain useful to a
skeptical reviewer:

1. **Cross-view identity:** PFN, PA, PID, process start identity, VA, DTB/PTE,
   module signature, package hash, and capture hash are recorded as identities,
   rather than inferred from screenshots taken at different times.
2. **Transactional physical editing:** the editor preserves a 4 KiB baseline,
   stages local dirty runs, detects concurrent modification before the write,
   performs bounded writes, verifies the entire page, independently reloads it,
   and records a verified rollback to the original CRC.
3. **Claim-separated evidence:** portable tests, Windows builds, driver I/O,
   live-VM behavior, mock benchmarks, and human-observed UI scenes are separate
   gates. Passing one cannot silently promote another.

The contribution is therefore a reproducible method for answering "what is
this physical page, what reaches it, what changed, and can you prove recovery?"
inside one Windows research workbench.

## Abstract

Windows memory tools usually make an operator choose between a friendly
process-memory editor, a page-table viewer, a forensic acquisition stack, and a
kernel debugger. That separation becomes painful when the question starts with
a physical frame number: who owns this page, which virtual address reaches it,
which translation entry grants access, what code or data does it contain, and
can a controlled modification be proven and reversed?

This talk presents KDBG, a Windows x64 PFN-centric memory workbench built around
that chain of evidence. A small kernel driver exposes bounded physical,
process-virtual, kernel-virtual, process-context, and translation primitives.
The user-mode application combines exact 4 KiB page editing, preflight conflict
detection, one-shot application, full read-back, independent reload, and
rollback with process scans, pointer paths, snapshots, PFN reverse mapping,
PTView-style walks, loaded kernel modules, exact-signature local symbols, and
x64 disassembly.

The engineering focus is not a permissive read/write primitive. It is making
low-level state observable and falsifiable: every boundary checks requested and
completed byte counts; every write-sensitive demonstration binds the target,
baseline, result, rollback, package identity, and capture evidence. The talk
also covers performance work that reduced same-machine mock First Scan latency
by roughly 4.9x and dense Next Scan backend calls from 262,144 to one, while
preserving exact-read fallback semantics. Mock numbers are labeled separately
from driver and VM runtime measurements.

The live demonstration follows one page from PFN to PID/VA/PTE, symbol and
disassembly context, then through a reversible edit inside a disposable Windows
VM. Attendees leave with concrete designs for page-table attribution,
transactional memory editing, truthful performance harnesses, and evidence that
survives a failed demo or a skeptical reviewer.

## Technical contributions

1. A PFN-first workflow joining physical memory, selected-process reverse
   mapping, page-table flags, module context, local symbols, and disassembly.
2. A physical-page transaction model with baseline, dirty runs, preflight,
   one-shot apply, full read-back, independent reload, and rollback evidence.
3. A bounded Windows driver/user ABI with exact byte-count and range contracts,
   single-controller lifetime, process context, LA57-aware translation, and
   kernel-only virtual reads.
4. High-throughput process analysis with aligned First Scan, density-bounded
   Next Scan batching, exact-read fallback, pointer scanning, address tables,
   verified Freeze, and checksummed snapshots.
5. Reproducible release and demo evidence that separates source, user-mode,
   WDK/package, live-VM, and optional MemProcFS claims.

## What this talk does not claim

- KDBG is not yet an execution debugger with breakpoints, register control, or
  single-step semantics.
- Mock benchmark timings are not driver, IOCTL, or target-runtime timings.
- Local-image PDB matching is not called live in-memory PE attestation until the
  VM evidence records that comparison.
- Historical package and VM results do not promote the current candidate.

## 45-minute outline

| Time | Segment | Evidence shown |
|---:|---|---|
| 0–4 min | The PFN attribution problem | one page, five disconnected tool views |
| 4–10 min | Driver and ABI design | IOCTL map, controller lifetime, range/byte-count invariants |
| 10–18 min | PFN → PID/VA/PTE | reverse mapper, LA57/4K/2M/1G walk, permissions |
| 18–24 min | Kernel context | module catalog, exact local PDB, kernel-only read, Zydis output |
| 24–31 min | Transactional edit | baseline, diff, preflight, one-shot apply, read-back, reload, rollback |
| 31–36 min | Process analysis | First/Next Scan, pointer path, address list, verified Freeze, snapshot |
| 36–40 min | Performance without false claims | schema-2 median/p95 harness and mock/live separation |
| 40–43 min | Product and evidence engineering | package identity, lifecycle rollback, capture manifest |
| 43–45 min | Failure modes and takeaways | short I/O, stale PID/CR3, symbol mismatch, demo recovery |

## Live demo spine

1. Boot the disposable Windows VM from the named snapshot and display package
   hashes, test-signing state, driver readiness, and locked write state.
2. Query KDbgProbe and load its exact 4 KiB PFN.
3. Show PFN ownership and follow PID/VA/PTE into the page-table view; confirm the
   final PA/PFN round trip.
4. Open a kernel module, load exact-signature local symbols, read a kernel VA,
   disassemble it, and hand the address to Page Tables.
5. At offset `0x100`, stage the shared eight-byte XOR mask
   `4B 44 42 47 A5 5A 3C C3` against the Probe baseline. Show the one exact
   dirty run, preflight, typed-PFN one-shot unlock, apply, full-page read-back,
   independent reload, rollback, restored baseline CRC, and final locked gate.
6. Run a process scan/pointer/snapshot sequence and show schema-2 benchmark JSON
   with `mock_only` and non-product-runtime labels visible.
7. Stop and restart the services, reconnect, and show that the write state is
   locked and no persisted Freeze is reactivated.

## Demo resilience

- Record every one of the 20 exact `kdbg.live-evidence.v4` scene identifiers
  from the same hash-bound package before travel. The authoritative ordered
  recording map is in [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md).
- Keep raw baseline/preflight/read-back/reload/rollback pages and the validated
  evidence manifest plus the hash-bound 20-scene human-review JSON beside the video.
- Prepare a read-only path through PFN attribution, PTView, modules, symbols,
  and disassembly if the write-sensitive segment cannot run.
- Never substitute archived evidence or a different package after a failure;
  display the failed gate and continue with the matching capture.

## Current 1.1.0 evidence boundary

| Gate | Current state |
|---|---|
| Source and deterministic tests | **PASS** — layout, core build, CTest 9/9 and source validator; snapshot `8f9a0474…f6a9` |
| MSVC/WDK Release and packages | **PASS (UNSIGNED PRODUCT EPOCH)** — main `3698e533…36f`, symbols `0b6dadf7…849`; production signature/timestamp not proved |
| Windows 11 required-core | **PASS (VM TEST TRUST)** — `run-20260918T091747Z-21a27820`, summary `c6bb846f…e50b`, archive `0457ba53…f6a9`; ABI 6, eight-byte apply, full read-back, 4096-byte rollback, locked cleanup, restore and Off |
| Windows 11 extended lifecycle/soak | **PASS (VM TEST TRUST)** — `extended-20260918T092819Z-66c07a32`, summary `12570c4c…6ee`, archive `f4c80a7c…c9c`; 2 cycles, 10 stop/start, 4 reboots, 1800-second soak, 488 reads, midpoint transaction, 7 benchmark runs, cleanup/restore/Off |
| Formal ordered 20-scene GUI evidence | **AUTOMATED CAPTURE PASS / HUMAN REVIEW FAIL (UNCHANGED)** — `run-20260918T092129Z-f14f5f7a`, 24 captures/20 scenes, `evidence_pass=false` |
| Presentation-only overlay | **PASS** — `run-20260918T102055Z-6c85cee7`, automatic and independent human presentation review PASS; 24 captures/20 scenes, cleanup/restore/Off |
| Final video-only artifact | **PASS FOR PRESENTATION QUALITY / NOT SUBMISSION PROOF** — `KDBG-demo-final2.mp4`, SHA-256 `4cd5a4f7…454`, 9,974,541 bytes, 1920x1080, 10 fps, 40.5 seconds, 405/405 frames; report `e13ddce3…1b7` |
| Formal GUI evidence human review | **FAIL (UNCHANGED)** — presentation overlay does not change `evidence_pass=false`; no deck or GIF is a current deliverable |
| Production signing/TSA and returned-driver clean-guest verification | **BLOCKED EXTERNAL** |
| Monitored support/security intake acknowledgement | **PENDING EXTERNAL/ORGANIZATIONAL** |

The physical-write and extended lifecycle claims are backed by the current
exact 1.1.0 test package. The captured ownership/PTView/Freeze/Kernel Explorer
scene set is retained as automated evidence and its formal readability review
remains failed. The separate overlay and final MP4 satisfy the presentation-
quality gate only. The older final v4 remains historical 1.0.0 evidence.
Speaker identity, biography, contact and conference-submission fields remain
outside the technical gate.

Presentation-only overlay summary/guest/capture SHA-256 are:

- `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`
- `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`
- `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`

Final video report SHA-256 is
`e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.
Final video SHA-256 is
`4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`.

## Submission fields still requiring the speaker

- Speaker name, biography, prior talks, contact details, and travel constraints.
- Disclosure status and any employer/client approval required for screenshots or
  code release.
- Final session length and format selected in the CFP form.
- A link to the reviewed demo video and, if public release is intended, the exact
  source/package revision.

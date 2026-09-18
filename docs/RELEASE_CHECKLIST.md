# KDBG 1.1.0 release checklist

Status date: 2026-09-18 KST. A gate is PASS only when the current workspace has
the command result and required artifact. Historical or external results do not
promote the current gate.

Epoch boundary: 1.1.0 is the current release target on branch
`feature/kdbg-1.1.0`. The unsigned build epoch is
`product-1.1.0-rc1-final-20260918`; the VM-test-signed derivative is
`product-1.1.0-rc1-test1-20260918`. Historical 1.0.0 hashes and
`product-rc1/test2` paths below remain evidence only for their named immutable
epochs and do not promote a 1.1.0 gate.

| Gate | PASS requirement | Current state |
|---|---|---|
| Source-complete | layout, core build/test, source validator | **PASS** — layout, core build, CTest 9/9 and source validator passed; source snapshot `8f9a0474…f6a9`, scope `bd2c93da…8932` |
| Windows-build-verified | MSVC Release GUI/bridge plus WDK signing inputs, validated main package and hashes | **PASS (UNSIGNED PRODUCT EPOCH)** — main `3698e533…36f`, symbols `0b6dadf7…849`; this is not production trust |
| Live-device-run-report | exact packaged drivers, controlled Probe transaction and final lock | **PASS (VM TEST TRUST)** — required-core run `run-20260918T091747Z-21a27820`, summary `c6bb846f…e50b`, archive `0457ba53…f6a9` |
| Live-VM-verified | ownership/PTView/Kernel Explorer and lifecycle/soak | **PASS for automated VM/lifecycle gates; formal GUI evidence review FAIL** — extended run `extended-20260918T092819Z-66c07a32` passed, while the official source-bound GUI run remains `evidence_pass=false` |
| Presentation-video-quality | video-only artifact, scene/capture counts and independent readability review | **PASS (PRESENTATION-ONLY)** — overlay run and final MP4 passed automatic and independent human review; this does not alter the formal GUI evidence flags or prove submission |

## Current 1.1.0 exact evidence

- Unsigned main ZIP SHA-256:
  `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f`.
- Symbols ZIP SHA-256:
  `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849`.
- Source snapshot/scope SHA-256:
  `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184` /
  `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
- VM-test-signed package SHA-256:
  `596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`;
  test certificate `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1`,
  signer thumbprint `ba34b393521d722ba01df87afccc6f3feb760b2c`.
- Required-core Windows 11 build 26200 run
  `run-20260918T091747Z-21a27820`: ABI 6, Probe PFN, eight-byte one-shot apply,
  full-page read-back, 4096-byte rollback, final lock, cleanup, checkpoint
  restore and final VM Off all passed. Summary/archive SHA-256:
  `c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b` /
  `0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`.
- Extended run: summary
  `12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee`,
  archive `f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`;
  two cycles,
  ten stop/start transitions, four reboots, 1800-second soak, 488 reads,
  midpoint transaction and seven benchmark runs passed, followed by cleanup,
  checkpoint restore and final VM Off.
- GUI run `run-20260918T092129Z-f14f5f7a` was captured automatically as
  `CAPTURED_UNREVIEWED`: summary
  `f5fd51ef18c319c37feb5adb997582e56cd2efe9b03a1d6ea3213237f6815d0b`,
  archive `6104933593259fb074466ba8d21a5fffd7e47803b2bfec71ce206e5c0a4ce252`,
  captures `bd254d7a98230db0199051085453b09ea33405f3efe57a9ded42b8a3bebb6d42`,
  24 captures/20 scenes. Human review is **FAIL**:
  the 1024 layout clips scene 03's grid and scene 20's diff row and wraps
  columns. `evidence_pass=false`; these formal source-bound flags remain
  unchanged.
- Presentation-only overlay run
  `out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7` passed its
  automated gate and independent human presentation review. Summary/guest/
  captures SHA-256:
  `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104` /
  `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce` /
  `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`.
  It contains 24 captures/20 scenes and finished with cleanup, checkpoint
  restore and VM Off. The scene 20 evidence-bound cue and scene 10/11 crops
  resolve the earlier visual blockers.
- Final video-only artifact (no deck/GIF):
  `out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`,
  SHA-256
  `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`,
  9,974,541 bytes, 1920x1080, 10 fps, 40.5 seconds, 405/405 frames. The
  report SHA-256 is
  `e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.

Production signer/TSA output, returned production-driver verification,
monitored support/security intake acknowledgement, formal source-bound GUI
human review, submission deadline/recipient and actual submission remain
unproved.

## Historical 1.0.0 completion inventory (not a 1.1.0 PASS)

The checked items through the next archive divider describe completed 1.0.0
engineering evidence. For 1.1.0 they become PASS only after the final package
rebuild and evidence rebind named in the authoritative table above.

### Source gate

- [x] `python .\src\tools\verify_layout.py`
- [x] `cmake --preset core-debug`, build, and CTest
- [x] `python .\src\tools\validate_release.py --source-complete`
- [x] Reconcile the current release notes/status documents, then rebuild the
  package so its source snapshot and packaged documents agree

### Windows build and package gate

- [x] Record Visual Studio/MSVC, Windows SDK, WDK, CMake, Python, and Syft versions
- [x] Run `.\src\tools\build.ps1 -Preset windows-release -Fresh -Package`
- [x] Confirm Release x64 versions and absence of Debug CRT imports
- [x] Confirm both SYS/INF/CAT sets; each INF declares its matching required CAT
- [x] Keep PDBs in the separate symbols package
- [x] Match every EXE/SYS RSDS GUID+age to its PDB and confirm CodeView stores only the PDB basename
- [x] Match main/symbol source snapshot and complete toolchain metadata exactly
- [x] Inspect SPDX SBOM, dependency pins, notices, and bundled licenses
- [x] Verify every main/symbol file through `SHA256SUMS.txt`
- [x] Validate main and symbols directories independently
- [x] Record ZIP and symbols ZIP SHA-256 sidecars
- [x] Run lifecycle script syntax and negative tamper tests
- [x] Confirm package-only VM tools include capture, live-evidence template/generator, and validator
- [x] Keep every generated report/page/log/media file outside the immutable package directory
- [x] Record that production signing and load success are not proved by package inspection

### Commercial operations contract

- [x] Package the security and private vulnerability-intake policy
- [x] Package supported-scope, lifecycle, diagnostics, and retention guidance
- [x] Package the no-automatic/network-telemetry and explicit local performance-data privacy policy
- [x] Package the MIT license/EULA decision and third-party redistribution rules
- [x] Package the manual offline update and rollback channel
- [x] Refresh release notes/status and republish the current 1771-check v4
  GUI/validator/document source snapshot as the paired main/symbol package
- [x] Build native elevated Setup with stable Program Files transaction,
  Install/Repair/Update/Uninstall, ARP/Start Menu registration and rollback
- [x] Exercise that exact packaged Setup across clean install, repair, update,
  uninstall and reboot, then prove registration/device/service/file cleanup
- [x] Configure support and security routes for the commercial release owner
- [ ] Prove route notification and end-to-end acknowledgement
- [x] Prepare all 11 production signing inputs
- [ ] Obtain production signer/TSA output and verify returned drivers on a clean guest

### Disposable VM lifecycle gate

The completed checks below are historical 1.0.0 evidence. Later 1.0.0 final
engineering runs also covered Windows 11 repeated lifecycle/reboot and soak;
neither set is automatically rebound to 1.1.0.

- [x] Confirm the owned disposable x64 guest and restorable snapshot
- [x] Confirm Administrator and supported test-signing configuration
- [x] Verify package, install, start, and pass `-RequireRunning`
- [x] Confirm both devices and ABI from the exact packaged binaries
- [x] Confirm pre-open runtime identity hashes match the exact verifier and both running packaged drivers
- [x] Stop/remove, reboot/reinstall, and update/rollback the package cleanly
- [x] Confirm default uninstall retains package and user data
- [x] Run explicit `-PurgePackage -PurgeUserData`; after helper exit confirm no package/user-data file remains
- [x] Run 2 full script-lifecycle cycles across 4 normal reboot boundaries and
  prove service 1060, device unavailable, registry/CIM/Driver Store/package/user-data/process cleanup

Completed: 10/10 stop/start cycles, installed-state reboot/start recovery, forced
GUI exit cleanup, default uninstall, distinct-driver prior-candidate repair/update/
rollback/forward-update, explicit package/user-data purge, absent service
registrations, and snapshot restore. Because 1.0.0 is the inaugural release, the
prior package is explicitly labeled a non-release candidate; the first post-1.0.0
release must repeat this with the published 1.0.0 package.

### Live evidence and demonstration gate

- [x] Discover the KDbgProbe PFN and record generation/CRC
- [x] Read exactly 4096 physical bytes and retain the baseline comparison
- [x] Show local hex edit, dirty diff, and Undo/Redo
- [x] Show typed PFN confirmation and one-shot unlock
- [x] Apply once and prove full expected/read-back match in the live-run JSON
- [x] Independently reload, roll back to baseline, and prove gate LOCKED
- [x] Validate the successful `kdbg.live-verify.v1` apply/rollback counters and final lock
- [x] Cross-check its three runtime identity hashes against candidate `artifact_sha256`
- [x] Show process/PID/VA/PTE ownership for the dedicated fixture PFN, distinct from Probe
- [x] Show PML5/PML4/PDPT/PD/PT visualization as applicable and final PFN match
- [x] Show scan, address-list/Freeze, pointer, disassembly, and snapshot scenes
- [x] Show Kernel Explorer module, symbol, and bounded kernel-read disassembly scenes
- [x] Produce a candidate with private paths, notifications, and unrelated process/memory data redacted
- [x] Generate the complete historical media candidate and hash it with the command log
- [x] Complete and hash-bind the 20-scene review JSON with reviewer/time, ranges, notes, and redaction decisions
- [x] Validate `kdbg.live-evidence.v4`, analysis metadata, and live-run report against the exact main/symbol package pair

Historical exact-package evidence is under
`out/evidence/public-symbols-r1-live/final-calibration-35-v4-published/` and the
77-entry final archive SHA-256 is `438881e7…a18e3`. Completed review and v4
validation are PASS only for `b6832712…e47f`. The historical Windows 11 required-core run
`run-20260918T042905Z-f19bda60` is PASS on Windows 11 Pro x64 build 26200, with
exact package/source hashes, guest cleanup, checkpoint restore and final VM Off.
Later 1.0.0 engineering evidence completed interactive GUI/media, repeated
reboot/lifecycle, the full process Freeze/ownership/PTView/Kernel Explorer
matrix and soak. Production signer/TSA/returned drivers and support/security
notification/ack evidence remain separate release gates; VM test trust does not
promote production signing or timestamp trust. The 1.1.0 release uses one MP4;
no slide deck or GIF is a current deliverable.

Optional MemProcFS is recorded separately. Its failure does not become a PASS;
the selected-process fallback requires its own ownership/PTView evidence.

---

## ARCHIVED / HISTORICAL release checklist

> The checklist below is preserved verbatim as a historical evidence index.
> Its `Current claim` column is not the current working-tree gate state; the
> gate table at the top of this file is authoritative for the current tree.

# KDBG 1.0.0 release checklist

기준: 2026-09-16 KST

| Gate | Required evidence | Current claim |
|---|---|---|
| Source-complete | layout, strict build/test, source validator | PASS |
| Windows-build-verified | MSVC Debug/Release, `/analyze`, WDK Debug/Release | PASS |
| VM-prerequisite-verified | existing `Windows-VM`, checkpoint, Administrator, test-signing | PASS |
| Interim physical transaction | ABI 6 Probe write/read-back/reload/rollback/gate lock | PASS — `DADF43AA...`, not final package |
| Candidate advanced read-only | `D3390AD4...` GUI/process/PFN/PTView workflow | PASS — no physical/process writes |
| Final-package-verified | source scope, version/arch/config, symbols split, SHA, SPDX, reproducibility, negatives | PASS |
| Final-package read-only/lifecycle | exact deploy/hash binding, device/main ABI6, fresh Probe/4 KiB read, invalid IOCTL rejection, stop/remove | PASS — physical writes 0 |
| Final write-sensitive/v2 | physical/process write, Freeze, Driver Verifier, hash-bound v2 | PASS |
| Exact-package DPI matrix | 100/125/150/200% existing VM profile captures | PASS |
| Optional MemProcFS backend | v5.18.11 out-of-process runtime | BLOCKED — fallback PASS |

- [x] Record toolchain versions and clean commands.
- [x] Record deterministic source-snapshot SHA-256 when Git metadata is unavailable.
- [x] Build/test Clang Debug and Release with warnings as errors.
- [x] Build/test ASan/UBSan and run sanitized benchmark.
- [x] Run clang-tidy analyzers and MSVC `/analyze /WX`.
- [x] Build/test Windows GUI/bridge Debug and Release.
- [x] Build both WDK drivers Debug and Release; produce SYS/PDB/INF/CAT.
- [x] Record signature reality: no production trust claim; user-mode EXEs unsigned.
- [x] Run deterministic negative, malformed, rollback and cancellation tests.
- [x] Rerun all six requested benchmark classes against the current Windows Release binary.
- [x] Capture and inspect the current candidate GUI across the advanced read-only workflow.
- [x] Generate and validate main and symbols package candidates with `kdbg.source-snapshot.v1` metadata.
- [x] Verify the candidate ZIP output with a same-input rerun.
- [x] Inspect SPDX SBOM, dependency pins and bundled licenses.
- [x] Run 5/5 negative validator fixtures for hash tamper, PDB leak, Debug mix and fabricated live evidence.
- [x] Synchronize implementation, validation, traceability and execution-status documents.
- [x] Confirm the existing `Windows-VM` checkpoint, Administrator and test-signing prerequisites.
- [x] Record the interim ABI 6 Probe physical transaction without promoting it to final-package PASS.
- [x] Exercise candidate `D3390AD4...` read-only process/PFN/PTView workflows and return all gates locked.
- [x] Generate and hash a scoped 17-frame demonstration GIF from actual VM screenshots.
- [x] Deploy and hash-bind the exact Release package; open devices and verify main ABI 6.
- [x] Run final-package fresh Probe query, exact 4 KiB read-only access, and invalid IOCTL rejection with physical writes 0.
- [x] Complete interim Probe read/edit/write/full read-back/independent reload/rollback/gate-lock.
- [x] Complete candidate read-only process, built-in PFN reverse map, and PTView evidence.
- [ ] Current-candidate process write/Freeze fixture evidence is not present;
  the historical run cannot promote this gate.
- [x] Exercise optional MemProcFS v5.18.11 runtime; record `pmem` initialization exit 2 and fallback PASS.
- [x] Stop/remove the exact Release drivers and record lifecycle evidence.
- [x] Run targeted volatile Driver Verifier flags `0x132` and remove settings.
- [x] Record and review the scoped redacted demonstration GIF.
- [x] Capture exact-package DPI 100/125/150/200% and hash every image.
- [x] Validate the hash-bound `kdbg.live-evidence.v2` bundle and reviewed 17-scene GIF.

Exact package identity is externalized in `out/evidence/final-live-manifest.json` and
`out/evidence/RELEASE-HASHES.txt`. Optional MemProcFS remains unavailable at
`VMMDLL_Initialize(device=pmem)`; the required built-in ownership/PTView fallback passed.

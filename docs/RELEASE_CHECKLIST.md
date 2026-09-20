# KDBG 1.1.0 release checklist

Status date: 2026-09-21 KST. A gate is PASS only when the current workspace has
the command result and required artifact. Historical or external results do not
promote the current gate.

## Current working-tree boundary

The current product target is `LocalHost` RawPfn editing of the same bare-metal
Windows `runtime_host` that runs KDBG and its driver. Source/portable validation
is PASS (`verify_layout.py`, core build, CTest 14/14, release-validator tests
92/92, and `validate_release.py --source-complete`). The current ABI 7 WDK
driver build is PASS through pinned NuGet WDK `10.0.26100.2454`; Inf2Cat,
driver contract, and symbol verification pass, but the resulting drivers are
unsigned. Same-host read-only and Probe-write direct verifier evidence are
PASS. The separate RawPfn CLI transaction is PASS; the required visible GUI
RawPfn scene remains incomplete.

The current direct runtime-host report is
`out/evidence/local-host-source-fix3-runtime-host-5/evidence.json`; it binds
the test-signed package and records read-only plus Probe write/read-back,
rollback, and cleanup.
The separate manual-input RawPfn report is
`out/evidence/local-host-source-fix6-rawpfn/raw-pfn.json` (schema
`kdbg.live-verify.raw-pfn.v1`, SHA-256 `017c2808…2d68f1f7`).
The repaired source/package validation epoch is
`out/release-epochs/local-host-source-fix3-20260921`, with VM-only test-signed
derivative `out/release-epochs/local-host-source-fix3-test-signed-20260921`.

The current unsigned Windows Release/package epoch is
`out/release-epochs/local-host-source-fix6-rawpfn-20260921`. Package and symbol
validation pass; `tools/TargetProfile.psm1` is included. Main ZIP SHA-256 is
`6673371b89e41c5e602fc32cfe87a2fd84e830875b0d0e6a398d76beca0f3526` and
symbols ZIP SHA-256 is
`56d91768eb9b727274058e364fa9996fd8b8f76aeea6eafd657ed92d1f5cb9ad`.
The source snapshot SHA-256 is
`2f5f82df9b400c5fc920cc80af83f4ab3aba965b0cd7de5ae409dfc59df829f6`.
These are unsigned build/package identities only; they do not establish
production signing or live memory access.

The RC4 table and artifacts below are historical records bound to their exact
source/package identities; they do not override this working-tree boundary.

Epoch boundary: 1.1.0 is the current release target on branch
`feature/kdbg-1.1.0`; the RC4 product-source commit is
`4b376bb0d61eab232af8a2f7f29033238b911022`. The unsigned build epoch is
`product-1.1.0-rc4-final-20260919`; the VM-test-signed derivative is
`product-1.1.0-rc4-test1-20260919`. Historical 1.0.0 hashes and
`product-rc1/test2` paths below remain evidence only for their named immutable
epochs and do not promote a 1.1.0 gate.

| Gate | PASS requirement | Current state |
|---|---|---|
| Source-complete | layout, core build/test, source validator | **PASS** — layout, core build, CTest 14/14 and source validator passed; current source snapshot `2f5f82df…9df829f6`, scope `bd2c93da…8932` |
| Windows-build-verified | MSVC Release GUI/bridge plus WDK signing inputs, validated main package and hashes | **PASS (UNSIGNED PRODUCT EPOCH)** — main `6673371b…ca0f3526`, symbols `56d91768…1f5cb9ad`; this is not production trust |
| Live-device-run-report | exact packaged drivers, controlled Probe transaction and final lock | **PASS (SEPARATE RUNTIME-HOST EVIDENCE)** — `out/evidence/local-host-source-fix3-runtime-host-5/evidence.json`; strict read-only and Probe-write validation pass |
| Bare-metal RawPfn transaction | manual PFN input, exact 4 KiB apply/read-back/reload/rollback, final lock | **PASS (CLI evidence)** — `out/evidence/local-host-source-fix6-rawpfn/raw-pfn.json`; visible GUI `RawPfn | manual PFN entry` scene not captured |
| Live-VM-verified | required-core plus optional extended/lifecycle/soak | **PARTIAL** — RC4 required-core PASS; optional extended/lifecycle/soak **NOT RUN**; historical RC1 result not rebound |
| GUI capture evidence | host/capture/archive integrity plus formal human review | **INTEGRITY PASS / FORMAL REVIEW INCOMPLETE** — `run-20260919T015850Z-1cfb0381`; `CAPTURED_UNREVIEWED`, `evidence_pass=false`, `human_review_complete=false` |
| Presentation-video-quality | redacted video-only artifact and independent readability review | **PASS (AUTOMATIC + INDEPENDENT PRESENTATION REVIEW)** — public-v4 passed; v2/v3 superseded; no formal promotion |
| Source freeze | annotated RC tag bound to exact source commit | **PASS (PUBLISHED RC TAG)** — `v1.1.0-rc4` is published to `origin` at `4b376bb0d61eab232af8a2f7f29033238b911022` |
| Production signing/release | trusted returned artifacts and stable tag/release | **BLOCKED** — staged inputs only; no production signer/HSM/TSA, returned signed artifacts, stable `v1.1.0`, or public release |

## Historical RC4 exact evidence

- Unsigned main ZIP SHA-256:
  `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9`.
- Symbols ZIP SHA-256:
  `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68`.
- Source snapshot/scope SHA-256:
  `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92` /
  `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
- Benchmark executable SHA-256:
  `7999ed886e5b8710f48cd8d08405e6aa8d52608cc4672b0980b7c696fcdef63f`.
- VM-test-signed package SHA-256:
  `7f7c179738eb670ca79d6c41bc9c46c445c1ffd31811c46f39bbbdcad3df45d5`;
  test certificate `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1`,
  signer thumbprint `ba34b393521d722ba01df87afccc6f3feb760b2c`.
- Required-core Windows 11 build 26200 run
  `run-20260919T015729Z-8445dddb`: ABI 6, Probe PFN, eight-byte one-shot apply,
  full-page read-back, 4096-byte rollback, final lock, cleanup, checkpoint
  restore and final VM Off all passed. Summary/archive SHA-256:
  `4ad612d9298d902066a95c47a64c213454ce229e2ebf23ea153b8e0a702f57b5` /
  `39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da`.
- RC4 optional extended/lifecycle/soak: **NOT RUN**. Any RC1 result is
  historical only.
- GUI run `run-20260919T015850Z-1cfb0381`: host/capture/cleanup/checkpoint and
  archive/hash integrity PASS; 24 frames, 20 scenes, 21 assertions, 229 actions.
  Summary/guest/captures SHA-256:
  `ded51b6fc1a71f670e00e709b53987416823f400c6d9e7010b2c7e55dc642cb1` /
  `c877e2b3695faf6489f0ff3fa517a97eb0cc6f0f334a0a4a4bad900f14446cf4` /
  `abfe37fe1694fe8e35229c306663dde0cc4ff688d1a1fa80139f74c8ea9b3695`.
  Formal status remains `CAPTURED_UNREVIEWED`, `evidence_pass=false`, and
  `human_review_complete=false`.
- Initial RC4 MP4: compositor PASS, independent public-suitability FAIL because
  private paths and weak crops remained; internal-only.
- Public v2 failed independent review because the taskbar remained visible;
  public v2/v3 are superseded.
- Presentation-only public-v4 candidate:
  `out/demo-product-1-1-0-rc4-test1-public-v4-20260919/KDBG-1.1.0-demo-public-v4.mp4`,
  SHA-256 `43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`,
  9,553,416 bytes, 1920x1080, 10 fps, 405 frames, 40.5 seconds. Automatic
  compositor and independent presentation review PASS. Review covered 405/405
  frames, 20 scenes, 24 segments, and 19 boundaries; no rendered path, username,
  taskbar, notification, or unrelated process was visible and core claims were
  readable. Report/scenes/contact-sheet SHA-256 values are
  `406054011b2e47dc144631e17e63d920acb715e4076c303556a852fd1009bd88` /
  `9e4a0543f4aaa61f44a39674e737b212df20474b8f063f1b44aa99d6817dcd04` /
  `fa8597a86ae39318e4cd52f2eea0e135623fa77ccf07956ca983702fed59258b`.
  Raw `frames/` are excluded from the public bundle because they contain private
  paths or the taskbar. Final video-only delivery copy
  `out/release-media/KDBG-1.1.0-demo-public.mp4` has the same SHA/bytes, and its
  directory contains only that MP4.
- Production signing staging: 11 inputs under
  `out/production-signing/product-1.1.0-rc4-final-20260919-prepared`, request
  `3f94c26060bc437460b22ced778c52f1f70165e49a7ac57f0979c1a347f64001`;
  `signing_performed=false`, `network_submission_performed=false`.

Production signer/private key/HSM or service, RFC 3161 TSA, returned signed
artifact verification, monitored route acknowledgement, formal GUI review,
stable `v1.1.0` tag, and public release remain unproved. The published annotated
`v1.1.0-rc4` source-freeze tag is not a stable production release. DEF CON
submission is explicitly excluded from this checklist scope.

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

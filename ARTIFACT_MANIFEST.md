# KDBG artifact manifest

## Codex configuration

- 7 project agents in `.codex/agents/`
- 10 repository skills in `.agents/skills/`
- root and nested `AGENTS.md`
- status and execution plans in `docs/exec-plans/`

## Product source

- restricted WDM physical/process-memory driver
- deterministic contiguous-page probe driver
- packaged deterministic 4096-byte user-mode process fixture and protocol tests
- user/kernel ABI and real `DeviceIoControl` backend
- transactional physical and process write sessions with byte-level Undo/Redo
- Dear ImGui/DirectX 11 GUI and hex editor
- process scanner, persistent address list, verified edit/freeze
- pointer scanner and Zydis disassembly
- cancellable snapshot capture, CRC32, save/load, diff
- native isolated MemProcFS PFN bridge
- selected-process page-table reverse mapper
- PTView-style VA-to-PA visualization
- elevated native Setup with stable Program Files transaction, ARP/Start Menu,
  lifecycle delegation, last-good rollback and committed post-exit purge with
  persistent succeeded/failed/cancelled status
- opt-in bounded fixed-local runtime JSON with atomic persistence for process-scan
  and GUI frame-stall measurements
- Windows build/service/package/evidence scripts and packaged config examples

## Documentation

PRD, architecture, implementation status, test plan, threat model, UX, source adoption, attribution, traceability, troubleshooting, demo checklist, ADRs, and explicit release gates.

## Generated outputs

- actual MSVC binaries under `out/build/windows-{debug,release}`
- actual WDK SYS/INF/CAT/PDB under `out/drivers/{Debug,Release}`
- validated main/symbol packages and deterministic ZIPs under `out/package`
- clean-VM preflight and pre-KDBG guest-failure diagnostics under
  `out/test-artifacts`

## KDBG 1.1.0 release candidate

The current unsigned build epoch is
`out/release-epochs/product-1.1.0-rc1-final-20260918/`. Its Windows Release
build, CTest 9/9, driver build, package validation and source provenance checks
passed. Exact identities are:

| Artifact | SHA-256 | Additional identity |
|---|---|---|
| `KDBG-1.1.0-win-x64.zip` | `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f` | 3,724,808 bytes |
| `KDBG-1.1.0-win-x64-symbols.zip` | `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849` | 20,710,820 bytes |
| canonical source snapshot | `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184` | 275 files |
| source scope | `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932` | `kdbg.product-source.v1` |
| `kdbg_benchmarks.exe` | `72348dff8a0a1623fd922fa316d3bf898a60f54b49bdc34c58a115924c25d4cf` | unsigned epoch |

The VM-only test-signed derivative is
`out/release-epochs/product-1.1.0-rc1-test1-20260918/`. Its main ZIP SHA-256 is
`596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`.
The disposable-VM certificate SHA-256 is
`bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1`
and signer thumbprint is `ba34b393521d722ba01df87afccc6f3feb760b2c`. This is
test trust only, not a production signature.

Current Windows 11 evidence bound to that derivative is:

- required-core run
  `out/win11-validation/product-1-1-0-rc1-test1-20260918/runs/run-20260918T091747Z-21a27820/`:
  PASS; host summary `c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b`;
  guest archive `0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`.
- extended lifecycle/soak run
  `out/win11-validation/product-1-1-0-rc1-test1-20260918/extended-runs/extended-20260918T092819Z-66c07a32/`:
  PASS; summary `12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee`;
  extended evidence archive
  `f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`.
- GUI capture run
  `out/win11-gui-product-1-1-0-rc1-test1-20260918/run-20260918T092129Z-f14f5f7a/`:
  automation success with `CAPTURED_UNREVIEWED`, 24 captures and 20 scenes;
  summary `f5fd51ef18c319c37feb5adb997582e56cd2efe9b03a1d6ea3213237f6815d0b`,
  guest archive `6104933593259fb074466ba8d21a5fffd7e47803b2bfec71ce206e5c0a4ce252`,
  and captures digest `bd254d7a98230db0199051085453b09ea33405f3efe57a9ded42b8a3bebb6d42`.

The intermediate source-bound MP4 composition check passed for
`out/demo-product-1-1-0-rc1-test1-20260918/KDBG-demo.mp4`: SHA-256
`c368dde54d19f46fedd32895f319223221538c006fcf4626277665b8fe5aad3d`,
9,759,713 bytes, 40.5 seconds, 405 frames, 24 captures and 20 scenes. Its
report SHA-256 is
`5b92b9086cd2a503f46fd309f4fd20099644aa17e453385d5f3a053a9714fdd0`.
The required human visual review **failed** for release/presentation use because
the 1024-wide capture clipped or omitted critical content (scene 03 has no grid,
scene 20 clips the diff row, and text wraps). Therefore `evidence_pass=false`:
the MP4 exists and passes mechanical composition checks, but final submission
evidence is not complete. No slide deck or GIF is part of the current target.

A separate presentation-only overlay run is available at
`out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7/`. It completed
24 captures/20 scenes with cleanup, checkpoint restore and final VM Off. Its
summary, guest archive and captures digests are:

- `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`
- `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`
- `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`

The current presentation video is
`out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`:
SHA-256 `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`,
9,974,541 bytes, 1920×1080, 10 fps, 40.5 seconds and 405/405 frames. Its
report SHA-256 is
`e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.
Automatic composition and an independent presentation-only human review both
passed. This polished overlay/video replaces the lower-quality `c368dde5…ad3d`
MP4 for presentation use only. It is not source-bound formal evidence and does
not promote the official GUI run, `evidence_pass`, production signing or
commercial-release gates.

## Historical 1.0.0 evidence

Historical 1.0.0 hash-bound live-run JSON is under the main ZIP SHA-256-named
`out/evidence/final-candidate-<package-prefix>/` directory. Its nonhuman preflight
binds the six raw physical pages, dedicated-fixture analysis pages,
process-write/Freeze proof, Kernel Explorer evidence, and 20-scene review
candidate from the byte-identical runtime session. `v4-nonhuman-preflight.json`
passes. The media is deliberately marked
`pending-human-review`; a completed reviewer record and final
`kdbg.live-evidence.v4` are not claimed yet. Forced-exit, distinct-driver
update/rollback, explicit purge, and snapshot-restore evidence is under
`out/lifecycle-closeout/live/`.

The exact C4 package's two-cycle/four-reboot clean-guest script-lifecycle run,
including seven readiness reports and full post-uninstall inventory, is under
`out/evidence/final-candidate-c4ed32a3/multiboot-clean-guest/`. It is baseline
evidence for the lifecycle scripts, not a substitute for exercising the newer
native Setup executable in its own exact final package.

The historical Windows 11 required-core live proof is under
`out/win11-validation/product-rc1-win11-test2-20260918/runs/run-20260918T042905Z-f19bda60/`.
It binds the VM-only test-signed package SHA-256
`41f90e2bd76386513d197ae8d77382238a14549e63608dd39eb2d2b4e2c92934`
to source snapshot
`98700c7c7797725b116b0a6333d644bc4df1793397556ce3572e35d451551eca`.
The 18-entry `guest-evidence.zip` SHA-256 is
`c4341cb571a7955f998d0c70914ee41fd98cef2cf7c0e6f1f244459956356c9e`.
For that exact 1.0.0 derivative, this proves the Win11 ABI-6 KDbgProbe
read/write/read-back/reload/rollback/relock
transaction, cleanup, exact checkpoint restore, and final VM Off; it does not
promote the test signer to production trust or mark the optional extended
GUI/media, repeated-lifecycle, full-feature, or long-run gates as run.
The run is authoritative only for that exact historical ZIP. Later
harness/documentation edits
changed the current checkout, so the present worktree is not claimed to be the
tested snapshot. The original 302-file snapshot and its canonical record are
retained under
`out/release-epochs/product-rc1-20260918/source-snapshot/KDBG-1.0.0-source/`.
Its `SOURCE-SNAPSHOT-SHA256SUMS.txt` contains 302 records and hashes to the
recorded `98700c7c...51eca` identity.

These generated files are deliberately outside product source directories. The
current packager uses the explicit `kdbg.product-source.v1` allowlist in
`src/tools/package_windows.ps1`. It includes the complete `src` product,
build-tool, test, and fixture tree; license inputs; release workflow inputs;
root release files; and the named build/operator documents. Main and symbols
packages both retain the exact canonical record as
`SOURCE-SNAPSHOT-SHA256SUMS.txt` and disclose the allowlist in metadata.
`build_public_release.ps1` also preserves `before-configure`,
`before-package-publication`, and `after-packaging` manifest/metadata pairs
under the selected epoch's `source-provenance/` directory. It verifies the
frozen tree at both publication boundaries and passes the baseline digest into
the packager, which rechecks it immediately before its atomic publish.
Mutable run/evidence ledgers, including `docs/exec-plans/**`,
`docs/VALIDATION_REPORT.md`, and `docs/TRACEABILITY_MATRIX.md`, are excluded so
post-run bookkeeping cannot change the packaged product-source identity. The
source snapshot also does not embed:

- third-party `vmm.dll`
- signing private keys or certificates
- live-VM evidence and submission recording

Live-only outputs must be produced and validated separately in the designated
disposable snapshot VM.

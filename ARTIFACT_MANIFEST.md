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

## KDBG 1.1.0 RC4 release candidate

The current source-bound unsigned epoch is
`out/release-epochs/product-1.1.0-rc4-final-20260919/`, built from Git commit
`4b376bb0d61eab232af8a2f7f29033238b911022`. Its source, Windows Release,
CTest 9/9, driver, package, and provenance checks passed. Exact identities are:

| Artifact | SHA-256 | Additional identity |
|---|---|---|
| `KDBG-1.1.0-win-x64.zip` | `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9` | 3,724,846 bytes |
| `KDBG-1.1.0-win-x64-symbols.zip` | `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68` | 20,563,309 bytes |
| canonical source snapshot | `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92` | 275 files |
| source scope | `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932` | `kdbg.product-source.v1` |
| `kdbg_benchmarks.exe` | `7999ed886e5b8710f48cd8d08405e6aa8d52608cc4672b0980b7c696fcdef63f` | unsigned epoch |

The VM-only test-signed derivative is
`out/release-epochs/product-1.1.0-rc4-test1-20260919/`; its main ZIP SHA-256 is
`7f7c179738eb670ca79d6c41bc9c46c445c1ffd31811c46f39bbbdcad3df45d5`.
The disposable-VM certificate SHA-256 remains
`bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1`
with signer thumbprint `ba34b393521d722ba01df87afccc6f3feb760b2c`. This is
test trust only, not a production signature.

Current Windows 11 evidence bound to that exact derivative is:

- required-core run `run-20260919T015729Z-8445dddb`: PASS; host summary
  `4ad612d9298d902066a95c47a64c213454ce229e2ebf23ea153b8e0a702f57b5`;
  guest archive `39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da`;
  exact checkpoint restored and VM final state Off.
- GUI run `run-20260919T015850Z-1cfb0381`: host execution, capture, cleanup,
  checkpoint restore, and independent archive/hash integrity audit PASS; 24
  frames, 20 scenes, 21 assertions, and 229 actions; summary
  `ded51b6fc1a71f670e00e709b53987416823f400c6d9e7010b2c7e55dc642cb1`,
  guest evidence `c877e2b3695faf6489f0ff3fa517a97eb0cc6f0f334a0a4a4bad900f14446cf4`,
  captures `abfe37fe1694fe8e35229c306663dde0cc4ff688d1a1fa80139f74c8ea9b3695`.
  Its formal state remains `CAPTURED_UNREVIEWED`, `evidence_pass=false`, and
  `human_review_complete=false`; integrity PASS is not formal visual approval.
- RC4 optional extended/lifecycle/soak validation was **NOT RUN**. Any RC1
  extended result retained elsewhere is historical only and is not rebound.

The initial RC4 MP4 exists and passed the mechanical compositor, but independent
public-suitability review failed because private paths and weak crops remained;
it is internal-only and is not a release/presentation PASS. Public v2 also
failed independent review because the taskbar remained visible; v2/v3 are
superseded. The current redacted presentation-only v4 artifact is
`out/demo-product-1-1-0-rc4-test1-public-v4-20260919/KDBG-1.1.0-demo-public-v4.mp4`:
SHA-256 `43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`,
9,553,416 bytes, 1920x1080, 10 fps, 405 frames, and 40.5 seconds. The automatic
compositor and independent presentation review passed. Review covered 405/405
frames, 20 scenes, 24 segments, and 19 boundaries; no rendered path, username,
taskbar, notification, or unrelated process was visible, and the core claims
were readable. Exact review bindings are report
`406054011b2e47dc144631e17e63d920acb715e4076c303556a852fd1009bd88`,
scenes `9e4a0543f4aaa61f44a39674e737b212df20474b8f063f1b44aa99d6817dcd04`,
and contact sheet
`fa8597a86ae39318e4cd52f2eea0e135623fa77ccf07956ca983702fed59258b`.
The video-only delivery copy is
`out/release-media/KDBG-1.1.0-demo-public.mp4` with the same SHA-256 and byte
count; that directory contains only the MP4. Raw `frames/` remain excluded from
the public bundle because they contain private paths or the taskbar. This
presentation PASS does not promote the formal GUI evidence flags.

Production signing inputs are staged at
`out/production-signing/product-1.1.0-rc4-final-20260919-prepared/`: 11 exact
inputs, request SHA-256
`3f94c26060bc437460b22ced778c52f1f70165e49a7ac57f0979c1a347f64001`,
`signing_performed=false`, and `network_submission_performed=false`. No
production certificate/private key, HSM or signer service, or RFC 3161 TSA is
available in this workspace. Annotated source-freeze tag `v1.1.0-rc4` is
published to `origin` at commit `4b376bb0d61eab232af8a2f7f29033238b911022`; stable tag
`v1.1.0` and release publication remain blocked until returned
production-signed artifacts are verified. DEF CON submission is explicitly
outside this release-work scope.

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

# KDBG 1.1.0 validation report

Status date: 2026-09-21 KST

## Current working-tree gate summary (authoritative)

The product target is the local physical RAM exposed to the same bare-metal
Windows `runtime_host` that runs `KDBG.exe` and `KDbgDriver.sys`.
`orchestrator_host` is a lifecycle/evidence controller, not an implicit memory
target, and `regression_guest` is an independent regression lane.

| Gate | State | Current evidence boundary |
|---|---|---|
| Source-complete | PASS | layout, core configure/build, CTest 14/14, and `validate_release.py --source-complete` PASS |
| Release validator tests | PASS | `python -m unittest src.tests.test_validate_release`: 90/90 |
| ABI 7 exact-page transaction | SOURCE PASS | 4096-byte compare/write/full read-back implementation and deterministic coverage are present |
| Windows WDK driver build | PASS (PINNED NUGET, UNSIGNED) | WDK `10.0.26100.2454`; Debug/Release, Inf2Cat, driver contract, and symbol verification pass |
| Current Windows Release/package | PASS (UNSIGNED) | epoch `local-host-source-fix3-20260921`; package/symbol validation pass; production trust not claimed |
| Bare-metal runtime-host read-only | PASS | `out/evidence/local-host-source-fix3-runtime-host-5/evidence.json`; current test-signed package, ABI 7, live backend |
| Bare-metal Probe-write | PASS | same evidence; six 4 KiB artifacts, full rollback and final lock; strict validator PASS |
| Bare-metal RawPfn live write | NOT RUN | no actual runtime-host PFN write or read-back success is claimed |
| Historical regression-guest evidence | PRESERVED | remains bound to its recorded source/package identity and does not establish a current bare-metal gate |

LocalHost RawPfn is the ordinary product path. ProbeFixture is the default
destructive evidence target, not a restriction on product capability. Optional
machine/boot/session provenance is captured automatically when available; it is
not a manual confirmation or product prerequisite. No dedicated-machine,
recovery-plan, Probe-only, or equivalent new product usage restriction was added.

Current unsigned package identity: main ZIP SHA-256
`3386b2e02a4918da0bf85fd5a7eb79a8eb2c9936c805dd941ffc3cd639f54e70`, symbols
ZIP SHA-256 `365da09fc18cd621a97ddeb71930a3ad34fb8d557679e8e7e19ddc093ae4a624`,
and source snapshot SHA-256
`a75d84e3de1ee369a242891cee3df14785c7503470e5a7ba68733532ade88dc8`.
`tools/TargetProfile.psm1` is present in the package. The drivers are unsigned;
no production signature or runtime-host memory-write claim is made.

The remainder of this report preserves the RC4/RC1 and earlier evidence as
historical records. Its PASS results are not rebound to the current working tree.

The current source-fix3 package epoch is
`out/release-epochs/local-host-source-fix3-20260921`; its VM-only test-signed
derivative is `out/release-epochs/local-host-source-fix3-test-signed-20260921`
with package SHA-256
`c58fad5fe6cf7027115a6c3f599d548644a14278193e36c710ec71c884d1ae76`.
The GUI service registration now passes the raw driver path to SCM; the
embedded-quote regression is covered by the 90-test validator suite.
The package/install, host-facts, atomic-evidence, backend-name, and JSON-array
repairs were validated in both PowerShell 5.1 and PowerShell 7. The current
signed-package runtime-host evidence is
`out/evidence/local-host-source-fix3-runtime-host-5/evidence.json`; strict
validation passes the Windows package, symbols package, read-only gate, and
Probe-write gate. RawPfn live-write remains NOT RUN.

## Historical RC4 report boundary

This report's RC4 boundary is Git commit
`4b376bb0d61eab232af8a2f7f29033238b911022`, unsigned epoch
`product-1.1.0-rc4-final-20260919`, and VM-only test derivative
`product-1.1.0-rc4-test1-20260919`. Source, Windows build/package, and exact
Windows 11 required-core validation have hash-bound PASS evidence. The RC4 GUI
run passed host execution, capture, cleanup, and independent archive/hash
integrity audit, but its formal state remains `CAPTURED_UNREVIEWED` with
`evidence_pass=false` and `human_review_complete=false`.

RC4 optional extended/lifecycle/soak validation was **NOT RUN**. Any RC1
extended PASS retained below is historical only and is not rebound to RC4. The
initial RC4 MP4 passed mechanical composition but failed public-suitability
review due to visible private paths and weak crops. Public v2 then failed
independent review because the taskbar remained visible; v2/v3 are superseded.
The redacted public-v4 MP4 passed the automatic compositor and independent
presentation review. Review covered all 405 frames, 20 scenes, 24 segments, and
19 boundaries; no rendered path, username, taskbar, notification, or unrelated
process was visible, and core claims were readable. Raw frames remain excluded
from the public bundle because they contain private paths or the taskbar.
Production signing inputs are staged, but no production signing or network
submission occurred. Annotated source-freeze tag `v1.1.0-rc4` is published to
`origin` at the recorded commit; stable tag `v1.1.0` and public release remain blocked. DEF
CON submission is explicitly outside this work scope.

## Historical RC4 1.1.0 gate summary

| Gate | State | Evidence in this workspace |
|---|---|---|
| Source-complete | PASS | layout, core build/CTest 9/9 and `validate_release.py --source-complete` PASS; source `966c51f2…0f92`, scope `bd2c93da…8932` |
| MSVC Release user-mode | PASS | exact `product-1.1.0-rc4-final-20260919` Windows Release build and CTest 9/9 |
| Sanitizers | BLOCKED (toolchain) | current MinGW distribution cannot link `-lasan` or `-lubsan` |
| Windows-build-verified | PASS | main `4dd98b12…34d9`, symbols `1f042e5e…ac68`, benchmark `7999ed88…f63f`; package/symbol validation PASS |
| Previous path-mapped exact package | PACKAGE/LIVE PASS (Windows 10) | cal35/final v4 remain bound to `b6832712…e47f`; no current-candidate rebind |
| Commercial operations documents | PASS / operational proof pending | support/security routes configured; notification and acknowledgement evidence missing |
| Production signing | INPUT READY / BLOCKED | 11 exact inputs, request `3f94c260…4001`; `signing_performed=false`, `network_submission_performed=false`; production signer/HSM/TSA and returned signed artifacts absent |
| Clean-VM package preflight | PASS (previous b683 exact package) | Windows 10 Pro build 19044: archive/hash validation, native Setup install, installed diagnostics/start and static-runtime execution PASS |
| Native Setup UX | LIVE PASS (previous b683 exact package) | Install/Repair/Update/Uninstall UI, exact roots, installed reboot, persistent purge, clean reboot inventory and snapshot restore PASS |
| Runtime telemetry | LIVE PASS (previous b683 exact package) | opt-in fixed-local JSON recorded a successful First/Next GUI sequence, nonzero completed bytes and frames, privacy flags false and writer errors 0; raw evidence carries exact counters |
| Clean-VM lifecycle/reboot | PASS (script lifecycle scope) | VMware snapshot VM: prior 10-cycle run plus exact C4 two-cycle/four-reboot run with seven readiness reports and clean service/device/registry/CIM/package inventory |
| Live-device-run-report | PASS | required-core `run-20260919T015729Z-8445dddb`; package `7f7c1797…45d5`, summary `4ad612d9…57b5`, archive `39c31476…57da` |
| Live-VM-verified | PARTIAL | RC4 required-core PASS; optional extended/lifecycle/soak **NOT RUN**; historical RC1 extended result is not rebound |
| GUI capture automation | INTEGRITY PASS / `CAPTURED_UNREVIEWED` | `run-20260919T015850Z-1cfb0381`; 24 frames/20 scenes/21 assertions/229 actions, cleanup/checkpoint restore/final Off; formal flags remain false |
| Initial RC4 media | FAIL (public suitability) | automatic compositor PASS, but independent review found private paths and weak crops; internal-only |
| Presentation media | PASS (automatic + independent presentation review) | public-v4 MP4 `43eda62e…5260`, 9,553,416 bytes, 1920x1080/10 fps/405 frames/40.5 s; 20 scenes/24 segments/19 boundaries reviewed; raw frames excluded; no formal promotion |
| Source freeze | PASS (published RC tag) | annotated `v1.1.0-rc4` is published to `origin` at `4b376bb0d61eab232af8a2f7f29033238b911022` |
| Commercial release | BLOCKED | production signer/private key/HSM or service, RFC 3161 TSA, returned signed artifacts, stable `v1.1.0`, and release publication remain absent |

Historical PASS evidence is never silently rebound to the current candidate.
The media/review boundary does not invalidate the RC4 required-core physical
transaction, but it also cannot substitute for RC4 extended or formal visual
review.

### Exact 1.1.0 identities and live observations

| Artifact/run | Exact result |
|---|---|
| Git commit | `4b376bb0d61eab232af8a2f7f29033238b911022` |
| Unsigned epoch | `out/release-epochs/product-1.1.0-rc4-final-20260919/` |
| Main ZIP | `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9` (3,724,846 bytes) |
| Symbols ZIP | `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68` (20,563,309 bytes) |
| Source / scope | `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92` / `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932` |
| Benchmark executable | `7999ed886e5b8710f48cd8d08405e6aa8d52608cc4672b0980b7c696fcdef63f` |
| VM test package | `7f7c179738eb670ca79d6c41bc9c46c445c1ffd31811c46f39bbbdcad3df45d5` |
| VM test certificate/signer | `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1` / `ba34b393521d722ba01df87afccc6f3feb760b2c` |
| Required-core | `run-20260919T015729Z-8445dddb`; ABI 6, one-shot apply/full read-back/reload/rollback/final lock, cleanup/restore/final Off |
| Required-core summary/archive | `4ad612d9298d902066a95c47a64c213454ce229e2ebf23ea153b8e0a702f57b5` / `39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da` |
| RC4 extended/lifecycle/soak | **NOT RUN** |
| GUI summary/archive/captures | `ded51b6fc1a71f670e00e709b53987416823f400c6d9e7010b2c7e55dc642cb1` / `c877e2b3695faf6489f0ff3fa517a97eb0cc6f0f334a0a4a4bad900f14446cf4` / `abfe37fe1694fe8e35229c306663dde0cc4ff688d1a1fa80139f74c8ea9b3695` |
| Presentation public-v4 MP4 | `43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260` (9,553,416 bytes; 1920x1080/10 fps/405 frames/40.5 s; automatic + independent presentation review PASS) |
| Presentation report/scenes/contact sheet | `406054011b2e47dc144631e17e63d920acb715e4076c303556a852fd1009bd88` / `9e4a0543f4aaa61f44a39674e737b212df20474b8f063f1b44aa99d6817dcd04` / `fa8597a86ae39318e4cd52f2eea0e135623fa77ccf07956ca983702fed59258b` |
| Video-only delivery copy | `out/release-media/KDBG-1.1.0-demo-public.mp4`; same MP4 SHA/bytes; directory contains only this MP4 |
| Production-signing request | `3f94c26060bc437460b22ced778c52f1f70165e49a7ac57f0979c1a347f64001`; 11 inputs; not signed/not submitted |

Multiple superseded ZIPs were exercised through the native Setup UI. `487bd9cb…745f5`
exposed a staged-root mismatch before service registration. `d294c547…d32b` completed
package verification and driver lifecycle but exposed PowerShell callback output
contaminating the structured result. `604823e0…9e71` then passed install, physical
write/read-back/rollback, repair, update and installed-state reboot before exposing a
purge worker inheriting the captured Setup output handle at Uninstall. The final native
launcher creates the detached purge worker with explicit non-inherited handles and
records persistent ProgramData status/logs. Failure evidence was retained,
and every run ended with snapshot restore and the KDBG VMware test VM stopped. These rejected candidates prove
the live installer gate detects product blockers; none is a successful release artifact.
The succeeding exact-package run completed Setup lifecycle, Probe physical transaction,
runtime telemetry, both reboot boundaries, uninstall cleanup and snapshot restoration.

## Reproducible source commands

```powershell
python .\src\tools\verify_layout.py
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

Observed current 1.1.0 result:

```text
Layout validation PASS
Core build and CTest 9/9 PASS
Release validator tests 75/75 PASS
Package lifecycle contracts 134 PASS
Windows Release build and CTest 9/9 PASS
Pinned NuGet WDK Release driver/CAT build PASS; Inf2Cat errors/warnings 0
Release driver symbols 2/2 PASS
Main/symbol package validation PASS
Release validation PASS: source-complete
Windows-build-verified PASS: exact main/symbol/source identities recorded
Windows 11 required-core PASS: ABI 6, one-shot apply/read-back/reload/rollback/final lock
Windows 11 optional RC4 extended/lifecycle/soak NOT RUN
GUI host/capture/integrity PASS: CAPTURED_UNREVIEWED, 24 frames/20 scenes/21 assertions/229 actions
Formal GUI review not complete: evidence_pass=false, human_review_complete=false
Initial RC4 MP4 public-suitability review FAIL: private paths and weak crops
Presentation public-v4 MP4 automatic + independent presentation review PASS
Production signing NOT PERFORMED; stable v1.1.0 tag/release blocked
```

The sanitizer preset compiled owned sources but could not link because this
MinGW installation has no ASan/UBSan runtime libraries. No machine-wide WDK is
installed; the locked NuGet fallback instead produced both current drivers and
catalogs. The paired package validator passed. Current Windows 11 evidence
proves disposable-VM test-signature trust, actual load, and the Probe physical
transaction. It does not prove RC4 optional extended workflows or production
publisher trust. The later final-v4 discussion is historical 1.0.0 evidence and
does not override the current RC4 gate states.

## Historical 1.0.0 mock performance snapshot

The schema-2 Release benchmark performs one warm-up and seven measured repeats.
It explicitly emits `mode: mock_only`, `live_driver_access: false`, and
`timing_represents_product_runtime: false`; these values are same-machine
regression evidence, not driver/IOCTL product claims.

| Metric | Current result |
|---|---|
| Physical 4 KiB mock transaction | 0.012 ms median; 200 writes; gate closed |
| First Scan, 32 MiB | 138.714 ms median, 230.690 MiB/s |
| Sparse Next Scan, 8192 candidates | 2.058 ms median |
| Dense Next Scan, 262144 candidates | 1 backend read, 35.611 ms median |
| Pointer cap, 32768 results | 7.267 ms median |
| Snapshot 16 MiB capture/save/load | 36.704/6.450/50.437 ms median; integrity PASS |
| Cancellation | 0.164 ms median, 15.966 ms p95 request-to-completion |

Deterministic tests cover the dense range-read path and the failed range-read
fallback to exact candidate reads.

## Reproducible Windows candidate command

Run on the prepared Windows/MSVC/WDK machine with Syft available:

```powershell
.\src\tools\build.ps1 -Preset windows-release -Fresh -Package
```

This builds/tests the Release GUI and bridge, builds Release drivers, stages and
validates the package, and creates deterministic-order ZIP files plus SHA-256
sidecars before publishing. Package directories, ZIP files, and sidecars are
published as one rollback set, so a staged validation or publish failure retains
the prior published set.

Independent checks after a real package exists:

```powershell
python .\src\tools\validate_release.py `
  --windows-package .\out\package\KDBG-1.1.0-win-x64 `
  --symbols-package .\out\package\KDBG-1.1.0-win-x64-symbols
Get-FileHash -Algorithm SHA256 .\out\package\KDBG-1.1.0-win-x64.zip
Get-FileHash -Algorithm SHA256 .\out\package\KDBG-1.1.0-win-x64-symbols.zip
```

Do not mark this gate PASS unless those artifacts exist and the command output
has been checked. CAT presence indicates catalog generation only; signature
trust and successful driver load are separate observations.

## Discarded VirtualBox preflight history

An earlier VirtualBox 6.1.32 guest was created for this pass rather than reusing the
archived VM. It is Windows 10 Pro x64 build 19044, has one internal-only adapter
(`kdbg-isolated`), no default route, Administrator access, and official
`testsigning Yes`. The pre-load snapshot is
`61e37cf7-e714-461a-aee0-0f40afcb0ce3`. No KDBG service or driver was installed
or loaded before that snapshot.

The first copied package exposed a real clean-machine defect: all three dynamic
MSVC runtime DLLs were absent. The build now uses the static MSVC runtime, and a
new package copy produced this guest result:

```text
OS: Microsoft Windows 10 Pro, build 19044, 64-bit
Visual C++ Redistributable: not required (static MSVC runtime)
KDBG service: not registered
KDBGProbe service: not registered
KDBG diagnostics PASS for the requested checks.
kdbg_live_verify.exe --help: exit 0
```

That discarded guest was not acceptable for live-write evidence. Before any KDBG
install/load, Windows repeatedly stopped with `IRQL_NOT_LESS_OR_EQUAL` (`0xA`).
The two non-empty mini dumps, one from initial OOBE and one after Guest
Additions, contain the same parameters (`1, 2, 0`) and the same kernel
instruction offset; three later dump files were zero-length after interrupted
capture. Disabling the demand-start `VBoxWddm` service allowed one login but did
not eliminate the next cold-boot failure. These observations establish a VM
substrate blocker, not a KDBG-driver failure. Current artifacts are under
`out/test-artifacts/vm-evidence/`; `vm-bcdedit-testsigning.png` records the BCD
setting and `vm-desktop-testmode.png` records the subsequent pre-KDBG stop. The
current live-device result instead comes from the VMware snapshot and evidence
listed in the gate summary and section 16.

## Package contents and lifecycle validation

The package contract requires:

- `KDBG.exe`, the isolated `kdbg_memprocfs_bridge.exe`, and packaged
  `tools/kdbg_live_verify.exe`
- KDbgDriver and KDbgProbe SYS/INF/CAT; each INF must name exactly its matching CAT
- example configuration, operator docs, project and third-party notices
- security, support, privacy, MIT/EULA, offline update/rollback, vulnerability
  intake and release-note documents
- SPDX 2.3 SBOM, build metadata, and complete lowercase SHA-256 manifest
- separate mandatory PDB-only symbols package with PE/PDB RSDS GUID+age matching
- diagnose/install/start/run/stop/uninstall plus package-only live-evidence tools

`validate_release.py` checks PE x64/version/dynamic MSVC CRT, exact INF/CAT pairing,
main/symbol source and toolchain provenance, PE/PDB GUID+age, CodeView path
privacy, SBOM names, manifest coverage, private-path/email leakage, lifecycle
markers, and PowerShell AST syntax for every lifecycle script.

## Lifecycle and recovery scope

The packaged flow verifies hashes before service mutation and binds KDBG service
paths to the extracted package. Update requires stopped old services and an
installer rerun; stop/remove refuse a same-named service registered to another
package. Start rolls back only services started by the failed attempt.
Uninstall retains extracted binaries and `%LOCALAPPDATA%\KDBG`.

Historical VMware evidence independently proves install/start, device/ABI open,
the Probe physical transaction, ten service cycles, reboot recovery, forced
GUI-exit cleanup, update/rollback, purge, and snapshot restoration for its named
epoch. RC4 independently rebinds only the required-core and GUI-capture scopes
listed above; RC4 extended lifecycle/soak was not run.

Current packaging negative checks:

```text
PowerShell direct parser: PASS (changed/new lifecycle and evidence scripts)
PowerShell AST invalid-script fixture: PASS (invalid script rejected)
Missing Release driver input: PASS (failed before altering published artifacts)
Publish rollback failure injection: PASS (old directory and sidecar restored)
SCM marked-delete mock: PASS for stop/uninstall/install (1072 -> 0 -> 1060)
SCM already-absent idempotency: PASS for stop/uninstall/install (1060)
Package lifecycle regression harness: PASS (27 checks)
git diff --check: PASS
```

The package start rollback now waits for every service it started and preserves
both the startup and cleanup failures. Install rollback restores path/type/start
through `sc.exe config`, then re-reads and compares the persisted configuration;
newly-created service deletion waits for SCM error 1060.

## Required live-VM evidence

The v4 live bundle must bind hashes of the exact main and symbols packages,
packaged GUI, bridge, live verifier, and both drivers. It must also bind a
successful `kdbg.live-verify.v1` report recording the KDbgProbe PFN, exact
4096-byte baseline/preflight, one-shot write, full read-back, independent reload,
verified rollback, final locked gate, ABI/counters, ownership PID/VA/PTE, and
page-table final PFN. Before either device is opened, that verifier requires
Windows x64 build 19041+ and hashes itself plus both SCM-configured running
kernel drivers; the validator cross-checks those three runtime hashes against
the exact package artifacts. The reviewed redacted demonstration must include a
separate hash-bound scene-review record with the real reviewer/time, GIF hash,
redaction decisions, and an observed millisecond range plus concrete note for
each of the 20 ordered scenes. The repository owner confirmed all scenes and
redaction decisions; final v4 SHA `fc0afb4b…9823` and final archive
`438881e7…a18e3` passed the official schema validator and independent audit.

## Historical 1.0.0 Windows 11 required-core live validation

The authoritative historical run is
`out/win11-validation/product-rc1-win11-test2-20260918/runs/run-20260918T042905Z-f19bda60`.
It ran on Windows 11 Pro x64 build 26200 in disposable generation-2 VM
`KDBG-Win11-25H2` (`66935024-37f7-4f21-b2c8-12ca5fe677bf`). The exact checkpoint
`KDBG-Win11-Clean-TestSigning-20260918`
(`f60a775a-26f6-4ef9-bb19-f61c93346bb4`) was restored and the VM ended Off.

| Binding/evidence | SHA-256 |
|---|---|
| VM-only test-signed package | `41f90e2bd76386513d197ae8d77382238a14549e63608dd39eb2d2b4e2c92934` |
| Source snapshot | `98700c7c7797725b116b0a6333d644bc4df1793397556ce3572e35d451551eca` |
| Host validation summary | `f5dc301f2e086c6fcfcec2743773a50da84bae2006a4a97c2c56bb6f79c53cb7` |
| Host preflight | `7f6ade71a20cf9ca88c852eee75a3bd1c06c138a275b9e002b05e87ed6a309df` |
| Guest evidence archive (18 entries) | `c4341cb571a7955f998d0c70914ee41fd98cef2cf7c0e6f1f244459956356c9e` |
| Guest validation summary | `faae5b196ced3092dc2dfa931cbfb9867a133c111d9fede47f03177937cd92ac` |
| Probe transaction report | `0636b7efe09a632e5e8bb0f009d4190b6632d5ab23bc702e82f10a50fa2bf204` |

Required core is PASS: ABI 6, KDbgProbe PFN `2117631`, one 8-byte apply at
offset `0x100`, exact full-page read-back, independent reload, 4096-byte
rollback, final write gate locked, package cleanup, exact checkpoint restore,
and final VM Off. The package is a VM-only test-signed derivative, not a
production-trusted release. This PASS applies to the exact ZIP named above;
the current checkout is a later, different source state and is not an independent
reproduction of the recorded `98700c7c…51eca` snapshot.

That required-core run did not include the extended scope. A later 1.0.0 final
engineering epoch completed interactive GUI capture, process Freeze,
ownership/PTView/Kernel Explorer evidence, repeated lifecycle/reboot and soak.
Neither historical result is a 1.1.0 rebind.

## Known unverified items

- Production publisher/signature trust; 11 inputs are prepared but signer/private key/HSM or service, TSA, and returned signed artifacts are absent
- Optional MemProcFS acquisition backend
- Formal human review of the RC4 source-bound GUI evidence; automation and
  integrity passed, but `evidence_pass=false` and `human_review_complete=false`
- RC4 optional extended/lifecycle/soak validation
- Configured commercial support/security routes lack notification/acknowledgement evidence
- Stable `v1.1.0` tag and public release publication; published `v1.1.0-rc4`
  source-freeze tag exists but is not a production release

The packaged `new_live_evidence.ps1`/validator mismatch was fixed in the historical
`product-rc1-20260918` source. The prior Windows 10 final archive retains its original
derived-generator/normalization provenance and remains bound to `b6832712…e47f`.

---

## Detailed historical 1.0.0 records and VMware addendum

> Sections 1-15 below are historical records and do not promote the current
> working-tree gates. Section 16 is the historical then-current VMware live-device addendum; the
> gate summary at the top remains the authoritative overall result.

# KDBG 1.0.0 검증 보고서

검증 일자: 2026-08-23 KST
최종 live addendum: 2026-09-16 KST — 아래 15절이 11~14절의 당시 BLOCKED 판정을 대체한다.

## 1. 환경과 안전 판정

| 항목 | 값 |
|---|---|
| OS | Windows 11 Pro x64, build 26200 (build host only; not current live-target proof) |
| Host | HP ProBook 물리 장비 |
| Privilege | 비관리자 |
| CMake / Ninja | 4.4.0 / 1.12.1 |
| Python | 3.11.9 |
| Clang | 22.1.8 |
| MSVC | 19.51.36248.0, tools 14.51.36231 |
| MSBuild | 18.7.8 |
| WDK | 10.0.28000.0 |
| Syft | 1.49.0, SPDX schema 16.1.10 |
| Git revision | 저장소에 `.git` metadata 없음; deterministic source-snapshot SHA-256 사용 |
| Live VM | 기존 `Windows-VM`; checkpoint, Administrator, test-signing 확인 |

Fresh core Debug/Release/sanitized/clang-tidy, Windows Debug/Release/`windows-analyze`, WDK Debug/Release clean과 package gates가 PASS했다. 기존 `Windows-VM`은 checkpoint, Administrator, test-signing 조건을 만족했다. 같은 VM에서 exact Release package의 deploy/hash binding/device/main ABI6/fresh Probe query/exact 4 KiB read-only/invalid IOCTL rejection/stop-remove를 physical writes 0으로 완료했다. Interim DADF physical transaction과 D339 advanced read-only 결과는 각자의 제한된 범위로 유지한다.

## 2. 필수 baseline

```powershell
python .\src\tools\verify_layout.py
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

최종 결과:

```text
Layout: PASS
Configure/build: PASS
CTest: 1/1 PASS
Direct test binary: 707 checks, 0 failures
Source-complete validator: PASS
```

검사 범위에는 PFN/ABI/overflow, exact and short I/O, full-page transaction/recovery, PID identity, scanner types and filters, malformed persistence, pointer bounds, snapshots, PFN reverse mapping, LA57/large pages, MemProcFS protocol/cancel/timeout가 포함된다.

## 3. Portable, sanitizer, static analysis

다음 preset을 모두 `-Fresh`로 configure/build/CTest했다.

```powershell
.\src\tools\build.ps1 -Preset core-debug -Fresh
.\src\tools\build.ps1 -Preset core-release -Fresh
.\src\tools\build.ps1 -Preset core-sanitized -Fresh
.\src\tools\build.ps1 -Preset core-clang-tidy -Fresh
.\src\tools\build.ps1 -Preset windows-analyze
```

| Gate | 결과 |
|---|---|
| Clang Debug strict warnings | PASS, CTest 1/1 |
| Clang Release strict warnings | PASS, CTest 1/1 |
| Windows Clang ASan/UBSan RelWithDebInfo | PASS, CTest 1/1, finding 0 |
| clang-tidy `clang-analyzer-*` warnings-as-errors | PASS, CTest 1/1 |
| MSVC `/analyze /WX` | PASS, CTest 1/1 |
| Sanitized benchmark correctness | six metrics PASS |

MSVC analyzer가 발견한 실제 결함은 null module handle, WOW64 constant condition, bridge/diagnostic/test stack pressure, function-pointer flow, SAL mismatch였다. 제품 코드를 수정하고 large test/session objects를 heap 또는 preallocated static storage로 이동했다. pinned `imgui_memory_editor`의 U64 formatter C6340은 KDBG wrapper header 안에서 해당 외부 헤더에만 범위를 제한해 suppression했다. KDBG-owned C6340은 계속 `/WX` 대상이다.

## 4. 실제 MSVC Windows build

```powershell
.\src\tools\build.ps1 -Preset windows-debug -Fresh
.\src\tools\build.ps1 -Preset windows-release -Fresh
```

두 preset 모두 실제 MSVC x64 GUI, native bridge, core tests를 compile/link했고 CTest 1/1 PASS였다.

- `KDBG.exe`: x64, FileVersion 1.0.0.0, ProductVersion 1.0.0
- `kdbg_memprocfs_bridge.exe`: x64, FileVersion/ProductVersion 1.0.0.0
- Release EXE에서 Debug CRT import 없음
- GUI에서 `Dbghelp` import 확인
- fetched ImGui checkout은 pinned docking commit이며 `IMGUI_HAS_DOCK` 활성

pinned Zydis/Zycore의 오래된 minimum CMake version과 Doxygen 미설치 경고는 외부 configure warning이며 KDBG compile/analyzer warning은 아니다.

## 5. 실제 WDK build

```powershell
.\src\tools\build_drivers.ps1 -Configuration Debug -Clean
.\src\tools\build_drivers.ps1 -Configuration Release -Clean
```

| Configuration | KDbgDriver | KDbgProbe | 결과 |
|---|---|---|---|
| Debug | SYS/PDB/INF/CAT | SYS/PDB/INF/CAT | PASS, errors 0, warnings 0 |
| Release | SYS/PDB/INF/CAT | SYS/PDB/INF/CAT | PASS, errors 0, warnings 0 |

두 INF 모두 `DriverVer=08/15/2026,1.0.0.0`으로 deterministic stamp됐다. WDK signability test와 CAT generation은 통과했다. build script는 불완전한 WDK kit와 MSBuild output의 `: error`를 fail-closed로 처리한다. 이 결과는 production certificate trust 또는 실제 load 성공을 뜻하지 않는다.

## 6. GUI와 local diagnostics

2026-08-20 Release package의 clean-profile 120 DPI 캡처는 historical이다. 현재
candidate `D3390AD4...`는 같은 live VM에서 Probe, process selector, memory map,
scanner/address list, disassembly, snapshot, pointer, PFN reverse mapping, Page Tables,
About와 최종 locked 상태의 full-window 캡처를 새로 만들었다. 따라서 현재 candidate
visual workflow는 PASS지만, 별도의 clean-profile DPI matrix는 재실행하지 않았다.

```text
Window appeared: PASS
Default docking: PASS
Left/central/right/bottom panes visible: PASS
Right tab overflow arrows visible: PASS
Normal CloseMainWindow shutdown: PASS
Forced termination: false
KDBG/KDBGProbe services after smoke: not registered
```

진단 smoke:

- 36,000 safe enum events → 3 rotating files, 각 파일 1 MiB 이하
- 파일 크기 227,198 / 1,048,570 / 1,048,570 bytes
- sensitive-pattern scan 0 matches
- intentional isolated unhandled exception → 171,894-byte `MiniDumpNormal`과 216-byte text report
- report에 UTC/PID/TID/code/address/write status와 `External transmission: none` 기록

crash smoke는 별도 temporary process/profile에서 수행했으며 제품 live driver를 사용하지 않았다.

## 7. 성능 benchmark — current Windows Release

최종 Windows Release build 뒤 `out/build/windows-release/benchmarks/kdbg_benchmarks.exe`를
다시 실행했다. 결과는 `out/evidence/benchmark-windows-release.json`에 있으며
deterministic mock-only이고 `live_driver_access=false`다.

| Metric | Result |
|---|---:|
| 200 × 4 KiB transaction | median 0.006 ms, p95 0.006 ms, max 0.035 ms |
| 32 MiB First Scan | 98.924 ms, 323.479 MiB/s, 8192 results |
| Candidate estimate | 581,632 bytes |
| Peak RSS / delta | 41,578,496 / 2,859,008 bytes |
| Next Scan | 1.941 ms, 8192 → 4096 |
| Pointer cap | 128/128, 0.171 ms |
| 16 MiB snapshot | capture 127.185, save 2393.239, load 105.435 MiB/s |
| Cancel response | 4.152 ms request-to-completion |

모든 correctness/cap/integrity/cancellation gate가 PASS였다. 관측 시간은 현재 호스트의 회귀 기준이며 일반화된 성능 보장은 아니다.

## 8. Release package

```powershell
.\src\tools\package_windows.ps1 -Configuration Release -Zip
python .\src\tools\validate_release.py `
  --windows-package .\out\package\KDBG-1.0.0-win-x64 `
  --symbols-package .\out\package\KDBG-1.0.0-win-x64-symbols
```

현재 candidate 검증 결과:

- main package validator PASS
- symbols package validator PASS
- required EXE/SYS/INF/CAT/config/tools/docs/licenses present and nonempty
- main package PDB 0; driver PDBs in separate symbols package
- SPDX-2.3 SBOM contains KDBG, ImGui, imgui_memory_editor, Zydis, Zycore
- `SHA256SUMS.txt` covers every packaged file exactly once
- package-local `diagnose.ps1 -VerifyPackage` PASS
- identical input으로 두 번 패키징한 main/symbol ZIP SHA-256이 각각 동일
- source revision이 없을 때 defined source snapshot의 SHA-256과 file count를 metadata에 기록

Fail-closed negative cases:

| Mutation | Expected | Result |
|---|---|---|
| hashed document content tamper | hash mismatch | rejected, exit 1 |
| PDB inserted into main package | symbols separation error | rejected, exit 1 |
| metadata changed to Debug | configuration mismatch | rejected, exit 1 |
| empty/fabricated live JSON | v2 schema/evidence errors | rejected, exit 1 |

2026-08-23에 source snapshot을 explicit root allowlist로 제한하고 metadata에
`source_snapshot_scope = kdbg.source-snapshot.v1`을 기록했다. source scope는 230개
파일을 포함하며 main/symbol strict validators가 PASS했다. 변경 없는 동일 입력으로
두 번 생성한 main/symbol ZIP은 각각 동일했고, package negative report는 5/5
expected exit-1이었다. 근거는 `out/evidence/package-provenance-candidate.txt`와
`out/evidence/package-negative-20260823-065145-394-75a2c8a6.json`이다. 문서 반영
후 최종 repack에서 공개 SHA만 갱신하며 candidate digest/ZIP SHA는 여기에 고정하지
않는다. Package PASS는 live PASS를 뜻하지 않는다.

## 9. 라이선스와 privacy

- dependency lock revisions match fetched ImGui docking, imgui_memory_editor, Zydis and Zycore sources
- project and all bundled dependency notices are included in `licenses/`
- MemProcFS is optional/out-of-process and is not bundled or linked into the GUI
- package text scan found no private user path or email address
- logs and crash dumps remain local; automatic telemetry/upload 없음

## 10. Same-VM ABI6 physical transaction

같은 continuously running `Windows-VM`에서 KDBG PID 1140, ABI 6으로 다음을
검증했다. write 대상은 KDbgProbe fixture 한 페이지뿐이다.

| 항목 | 값/판정 |
|---|---|
| Package identity | `DADF43AA...` — interim, final 아님 |
| Probe | PFN `0xDA9FE`, PA `0x00000000DA9FE000`, generation 1 |
| Baseline | CRC32 `0x9DA6C668` |
| Edit | offset `0x100`, `3D4E5F70` → `4B444247` |
| Preflight | PASS — full 4096-byte baseline match |
| Apply read-back | PASS — full 4096-byte expected match |
| Independent reload | PASS — full 4096-byte expected match |
| Rollback | PASS — full 4096-byte baseline match, CRC32 `0x9DA6C668` restored |
| Write gate | PASS — locked after transaction |
| Driver counters after rollback | reads 11, writes 2, rejected 0, stage 4, status 0, transferred 4096 |

Evidence:

- extracted directory: `out/evidence/live-20260823-110826-359/`
- archive: `out/evidence/live-20260823-110826-359.zip`
- archive SHA-256: `b8e88cb7cc78ab42f5edf0b4409b99ab4e6e60ab2761ed08f98233ee11bd0769`

## 11. D3390AD4 advanced read-only live

같은 `Windows-VM`에서 D3390AD4 candidate의 fresh Probe query와 read-only workflow를
수행했다. 이 candidate에서는 physical write를 실행하지 않았다(`NOT_RUN`).

| 항목 | 상태 | 실제 관측 |
|---|---|---|
| Built-in selected-process PFN reverse map | PASS | 2,000,000 table-page cap에서 mapping 1개 |
| Page-table visualization | PASS | selected VA의 최종 PA/PFN이 Probe `0x00000000DA9FE000` / `0xDA9FE`와 exact match |
| Process map/modules | PASS | memory regions/modules와 module header 표시 |
| First/Next Scan | PASS | first 26, next 26 |
| Address list | PASS | entry 1개, Freeze OFF |
| Disassembly | PASS | 456 instructions |
| Snapshot comparison | PASS | 4096 bytes, changed runs 0 |
| Pointer scan | PASS | 10,385 paths |
| About/counters/final safe state | PASS | process detached; process/physical gates LOCKED; physical page CLEAN |
| Optional MemProcFS | HISTORICAL BLOCKED | 이 당시 error 126; 15절 final attempt가 대체 |
| Process live write/freeze | HISTORICAL BLOCKED | 이 당시 read-only; 15절 final PASS가 대체 |
| Candidate physical write | BLOCKED | `NOT_RUN`; successful physical write evidence remains DADF interim only |

Evidence manifest: `out/evidence/candidate-d3390ad4-advanced-live.json`.

## 12. Demonstration media

`out/evidence/KDBG-1.0.0-demonstration.gif` is PASS for its declared scope: 17
frames at 1280×720, with frames 1–5 showing the interim ABI6 physical transaction
and frames 6–17 showing D339 candidate read-only validation. It is not final-package
`kdbg.live-evidence.v2`가 아니었다. 이 당시 판정은 15절 final v2 PASS가 대체한다.

## 13. Exact Release read-only/lifecycle gate

동일 `Windows-VM`에서 exact Release package에 대해 다음을 검증했다.

| 항목 | 상태 | 경계 |
|---|---|---|
| Deploy and hash binding | PASS | exact identity는 external manifest/hash set에 기록 |
| Device/main ABI | PASS | ABI 6 |
| Fresh Probe query | PASS | clean fixture query |
| Physical read-only | PASS | exact 4096-byte read; physical writes 0 |
| Invalid IOCTL rejection | PASS | fail-closed rejection |
| Stop/remove | PASS | both drivers stopped and removed |
| Final physical write | HISTORICAL BLOCKED | 이 당시 `NOT_RUN`; 15절 final PASS가 대체 |

Authoritative identity/evidence binding:

- `out/evidence/final-live-manifest.json`
- `out/evidence/RELEASE-HASHES.txt`

Source documentation intentionally does not embed the Release ZIP digest.

## 14. VM prerequisite와 남은 BLOCKED gate

| 항목 | 상태 | 실제 범위 |
|---|---|---|
| 기존 `Windows-VM` checkpoint | PASS | 복원 가능한 checkpoint 확인 |
| Administrator | PASS | guest 관리자 세션 확인 |
| test-signing | PASS | guest test-signing 활성 확인 |
| 이전 package install/start | PASS | 이전 ZIP 설치 및 두 서비스 Running |
| 최종 main/symbol package | PASS | new scope, validators, reproducibility, 5/5 negative fixtures |
| Interim package device/ABI6/Probe transaction | PASS | same VM, PID 1140, full-page transaction evidence |
| D339 candidate advanced read-only | PASS | reverse map/PTView/process read-only workflow; final gates locked |
| Scoped demonstration GIF | PASS | interim physical + D339 read-only frames |
| Final Release read-only/lifecycle | PASS | external hash binding, ABI6, Probe/4 KiB read, invalid IOCTL, stop/remove; writes 0 |

다음은 이 보고서에서 PASS가 아니다.

- final physical write (`NOT_RUN`)
- Driver Verifier (`NOT_RUN`)
- process live write/freeze
- optional MemProcFS runtime (`vmm.dll` error 126)
- final-package hash-bound `kdbg.live-evidence.v2`

VM 전제, package gate, exact Release read-only/lifecycle, interim ABI6 physical transaction,
D339 advanced read-only workflow와 scoped GIF는 PASS다. 현재 차단 원인은 final physical
write, Driver Verifier, process write/freeze, optional MemProcFS와 final v2 evidence다.
문서 repack 후 같은 read-only/lifecycle 검증을 재실행해 external manifest/hash를
갱신한다. Production Authenticode trust는 주장하지 않는다.

## 15. 2026-09-16 exact-package 최종 live addendum (historical at that time)

이 절은 11~14절의 역사적 candidate/당시 BLOCKED 상태를 대체한다. Runtime ZIP은
`91042aab214e4c56daca29159b46c81574afb2aac700257d46baa7a8bf99e54f`로 고정했다.

| Gate | 최종 상태 | 실제 증거 |
|---|---|---|
| Driver Verifier | PASS | volatile `0x132`, `KDbgDriver.sys`/`KDbgProbe.sys`, cleanup PASS |
| Exact physical transaction | PASS | PFN `0xBC1E6`, 4096-byte preflight/read-back/reload/rollback, baseline 복원, gate lock |
| Process write/Freeze | HISTORICAL PASS ONLY | dedicated 4096-byte buffer run was recorded for the archived candidate; its artifact is absent from the current workspace and does not promote the current gate |
| PFN owner/PTView | PASS | PID `10072`, VA `0xFFFFBA8098262000`, PTE PA `0x3A991310`, PML4/PDPT/PD/PT, final PA exact match |
| DPI 100/125/150/200% | PASS | exact package, 기존 VM 사용자 프로필, 네 PNG의 SHA-256 기록 |
| Hash-bound evidence v2 | PASS | 17-frame 1600x900 GIF, redacted log, six raw page files, four final artifacts, validator exit 0 |
| Stop/remove/safety | HISTORICAL PASS ONLY | archived candidate cleanup included the process fixture; current VMware cleanup proves service removal and Probe restoration only |
| Optional MemProcFS v5.18.11 | BLOCKED (optional) | error 126 해소 후 `VMMDLL_Initialize(device=pmem)` exit 2; built-in fallback PASS |

Authoritative evidence:

- `out/evidence/final-91042aab-unblock-result.json`
- `out/evidence/final-91042aab-v2-raw/`
- `out/evidence/dpi-final-91042aab/`
- `out/evidence/final-91042aab-live-evidence-v2.json`
- `out/evidence/final-91042aab-live-evidence-v2.gif`
- `out/evidence/final-91042aab-live-command-log.txt`

당시 v2 media는 exact final runtime 값/raw hashes와 exact-package DPI 캡처를 결합했다.
이전 ABI6 GUI workflow 이미지는 영상에서 supporting UI로 명시하며 exact-package
runtime capture로 승격하지 않는다. 이 archived candidate의 필수 제품 gate는 당시
PASS였지만 현재 working-tree gate를 승격하지 않는다. 현재 판정은 이 문서 맨 위의
gate summary만 authoritative하다.

## 16. 2026-09-17 historical signed-binary VMware addendum

이 절은 현재 signed-driver/runtime binary lineage의 authoritative addendum다.
과거 VirtualBox 중단이나 archived v2 결과를 승격하지 않고, 새 VMware VM과
현재 package의 exact runtime binaries로 다시 실행했다. Evidence-only harness와
source-snapshot 변경 뒤에는 package ZIP identity를 다시 고정하고 동일 live gate를
재실행해야 한다.

| 항목 | 상태 | 현재 관측 |
|---|---|---|
| VM prerequisite | PASS | VMware Workstation, Windows 10 Pro x64 build 19044, Administrator, test-signing, host-only network |
| Snapshot | PASS | `win10pro-testmode-pre-kdbg-load`; KDBG 적재 전 생성, 각 검증 뒤 복원, KDBG VMware test VM stopped (`vmrun` 0, `vmware-vmx` 0) |
| Test trust/load | PASS | KDbgDriver/KDbgProbe SYS와 CAT `Valid`; 두 kernel services `Running`; both devices ready |
| Runtime identity | PASS | ABI 6; packaged verifier and both running driver hashes verified before device operations |
| Exact Probe read | PASS | cal35 driver-owned PFN `1835000`, exact 4096 bytes |
| Physical apply | PASS | offset `0x100`, 8 bytes, one-shot gate consumed, full-page read-back match |
| Independent reload | PASS | expected page CRC/hash match, 4096/4096 bytes |
| Rollback | PASS | full 4096-byte baseline restore, independent post-rollback match |
| Final state | PASS | write gate locked, rollback verified, errors empty |
| Driver Verifier soak | PASS | exact KDBG pair, active volatile mask `0x132`, 10/10 stop/start/readiness cycles |
| Verifier cleanup | PASS | drivers unloaded, each target removed separately, mask cleared, no targets remained, package readiness restored |
| Process/analysis | PASS | cal35 fixture PID 4456/PFN 1401190, value 610839776→305419896, Freeze ON/OFF/baseline restore, PFN↔PID/VA/PTE, four-level walk and Kernel Explorer read |
| Lifecycle closeout | PASS | forced-exit cleanup, prior-candidate repair/update/rollback/forward-update, explicit package/user-data purge, no stale services |
| Media/v4 | PASS | repository-owner-confirmed 40.5-second/20-scene review; v4 SHA `fc0afb4b…9823`; all four validator gates PASS |

Historical cal35 hashes:

- main/symbol/source: `b6832712613ad486df6dc505327a2977740107694473a5d0ac23dc4bdf32e47f` /
  `7801bfef1b96dac5522b9620b9c02d906aa00adcc9d0754603d8723bd59670aa` /
  `0484b5dda70daaa282c744e2f3c915dc7abf21f0a0d32e7f4acc53c559ec49ee`
- runtime driver/probe: `47fa28f44a23fb53f842f08c21394153345cc8ef15bfafc13cba5e2155a63450` /
  `9abcef052d2ec55605d580596691fcd530383ce20e3d753a7df48b4e06a12ffd`
- live report/analysis metadata: `00f7c64919ef6080d959123581e95469cf1447e610e74612ea22f080b75b31ff` /
  `8a8dd75577ac2bd68a32af5cd2583207ae088aba59b5156f24db70555216a88a`
- GIF/candidate archive: `fde0bf78d264a568762ea491a61c36c2af286d8f88381f68205384dee0614ee8` /
  `eb465a4eaf366ad7ecbdbf9f972952358aefdc2000ea17d2059f2c6cccbef16c`
- scene review/final v4/final archive: `e2d319218cdaf903e6c49a968e4d167cd341058e2ed23cf41f8db17258617df6` /
  `fc0afb4bb2c2c4dc176e53c2c50e229e867e7d1848ebda9425b133c729149823` /
  `438881e7423467f1a53d7e76f7d952163fd69e1ffdf26b8ec25622a81c0a18e3`

Historical evidence:

- `out/evidence/public-symbols-r1-live/exact-analysis-v4/calibration-35/`
- `out/evidence/public-symbols-r1-live/final-calibration-35-v4/`
- `out/evidence/public-symbols-r1-live/KDBG-1.0.0-public-symbols-r1-live-evidence-candidate.zip`
- `out/evidence/public-symbols-r1-live/KDBG-1.0.0-public-symbols-r1-live-evidence-final.zip`
- `out/lifecycle-closeout/live/lifecycle-closeout.json`

Cal35의 guest-local `captures.zip` 자체는 보존되지 않았다. 대신 24개 개별 PNG,
각 SHA-256과 1024x768 dimensions, `capture-run.json`, 50-entry `evidence-bundle.zip`은
후보에 보존되고 독립 검증됐다. 이는 provenance caveat이지 현재 자동 gate blocker는 아니다.
Repository owner가 20-scene review를 확인해 같은 GIF/metadata/live report로
final v4를 생성·검증했으며 추가 VM run은 필요하지 않았다.

The exact main/symbol package plus `--live-run-report` and the automated v4
preflight returned PASS. This promotes the physical-memory R/W product slice,
dedicated-process workflow, covered lifecycle and Windows 10 final v4 to PASS.
This historical Windows 10 addendum itself does not promote production
Authenticode, optional MemProcFS, monitored operations, or Windows 11 coverage;
the separate Windows 11 required-core result is governed by the authoritative
gate summary and dedicated section above.

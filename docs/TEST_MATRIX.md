# Test matrix

## KDBG 1.1.0 binding status

The RC4 product-source boundary is commit `4b376bb0d61eab232af8a2f7f29033238b911022`,
unsigned epoch `product-1.1.0-rc4-final-20260919`, and VM-only derivative
`product-1.1.0-rc4-test1-20260919`. Source, Windows build/package, and exact
required-core gates are PASS. GUI host/capture/archive integrity passed, but
formal review remains `CAPTURED_UNREVIEWED`, `evidence_pass=false`, and
`human_review_complete=false`. RC4 extended/lifecycle/soak was not run.
Production signing and stable release are blocked. DEF CON submission is out of
scope. Historical rows remain bound only to their named epochs.

| Current 1.1.0 gate | Status | Exact evidence |
|---|---|---|
| Source | PASS | source `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92`; scope `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`; core CTest 9/9; source validator PASS |
| Windows build/package | PASS | main `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9`; symbols `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68`; benchmark `7999ed886e5b8710f48cd8d08405e6aa8d52608cc4672b0980b7c696fcdef63f` |
| Required-core Win11 | PASS | `run-20260919T015729Z-8445dddb`; summary `4ad612d9298d902066a95c47a64c213454ce229e2ebf23ea153b8e0a702f57b5`; archive `39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da` |
| Extended/lifecycle/soak Win11 | NOT RUN | no RC4 result; RC1 extended evidence is historical only |
| GUI automation/integrity | PASS / unreviewed | `run-20260919T015850Z-1cfb0381`; 24 frames/20 scenes/21 assertions/229 actions; guest `c877e2b3…46cf4`; captures `abfe37fe…b3695`; `CAPTURED_UNREVIEWED` |
| Formal GUI review | NOT COMPLETE | `evidence_pass=false`; `human_review_complete=false` |
| Initial RC4 MP4 | AUTO PASS / PUBLIC FAIL | mechanical compositor passed; independent review found private paths and weak crops; internal-only |
| Presentation public-v4 MP4 | PASS (automatic + independent presentation review) | `43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`; 9,553,416 bytes; 1920x1080/10 fps/405 frames/40.5 s; 20 scenes/24 segments/19 boundaries reviewed; no rendered path/username/taskbar/notification/unrelated process; raw frames excluded; no formal promotion |
| Production signing | BLOCKED | 11 inputs staged, request `3f94c260…4001`; not signed/not submitted; signer/HSM/TSA absent |

| Area | Portable | Windows build | Live VM |
|---|---|---|---|
| PFN/range/page walk | deterministic unit tests | backend compile/link | Probe PFN/PA match |
| Physical transaction | mock conflict/short I/O/read-back/rollback | GUI/driver ABI | write/reload/rollback |
| Process scanner/address list | fixture tests | Win32 integration | fixture process |
| Pointer/disassembly/snapshot | deterministic fixtures | Zydis/GUI build | visible workflow |
| PFN ownership/PTView | synthetic mapper | bridge/provider build | PID/VA/PTE and final PA |
| Package | source contract | PE/PDB GUID+age, INF/CAT, provenance/hash/SBOM validator | install/diagnose/remove |
| Native Setup | plan/quoting/marker tests | `KDBGSetup.exe` MSVC/MinGW build, PE/PDB/package binding | clean install/repair/update/uninstall/reboot inventory |
| Runtime telemetry | deterministic bounded/privacy tests | MSVC GUI hook and JSON writer | scan region/byte/I/O/cancel plus GUI frame-stall raw JSON |
| Evidence | schema and scene-review negative tests | artifact/MP4/report hash binding | video/log/redaction, 20-scene capture and required human visual review |

PASS must include command output and artifacts from the corresponding column.
Portable results never promote the Windows or live columns.

## Historical 1.0.0 candidate evidence boundary

고정된 `out/package/KDBG-1.0.0-win-x64` main/symbol package pair와
`out/evidence/vmware-live-write/live-write-report.json`은 frozen 1.0.0 epoch
근거다. 새 `out/release-epochs/public-symbols-r1` path-mapped main/symbol
package pair는 strict package validation과 Windows 10 build 19044 cal35 live rebind를 통과했다.
아래 2026-09-16 snapshot과 VM lifecycle 행의 PASS는 frozen epoch에만
적용하며 새 epoch의 Live VM PASS로 승계하지 않는다.

Historical source 결과는 GNU 15.1.0 core build, CTest 9/9, 직접
1771 checks/0, validator 73/73, package lifecycle 117/117, layout/source validator PASS다. 당시 MSVC
product-rc1 Release build와 CTest 9/9, Debug/`/analyze` user-mode build와 CTest 7/7,
5-second no-driver GUI smoke, pinned NuGet WDK
Debug/Release build 및 새 main/symbol package validation도 PASS했다. VMware snapshot
VM의 test-signed SYS/CAT load, Probe transaction, process/analysis, lifecycle,
repository-owner-confirmed 20-scene review와 final v4는 당시 exact epoch에서도 PASS다.
Historical package의 Windows 11 required-core run도 Windows 11 Pro x64 build 26200에서
PASS했다. Exact package/source snapshot SHA-256은
`41f90e2bd76386513d197ae8d77382238a14549e63608dd39eb2d2b4e2c92934`/
`98700c7c7797725b116b0a6333d644bc4df1793397556ce3572e35d451551eca`다.
후자는 tested ZIP 내부에 결속된 302-file source identity이며 post-package
harness/document edits가 있는 현재 checkout identity가 아니다. 원본 canonical
302-file manifest는 별도로 보존되지 않았다.
Interactive GUI/media, repeated reboot/lifecycle, full process Freeze/ownership/
PTView/Kernel Explorer matrix와 long-run performance는 optional extended scope로
NOT RUN이다. Sanitizer preset은 현재 MinGW runtime library 부재로 링크되지 않았다.

별도 frozen multiboot clean-guest run은 exact C4 package에서 두 lifecycle cycle, 네 번의
정상 shutdown/boot, 일곱 readiness와 최종 service/device/registry/CIM/package 잔여물
0을 증명했다. frozen exact package의 native Setup
Install/Repair/Update/Uninstall, 두 reboot boundary, Probe physical transaction과 raw
runtime telemetry도 LIVE PASS였다. 당시 newer epoch는 대응 package lifecycle/reboot,
Probe transaction과 cal35 analysis/media가 PASS였다.

## 2026-09-16 archived final gate snapshot

| Gate | Status | Boundary |
|---|---|---|
| Portable/source | ARCHIVED PASS | 당시 707 checks, 0 failures; 현재 candidate 근거 아님 |
| Windows build | PASS | MSVC Debug/Release/`/analyze`; WDK Debug/Release |
| VM prerequisites | PASS | existing `Windows-VM`, checkpoint, Administrator, test-signing |
| Interim physical transaction | PASS | `DADF43AA...`: ABI 6, Probe write/read-back/reload/rollback/gate lock |
| Candidate advanced read-only | PASS | `D3390AD4...`: current GUI, scanner, pointer, snapshot, PFN reverse map, PTView |
| Final Release package | PASS | new scope, strict validators, same-input ZIP, 5/5 negatives; exact identity externalized |
| Optional MemProcFS runtime | BLOCKED (optional) | error 126 resolved; v5.18.11 `VMMDLL_Initialize(device=pmem)` exit 2; fallback PASS |
| Final-package read-only/lifecycle | PASS | exact deploy/hash binding, device/main ABI6, Probe/4 KiB read, invalid IOCTL rejection, stop/remove; writes 0 |
| Final physical write | PASS | PFN `0xBC1E6`, 8-byte write, full read-back/reload/rollback, baseline restored |
| Process write/Freeze | PASS | 16-byte fixture, 3 restore ticks, rollback/gate lock |
| Driver Verifier | PASS | volatile `0x132`, exact two-driver target, cleanup PASS |
| Exact-package DPI | PASS | 100/125/150/200% actual captures and hashes |
| Final v2 | PASS | 17 scenes, raw page/log/video/artifact hashes, validator exit 0 |

That archived identity was externalized in `out/evidence/final-live-manifest.json`
and `out/evidence/RELEASE-HASHES.txt`; both are absent from this workspace.

## Productization lifecycle coverage

| ID | Environment | Expected result | Evidence status |
|---|---|---|---|
| PORT-LIFE-01 | portable mock | abandoned local edit is not written; restart is clean/locked | automated |
| PORT-LIFE-02 | portable mock | 50 backend reconnects start locked | automated |
| PORT-LIFE-03 | portable mock | 10 apply/verify/reload/rollback cycles restore baseline | automated |
| PORT-MIG-01 | portable fixtures | legacy load is idempotent and Freeze-disarmed | PASS — deterministic migration suite |
| WIN-LIFE-01 | disposable Windows VM | clean install/reboot/startup locked | HISTORICAL WINDOWS 10 PASS — installed-reboot attempt-02, final gate locked, exact snapshot restored |
| WIN-LIFE-02 | disposable Windows VM | 10 service cycles without stale handle or bugcheck | HISTORICAL WINDOWS 10 PASS — public-symbols-r1 lifecycle-soak 10/10 |
| WIN-CRASH-01 | disposable Windows VM | forced GUI exit releases controller and locks gate | HISTORICAL WINDOWS 10 PASS — failure surfaced, cleanup and subsequent readiness recovered |
| WIN-UPD-01 | disposable Windows VM | previous package update/rollback leaves no stale binary | HISTORICAL WINDOWS 10 PASS — distinct candidate transition; published N-1 remains future-release gate |
| WIN-READY-01 | disposable Windows VM | Bring Online loads Probe and reaches consistent ready state | HISTORICAL WINDOWS 10 PASS — cal35 readiness and exact runtime identity |
| WIN-READY-02 | disposable Windows VM | lifecycle cancel/progress has no stale running state | HISTORICAL WINDOWS 10 PASS — lifecycle/reboot/cleanup artifacts |
| WIN-PROBE-01 | disposable Windows VM | Probe failure stays disconnected and fail-closed | PASS — negative portable/package coverage; cal35 positive exact Probe path PASS |
| WIN-CAL35-01 | Windows 10 build 19044 snapshot VM | exact Probe transaction + fixture write/Freeze + ownership/PTView/Kernel Explorer | PASS — `exact-analysis-v4/calibration-35`, 24 captures, two exports, cleanup/restore |
| WIN-MEDIA-01 | human-reviewed final assembly | 1600x900 GIF, 24 frames/20 scenes, manifest/archive/parsed+escaped+nested privacy checks | PASS — v4 `fc0afb4b…9823`, final archive `438881e7…a18e3` |
| WIN11-CORE-01 | disposable Windows 11 Pro x64 build 26200 VM | current exact package install/load, ABI 6, Probe write/read-back/reload/rollback, cleanup, checkpoint restore, final Off | RC4 PASS — `run-20260919T015729Z-8445dddb`; package `7f7c1797…45d5`; archive `39c31476…57da`; exact checkpoint restored and VM Off |
| WIN11-EXT-01 | disposable Windows 11 x64 VM | repeated reboot/lifecycle, full process Freeze/ownership/PTView/Kernel Explorer matrix and long-run performance | RC4 NOT RUN — historical RC1 extended result is not rebound |
| WIN11-GUI-01 | disposable Windows 11 x64 VM | 24 frames/20 ordered scenes with cleanup/restore/final Off | HOST/CAPTURE/INTEGRITY PASS / `CAPTURED_UNREVIEWED` — `run-20260919T015850Z-1cfb0381`; 21 assertions/229 actions; formal flags remain false |
| WIN11-MEDIA-01 | source-bound MP4 composition and formal human review | exact MP4 hash/report, critical content visible, private paths removed | INITIAL MP4 AUTO PASS / PUBLIC FAIL; formal review not complete; `evidence_pass=false` |
| WIN11-PRESENT-01 | presentation-only redacted MP4 | automatic composition plus independent visual review | PASS FOR PRESENTATION ONLY — public-v4 MP4 `43eda62e…5260`, report `40605401…bd88`, scenes `9e4a0543…cd04`, contact sheet `fa8597a8…58b`; 405/405 frames reviewed; raw frames excluded; does not replace formal evidence |

The Windows 11 required-core PASS uses disposable-VM test trust. It is not evidence
of production signing, trusted timestamping, or customer-machine production trust.

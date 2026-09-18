# Test matrix

## KDBG 1.1.0 binding status

The exact 1.1.0 source, Windows build/package, required-core and extended
live-VM gates are PASS. The source-bound GUI capture and MP4 composition
automation passed, but formal human visual review failed because critical
1024-wide layout content is omitted or clipped. Final formal evidence therefore
remains incomplete with `evidence_pass=false`. A separate polished overlay and
1080p MP4 passed presentation-only automatic and independent human review; it
does not promote formal evidence. Historical 1.0.0 rows remain historical.

| Current 1.1.0 gate | Status | Exact evidence |
|---|---|---|
| Source | PASS | source `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184`; scope `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`; core CTest 9/9; source validator PASS |
| Windows build/package | PASS | main `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f`; symbols `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849`; benchmark `72348dff8a0a1623fd922fa316d3bf898a60f54b49bdc34c58a115924c25d4cf` |
| Required-core Win11 | PASS | `run-20260918T091747Z-21a27820`; summary `c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b`; archive `0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9` |
| Extended Win11 | PASS | `extended-20260918T092819Z-66c07a32`; summary `12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee`; archive `f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c` |
| GUI automation | PASS / unreviewed | `run-20260918T092129Z-f14f5f7a`; 24 captures/20 scenes; `CAPTURED_UNREVIEWED` |
| Source-bound intermediate MP4 | MECHANICAL PASS | `c368dde54d19f46fedd32895f319223221538c006fcf4626277665b8fe5aad3d`; 9,759,713 bytes; 40.5 s; 405 frames; report `5b92b9086cd2a503f46fd309f4fd20099644aa17e453385d5f3a053a9714fdd0` |
| Formal human visual/submission review | FAIL | scene 03 no grid; scene 20 clipped diff row; wrapping; `evidence_pass=false` |
| Presentation-only overlay | PASS | `run-20260918T102055Z-6c85cee7`; 24 captures/20 scenes; summary `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`; guest `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`; captures `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`; cleanup/restore/final Off |
| Presentation final2 MP4 | AUTO + HUMAN PASS (presentation-only) | `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`; 9,974,541 bytes; 1920×1080; 10 fps; 40.5 s; 405/405 frames; report `e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`; no formal promotion |

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
| WIN-LIFE-01 | disposable Windows VM | clean install/reboot/startup locked | CURRENT WINDOWS 10 PASS — installed-reboot attempt-02, final gate locked, exact snapshot restored |
| WIN-LIFE-02 | disposable Windows VM | 10 service cycles without stale handle or bugcheck | CURRENT WINDOWS 10 PASS — public-symbols-r1 lifecycle-soak 10/10 |
| WIN-CRASH-01 | disposable Windows VM | forced GUI exit releases controller and locks gate | CURRENT WINDOWS 10 PASS — failure surfaced, cleanup and subsequent readiness recovered |
| WIN-UPD-01 | disposable Windows VM | previous package update/rollback leaves no stale binary | CURRENT WINDOWS 10 PASS — distinct candidate transition; published N-1 remains future-release gate |
| WIN-READY-01 | disposable Windows VM | Bring Online loads Probe and reaches consistent ready state | CURRENT WINDOWS 10 PASS — cal35 readiness and exact runtime identity |
| WIN-READY-02 | disposable Windows VM | lifecycle cancel/progress has no stale running state | CURRENT WINDOWS 10 PASS — lifecycle/reboot/cleanup artifacts |
| WIN-PROBE-01 | disposable Windows VM | Probe failure stays disconnected and fail-closed | PASS — negative portable/package coverage; cal35 positive exact Probe path PASS |
| WIN-CAL35-01 | Windows 10 build 19044 snapshot VM | exact Probe transaction + fixture write/Freeze + ownership/PTView/Kernel Explorer | PASS — `exact-analysis-v4/calibration-35`, 24 captures, two exports, cleanup/restore |
| WIN-MEDIA-01 | human-reviewed final assembly | 1600x900 GIF, 24 frames/20 scenes, manifest/archive/parsed+escaped+nested privacy checks | PASS — v4 `fc0afb4b…9823`, final archive `438881e7…a18e3` |
| WIN11-CORE-01 | disposable Windows 11 Pro x64 build 26200 VM | current exact package install/load, ABI 6, Probe write/read-back/reload/rollback, cleanup, checkpoint restore, final Off | 1.1.0 PASS — `run-20260918T091747Z-21a27820`; package `596ccdf0…4413`; PFN `2117631`; offset `0x100`; 8-byte apply; 4096-byte rollback; exact checkpoint restored and VM Off |
| WIN11-EXT-01 | disposable Windows 11 x64 VM | repeated reboot/lifecycle, full process Freeze/ownership/PTView/Kernel Explorer matrix and long-run performance | 1.1.0 PASS — `extended-20260918T092819Z-66c07a32`; 2 cycles, 10 stop/start, 4 reboot, 1800-second soak, 488 reads, midpoint transaction, 7 benchmarks, cleanup/restore/final Off |
| WIN11-GUI-01 | disposable Windows 11 x64 VM | 24 captures/20 ordered scenes with cleanup/restore/final Off | AUTOMATION PASS / `CAPTURED_UNREVIEWED` — `run-20260918T092129Z-f14f5f7a`; human visual review FAIL |
| WIN11-MEDIA-01 | source-bound MP4 composition and formal human review | 40.5-second/405-frame MP4, exact hash/report, critical content visible | MECHANICAL PASS, FORMAL HUMAN FAIL — intermediate MP4 `c368dde5…ad3d`; scene 03 grid missing, scene 20 diff row clipped, wrapping; `evidence_pass=false` |
| WIN11-PRESENT-01 | presentation-only overlay and final 1080p MP4 | 24/20 overlay capture, cleanup/restore/off, 1920×1080/10 fps/405-frame output, independent human review | PASS FOR PRESENTATION ONLY — run `run-20260918T102055Z-6c85cee7`, MP4 `4cd5a4f7…d454`; does not replace source-bound formal evidence |

The Windows 11 required-core PASS uses disposable-VM test trust. It is not evidence
of production signing, trusted timestamping, or customer-machine production trust.

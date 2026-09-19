# KDBG 요구사항 추적표

기준: 2026-09-19 RC4, product-source commit
`4b376bb0d61eab232af8a2f7f29033238b911022`

## KDBG 1.1.0 RC4 release binding (authoritative)

| Gate | RC4 state |
|---|---|
| Source-complete | PASS — layout, core build/CTest 9/9, source validator |
| Windows-build-verified | PASS — exact unsigned main/symbol/source package |
| Live-device/runtime | PASS — exact RC4 VM derivative required-core |
| RC4 extended lifecycle/soak/full feature | NOT RUN — RC1 result는 historical only |
| GUI host/capture/integrity | PASS — 24 frames, 20 scenes, 21 assertions, 229 actions |
| Formal GUI evidence | `CAPTURED_UNREVIEWED`; `evidence_pass=false`; `human_review_complete=false` |
| Initial MP4 public suitability | FAIL — internal path/crop/readability blocker |
| Public v4 presentation media | PASS (automatic + independent review); formal evidence 승격 아님 |
| Production signing | BLOCKED — inputs staged; signing/network submission not performed |
| Source-freeze tag | PASS (published RC tag) — annotated `v1.1.0-rc4` on `origin` at the RC4 product-source commit |
| Stable `v1.1.0` / public release | BLOCKED — production-signed returned artifacts/TSA absent |

Exact main/symbol/source/scope SHA-256:

- `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9`
- `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68`
- `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92`
- `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`

VM-only derivative `product-1.1.0-rc4-test1-20260919` package SHA-256은
`7f7c179738eb670ca79d6c41bc9c46c445c1ffd31811c46f39bbbdcad3df45d5`다.

| 요구사항 | RC4 exact evidence | 상태/경계 |
|---|---|---|
| FR-001, FR-007 | required-core `run-20260919T015729Z-8445dddb`; exact derivative install/load, ABI/Probe workflow | LIVE PASS |
| FR-002, FR-003 | Probe PFN discovery와 exact 4096-byte physical read | LIVE PASS |
| FR-004 | GUI run `run-20260919T015850Z-1cfb0381`; hex edit/diff scene capture | AUTOMATION/INTEGRITY PASS; HUMAN REVIEW PENDING |
| FR-005 | one-shot unlock/apply/full-page read-back match | LIVE PASS |
| FR-006 | independent reload/rollback/final lock | LIVE PASS |
| FR-008–FR-013 | exact GUI workflow의 process scan, address Freeze, pointer, disassembly, snapshot scenes | AUTOMATION/INTEGRITY PASS; formal GUI evidence 미승격 |
| FR-014, FR-015 | process/VA ownership과 page-table visualization scenes | AUTOMATION/INTEGRITY PASS; formal GUI evidence 미승격 |
| FR-016 | Kernel Explorer scenes | AUTOMATION/INTEGRITY PASS; formal GUI evidence 미승격 |
| FR-017 | source/build tests와 GUI action log | SOURCE/WINDOWS PASS; RC4 extended/soak NOT RUN |
| FR-018 | required-core install/load/cleanup/checkpoint restore/final Off | LIVE PASS |
| NFR-001 | one-shot gate, read-back/rollback, final locked state | SOURCE/LIVE PASS |
| NFR-002 | deterministic source/build tests and finite GUI automation | PASS; RC4 long-run soak NOT RUN |
| NFR-003 | isolated bridge/source boundary | SOURCE PASS; optional MemProcFS pmem UNVERIFIED |
| NFR-004 | RC4 status, implementation status, traceability and exact hashes | SOURCE PASS |
| Production trust | signing request SHA `3f94c26060bc437460b22ced778c52f1f70165e49a7ac57f0979c1a347f64001`, 11 inputs | BLOCKED; `signing_performed=false`, `network_submission_performed=false` |

Required-core guest archive SHA-256은
`39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da`다.
GUI guest evidence/captures SHA-256은
`c877e2b3695faf6489f0ff3fa517a97eb0cc6f0f334a0a4a4bad900f14446cf4` /
`abfe37fe1694fe8e35229c306663dde0cc4ff688d1a1fa80139f74c8ea9b3695`다.

Public v2는 independent review에서 taskbar 노출로 FAIL했고 v2/v3는 superseded다.
최종 presentation-only public v4는
`out/demo-product-1-1-0-rc4-test1-public-v4-20260919/KDBG-1.1.0-demo-public-v4.mp4`,
SHA-256
`43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`,
9,553,416 bytes, 1920x1080, 10 fps, 405/405 frames, 40.5 seconds다. Automatic
compositor와 independent presentation review가 모두 PASS했다. 20 scenes/24
segments/19 boundaries에서 rendered path/username/taskbar/notification/unrelated
process가 없고 core claims가 읽힌다. Video-only delivery copy
`out/release-media/KDBG-1.1.0-demo-public.mp4`는 같은 SHA-256/크기이며 해당
directory에는 MP4만 있다. Raw frames는 공개에서 제외한다. 공식 GUI evidence를
승격하지 않는다. DEF CON 제출은 이번 범위에서 제외한다.

Annotated source-freeze tag `v1.1.0-rc4`는 `origin`의
`4b376bb0d61eab232af8a2f7f29033238b911022`에 게시됐다. Stable `v1.1.0` tag와
public release는 production signing 전까지 차단한다.

## Historical RC1 KDBG 1.1.0 release binding (superseded)

아래 RC1 판정은 해당 exact identity의 이력이며 현재 RC4 판정이 아니다.

| Gate | Current 1.1.0 state |
|---|---|
| Source-complete | PASS — layout, core build/CTest 9/9 and source validator |
| Windows-build-verified | PASS — unsigned main/symbol/source hashes recorded below |
| Live-device/runtime | PASS — exact 1.1.0 VM derivative and required-core archive |
| Win11 extended lifecycle/soak/full feature | PASS — exact extended archive, 30-minute soak and repeated lifecycle |
| GUI capture automation | PASS / `CAPTURED_UNREVIEWED` — 24 captures, 20 scenes, cleanup/restore/final Off |
| Submission evidence | FAIL (human visual review) — MP4 mechanical checks PASS, but 1024-wide layout omissions/clipping keep `evidence_pass=false`; no deck/GIF |
| Presentation media | PASS (presentation-only) — polished overlay and 1920×1080 final MP4 passed automatic and independent human review; no formal evidence promotion |

The current 1.1.0 identities are main/symbol/source/scope SHA-256
`3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f` /
`0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849` /
`8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184` /
`bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
The VM derivative package SHA-256 is
`596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`.
Detailed older observations remain historical unless explicitly tied to these
identities.

아래 문단의 path-mapped-symbol 결과는 historical 1.0.0 context다. 상태는
`SOURCE PASS`, `PORTABLE PASS`, `MSVC USER-MODE PASS`, `LIVE PASS`,
`BLOCKED`, `NOT RUN`, `UNVERIFIED`로 분리한다. 새 path-mapped-symbol epoch는
user-mode/driver build, symbol privacy/identity, main/symbol package validation과
Windows 10 build 19044 exact live rebind가 PASS다. Exact main/symbol/source hashes는
`b6832712…e47f`/`7801bfef…70aa`/`0484b5dd…49ee`다. Frozen main/symbol ZIP (`7f6b0fd9…b265a`/`d8715bf7…c96f`)은
보존되고, private compiler path가 있는 frozen symbols는 공개하지 않는다.
`R:\`/`K:\`는 공개 metadata에 기록된 고정 logical aliases이지 private
physical path가 아니다. 별도 VM-only test-signed derivative의 Windows 11 Pro x64
build 26200 required-core live gate도 PASS했다. 이는 production trust 또는
optional extended/full-v4 GUI 범위의 승격이 아니다.

| 요구사항 | 주요 구현 | 자동/실행 검증 | 현재 상태 |
|---|---|---|---|
| FR-001 lifecycle/ABI | `DriverService`, `KDbgBackend`, Driver pane, package lifecycle tools, shared IOCTL headers | ABI tests, MinGW/MSVC/WDK builds, PowerShell parse | SOURCE/PORTABLE/MSVC/WDK PASS; VM install/reboot/10-cycle lifecycle LIVE PASS |
| FR-002 PFN/range | `PfnAddress`, backend/driver range and overflow validation | PFN/range/overflow negative tests | PORTABLE PASS; Probe PFN/PA LIVE PASS |
| FR-003 exact page read | `PhysicalPageSession::Load`, physical read IOCTL | exact/short-read tests | PORTABLE/WDK PASS; exact 4096-byte LIVE PASS |
| FR-004 Hex/diff/history | `HexEditorPanel`, `PhysicalPageSession` | edit/history/diff tests, current MSVC GUI build | PORTABLE/MSVC/LIVE AUTOMATION PASS; release visual review FAIL because required grid/diff content is omitted or clipped at 1024-wide capture |
| FR-005 one-shot physical write | review modal, preflight, per-handle gate, dirty-run writes, full read-back | conflict/gate/partial-write/mismatch/reconnect loop tests | PORTABLE PASS; 8-byte one-shot + full read-back LIVE PASS |
| FR-006 rollback | `RollbackBaseline`, independent reload evidence | rollback/reload/failure/repeated transaction tests | PORTABLE PASS; independent reload/full-page rollback LIVE PASS |
| FR-007 Probe fixture | `KDbgProbe`, `ProbeClient`, probe-first GUI | ABI/layout tests, user-mode/driver build | SOURCE/MSVC/WDK PASS; PFN/generation/CRC LIVE PASS |
| FR-008 process map/browser | `ProcessCatalog`, `Win32ProcessMemory`, process panels | mock/session/write tests, MSVC build | PORTABLE/MSVC/LIVE PASS; dedicated fixture PID/start identity/VA and verified write captured |
| FR-009 memory scan | scanner/codec/AOB/async controller | type/filter/short-read/cap/cancel tests | PORTABLE/LIVE PASS; exact First/Next Scan result captured |
| FR-010 address list/Freeze | `AddressList`, `WatchList` | v1→v2 migration, pointer persistence, loaded-freeze disarm and verified-write tests | PORTABLE/LIVE PASS; external mutation restored within 145.192 ms and baseline restored |
| FR-011 pointer scan | bounded `PointerScanner` and pane | boundary/overflow/cycle/depth/result-cap tests | PORTABLE/LIVE PASS; two exact bounded paths captured |
| FR-012 disassembly | pinned Zydis and panel | dependency audit, current MSVC Debug/Release link | MSVC USER-MODE/LIVE PASS; fixture 64-byte/22-instruction Zydis result captured |
| FR-013 snapshot | bounded `MemorySnapshot` and panel | capture/cancel/CRC/save/load/diff tests | PORTABLE/LIVE PASS; baseline/current CRC and one contiguous changed run captured |
| FR-014 PFN owner | isolated bridge/provider and selected-process mapper | parser/timeout/cap/reverse-map tests, missing-DLL/export negative runs | PORTABLE/MSVC/LIVE FALLBACK PASS; dedicated fixture PFN↔PID/VA/PTE; optional pmem UNVERIFIED |
| FR-015 page tables | translation backend, `X64PageTable`, panel | LA57/4K/2M/1G/permission tests | PORTABLE/MSVC/WDK/LIVE PASS; complete PML4/PDPT/PD/PT walk and final PFN match |
| FR-016 Kernel Explorer | bounded module catalog, local-image exact PDB resolver, kernel-only VA reader, Zydis table | PE/canonical/path/backend-range tests, MSVC Debug/Release/`/analyze`, GUI smoke | PORTABLE/MSVC/LIVE PASS; exact module/local-header/PDB/DriverEntry/kernel-read/Zydis proof captured |
| FR-017 performance/live harness | aligned First Scan, bounded dense Next Scan batching/fallback, schema-2 benchmark, packaged `kdbg_live_verify`, opt-in `kdbg.runtime-telemetry.v1` | fixed-local path, initial persistence, atomic replacement, privacy/bounds and partial-outcome tests; mock repeats; live IOCTL plus final raw scan/frame JSON | PORTABLE/MSVC PASS; real driver 4 KiB and current exact-package GUI scan/frame telemetry LIVE PASS |
| FR-018 product lifecycle | transactional SCM helpers, packaged scripts, elevated native Setup, stable Program Files root, ARP/shortcut and two-phase exact purge | root-mode integration, rollback/backup/purge fault tests, exact-package native UI lifecycle and reboot inventory | SOURCE/MSVC/LIVE PASS; Install/Repair/Update/Uninstall, two normal reboot boundaries, purge state and clean inventory verified |
| NFR-001 safety | driver ACL/controller/gates/limits; transactional core and typed UI confirmation | ABI/negative/recovery tests, code audit, WDK `/W4 /WX`, live counters/final lock | SOURCE/PORTABLE/WDK PASS; Probe live run final gate locked |
| NFR-002 responsiveness | stoppable workers, clipping, async lifecycle future | cancellation tests and MSVC GUI build | SOURCE/PORTABLE/MSVC PASS; 1.1.0 extended run completed 1800-second soak and seven benchmarks; presentation layout review FAIL is tracked separately |
| NFR-003 isolation | portable core; Win32 guards; MemProcFS subprocess | MinGW/MSVC builds and bridge negative tests | PASS for source boundary; pmem runtime UNVERIFIED |
| NFR-004 traceability | this matrix, test plan, status and validator gate table | layout and source validator | SOURCE PASS |
| Windows package | package staging/publish/rollback, metadata, hashes, SBOM and lifecycle tools | validator/source fixtures plus current main/symbol package | SOURCE/WINDOWS PACKAGE PASS; disposable-VM SYS/CAT test trust and live load PASS; production trust BLOCKED |
| Commercial operations | packaged security/support/privacy/MIT-EULA/update-rollback/vulnerability/release-note contract | required-file and required-marker validator plus deterministic positive/negative tests | SOURCE/PACKAGE CONTRACT PASS; monitored intake and production trust BLOCKED |
| Live evidence | hash-bound required-core, extended lifecycle/soak, GUI capture and MP4 report | validators check apply/rollback, runtime/package identity, cleanup, ordered scenes and final lock | 1.1.0 required-core and extended runs PASS; GUI automation and MP4 composition PASS; human visual review FAIL, so final evidence/submission is incomplete |

## Historical RC1 1.1.0 Windows 11 mapping (superseded)

The required-core run is
`out/win11-validation/product-1-1-0-rc1-test1-20260918/runs/run-20260918T091747Z-21a27820`.
Its host summary and 26-entry guest archive SHA-256 values are
`c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b` and
`0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`.

| Requirement | Current evidence | State/boundary |
|---|---|---|
| FR-001, FR-007 | Windows 11 build 26200, ABI 6, exact derivative install/start and KDbgProbe PFN `2117631` | LIVE PASS |
| FR-002, FR-003 | discovered Probe PFN and exact 4096-byte physical baseline/read | LIVE PASS |
| FR-005 | offset `0x100`, 8-byte one-shot apply and full-page read-back match | LIVE PASS |
| FR-006 | independent reload and 4096-byte rollback to baseline | LIVE PASS |
| NFR-001 | final gate locked, cleanup PASS, checkpoint restored, VM final Off | LIVE PASS |
| Trust boundary | package `596ccdf0a…4413`, certificate `bd7de7eb…58b1`, signer `ba34b393521d722ba01df87afccc6f3feb760b2c` | VM-only test trust; not production signing |

The extended run
`out/win11-validation/product-1-1-0-rc1-test1-20260918/extended-runs/extended-20260918T092819Z-66c07a32`
passed two lifecycle cycles, 10 stop/start operations, four reboot boundaries,
an 1800-second soak, 61×8 = 488 reads, a verified midpoint transaction and
seven benchmark runs. Summary/archive SHA-256 values are
`12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee` /
`f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`.
Cleanup, exact checkpoint restore and final VM Off all passed.

The official GUI run
`out/win11-gui-product-1-1-0-rc1-test1-20260918/run-20260918T092129Z-f14f5f7a`
completed 24 captures/20 scenes with `CAPTURED_UNREVIEWED`; summary, guest
archive and captures digests are `f5fd51ef…5d0b`, `61049335…252`, and
`bd254d7a…6d42`. The generated 40.5-second MP4 has SHA-256
`c368dde54d19f46fedd32895f319223221538c006fcf4626277665b8fe5aad3d`
and passed automatic composition. Human review failed because scene 03 lacks
the grid, scene 20 clips the diff row, and wrapping obscures presentation
content. This keeps `evidence_pass=false` and does not complete formal
submission evidence. The `c368dde5…ad3d` MP4 is retained only as an intermediate.

For presentation use, the separate overlay run
`out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7` completed
24 captures/20 scenes with cleanup, checkpoint restore and final VM Off. Its
summary, guest archive and captures digests are
`e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`,
`32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`, and
`fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`.
The resulting presentation video
`out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`
is 1920×1080 at 10 fps, 40.5 seconds, 405/405 frames and 9,974,541 bytes.
Its MP4/report SHA-256 values are
`4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454` /
`e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.
Automatic validation and an independent presentation-only human review passed.
This does not replace the source-bound GUI run or promote formal evidence.

## Historical 1.0.0 Windows 11 required-core mapping

Authoritative evidence:
`out/win11-validation/product-rc1-win11-test2-20260918/runs/run-20260918T042905Z-f19bda60`.
The bound package/source SHA-256 values are
`41f90e2bd76386513d197ae8d77382238a14549e63608dd39eb2d2b4e2c92934` and
`98700c7c7797725b116b0a6333d644bc4df1793397556ce3572e35d451551eca`.

| 요구사항 | Win11 required-core 증거 | 상태/경계 |
|---|---|---|
| FR-001, FR-007 | ABI 6; exact package install/start; KDbgProbe PFN `2117631`; uninstall removed both services/devices | LIVE PASS |
| FR-002, FR-003 | discovered Probe PFN and exact 4096-byte baseline/read operations | LIVE PASS |
| FR-005 | offset `0x100`, 8-byte one-shot apply and exact full-page read-back | LIVE PASS |
| FR-006 | independent reload and 4096-byte rollback to the baseline | LIVE PASS |
| NFR-001 | final write gate locked; exact checkpoint restored; final VM Off | LIVE PASS |
| VM/package binding | Windows 11 Pro x64 build 26200; VM `66935024-37f7-4f21-b2c8-12ca5fe677bf`; checkpoint `KDBG-Win11-Clean-TestSigning-20260918` (`f60a775a-26f6-4ef9-bb19-f61c93346bb4`) | LIVE PASS; VM-only test-signed derivative, not production trust |
| Extended in this required-core run | full v4/interactive GUI/media, process Freeze, ownership/PTView, repeated reboot/lifecycle, long-run performance | NOT RUN in this run; a later 1.0.0 final engineering epoch completed this scope, but it is not 1.1.0 evidence |

Host summary/preflight SHA-256 values are
`f5dc301f2e086c6fcfcec2743773a50da84bae2006a4a97c2c56bb6f79c53cb7` and
`7f6ade71a20cf9ca88c852eee75a3bd1c06c138a275b9e002b05e87ed6a309df`.
The 18-entry guest archive, guest summary and transaction SHA-256 values are
`c4341cb571a7955f998d0c70914ee41fd98cef2cf7c0e6f1f244459956356c9e`,
`faae5b196ced3092dc2dfa931cbfb9867a133c111d9fede47f03177937cd92ac`, and
`0636b7efe09a632e5e8bb0f009d4190b6632d5ab23bc702e82f10a50fa2bf204`.

Historical v4의 20개 scene identifier는 요구사항과 다음처럼 연결된다. Cal35 candidate에는
각 scene의 24개 실제 캡처와 40.5초 GIF가 있지만, 아래 매핑과 nonhuman audit는
필수 real-human review 완료를 뜻하지 않는다.

| 요구사항/증거 | exact scene identifiers |
|---|---|
| FR-001, FR-007 lifecycle/Probe readiness | `driver_probe_ready`, `probe_pfn_discovery` |
| FR-003 exact physical read | `physical_read_4096` |
| FR-004 local edit/history | `hex_edit_and_diff`, `undo_redo` |
| FR-005 one-shot write | `typed_pfn_unlock`, `write_and_readback` |
| FR-006 independent verification/rollback | `independent_reload`, `rollback_baseline` |
| FR-014, FR-015 attribution/translation | `pfn_owner_pid_va_pte`, `page_table_walk` |
| FR-009–FR-013 process analysis | `process_first_next_scan`, `address_list_verified_freeze`, `pointer_scan`, `zydis_disassembly`, `snapshot_diff` |
| FR-016 Kernel Explorer | `kernel_module_catalog`, `kernel_symbol_resolution`, `kernel_read_disassembly` |
| Candidate identity | `about_version` |

현재 결정적 suite 근거는 fresh GNU 15.1.0 Debug/Release build 후
`kdbg_core_tests`의 `1771 checks, 0 failures`와 core CTest 7/7 PASS다. MSVC
Debug/Release/`/analyze` user-mode build도 현재 tree에서 CTest 7/7 PASS했고 Release
GUI no-driver smoke를 5초 실행했다. 설치형 WDK는 없지만 locked NuGet WDK
offline fallback으로 Debug/Release driver와 CAT를 만들었고 Release SYS/PDB 2/2를
검증했다. VM test-signed package, driver load, Probe physical write와 reboot/recovery는
PASS했다. Current process write/Freeze와 complete visual candidate/nonhuman preflight도
PASS했다. Repository-owner-confirmed review와 final v4 validator도 PASS했다.

# Active plan — disposable-VM live validation

Current target: KDBG 1.1.0 on `feature/kdbg-1.1.0`. Exact 1.1.0 build,
required-core and extended lifecycle/soak gates are complete under disposable-
VM test trust. The formal source-bound GUI capture remains human-review FAIL
with `evidence_pass=false`. A separate presentation-only overlay and final MP4
passed automatic and independent human presentation review. Everything below
that names `product-rc1/test2`,
`b683…`, or a 1.0.0 package is historical evidence only.

Frozen 1.0.0 exact-final (`7f6b0fd9…b265a`/`d8715bf7…c96f`)과 previous
path-mapped-symbol epoch의 Windows 10 physical/process/analysis/lifecycle evidence는
각 exact identity에만 결속한다. Historical package의 Windows 11 required-core live는
별도의 hash-bound run으로 PASS했다. Windows 11 interactive GUI/media, repeated
reboot/lifecycle, full process Freeze/ownership/PTView/Kernel Explorer matrix와
later 1.0.0 final engineering evidence completed the extended lifecycle/soak and
full-feature capture, but neither result is 1.1.0 evidence.

## 전제

- disposable Windows x64 VM and recoverable snapshot
- Administrator and test-signing
- current MSVC/WDK Release artifacts
- validator를 통과할 exact `KDBG-1.1.0-win-x64` package and recorded SHA-256

## Current 1.1.0 Windows 11 results

Exact identities:

- unsigned main/symbol/source/scope SHA-256:
  `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f` /
  `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849` /
  `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184` /
  `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
- test-signed package/certificate/signer:
  `596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413` /
  `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1` /
  `ba34b393521d722ba01df87afccc6f3feb760b2c`.

Required-core run `run-20260918T091747Z-21a27820` is **PASS**:

- Windows 11 build 26200 and ABI 6.
- Probe PFN, exact 4096-byte read, eight-byte one-shot apply, full-page
  read-back match, 4096-byte rollback and final write gate LOCKED.
- guest cleanup, exact checkpoint restore and final VM Off.
- summary/archive SHA-256:
  `c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b` /
  `0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`.

Extended run `extended-20260918T092819Z-66c07a32` is **PASS**:

- two lifecycle cycles, ten stop/start transitions and four reboot boundaries.
- 1800-second soak with 61x8=488 reads, midpoint transaction and seven
  benchmark runs.
- cleanup, checkpoint restore and final VM Off.
- summary/archive SHA-256:
  `12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee` /
  `f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`.

GUI run `run-20260918T092129Z-f14f5f7a` completed automation with
`CAPTURED_UNREVIEWED`, 24 captures and 20 scenes; summary/archive/capture hashes
are `f5fd51ef18c319c37feb5adb997582e56cd2efe9b03a1d6ea3213237f6815d0b` /
`6104933593259fb074466ba8d21a5fffd7e47803b2bfec71ce206e5c0a4ce252` /
`bd254d7a98230db0199051085453b09ea33405f3efe57a9ded42b8a3bebb6d42`. Cleanup, restore and
final Off passed. Human review is **FAIL**: scene 03's grid and scene 20's diff
row are clipped and columns wrap at the 1024 layout. `evidence_pass=false` and
the formal flags remain unchanged.

Presentation-only overlay run
`out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7` passed automatic
checks and independent human presentation review. Summary/guest/captures
SHA-256 are:

- `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`
- `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`
- `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`

It contains 24 captures/20 scenes and completed cleanup, checkpoint restore and
final VM Off. The scene 20 evidence-bound cue and scene 10/11 crop corrections
resolve the previous presentation blockers.

The final video-only artifact is
`out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`,
SHA-256 `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`,
9,974,541 bytes, 1920x1080, 10 fps, 40.5 seconds and 405/405 frames. Report
SHA-256 is
`e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.
It passes the presentation-video quality gate only. It does not modify the
formal GUI evidence flags or prove actual submission. No deck or GIF is a
current deliverable.

## Historical 1.0.0 Windows 11 required-core gate

Run `out/win11-validation/product-rc1-win11-test2-20260918/runs/run-20260918T042905Z-f19bda60`
is PASS:

- Microsoft Windows 11 Pro x64 build 26200
- exact package SHA-256
  `41f90e2bd76386513d197ae8d77382238a14549e63608dd39eb2d2b4e2c92934`
- exact source snapshot SHA-256
  `98700c7c7797725b116b0a6333d644bc4df1793397556ce3572e35d451551eca`
- the source hash identifies the 302-file snapshot embedded in the tested ZIP,
  not the post-package edited current checkout; its original canonical file
  manifest was not retained separately
- test-signed package preflight, install/start, both running driver identities and ABI 6
- driver-owned Probe PFN, exact 4 KiB baseline, 8-byte one-shot apply, full-page
  read-back, independent reload, full-page rollback, final write gate LOCKED
- uninstall cleanup, both services/devices absent
- exact checkpoint `f60a775a-26f6-4ef9-bb19-f61c93346bb4` restored and final VM Off

This is disposable-VM test-trust evidence. It does not satisfy production
Authenticode signing, trusted timestamping or returned production-driver trust.

## Windows 10 extended lifecycle gate

완료: 1–7. Forced exit는 run failure와 두 service stop을 확인했고, update는
서로 다른 signed driver hashes의 prior→current→prior→current 전환과 각 단계
readiness/final lock을 확인했다. Explicit package/user-data purge와 snapshot
restore도 PASS다.

1. clean install and readiness diagnostics
2. start, device/ABI check and startup gate LOCKED observation
3. reboot and startup state check
4. ten start/stop cycles
5. forced GUI exit and controller/gate recovery
6. stopped-package update, repair and rollback
7. stop/remove and no stale registration/device

## Windows 10 full Probe/live-analysis gate

1–6 모두 PASS. Current report는
`out/evidence/vmware-live-write/live-write-report.json`이며 live-run validator가
exact packaged verifier와 두 running driver hash를 대조했다.

1. fresh Probe query and exact 4096-byte baseline
2. packaged live verifier read-only report and typed current PFN confirmation
3. live verifier write mode: full-page preflight, 8-byte one-shot write and full read-back
4. independent reload
5. explicit rollback and full-page baseline restoration
6. final gate LOCKED observation

첫 write 대상은 current `KDbgProbe`가 반환한 fixture PFN으로 제한한다.

## Evidence boundary

Current 1.1.0 required-core and extended results bind the exact test-signed
package and source identity above. They prove the controlled Windows 11 VM path,
not production signing or timestamp trust. The formal GUI run proves automated
capture and cleanup only and retains its failed human review. The separate
overlay/final MP4 proves presentation-video quality, not formal source-bound GUI
evidence or submission.

Previous Windows 10 evidence binds package EXE/bridge/SYS hashes, command log,
raw page states, lifecycle results, successful `kdbg.live-verify.v1`, process/
ownership/PTView/Kernel Explorer scenes and reviewed redacted video into
`kdbg.live-evidence.v4`; that full evidence is PASS for its exact epoch. The
historical evidence must not be promoted to the current 1.1.0 epoch.

```powershell
python .\src\tools\validate_release.py `
  --windows-package .\out\package\KDBG-1.1.0-win-x64 `
  --symbols-package .\out\package\KDBG-1.1.0-win-x64-symbols `
  --live-run-report .\out\evidence\<current-live-run.json> `
  --live-evidence .\out\evidence\<current-live-evidence-v4.json>
```

Optional MemProcFS pmem failure는 built-in reverse-mapper의 별도 결과와 구분해
기록한다. WDK build, VM prerequisite and every live observation remain independent
gates.

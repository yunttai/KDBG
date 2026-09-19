# KDBG 1.1.0 productization gate audit

> **Historical / superseded:** 이 문서는 RC1 시점의 감사 기록으로 보존한다.
> 현재 판정은 `docs/exec-plans/STATUS.md`의 RC4 status를 따른다.
> RC4 public v4 영상은 presentation review PASS이고 `origin`에 게시된
> `v1.1.0-rc4`는 source-freeze tag다. Formal GUI evidence는 `CAPTURED_UNREVIEWED`,
> `evidence_pass=false`, `human_review_complete=false`이며 stable release는 차단됐다.

Date: 2026-09-18 KST

Scope: documentation, integration judgement and existing immutable `out/`
evidence. This update does not modify product source, packages, drivers or
external services. A gate is PASS only for the exact identity and evidence named
here.

## Current 1.1.0 baseline

- Branch: `feature/kdbg-1.1.0`.
- Unsigned epoch: `product-1.1.0-rc1-final-20260918`.
- Main/symbol/source/scope SHA-256:
  `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f` /
  `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849` /
  `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184` /
  `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
- VM-test-signed derivative: `product-1.1.0-rc1-test1-20260918`, package
  `596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`,
  certificate `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1`,
  signer thumbprint `ba34b393521d722ba01df87afccc6f3feb760b2c`.
- Source-complete: PASS. Layout, core build, CTest 9/9 and source validator
  passed.
- Windows build/package: PASS for the unsigned product epoch. This does not
  establish production Authenticode or trusted timestamping.

## Exact Windows 11 evidence

Required-core run `run-20260918T091747Z-21a27820` is **PASS under VM test
trust**. On Windows 11 build 26200 it verified ABI 6, Probe PFN discovery,
physical read, eight-byte one-shot apply, full read-back, 4096-byte rollback,
final lock, guest cleanup, checkpoint restore and final VM Off. Summary/archive
SHA-256 are:

- `c6bb846f56db8679758dab486195916e952298ae0a0416929372da44d716e50b`
- `0457ba5352e5b9005bbada1b366684b8d120f662b83c26a24758ad95aab8f6a9`

Extended run `extended-20260918T092819Z-66c07a32` is **PASS under VM test
trust**. It completed two lifecycle cycles, ten stop/start transitions, four
reboots, a 1800-second soak, 61x8=488 reads, a midpoint transaction, seven
benchmark runs, cleanup, checkpoint restore and final VM Off. Summary/archive
SHA-256 are:

- `12570c4cdf41536d9a3be97461a0e58c043c5ba470baee948a14e8f1909c56ee`
- `f4c80a7c375a426bdd853e24118b623152cfbd556e56c146d20e3ded2896bc9c`

GUI run `run-20260918T092129Z-f14f5f7a` completed automation with
`CAPTURED_UNREVIEWED`, 24 captures/20 scenes, cleanup, checkpoint restore and
final VM Off. Summary/archive/capture SHA-256 are:

- `f5fd51ef18c319c37feb5adb997582e56cd2efe9b03a1d6ea3213237f6815d0b`
- `6104933593259fb074466ba8d21a5fffd7e47803b2bfec71ce206e5c0a4ce252`
- `bd254d7a98230db0199051085453b09ea33405f3efe57a9ded42b8a3bebb6d42`

Human review is **FAIL**. The 1024 layout clips scene 03's grid and scene 20's
diff row and wraps columns. `evidence_pass=false`; these formal source-bound
flags remain unchanged.

Presentation-only overlay run
`out/polished-1024-minimal/runs/run-20260918T102055Z-6c85cee7` passed automatic
checks and independent human presentation review. Its summary/guest/capture
SHA-256 are:

- `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`
- `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`
- `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`

The run contains 24 captures/20 scenes and completed cleanup, checkpoint restore
and final VM Off. Scene 20's evidence-bound cue and the scene 10/11 crop fixes
resolve the earlier visual blockers.

The final video-only artifact is
`out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`,
SHA-256 `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`,
9,974,541 bytes, 1920x1080, 10 fps, 40.5 seconds and 405/405 frames. Report
SHA-256 is
`e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.
Automatic and independent human presentation review passed. This is a
presentation-quality PASS only, not a formal GUI evidence promotion or proof of
submission. No slide deck or GIF is a current deliverable.

## Current gate table

| Gate and requirement | Current evidence-based state | Immediately executable work | New authority or external dependency |
|---|---|---|---|
| Source-complete | **PASS** for source `8f9a0474…f6a9` and scope `bd2c93da…8932` | Preserve the exact snapshot and rerun if included source changes | None for current source gate |
| Windows-build-verified | **PASS (UNSIGNED PRODUCT EPOCH)** for main `3698e533…36f` and symbols `0b6dadf7…849` | Preserve package manifests and sidecar hashes | Production signing is a separate gate |
| Required-core physical transaction | **PASS (VM TEST TRUST)** for `run-20260918T091747Z-21a27820` | Preserve report/archive and rerun after any package identity change | Production-signed clean-guest promotion remains external |
| Extended lifecycle and soak | **PASS (VM TEST TRUST)** for `extended-20260918T092819Z-66c07a32` | Preserve exact report/archive | Production-signed clean-guest promotion remains external |
| Formal 20-scene source-bound GUI evidence | **FAIL HUMAN REVIEW (UNCHANGED)**. Automated capture completed, but `evidence_pass=false` remains | Preserve the formal result; a new source-bound run would be required to change it | Formal human review would be required for any promotion |
| Presentation-video quality | **PASS (PRESENTATION-ONLY)**. Overlay automatic gate and independent human review passed; final MP4/report hashes recorded | Preserve the exact overlay and video identities | No external dependency for this quality gate; it does not prove submission |
| Production signing and trusted timestamp | **BLOCKED EXTERNAL**. Current trust is only the disposable-VM test certificate | Prepare a new hash-bound epoch after signing and validate returned drivers on a clean guest | Release owner must provide production signer/HSM access, TSA selection and publication authority |
| Monitored support and security operation | **PENDING EXTERNAL/ORGANIZATIONAL** | Execute notification and acknowledgement drills against the configured routes | Release owner must staff and acknowledge the routes |
| Submission metadata and actual submission | **PENDING**. Invite, deadline, recipient, speaker fields and completed submission are not proved | Populate the CFP fields and attach only the reviewed MP4 | Speaker/release owner input and conference intake |
| Optional MemProcFS `pmem` acquisition | **OPTIONAL / UNVERIFIED**, not a base-product blocker | With pinned third-party files, verify hashes/licenses and run the isolated bridge in the disposable VM | Compatible distribution, acquisition configuration and acceptance are required |

## Historical 1.0.0 baseline (preserved, not rebound)

- Frozen exact-final main/symbol hashes: `7f6b0fd9…b265a` /
  `d8715bf7…c96f`.
- Path-mapped main/symbol/source epoch: `b6832712…e47f` /
  `7801bfef…70aa` / `0484b5dd…49ee`.
- Windows 10 build 19044 human-reviewed final v4: `fc0afb4b…9823`;
  77-entry archive `438881e7…a18e3`.
- Historical Windows 11 required-core run
  `run-20260918T042905Z-f19bda60` passed for package/source
  `41f90e2b…2934` / `98700c7c…1eca`, restored checkpoint
  `f60a775a-26f6-4ef9-bb19-f61c93346bb4` and finished Off.
- Later 1.0.0 engineering evidence covered extended lifecycle/soak and the full
  feature capture matrix. Those results remain bound to their exact 1.0.0
  identities and do not promote 1.1.0.

## Integration decision

KDBG 1.1.0 is source-complete, Windows-build-verified and live-VM-verified for
the exact identities above under disposable-VM test trust. The presentation-
only final MP4 passed automatic and independent human presentation review. The
formal source-bound GUI evidence remains `evidence_pass=false` and is not
promoted by that overlay. Commercial release remains blocked by production
signer/TSA output, returned-driver clean-guest verification and monitored
support/security acknowledgement. Actual DEF CON submission state, deadline,
recipient and invite are not claimed.

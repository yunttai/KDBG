# Known limitations

These statements describe the exact KDBG 1.1.0 release-candidate epochs checked
on 2026-09-18. Historical 1.0.0 observations are retained separately and are not
used as 1.1.0 PASS evidence.

- Supported guest floor is Windows x64 build 19041 because the driver uses the
  modern nonpaged-pool and physical-range APIs; older Windows builds fail the
  packaged prerequisite check.
- The exact unsigned 1.1.0 main/symbol package pair passed clean MSVC/WDK build,
  CTest 9/9, Inf2Cat with 0 errors/0 warnings, PE/PDB binding and strict package
  validation. Main/symbol/source/scope SHA-256 values are
  `3698e5333957bec112bb39c372ae933a623af86bbc12e310c2f1bddc7bdce36f`,
  `0b6dadf7e4d1f8cfe7a77200cb6c76e01b01ec1a270ed3c4f5ae25c6ffe8f849`,
  `8f9a04740cc576e97a56776b017da7fc0c8d344289677b9be8d579f9d4edc184`
  and `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
- The driver fallback uses three exact-version NuGet archives whose SHA-512
  values are locked and rechecked before each offline build.
- SYS/CAT test trust and load pass only in the disposable Windows 11 VM. The
  derivative package SHA-256 is
  `596ccdf0a65818591e87b28737115da3066328ede42583ef95bc83d8f3d74413`;
  the test certificate SHA-256 is
  `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1`.
  This does not establish production Authenticode signing, a trusted timestamp,
  or clean-customer production trust.
- Windows 11 Pro x64 build 26200 required-core run
  `run-20260918T091747Z-21a27820` passed install/load, ABI 6, exact Probe PFN
  2117631 write/read-back/reload/rollback, final lock, cleanup, exact checkpoint
  restore and final VM Off.
- Extended run `extended-20260918T092819Z-66c07a32` passed two lifecycle cycles,
  10 stop/start operations, four reboot boundaries, an 1800-second soak with
  61 reports x 8 reads, midpoint verified write/rollback, seven mock-only
  benchmark processes, guest validation, checkpoint restore and final VM Off.
- The current N-1 lifecycle transition used a preserved 1.0.0 previous candidate.
  It does not claim a round-trip against an artifact downloaded again from a
  public release channel.
- GUI run `run-20260918T092129Z-f14f5f7a` passed its automatic 24-capture,
  20-scene integrity checks and remains `CAPTURED_UNREVIEWED`. Independent human
  presentation review failed: at 1024-pixel guest capture, scene 03 lacks the
  required grid, scene 20 clips the diff row, and some text wraps excessively.
- The source-bound MP4 compositor passed automatically. `KDBG-demo.mp4` is 9,759,713 bytes,
  405 frames and 40.5 seconds with SHA-256
  `c368dde54d19f46fedd32895f319223221538c006fcf4626277665b8fe5aad3d`.
  It remains `evidence_pass=false`; the formal source-bound evidence has not been
  promoted.
- A separate presentation-only overlay run
  `run-20260918T102055Z-6c85cee7` passed 24 captures/20 scenes, cleanup, exact
  checkpoint restore and final VM Off. Scene 20 exact cue and widened crops
  resolve the earlier visual blockers. Its host summary, guest archive and
  captures SHA-256 values are
  `e579e3fb5351e7a9f8c6b7652e37859916f2430ad23048cb08e1f95bbc38e104`,
  `32945bd31a181ff05d55e9e0d1db6a7c2800941baaaa4225a38b1631fc0cf6ce`
  and `fffb17d8d0aba0b3ef3179379d97a6be3703d510e75352ae96cba02a264e3038`.
- Final presentation video
  `out/demo-product-1-1-0-rc1-test1-polished-20260918/KDBG-demo-final2.mp4`
  passed automatic validation and
  independent presentation-only human review. It is 9,974,541 bytes, 1920x1080,
  10 fps, 405/405 frames and 40.5 seconds with SHA-256
  `4cd5a4f71e7baabc758c1097814cca9fc3371f6dc460ef0483faef5b2263d454`;
  its report SHA-256 is
  `e13ddce3aa9cffec601f94f3ee928a5d4ec06e23e96b4757ea4edb3def9a31b7`.
  This presentation-quality PASS does not change the formal source-bound run's
  status. No slide deck or GIF is part of 1.1.0.
- The discarded VirtualBox 6.1.32 guest repeatedly bugchecked `0xA` before KDBG.
  Current live evidence uses the disposable Hyper-V Windows 11 VM and exact
  checkpoint restore.
- MemProcFS/`vmm.dll` is optional and not distributed. The isolated bridge and
  negative diagnostics pass, but actual `pmem` initialization/query is
  unverified because the compatible runtime/acquisition driver is unavailable.
- The built-in reverse mapper is bounded to the attached process and may not
  find ownership elsewhere; the dedicated-fixture live path is verified.
- User-mode executables are unsigned and no production Authenticode trust claim
  is made. CAT creation/signability is separate from trusted driver load.
- The package contains support, privacy, license/EULA, update/rollback and
  vulnerability-intake contracts, but no paid SLA or monitored commercial
  contact is asserted. Support/security notification and acknowledgement remain
  release-owner gates.
- Package SBOM generation requires Syft. Windows user-mode artifacts use the
  static MSVC runtime, so a separate Microsoft VC++ Redistributable is not a
  clean-VM prerequisite.
- Scanner/analysis benchmarks use mock/synthetic backends. The required-core
  report records exact live 4 KiB transaction behavior, but the seven-run
  benchmark result does not claim live-driver performance or population-wide
  workload performance.
- No code injection, signing bypass, vulnerable-driver loading, stealth,
  debugging evasion or arbitrary kernel-virtual write feature is provided.

Historical 1.0.0 evidence, including Windows 10 build 19044 and earlier Windows
11 engineering runs, remains valid only for the exact historical package/source
identities recorded with it.

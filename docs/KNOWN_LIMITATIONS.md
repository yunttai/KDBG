# Known limitations

These statements describe KDBG 1.1.0 RC4 at commit
`4b376bb0d61eab232af8a2f7f29033238b911022`, checked on 2026-09-19.
Historical observations are not used as RC4 PASS evidence. DEF CON submission
is outside the current release-work scope.

- Supported guest floor is Windows x64 build 19041 because the driver uses the
  modern nonpaged-pool and physical-range APIs; older Windows builds fail the
  packaged prerequisite check.
- The exact unsigned 1.1.0 main/symbol package pair passed clean MSVC/WDK build,
  CTest 9/9, Inf2Cat with 0 errors/0 warnings, PE/PDB binding and strict package
  validation. Main/symbol/source/scope SHA-256 values are
  `4dd98b120a725d1804078a394c4d659cdb059a568a38a78643a936ce5f1f34d9`,
  `1f042e5e7a51cb1e2428b6ddb3c955c277de4993a264444e242fe469d104ac68`,
  `966c51f26c9e4da27491a4c00b8989c0eb8360ea3b85d8e9513adf1915ee0f92`
  and `bd2c93dad7604e84534515a00437e8198fa565a654fa665b6cbf235585b98932`.
- The driver fallback uses three exact-version NuGet archives whose SHA-512
  values are locked and rechecked before each offline build.
- SYS/CAT test trust and load pass only in the disposable Windows 11 VM. The
  derivative package SHA-256 is
  `7f7c179738eb670ca79d6c41bc9c46c445c1ffd31811c46f39bbbdcad3df45d5`;
  the test certificate SHA-256 is
  `bd7de7eb5e0dd305604d5f3dc617c13d268f844dbe541677f6eb4b7f166058b1`.
  This does not establish production Authenticode signing, a trusted timestamp,
  or clean-customer production trust.
- Windows 11 Pro x64 build 26200 required-core run
  `run-20260919T015729Z-8445dddb` passed install/load, ABI 6, exact Probe
  write/read-back/reload/rollback, final lock, cleanup, exact checkpoint restore
  and final VM Off. Guest archive SHA-256 is
  `39c31476928084337d402b6f8b772388c1cfb321c216f3ea4a7ea2d5460857da`.
- RC4 optional extended/lifecycle/soak validation was not run. Any RC1
  extended-run result is historical only and is not rebound to RC4.
- The historical N-1 lifecycle transition used a preserved 1.0.0 previous candidate.
  It does not claim a round-trip against an artifact downloaded again from a
  public release channel.
- GUI run `run-20260919T015850Z-1cfb0381` passed host execution, capture,
  cleanup, checkpoint restore, and independent archive/hash integrity audit
  with 24 frames, 20 scenes, 21 assertions, and 229 actions. It remains
  `CAPTURED_UNREVIEWED`, `evidence_pass=false`, and
  `human_review_complete=false`; integrity PASS is not human visual approval.
- The initial RC4 MP4 passed automatic composition but failed independent
  public-suitability review because private paths and weak crops remained. It is
  internal-only and is not a presentation or release PASS.
- Public v2 failed independent review because the taskbar remained visible;
  v2/v3 are superseded. Presentation-only public-v4
  `out/demo-product-1-1-0-rc4-test1-public-v4-20260919/KDBG-1.1.0-demo-public-v4.mp4`
  is 9,553,416 bytes, 1920x1080, 10 fps, 405 frames, and 40.5 seconds with
  SHA-256
  `43eda62e57607d36517c4bf139094cae8ef786dd7a8e0ea688154f3787475260`.
  The automatic compositor and independent presentation review passed. Review
  covered 405/405 frames, 20 scenes, 24 segments, and 19 boundaries; no rendered
  path, username, taskbar, notification, or unrelated process was visible, and
  core claims were readable. Report/scenes/contact-sheet SHA-256 values are
  `406054011b2e47dc144631e17e63d920acb715e4076c303556a852fd1009bd88`,
  `9e4a0543f4aaa61f44a39674e737b212df20474b8f063f1b44aa99d6817dcd04`,
  and `fa8597a86ae39318e4cd52f2eea0e135623fa77ccf07956ca983702fed59258b`.
  Raw `frames/` are excluded from the public bundle because they contain
  private paths or the taskbar. The video-only delivery copy under
  `out/release-media/` has the same MP4 SHA/bytes and is the directory's only
  file. This presentation PASS does not promote the formal source-bound run.
- The discarded VirtualBox 6.1.32 guest repeatedly bugchecked `0xA` before KDBG.
  Current live evidence uses the disposable Hyper-V Windows 11 VM and exact
  checkpoint restore.
- MemProcFS/`vmm.dll` is optional and not distributed. The isolated bridge and
  negative diagnostics pass, but actual `pmem` initialization/query is
  unverified because the compatible runtime/acquisition driver is unavailable.
- The built-in reverse mapper is bounded to the attached process and may not
  find ownership elsewhere; the dedicated-fixture live path is verified.
- User-mode executables are unsigned and no production Authenticode trust claim
  is made. Eleven exact production-signing inputs are staged with request hash
  `3f94c26060bc437460b22ced778c52f1f70165e49a7ac57f0979c1a347f64001`,
  but `signing_performed=false` and `network_submission_performed=false`.
  Production certificate/private key, HSM or signer service, RFC 3161 TSA, and
  returned signed artifacts are absent. CAT creation/signability is separate
  from trusted driver load.
- Annotated source-freeze tag `v1.1.0-rc4` is published to `origin` at
  `4b376bb0d61eab232af8a2f7f29033238b911022`. Stable tag `v1.1.0` and public
  release have not been created; they remain blocked on production signing and
  verification of the returned artifacts.
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

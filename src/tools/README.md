# KDBG developer tools

| File | Purpose |
|---|---|
| `build.ps1` | Configure/build/test a CMake preset; `-Package` also builds Release drivers and a ZIP package |
| `build_drivers.ps1` | Build both drivers with an installed WDK or the pinned NuGet WDK fallback |
| `build_drivers_nuget.ps1` | Verify the locked WDK/SDK NuGet archives and invoke MSVC plus Inf2Cat without machine-wide WDK installation |
| `package_windows.ps1` | Stage, validate, and publish GUI, bridge, mandatory INF-matched driver catalogs, VM evidence tools, docs, hashes, toolchain metadata, and SBOM |
| `setup/` | Build the elevated native Setup UI and its stable-root transactional PowerShell bootstrap |
| `manage_drivers.ps1` | Manage build-tree driver services in the disposable VM |
| `run.ps1` | Run a build-tree GUI after the existing VM/snapshot confirmations |
| `verify_layout.py` | Check repository layout, ABI ownership, and CMake references |
| `validate_release.py` | Independently validate source, Windows package, symbols, and live evidence gates |
| `new_live_evidence.ps1` | Create fail-closed `kdbg.live-evidence.v4` metadata bound to the Probe transaction, dedicated process analysis, live verifier report, and real artifacts |
| `live_verify/` | Build the packaged read-only-by-default Probe write/read-back/rollback evidence CLI |
| `../fixtures/process_fixture/` | Build the packaged deterministic process/ownership/page-table target |
| `capture_demo.ps1` | Launch the visible demo and create the mandatory 20-scene human-review template outside the package |
| `win11_validation/New-Win11ValidationWorkspace.ps1` | Create a release-hash-bound Win11 Hyper-V validation workspace under `out/win11-validation/<epoch>`; generated readiness is read-only and live execution remains separately confirmed |

One-command Release candidate build on the prepared Windows/WDK machine:

```powershell
.\src\tools\build.ps1 -Preset windows-release -Fresh -Package
```

`syft` is a required packaging prerequisite and must be on `PATH`. Packaging
fails before publishing when Syft, either INF-declared CAT, MSVC compiler
identity, Windows SDK identity, or WDK identity cannot be verified. Both main
and symbols `BUILD-METADATA.json` files record the MSVC compiler/toolset,
Windows SDK, WDK, CMake, Python, PowerShell, and Syft versions.
Release user-mode targets emit full PDBs while `/PDBALTPATH:%_PDB%` keeps private
build paths out of PE CodeView records. Paired validation compares every
EXE/SYS RSDS GUID+age with its required PDB and rejects stale symbols.

The package root contains `KDBGSetup.exe` for the normal interactive
Install/Repair/Update/Uninstall path. The packaged `tools/` directory contains
`setup.ps1`, `setup_contract.psm1`, and its own `diagnose.ps1`, `install.ps1`,
`start.ps1`, `run.ps1`, `stop.ps1`, and `uninstall.ps1` lifecycle. Package
assembly uses a validated staging directory so a missing input or validator
failure does not replace the last published package directory.

It also contains `capture_demo.ps1`, `new_live_evidence.ps1`,
`live-evidence.example.json`, and the validator used by the evidence generator.
With the matching symbols package present, the disposable VM therefore does
not need a source checkout to assemble and validate the v4 evidence bundle.
Python 3.11+ is still required. Write all raw pages, reports, logs, media, and
the final JSON to a separate evidence directory, never below the immutable
main package; otherwise its complete `SHA256SUMS.txt` file set is invalidated.
The final JSON also binds a separate human scene-review file containing the GIF
hash, reviewer/time, redaction decisions, and observed millisecond range plus
concrete note for every required scene.
Running packaged `tools/validate_release.py` with no arguments infers the main
package and its sibling symbols directory; the source-tree copy keeps the
source-complete default.

The live verifier supports Windows x64 build 19041+ and attests its packaged
executable plus both running SCM kernel-driver binaries before device open.
Its safe relative-path hashes are bound to the final v4 evidence bundle.

These tools do not configure Code Integrity, create a certificate, or prove a
live write. Windows build and live-VM evidence remain separate gates.

Create a Win11 validation workspace by explicitly supplying the immutable ZIP,
its SHA-256, the source-snapshot SHA-256 embedded in its build metadata, a bound
Hyper-V VM name, and a lowercase epoch slug. The workspace copies the exact ZIP,
records only relative paths, validates all harness script hashes/ASTs, and keeps
every later report below its own directory. `Check-Win11Readiness.ps1` never
mutates a VM. `Invoke-Win11Validation.ps1` additionally requires an initially
Off VM, one exact checkpoint Name/GUID pair, a guest Administrator credential,
and both explicit disposable-VM and restore confirmations.

The required Win11 gate is one platform-delta vertical slice only. Interactive
GUI/media review, repeated reboot/lifecycle testing, the full GUI feature
matrix, and long-run performance remain an optional Extended gate with status
`NOT RUN`; they do not block a passing required core result.

The portable driver fallback pins `Microsoft.Windows.WDK.x64` 10.0.26100.2454
and both transitive SDK packages in `src/driver/WdkBootstrap/packages.lock.json`.
Use `build_drivers.ps1 -WdkMode NuGet -Offline` after the cache is populated to
prove that no network or machine-wide WDK is required. The WDK cache is a
build-only input and is never copied into the release package.

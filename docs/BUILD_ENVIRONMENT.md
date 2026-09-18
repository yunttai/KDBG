# KDBG 빌드·실행 환경

## 1. Portable core

GUI/driver를 제외한 PFN, transaction, scanner, pointer, snapshot, page-table core와 deterministic tests를 Linux/macOS/Windows에서 빌드한다.

필수:

- CMake 3.25+
- Ninja
- C++20 compiler
- Python 3.11+

```powershell
Push-Location .\src
cmake --preset core-debug
cmake --build --preset core-debug --parallel
ctest --preset core-debug --output-on-failure
Pop-Location
python .\src\tools\validate_release.py --source-complete
```

Output: `out/build/core-debug/`.

## 2. Windows GUI와 native bridge

필수:

- Windows 10/11 x64
- Visual Studio 2022 Desktop development with C++
- Windows SDK
- CMake, Ninja, Git

```powershell
.\src\tools\build.ps1 -Preset windows-debug
# 또는
.\src\tools\build.ps1 -Preset windows-release
```

CMake가 lock file에 고정된 Dear ImGui, imgui_memory_editor, Zydis source를 가져온다. `kdbg_memprocfs_bridge.exe`도 같은 preset에서 빌드되고 GUI output의 `plugins/memprocfs_bridge/`에 복사된다.

## 3. WDK drivers

Visual Studio 2022 C++ tools가 필요하다. 설치형 WDK가 있으면 기존 MSBuild
toolset을 사용하고, 없으면 `Microsoft.Windows.WDK.x64` 10.0.26100.2454와
그 전이 SDK 패키지를 lock file 및 package SHA-512로 검증한 뒤 공식 NuGet
cache에서 직접 `cl`/`link`/`Inf2Cat` 경로를 사용한다. WDK package는 build-only이며
제품 package에 재배포하지 않는다. Windows package metadata는 실제 `cl.exe`,
MSVC toolset, Windows SDK와 WDK/NuGet identity를 기록한다.

```powershell
.\src\tools\build_drivers.ps1 -Configuration Debug
# clean rebuild
.\src\tools\build_drivers.ps1 -Configuration Debug -Clean
# 이미 복원된 cache만 사용하는 완전 offline 재현
.\src\tools\build_drivers.ps1 -Configuration Release -Clean `
  -WdkMode NuGet -Offline -NuGetPackageCache .\out\wdk-nuget
```

기본 `-WdkMode Auto`는 완전한 설치형 WDK를 우선하고, 없을 때 pinned NuGet
fallback을 쓴다. cache가 없으면 .NET 8 SDK로 exact locked restore를 한 번 수행한다.
`-Offline`에서는 누락 cache나 hash mismatch를 즉시 거부한다. 설치형 경로의
solution은 `src/driver/KDBGDrivers.sln`이다.

NuGet fallback은 configuration/version별 고정 intermediate 경로를 배타 파일
잠금으로 직렬화하고 `/Z7`, `/DEBUG:FULL`, `/BREPRO`를 사용한다. 반복 build에서
Release SYS는 byte-identical이어야 한다. MSVC PDB 내부 스트림과 Inf2Cat CTL의
생성 시각/identifier는 새 build마다 달라질 수 있으므로 새 driver build는 새
candidate hash로 취급한다. 한 번 고정된 SYS/PDB/CAT 입력을 package assembler로
반복 조립하면 main/symbol ZIP은 byte-identical이어야 한다.

스크립트는 signing을 우회하지 않는다. `.sys` load에는 VM test-signing 또는 적절한 정식 인증서가 필요하다.

## 4. Windows package

GUI/bridge와 driver가 먼저 빌드되어 있어야 한다. `syft` CLI도 `PATH`에
있어야 하며, package 조립기는 실제 Syft version을 metadata에 기록하고
SPDX 2.3 SBOM 생성에 실패하면 publish 전에 종료한다.

```powershell
.\src\tools\package_windows.ps1 -Configuration Release -Zip
```

배포 패키지는 Release-only 계약이며 Debug package 요청은 거부된다.

기본 output:

```text
out/package/KDBG-1.1.0-win-x64/
out/package/KDBG-1.1.0-win-x64-symbols/
```

Package에는 GUI, bridge, `tools/kdbg_process_fixture.exe`, 두 driver의 SYS/INF/CAT, config, standalone lifecycle
및 live-evidence tools, operator docs, security/support/privacy/license-EULA/
update-rollback/vulnerability/release-note documents, licenses, SPDX SBOM,
build metadata와 `SHA256SUMS.txt`가 포함된다. 각 INF의 `CatalogFile`과 정확히 일치하는 두
CAT가 모두 release prerequisite이며, PDB는 symbols package로 분리한다.
`validate_release.py --windows-package`가 PE x64/version/Debug CRT, package coverage,
hash, SBOM, 개인 경로까지 다시 확인한다. Release CMake target은 전체 PDB를
생성하고 PE CodeView에는 PDB basename만 기록한다. Paired validator는 각
EXE/SYS의 RSDS GUID+age를 대응 PDB information stream과 비교하고 main/symbol
metadata의 source snapshot과 toolchain identity도 정확히 일치시킨다.

Package-only VM에서는 main package와 symbols package를 함께 복사한 뒤 main
package의 `tools/capture_demo.ps1`, `tools/kdbg_live_verify.exe`,
`tools/kdbg_process_fixture.exe`,
`tools/new_live_evidence.ps1`, `tools/live-evidence.example.json`,
`tools/validate_release.py`만으로 capture 안내, live report 생성, v4 evidence
조립과 paired validation을 수행할 수 있다. Python 3.11+는 VM에 설치되어
있어야 하지만 원본 repository 경로는 필요 없다. raw page, live report,
command log, media와 최종 evidence JSON은 immutable package directory 내부가
아닌 별도 evidence directory에 둔다. Package 내부에 결과를 쓰면
`SHA256SUMS.txt`의 완전한 file-set 계약이 깨지므로 validation이 실패한다.

## 5. Driver service 관리

전제:

- dedicated/disposable VM
- 복원 가능한 snapshot
- Administrator PowerShell
- KDBG/KDBGProbe binary와 ABI가 같은 build

```powershell
.\src\tools\manage_drivers.ps1 `
  -Action Install -Configuration Debug `
  -ConfirmDedicatedVm -ConfirmSnapshot

.\src\tools\manage_drivers.ps1 `
  -Action Start -Configuration Debug `
  -ConfirmDedicatedVm -ConfirmSnapshot

.\src\tools\manage_drivers.ps1 -Action Status
```

Stop/Remove:

```powershell
.\src\tools\manage_drivers.ps1 -Action Stop
.\src\tools\manage_drivers.ps1 -Action Remove
```

## 6. GUI 실행

```powershell
.\src\tools\run.ps1 `
  -Configuration Debug -NoBuild `
  -ConfirmDisposableVm -ConfirmSnapshot
```

## 7. MemProcFS 선택 구성

GUI 자체 필수 기능은 KDBG driver와 Probe만으로 동작한다. PFN owner 가산점에 MemProcFS를 사용할 경우 package의 bridge directory에 compatible `vmm.dll` 및 필요한 runtime을 별도로 배치한다.

기본 acquisition device는 `pmem`이다. 변경:

```powershell
$env:KDBG_MEMPROCFS_DEVICE = 'C:\dumps\memory.raw'
```

AGPL runtime은 KDBG GUI에 직접 링크하지 않는다.

## 8. Gate 구분

Portable build 성공은 Win32/WDK compile 성공을 의미하지 않는다. Windows build 성공도 실제 physical write 증거를 의미하지 않는다. Source, Windows build, Live VM Gate를 독립적으로 기록한다.

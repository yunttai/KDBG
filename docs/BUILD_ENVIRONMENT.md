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

추가 요구사항: Windows Driver Kit.

```powershell
.\src\tools\build_drivers.ps1 -Configuration Debug
# clean rebuild
.\src\tools\build_drivers.ps1 -Configuration Debug -Clean
```

Solution: `src/driver/KDBGDrivers.sln`.

스크립트는 signing을 우회하지 않는다. `.sys` load에는 VM test-signing 또는 적절한 정식 인증서가 필요하다.

## 4. Windows package

GUI/bridge와 driver가 먼저 빌드되어 있어야 한다.

```powershell
.\src\tools\package_windows.ps1 -Configuration Release -Zip
```

배포 패키지는 Release-only 계약이며 Debug package 요청은 거부된다.

기본 output:

```text
out/package/KDBG-1.0.0-win-x64/
out/package/KDBG-1.0.0-win-x64-symbols/
```

Package에는 GUI, bridge, two drivers/INF, config, standalone lifecycle tools,
operator docs, licenses, SPDX SBOM, build metadata와 `SHA256SUMS.txt`가 포함된다.
CAT은 실제 생성된 경우에만 포함하고 PDB는 symbols package로 분리한다.
`validate_release.py --windows-package`가 PE x64/version/Debug CRT, package coverage,
hash, SBOM, 개인 경로까지 다시 확인한다.

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

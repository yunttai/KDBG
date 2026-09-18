# KDBG DEF CON / product roadmap

기준일: 2026-09-16 KST. 일정이 아니라 검증 가능한 exit criteria로 단계를
승격한다. 각 단계의 결과는 같은 source revision과 artifact hash에 묶는다.

## P0 — Current source candidate

- portable/MSVC 빌드와 deterministic tests를 전부 통과시킨다.
- persistence migration, MemProcFS subprocess, SCM/package rollback 회귀를 닫는다.
- First/Next Scan, pointer, snapshot과 backend hot path의 전후 benchmark를 남긴다.
- false PASS와 현재 candidate에 없는 historical evidence를 분리한다.

Exit: source validator, repeated CTest, static analysis와 benchmark correctness가
PASS하고 미검증 Windows/live 항목이 명시돼야 한다.

## P1 — Kernel memory debugger/editor vertical slice

- loaded kernel module catalog와 주소 탐색
- 명시적 local symbol path/PDB의 주소↔symbol 해석
- kernel virtual read + Zydis disassembly
- symbol/address → page-table → PA/PFN → physical page cross-navigation
- exact-byte transaction, independent reload와 rollback evidence

Exit: 한 GUI 세션에서 임의의 관찰 주소가 module/symbol/instruction/PTE/PFN으로
이어지고, short read나 symbol 부재가 성공으로 표시되지 않아야 한다.

## P2 — High-performance analysis

- First Scan throughput와 memory footprint 최적화
- Next Scan candidate filtering과 cache locality 최적화
- pointer edge enumeration, snapshot capture/save/load 최적화
- backend IOCTL/copy/page-walk hot path 최적화
- large result virtualization과 render-thread stall 측정

Exit: 동일 machine/build에서 correctness hash를 유지한 7회 측정의 median/p95를
전후 JSON으로 제시한다. 한 번의 최고값은 발표 수치로 사용하지 않는다.

## P3 — Exact Windows VM runtime

- WDK Release clean build와 production candidate package
- clean install, reboot, update/repair/rollback, 10회 start/stop, uninstall/reinstall
- device/main ABI, Probe, physical range와 kernel module/symbol readiness
- Probe PFN physical transaction과 process write/Freeze recovery
- forced GUI exit와 cancellation 중단 복구

Exit: VM snapshot ID, OS build, binary hashes, raw page hashes, command log와 종료
상태가 하나의 evidence bundle로 검증돼야 한다.

## P4 — DEF CON submission packet

- 한 문장 논지: PFN을 PID/VA/PTE/심볼까지 역추적하는 트랜잭션형 Windows 커널
  메모리 워크벤치
- 새 기술 기여, 기존 접근의 측정 가능한 병목, 구현 세부와 실패 사례
- 20/45분 talk outline, architecture/threat diagrams, reproducible demo script
- live demo와 동일한 5분 backup video, redacted logs와 benchmark raw JSON
- breakpoint/register/single-step 부재를 포함한 정확한 capability statement

Exit: 독립 검토자가 clean VM에서 문서만으로 데모를 재현하고 모든 발표 수치를
raw evidence에서 다시 계산할 수 있어야 한다.

## P5 — Commercial release candidate

- production driver signing과 clean-machine trust/load 검증
- 설치/복구/업데이트 UX, version migration과 rollback channel — native Setup
  source/build, stable install root와 exact-package VM lifecycle 완료
- packaged support, privacy, MIT license/EULA decision, vulnerability intake,
  offline update/rollback contract와 release notes — source/package contract 완료
- main/symbol package, SBOM, attribution, hashes와 crash diagnostics
- clean guest install/reboot/update/uninstall soak

현재 local documentation/package contract, native Setup source/build와 disposable
test-trust guest의 script soak 및 exact-package Setup UI install/repair/update/reboot/
uninstall/clean-reboot가 완료됐다. Monitored support/security route와 production
signing/trust는 아직 외부/실행 gate다.

Exit: 서명·설치·지원 같은 외부 gate까지 완료된 뒤에만 commercial-ready로 표시한다.

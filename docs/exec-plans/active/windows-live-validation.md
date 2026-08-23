# Active plan — disposable-VM live Probe validation

Host-side Windows/MSVC/WDK builds are PASS as recorded in
`docs/VALIDATION_REPORT.md`. The `kdbg.source-snapshot.v1` main/symbol candidate
also passed strict validators, same-input ZIP reproducibility, and 5/5 negative
fixtures. A document-only final repack will refresh published hashes. This plan
covers the remaining live gates. One DADF ABI6 physical transaction, one D339
advanced read-only workflow, and the exact Release read-only/lifecycle gate
completed in the same continuously running VM. Write-sensitive gates stay separate.

## 전제

- existing `Windows-VM` (confirmed)
- 복원 가능한 checkpoint (confirmed)
- Administrator PowerShell (confirmed)
- final validated `KDBG-1.0.0-win-x64` package copied into the VM
- test-signing (confirmed) 또는 적절한 정식 driver certificate

Interim package(`DADF43AA...`)의 install/device/ABI6와 Probe transaction은 같은
VM에서 PASS했다. 이 package는 final로 간주하지 않으며 final package의
device/ABI/live transaction 증거로 재사용하지 않는다.

D3390AD4 candidate는 fresh Probe query와 advanced read-only evidence를 PASS했지만
physical write는 `NOT_RUN`이다. 두 candidate 모두 final package binding이 아니다.

Exact Release package는 deploy/hash binding/device/main ABI6/fresh Probe query/exact
4 KiB read-only/invalid IOCTL rejection/stop-remove를 physical writes 0으로 PASS했다.
Identity는 `out/evidence/final-live-manifest.json`과
`out/evidence/RELEASE-HASHES.txt`가 authoritative다.

## 1. Verify or rebuild the package

```powershell
.\src\tools\build.ps1 -Preset windows-release -Fresh
.\src\tools\build_drivers.ps1 -Configuration Release -Clean
.\src\tools\package_windows.ps1 -Configuration Release -Zip
```

PASS 조건은 충족됐다: metadata의 `source_snapshot_scope`는
`kdbg.source-snapshot.v1`이고, package-local verify와 main/symbol strict validators,
same-input ZIP 재현성, 5/5 package negative fixtures가 모두 PASS다. 문서 반영
repack에서는 새 SHA를 기록한다. Package PASS alone은 write-sensitive live PASS를 뜻하지 않는다.

## 2. Load

Interim `DADF43AA...` package에서 KDBG PID 1140과 ABI 6 device open은 PASS했다.
Exact Release에서도 deploy/hash binding, device/main ABI 6, invalid IOCTL rejection과
stop/remove가 PASS했다. 문서 repack 후 아래 명령으로 같은 gate를 재실행하고 external
manifest/hash set을 갱신한다.

```powershell
.\src\tools\manage_drivers.ps1 -Action Install -ConfirmDedicatedVm -ConfirmSnapshot
.\src\tools\manage_drivers.ps1 -Action Start -ConfirmDedicatedVm -ConfirmSnapshot
```

PASS 조건: 두 device open, ABI 일치, write gate LOCKED, physical range query 성공.
ABI mismatch, zero/oversize length, address overflow, out-of-RAM PA, unarmed
write, bad acknowledgement, second controller, short output, close/reopen gate
reset과 Probe unload/reload도 이 disposable VM에서 fail-closed인지 기록한다.

## 3. Probe transaction

Interim package에서 다음 exact transaction은 PASS했다.

- PFN `0xDA9FE`, PA `0x00000000DA9FE000`, generation 1
- baseline CRC32 `0x9DA6C668`
- offset `0x100`: `3D4E5F70` → `4B444247`
- full-page preflight, read-back, independent reload, rollback 모두 PASS
- rollback CRC32 `0x9DA6C668` 복원, write gate LOCKED
- final counters: reads 11, writes 2, rejected 0, stage 4, status 0, transferred 4096
- evidence ZIP SHA-256: `b8e88cb7cc78ab42f5edf0b4409b99ab4e6e60ab2761ed08f98233ee11bd0769`

Exact Release에서는 fresh Probe query와 exact 4096-byte read-only가 PASS했고
physical writes는 0이었다. Final physical write는 `NOT_RUN`으로 BLOCKED다.

아래 절차는 final package hash에 바인딩해 다시 확인할 checklist다.

1. Probe Query로 VA/PA/PFN/generation/CRC를 기록한다.
2. GUI Physical Memory 탭에서 PFN을 읽고 4096/4096을 확인한다.
3. 작은 데이터 구간만 local edit한다.
4. diff와 preflight 상태를 기록한다.
5. PFN을 다시 입력해 one-shot unlock한다.
6. Apply 후 전체 페이지 read-back PASS를 확인한다.
7. PFN을 다시 load하고 Probe CRC를 재조회한다.
8. rollback 후 baseline과 다시 일치하는지 확인한다.
9. driver/session write gate가 LOCKED인지 확인한다.

## 4. Advanced UI evidence

D3390AD4 candidate의 read-only 결과:

- built-in selected-process PFN reverse mapping PASS: 2M table-page cap, mapping 1개
- Page Tables PASS: selected VA → PA/PFN이 Probe와 exact match
- memory map/modules PASS
- First/Next Scan PASS: 26 → 26
- address-list entry PASS, Freeze OFF
- pointer scan PASS: 10,385 paths
- Zydis disassembly PASS: 456 instructions
- snapshot PASS: 4096 bytes, changed runs 0
- About/counters/final state PASS: process detached, both gates LOCKED, page CLEAN
- optional MemProcFS BLOCKED: actual launch error 126 loading `vmm.dll`
- process live write/freeze BLOCKED
- D339 physical write BLOCKED (`NOT_RUN`)

근거: `out/evidence/candidate-d3390ad4-advanced-live.json`.

## 5. Evidence JSON

Physical transaction archive와 extracted directory는 각각
`out/evidence/live-20260823-110826-359.zip`과
`out/evidence/live-20260823-110826-359/`에 있다. 이것은 verified physical
transaction evidence지만 submission video 또는 hash-bound v2 bundle PASS는 아니다.
`out/evidence/KDBG-1.0.0-demonstration.gif`는 declared scope에서 PASS다. frames
1–5는 DADF interim physical transaction, frames 6–17은 D339 read-only validation이며
final-package live-evidence.v2는 아니다.
Exact Release read-only/lifecycle binding은
`out/evidence/final-live-manifest.json`과 `out/evidence/RELEASE-HASHES.txt`에 있다.
`new_live_evidence.ps1`로 v2 template을 생성하고 실제 command log/video/final
package artifact hash를 채운 뒤 package와 함께 검증한다.

```powershell
python .\src\tools\validate_release.py `
  --windows-package .\out\package\KDBG-1.0.0-win-x64 `
  --live-evidence <evidence.json>
```

실패, short I/O, mismatch, verifier finding 또는 BSOD가 있으면 PASS로 표시하지
않고 dump/log를 보존하고 snapshot을 복원한다. Stop/remove는 exact Release에서
PASS했지만 Driver Verifier는 `NOT_RUN`으로 BLOCKED다. write gate가 잠긴 상태를
증거에 포함한다. production Authenticode trust는 별도
인증서 검증 증거가 없으면 PASS로 기록하지 않는다.

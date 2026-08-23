# ADR-0001: KDBG 전용 최소 메모리 드라이버를 구현한다

- 상태: Accepted
- 날짜: 2026-08-15

## Context

과제에는 물리 메모리 범위 조회, PFN 단위 Read/Write, 프로세스 주소 공간 접근, x64 VA→PA 변환이 필요하다. 범용 커널 디버거나 대규모 외부 드라이버 전체를 포함하면 기능 범위·검증 비용·공격 표면이 불필요하게 커진다.

## Decision

KDBG는 `kn-live-dbg`의 MIT 허용 범위와 좁은 user/kernel ABI 설계를 참고하되, 제품 이름·ABI·서비스·보안 경계를 KDBG 전용으로 독립 구현한다.

구현 범위:

- version/session query와 single-controller ownership
- Administrators/SYSTEM 전용 device ACL
- physical memory range enumeration
- bounded physical read/write
- per-handle one-shot write gate와 acknowledgement
- process resolve/read/write
- read-only kernel virtual memory read
- x64 PML5/PML4/PDPT/PD/PT walk와 large-page 처리
- deterministic `KDbgProbe.sys` validation fixture

제외 범위:

- Code Integrity/HVCI/Secure Boot 우회
- BYOVD 또는 취약 드라이버 로딩
- 임의 커널 가상주소 쓰기
- 은닉, 안티치트 우회, 프로세스 주입
- 범용 WinDbg/DbgEng 명령 호환 계층

## Consequences

### Positive

- 과제에 필요한 최소 공격 표면만 유지한다.
- GUI와 드라이버 사이의 ABI를 버전·길이·바이트 수로 엄격히 검증할 수 있다.
- Probe 페이지를 통해 실제 Write와 read-back을 재현 가능하게 증명할 수 있다.
- 외부 범용 프로젝트의 런타임 의존성을 줄인다.

### Negative

- Windows/WDK 환경에서 별도 빌드·서명·Driver Verifier 검증이 필요하다.
- Windows build별 구조 차이를 다루는 프로세스 해석 경로를 지속 검증해야 한다.
- 물리 메모리 쓰기는 VM 스냅샷과 제한된 fixture 사용을 전제로 한다.

## Rejected

- 범용 디버거 전체 포트: 범위와 의존성이 과다하다.
- Kernel-Bridge 전체 도입: GPLv3 및 기능 범위가 요구사항보다 넓다.
- Cheat Engine DBK 통합: 과제 기능보다 훨씬 넓고 라이선스·안전 검토 부담이 크다.
- vulnerable signed driver/BYOVD: 안전 경계와 과제 범위를 위반한다.

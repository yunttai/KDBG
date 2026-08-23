# KDBG source tree

`src/`는 제품과 개발 도구의 유일한 소스 루트다.

- `app/`: Win32, DirectX 11, Dear ImGui GUI
- `core/`: portable memory transaction, scanner, paging, PFN, snapshot logic
- `driver/`: KDbgDriver와 KDbgProbe WDK projects/solution
- `shared/`: user/kernel ABI
- `plugins/`: optional isolated native helpers
- `tests/`: deterministic portable tests
- `fixtures/`: fixed test data
- `config/`: 배포·안전 정책 예시(JSON; 현재 GUI 런타임 설정 파일은 아님)
- `tools/`: build, service, package, validation scripts
- `cmake/`: pinned GUI/disassembly dependencies

Portable core는 Linux/macOS/Windows에서 빌드할 수 있다. GUI와 native bridge는 Windows 전용이며, driver projects는 Visual Studio와 WDK가 필요하다.

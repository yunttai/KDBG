# KDBG developer tools

| 파일 | 역할 |
|---|---|
| `build.ps1` | CMake preset configure/build/test, 선택적 driver/package 연계 |
| `build_drivers.ps1` | Visual Studio/WDK solution 빌드 |
| `package_windows.ps1` | GUI, bridge, drivers, docs, SHA-256 manifest 조립 |
| `manage_drivers.ps1` | disposable VM에서 service install/start/stop/remove/status |
| `run.ps1` | VM/snapshot 확인 후 elevated GUI 실행 |
| `verify_layout.py` | Codex 구조, src-only 원칙, ABI 중복, CMake source 참조 검사 |
| `validate_release.py` | source, Windows package, live evidence gate 분리 검증 |
| `new_live_evidence.ps1` | package/page/log/video hash와 Probe live 결과를 fail-closed `kdbg.live-evidence.v2` JSON으로 기록 |
| `live-evidence.example.json` | live evidence 필드 예시; 기본값은 모두 fail-closed |
| `capture_demo.ps1` | 제출 영상 전제와 필수 장면 안내 |

Windows/live scripts는 호스트에서 임의로 실행하지 않는다. VM snapshot 확인 switch가 없는 driver service 작업은 차단된다.

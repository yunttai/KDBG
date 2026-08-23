# 라이선스와 Attribution 계획

이 문서는 법률 자문이 아니라 개발 시 혼합을 피하기 위한 운영 기준이다.

## 1. 직접 포함 가능

### kernullist/kn-live-dbg

- License: MIT
- 고정 commit: `8f792132f303a835975e0afcc3dbdbe168b7a040`
- 직접 포함 시:
  - 원 copyright
  - MIT license text
  - 수정 파일에 upstream 경로와 commit
  - 변경 사항 표시

### VollRagm/PTView

- License: MIT
- 고정 commit: `4a7d09cf65c755c3a7cd1a2d24ce60c6cc4cc367`
- PTE bit decoder 코드 일부를 가져오면 notice를 유지한다.
- 가능하면 개념만 보고 level-aware decoder를 새로 작성한다.

### imgui_memory_editor

- Header 자체에 MIT 표기
- 고정 commit: `a436e793fe44a2c8e827bfcbf138fcbe11940476`
- 파일 상단 license/comment 제거 금지

### Dear ImGui

- License: MIT
- 고정 docking-branch commit: `fd13a1e8923a0a7077b404fc36fd063b25a0c0b5`
- 배포물에 notice 포함

## 2. 독립 프로세스

### MemProcFS

- License: AGPLv3
- 고정 commit/version: `029d845408f5f89d7f401b35c5961696316ad356`, 5.18.4.243
- 메인 앱 소스에 코드를 복사하지 않는다.
- `memprocfs_bridge.exe`를 별도 프로그램으로 유지한다.
- bridge를 배포하면 해당 source/license 제공 요건을 별도로 충족한다.
- 과제 제출에 bridge binary가 꼭 필요하지 않으면 사용자가 별도 설치하도록 한다.

## 3. 참조 전용

### Kernel-Bridge

- GPLv3
- 코드 복사/정적·동적 링크 금지(현재 프로젝트 정책)
- API 이름과 아이디어를 참고해 독립 설계

### Cheat Engine

- repository-level license를 명확히 확인하지 못함
- 일부 파일은 restrictive copyright header를 가짐
- 코드 복사 금지
- UX 동작만 독립 구현

### Windows-Kernel-Explorer

- 공개 repository가 소스가 아니라 binary/data/screenshots 위주
- binary/driver 재배포 금지
- screenshots를 제품에 포함하지 않음
- UX 참고만 수행

## 4. 배포 notice 구조

```text
licenses/
├── LICENSE-PROJECT.txt
├── MIT-kn-live-dbg.txt
├── MIT-PTView.txt
├── MIT-imgui-memory-editor.txt
├── MIT-Dear-ImGui.txt
└── THIRD-PARTY-NOTICES.txt
```

실제 notice와 license 원문은 root `licenses/`에 있고 Release package에
그대로 복사된다. Zydis의 bundled transitive dependency Zycore commit
`0b2432ced0884fd152b471d97ecf0258ff4d859f`와 MIT 원문도 포함한다.

## 5. 자동 검사

`src/tools/validate_release.py`는 다음을 검사한다.

- `THIRD_PARTY.lock.json` 존재
- direct source reuse 항목에 license 지정
- release notice/license 경로와 package hash coverage
- CMake와 lock의 immutable commit 일치
- 금지 repository 이름이 `src/` 코드 include/import에 등장하지 않는지
- 제품 code가 `src/` 밖에 없는지

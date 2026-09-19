#include "Localization.h"

#include <array>
#include <atomic>
#include <cstddef>

namespace kdbg::ui {
namespace {

using namespace std::literals;

// Natural UI language is localized.  Established debugger terminology,
// identifiers, state tokens, driver names, and low-level diagnostics stay in
// English where that is clearer to a Korean technical audience.
constexpr auto kTranslations = std::to_array<TranslationEntry>({
    {"About KDBG"sv, "KDBG 정보"sv},
    {"Add"sv, "추가"sv},
    {"Add Address"sv, "주소 추가"sv},
    {"Add an address from scan results."sv, "Scan 결과에서 주소를 추가하세요."sv},
    {"Address"sv, "주소"sv},
    {"Address List / Freeze"sv, "주소 목록 / Freeze"sv},
    {"Address added to watch list."sv, "주소를 Watch 목록에 추가했습니다."sv},
    {"Address removed from the watch list."sv, "주소를 Watch 목록에서 제거했습니다."sv},
    {"Alignment"sv, "정렬"sv},
    {"Apply Changed Runs & Verify"sv, "변경 구간 적용 및 검증"sv},
    {"Apply Exact 4 KiB Transaction & Verify"sv,
     "정확한 4 KiB 트랜잭션 적용 및 검증"sv},
    {"Arm"sv, "활성화"sv},
    {"Arm Process Writes"sv, "프로세스 Write 활성화"sv},
    {"Attach"sv, "Attach"sv},
    {"Attached PID: %u | Pointer width: %u-bit | Gate: %s | Freeze authorization: %s"sv,
     "Attach된 PID: %u | Pointer 폭: %u-bit | Gate: %s | Freeze 권한: %s"sv},
    {"Attached PID: %u | Process write gate: %s"sv,
     "Attach된 PID: %u | 프로세스 Write gate: %s"sv},
    {"Attached PID: %u | Snapshot reads do not require the process write gate."sv,
     "Attach된 PID: %u | Snapshot 읽기에는 프로세스 Write gate가 필요하지 않습니다."sv},
    {"Attach a process for the built-in page-table reverse mapper."sv,
     "내장 Page Table 역매핑을 사용하려면 프로세스를 Attach하세요."sv},
    {"Attach to a process to browse and edit its memory."sv,
     "메모리를 탐색하고 편집하려면 프로세스를 Attach하세요."sv},
    {"Attach to a process to capture live snapshots."sv,
     "Live Snapshot을 캡처하려면 프로세스를 Attach하세요."sv},
    {"Attach to a process to disassemble memory."sv,
     "메모리를 Disassembly하려면 프로세스를 Attach하세요."sv},
    {"Attach to a process to enumerate its virtual memory map."sv,
     "Virtual Memory Map을 조회하려면 프로세스를 Attach하세요."sv},
    {"Attach to a process to scan pointer paths."sv,
     "Pointer 경로를 Scan하려면 프로세스를 Attach하세요."sv},
    {"Attach to a process to use the memory scanner."sv,
     "Memory Scanner를 사용하려면 프로세스를 Attach하세요."sv},
    {"Bring Lab Online & Load Probe"sv, "Lab 시작 및 Probe 로드"sv},
    {"After"sv, "변경 후"sv},
    {"Baseline"sv, "Baseline"sv},
    {"Baseline snapshot captured."sv, "Baseline Snapshot을 캡처했습니다."sv},
    {"Before"sv, "변경 전"sv},
    {"Byte Count"sv, "바이트 수"sv},
    {"Bytes"sv, "바이트"sv},
    {"Cancel"sv, "취소"sv},
    {"Cancel Analysis Export"sv, "분석 자료 내보내기 취소"sv},
    {"Cancel Disassembly"sv, "Disassembly 취소"sv},
    {"Cancel Operation"sv, "작업 취소"sv},
    {"Cancel PFN Query"sv, "PFN 조회 취소"sv},
    {"Cancel Pointer Scan"sv, "Pointer Scan 취소"sv},
    {"Cancel Read"sv, "읽기 취소"sv},
    {"Cancel Refresh"sv, "새로고침 취소"sv},
    {"Cancel Symbol Load"sv, "Symbol 로드 취소"sv},
    {"Cancel Watch I/O"sv, "Watch I/O 취소"sv},
    {"Capture Baseline"sv, "Baseline 캡처"sv},
    {"Capture Current"sv, "현재 상태 캡처"sv},
    {"Capture or load both baseline and current snapshots first."sv,
     "먼저 Baseline과 현재 Snapshot을 모두 캡처하거나 불러오세요."sv},
    {"Capturing baseline snapshot..."sv, "Baseline Snapshot 캡처 중..."sv},
    {"Capturing current snapshot..."sv, "현재 Snapshot 캡처 중..."sv},
    {"Clear Snapshots"sv, "Snapshot 지우기"sv},
    {"Close"sv, "닫기"sv},
    {"Committed"sv, "Committed"sv},
    {"Compare Snapshots"sv, "Snapshot 비교"sv},
    {"Connect Device"sv, "Device 연결"sv},
    {"Connect the KDBG driver to access physical memory."sv,
     "물리 메모리에 접근하려면 KDBG driver를 연결하세요."sv},
    {"Copy Analysis Evidence Path"sv, "분석 Evidence 경로 복사"sv},
    {"Copy build ID"sv, "Build ID 복사"sv},
    {"Copy Evidence Path"sv, "Evidence 경로 복사"sv},
    {"Copy final PA"sv, "최종 PA 복사"sv},
    {"Copy Kernel VA"sv, "Kernel VA 복사"sv},
    {"Copy PA"sv, "PA 복사"sv},
    {"Copy PFN"sv, "PFN 복사"sv},
    {"Copy Resolved VA"sv, "확인된 VA 복사"sv},
    {"Current"sv, "현재 값"sv},
    {"Current snapshot captured."sv, "현재 Snapshot을 캡처했습니다."sv},
    {"Delta"sv, "변화량"sv},
    {"Depth"sv, "깊이"sv},
    {"Description"sv, "설명"sv},
    {"Detach"sv, "연결 해제"sv},
    {"Dirty Diff"sv, "변경 Diff"sv},
    {"Disassemble"sv, "Disassemble"sv},
    {"Disassembly cancellation requested."sv, "Disassembly 취소를 요청했습니다."sv},
    {"Disassembler"sv, "Disassembler"sv},
    {"Disconnect process"sv, "프로세스 연결 해제"sv},
    {"Driver"sv, "드라이버"sv},
    {"Edit"sv, "편집"sv},
    {"English"sv, "English"sv},
    {"Enter a PFN and read a page."sv, "PFN을 입력한 뒤 페이지를 읽으세요."sv},
    {"Executable"sv, "실행 가능"sv},
    {"Export Analysis Evidence"sv, "분석 Evidence 내보내기"sv},
    {"Export Live Evidence Bundle"sv, "Live Evidence Bundle 내보내기"sv},
    {"filter module name or local image path"sv,
     "Module 이름 또는 로컬 image 경로 필터"sv},
    {"filter module or mapped path"sv, "Module 또는 mapped 경로 필터"sv},
    {"filter name or PID"sv, "이름 또는 PID 필터"sv},
    {"First Scan"sv, "첫 Scan"sv},
    {"First scan started."sv, "첫 Scan을 시작했습니다."sv},
    {"Freeze"sv, "Freeze"sv},
    {"Help"sv, "도움말"sv},
    {"Hexadecimal"sv, "16진수"sv},
    {"Include executable"sv, "실행 가능 영역 포함"sv},
    {"Include guard"sv, "Guard 영역 포함"sv},
    {"Independent Reload (keep rollback)"sv,
     "독립 Reload (Rollback 유지)"sv},
    {"Observe Live Page (recover rollback state)"sv,
     "Live 페이지 관찰 (Rollback 상태 복구)"sv},
    {"Install/Update KDBG"sv, "KDBG 설치/업데이트"sv},
    {"Install/Update Probe"sv, "Probe 설치/업데이트"sv},
    {"Instruction"sv, "명령어"sv},
    {"Invalid disassembly address."sv, "Disassembly 주소가 올바르지 않습니다."sv},
    {"Kernel Explorer"sv, "커널 탐색기"sv},
    {"Kernel Explorer (read-only inspection)"sv,
     "커널 탐색기 (읽기 전용 분석)"sv},
    {"Korean"sv, "한국어"sv},
    {"Language"sv, "언어"sv},
    {"Licenses / attribution"sv, "라이선스 / 저작자 표시"sv},
    {"Live VA -> PA Translation"sv, "Live VA -> PA 변환"sv},
    {"Load Baseline"sv, "Baseline 불러오기"sv},
    {"Load Current"sv, "현재 상태 불러오기"sv},
    {"Load a PFN first."sv, "먼저 PFN을 로드하세요."sv},
    {"Load Local Symbols"sv, "로컬 Symbol 로드"sv},
    {"Load Table"sv, "Table 불러오기"sv},
    {"Loaded Modules"sv, "로드된 Module"sv},
    {"Loaded %llu region(s) and %llu module(s)."sv,
     "영역 %llu개와 Module %llu개를 로드했습니다."sv},
    {"Lock all writes"sv, "모든 Write 잠금"sv},
    {"Lock Process Writes"sv, "프로세스 Write 잠금"sv},
    {"Manual Hex"sv, "Hex 직접 입력"sv},
    {"Manual Address"sv, "직접 입력 주소"sv},
    {"Manual address added to the address list."sv,
     "직접 입력한 주소를 목록에 추가했습니다."sv},
    {"Manual Type"sv, "직접 입력 형식"sv},
    {"Max results"sv, "최대 결과 수"sv},
    {"Maximum Depth"sv, "최대 깊이"sv},
    {"Maximum Offset"sv, "최대 Offset"sv},
    {"Memory Map"sv, "메모리 맵"sv},
    {"MemProcFS ownership query started."sv, "MemProcFS 소유권 조회를 시작했습니다."sv},
    {"Module"sv, "Module"sv},
    {"Navigate"sv, "이동"sv},
    {"New Value"sv, "새 값"sv},
    {"New First Scan"sv, "새 First Scan"sv},
    {"Next Scan"sv, "다음 Scan"sv},
    {"Next scan started."sv, "다음 Scan을 시작했습니다."sv},
    {"Next Scan is blocked; start a new First Scan."sv,
     "다음 Scan을 진행할 수 없습니다. 새 First Scan을 시작하세요."sv},
    {"No local changes."sv, "로컬 변경 없음."sv},
    {"No physical page loaded."sv, "로드된 물리 페이지가 없습니다."sv},
    {"No scan results."sv, "Scan 결과가 없습니다."sv},
    {"Not captured or loaded."sv, "캡처하거나 불러온 데이터가 없습니다."sv},
    {"Open final PA in Physical Memory"sv, "최종 PA를 Physical Memory에서 열기"sv},
    {"Open Resolved VA in Page Tables"sv, "확인된 VA를 Page Tables에서 열기"sv},
    {"Open VA in Page Tables"sv, "VA를 Page Tables에서 열기"sv},
    {"optional label"sv, "선택 입력"sv},
    {"Page Tables"sv, "페이지 테이블"sv},
    {"Path"sv, "경로"sv},
    {"PFN -> Process / Virtual Address"sv, "PFN -> 프로세스 / Virtual Address"sv},
    {"PFN Navigator"sv, "PFN Navigator"sv},
    {"PFN Ownership"sv, "PFN 소유권"sv},
    {"PFN ownership query complete: %llu mapping(s)."sv,
     "PFN 소유권 조회 완료: mapping %llu개."sv},
    {"Physical Memory"sv, "물리 메모리"sv},
    {"Physical Page"sv, "물리 페이지"sv},
    {"Physical Address"sv, "물리 주소"sv},
    {"Local physical RAM — this Windows instance"sv,
     "로컬 물리 RAM — 현재 Windows 인스턴스"sv},
    {"Runtime host identity: %s"sv, "Runtime host 식별값: %s"sv},
    {"Runtime host identity: %.*s"sv, "Runtime host 식별값: %.*s"sv},
    {"Target binding: CURRENT RUNTIME SESSION"sv,
     "대상 binding: 현재 Runtime 세션"sv},
    {"Target binding: STALE / RELOAD REQUIRED"sv,
     "대상 binding: 만료됨 / 다시 로드 필요"sv},
    {"Target kind: %s"sv, "대상 종류: %s"sv},
    {"Provenance: %s"sv, "출처: %s"sv},
    {"Provenance: %.*s"sv, "출처: %.*s"sv},
    {"Transfer size: 4096 bytes (one physical page)"sv,
     "전송 크기: 4096바이트 (물리 페이지 1개)"sv},
    {"Session revision: %llu"sv, "세션 revision: %llu"sv},
    {"Baseline CRC32: %08X | Current CRC32: %08X"sv,
     "Baseline CRC32: %08X | 현재 CRC32: %08X"sv},
    {"Driver physical gate: %s"sv, "드라이버 물리 gate: %s"sv},
    {"RANGE-VALIDATED RAW PFN TARGET — ownership is not implied"sv,
     "RAM 범위가 검증된 Raw PFN 대상 — 소유권을 의미하지 않음"sv},
    {"WRITE TARGET: RANGE-VALIDATED RAW PFN"sv,
     "WRITE 대상: RAM 범위가 검증된 Raw PFN"sv},
    {"The complete 4096-byte page is inside a driver-reported RAM range; ownership is not implied."sv,
     "전체 4096바이트 페이지가 드라이버가 보고한 RAM 범위 안에 있습니다. 소유권을 의미하지 않습니다."sv},
    {"PID confirmation"sv, "PID 확인"sv},
    {"Pointer Scanner"sv, "포인터 스캐너"sv},
    {"Pointer scan complete:"sv, "Pointer Scan 완료:"sv},
    {"Pointer scan started."sv, "Pointer Scan을 시작했습니다."sv},
    {"Pointer-size aligned"sv, "Pointer 크기 정렬"sv},
    {"Probe fixture has not been queried and verified in this session."sv,
     "이 세션에서 Probe fixture 조회 및 검증을 완료하지 않았습니다."sv},
    {"Previous"sv, "이전 값"sv},
    {"Process Memory"sv, "프로세스 메모리"sv},
    {"Process memory browser ready for PID %u."sv,
     "PID %u 프로세스 메모리 탐색 준비 완료."sv},
    {"Process memory view loaded."sv, "프로세스 메모리 View를 로드했습니다."sv},
    {"Process memory view reloaded from the target."sv,
     "대상에서 프로세스 메모리 View를 다시 로드했습니다."sv},
    {"Process Scanner"sv, "프로세스 메모리 스캐너"sv},
    {"Process scanner ready."sv, "프로세스 메모리 스캐너 준비 완료."sv},
    {"Process value written and verified."sv,
     "프로세스 값 Write 및 검증을 완료했습니다."sv},
    {"Process writes armed."sv, "프로세스 Write가 활성화되었습니다."sv},
    {"Process writes locked."sv, "프로세스 Write가 잠겼습니다."sv},
    {"Query & Load Probe Fixture"sv, "Probe Fixture 조회 및 로드"sv},
    {"Query Driver Counters"sv, "Driver Counter 조회"sv},
    {"Query MemProcFS"sv, "MemProcFS 조회"sv},
    {"Read"sv, "읽기"sv},
    {"Reading and decoding process memory asynchronously..."sv,
     "프로세스 메모리를 비동기로 읽고 Disassembly하는 중..."sv},
    {"Read + Disassemble"sv, "읽기 + Disassemble"sv},
    {"Read View"sv, "View 읽기"sv},
    {"Readable"sv, "읽기 가능"sv},
    {"Redo Byte Edit"sv, "바이트 편집 다시 실행"sv},
    {"Refresh"sv, "새로고침"sv},
    {"Refresh Map"sv, "Map 새로고침"sv},
    {"Refresh Modules"sv, "Module 새로고침"sv},
    {"Refresh process list"sv, "프로세스 목록 새로고침"sv},
    {"Refresh Service Status"sv, "Service 상태 새로고침"sv},
    {"Refresh Values"sv, "값 새로고침"sv},
    {"Reconnect KDBG driver"sv, "KDBG 드라이버 다시 연결"sv},
    {"Reload Live"sv, "Live Reload"sv},
    {"Remove"sv, "제거"sv},
    {"Remove KDBG"sv, "KDBG 제거"sv},
    {"Remove Probe"sv, "Probe 제거"sv},
    {"Request Cancel"sv, "취소 요청"sv},
    {"Request Lifecycle Cancel"sv, "Lifecycle 취소 요청"sv},
    {"Reset"sv, "초기화"sv},
    {"Result Limit"sv, "결과 제한"sv},
    {"Result"sv, "결과"sv},
    {"Result truncated at the 10,000 instruction cap."sv,
     "명령어 10,000개 제한에서 결과가 잘렸습니다."sv},
    {"Reset Probe Pattern"sv, "Probe Pattern 초기화"sv},
    {"Resolve Address -> Symbol"sv, "Address -> Symbol 확인"sv},
    {"Resolve Symbol -> Address"sv, "Symbol -> Address 확인"sv},
    {"Retry Probe Metadata (keep evidence)"sv,
     "Probe Metadata 재시도 (Evidence 유지)"sv},
    {"Reverse-map Attached Process"sv, "Attach된 프로세스 역매핑"sv},
    {"Revert Local Edits"sv, "로컬 편집 되돌리기"sv},
    {"Revert Staged Edits"sv, "준비된 편집 되돌리기"sv},
    {"Rollback Previous Apply"sv, "이전 Apply Rollback"sv},
    {"Safety"sv, "안전"sv},
    {"Save Baseline"sv, "Baseline 저장"sv},
    {"Save Current"sv, "현재 상태 저장"sv},
    {"Save Table"sv, "Table 저장"sv},
    {"Scan results cleared."sv, "Scan 결과를 지웠습니다."sv},
    {"Scan Type"sv, "Scan 방식"sv},
    {"Second Value"sv, "두 번째 값"sv},
    {"Select a process"sv, "프로세스를 선택하세요"sv},
    {"Selected PID %u | %s | %s"sv, "선택한 PID %u | %s | %s"sv},
    {"Selected-process reverse mapping started."sv,
     "선택한 프로세스의 역매핑을 시작했습니다."sv},
    {"Session"sv, "세션"sv},
    {"Snapshots"sv, "Snapshots"sv},
    {"Snapshot diff complete: %llu changed run(s)."sv,
     "Snapshot Diff 완료: 변경 구간 %llu개."sv},
    {"Snapshot loaded and checksum verified."sv,
     "Snapshot을 불러오고 checksum을 검증했습니다."sv},
    {"Snapshot saved."sv, "Snapshot을 저장했습니다."sv},
    {"Snapshot workspace cleared."sv, "Snapshot 작업 공간을 지웠습니다."sv},
    {"Snapshot workspace ready for PID %u."sv,
     "PID %u의 Snapshot 작업 공간이 준비되었습니다."sv},
    {"Stage Evidence Probe Pattern"sv, "Evidence Probe Pattern 준비"sv},
    {"Start Address"sv, "시작 주소"sv},
    {"Start KDBG"sv, "KDBG 시작"sv},
    {"Start Pointer Scan"sv, "Pointer Scan 시작"sv},
    {"Start Probe"sv, "Probe 시작"sv},
    {"Start and connect the KDBG driver first."sv,
     "먼저 KDBG driver를 시작하고 연결하세요."sv},
    {"Static roots only"sv, "Static root만"sv},
    {"Stop KDBG"sv, "KDBG 중지"sv},
    {"Stop Probe"sv, "Probe 중지"sv},
    {"Target Address"sv, "대상 주소"sv},
    {"Target"sv, "대상"sv},
    {"Target Process"sv, "대상 프로세스"sv},
    {"This comparison uses the previous snapshot and does not require a value."sv,
     "이 비교는 이전 Snapshot을 사용하므로 값을 입력할 필요가 없습니다."sv},
    {"Translate with KDBG"sv, "KDBG로 변환"sv},
    {"Undo Byte Edit"sv, "바이트 편집 실행 취소"sv},
    {"Unlock for one operation"sv, "한 번의 작업만 잠금 해제"sv},
    {"Unlock One Physical Apply"sv, "한 번의 Physical Apply 잠금 해제"sv},
    {"Unlock physical write"sv, "Physical Write 잠금 해제"sv},
    {"Unlock Rollback"sv, "Rollback 잠금 해제"sv},
    {"Value"sv, "값"sv},
    {"Value Type"sv, "값 형식"sv},
    {"Virtual Address"sv, "가상 주소"sv},
    {"View PFN Ownership"sv, "PFN Ownership 보기"sv},
    {"Writable"sv, "쓰기 가능"sv},
    {"Writable only"sv, "쓰기 가능 영역만"sv},
    {"Writable regions only"sv, "쓰기 가능 영역만"sv},
    {"Write & Verify"sv, "Write 및 검증"sv},
    {"Watch refresh cancellation completed."sv,
     "Watch 새로고침 취소를 완료했습니다."sv},
    {"Address frozen."sv, "주소를 Freeze했습니다."sv},
    {"Address list saved."sv, "주소 목록을 저장했습니다."sv},
    {"Address unfrozen."sv, "주소 Freeze를 해제했습니다."sv},
    {"apply changes to"sv, "변경 적용"sv},
    {"roll back"sv, "Rollback"sv},
    {"Dirty bytes: %llu"sv, "변경된 바이트: %llu"sv},
    {"PID or virtual address is invalid."sv,
     "PID 또는 Virtual Address가 올바르지 않습니다."sv},
    {"Process writes affect the attached process on this Windows instance. "
     "Enter the attached PID (%u) to open the shared process write gate."sv,
     "프로세스 Write는 이 Windows 인스턴스에서 Attach된 프로세스에 적용됩니다. "
     "공유 프로세스 Write gate를 열려면 Attach된 PID (%u)를 입력하세요."sv},
    {"Retype current PFN"sv, "현재 PFN 다시 입력"sv},
    {"Staged process-memory edits reverted."sv,
     "준비된 프로세스 메모리 편집을 되돌렸습니다."sv},
    {"State: %s | Range: 0x%016llX + 0x%llX | Dirty bytes: %llu"sv,
     "상태: %s | 범위: 0x%016llX + 0x%llX | 변경된 바이트: %llu"sv},
    {"There is no snapshot to save."sv, "저장할 Snapshot이 없습니다."sv},
    {"This will %s a physical RAM page exposed by KDbgDriver in "
     "this Windows instance. Raw PFNs require a complete in-range "
     "4 KiB page; probe and process targets retain provenance "
     "revalidation."sv,
     "현재 Windows 인스턴스에서 KDbgDriver가 제공하는 물리 RAM 페이지에 %s "
     "작업을 수행합니다. Raw PFN은 전체 4 KiB가 RAM 범위 안에 있어야 하며, "
     "Probe 및 Process 대상은 출처를 다시 검증합니다."sv},
    {"BLOCKED: the selected target no longer satisfies its write prerequisites."sv,
     "BLOCKED: 선택한 대상이 더 이상 Write 선행 조건을 충족하지 않습니다."sv},
    {"Verified probe target | generation %u | CRC32 %08X"sv,
     "검증된 Probe 대상 | generation %u | CRC32 %08X"sv},
    {"Verified process target | PID %u | VA 0x%016llX"sv,
     "검증된 프로세스 대상 | PID %u | VA 0x%016llX"sv},
    {"WARNING: the driver reports its physical write gate ARMED. Ctrl+L locks all writes."sv,
     "WARNING: driver의 Physical Write gate가 ARMED 상태입니다. Ctrl+L로 모든 "
     "Write를 잠그세요."sv},
    {"Writes affect the attached process on this Windows instance. "
     "Enter the attached PID (%u) to arm writes."sv,
     "Write는 이 Windows 인스턴스에서 Attach된 프로세스에 적용됩니다. "
     "Write를 활성화하려면 Attach된 PID (%u)를 입력하세요."sv},
    {"Action"sv, "작업"sv},
});

std::atomic<UiLanguage> g_language{UiLanguage::English};
std::atomic_bool g_korean_font_available{false};

[[nodiscard]] bool AsciiEqualIgnoreCase(
    std::string_view left,
    std::string_view right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index) {
        auto lhs = left[index];
        auto rhs = right[index];
        if (lhs >= 'A' && lhs <= 'Z') {
            lhs = static_cast<char>(lhs - 'A' + 'a');
        }
        if (rhs >= 'A' && rhs <= 'Z') {
            rhs = static_cast<char>(rhs - 'A' + 'a');
        }
        if (lhs != rhs) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::span<const TranslationEntry> UiTranslationCatalog() noexcept {
    return kTranslations;
}

UiLanguage CurrentUiLanguage() noexcept {
    return g_language.load(std::memory_order_acquire);
}

bool SetUiLanguage(UiLanguage language) noexcept {
    switch (language) {
        case UiLanguage::English:
            g_language.store(UiLanguage::English, std::memory_order_release);
            return true;
        case UiLanguage::Korean:
            if (!g_korean_font_available.load(std::memory_order_acquire)) {
                return false;
            }
            g_language.store(UiLanguage::Korean, std::memory_order_release);
            if (!g_korean_font_available.load(std::memory_order_acquire)) {
                g_language.store(UiLanguage::English, std::memory_order_release);
                return false;
            }
            return true;
    }
    return false;
}

void SetKoreanFontAvailable(bool available) noexcept {
    g_korean_font_available.store(available, std::memory_order_release);
    if (!available) {
        g_language.store(UiLanguage::English, std::memory_order_release);
    }
}

bool KoreanFontAvailable() noexcept {
    return g_korean_font_available.load(std::memory_order_acquire);
}

const char* UiLanguageCode(UiLanguage language) noexcept {
    switch (language) {
        case UiLanguage::English:
            return "en-US";
        case UiLanguage::Korean:
            return "ko-KR";
    }
    return "en-US";
}

std::optional<UiLanguage>
ParseUiLanguage(std::string_view language) noexcept {
    if (AsciiEqualIgnoreCase(language, "en") ||
        AsciiEqualIgnoreCase(language, "en-us") ||
        AsciiEqualIgnoreCase(language, "english")) {
        return UiLanguage::English;
    }
    if (AsciiEqualIgnoreCase(language, "ko") ||
        AsciiEqualIgnoreCase(language, "ko-kr") ||
        AsciiEqualIgnoreCase(language, "korean") ||
        language == "한국어") {
        return UiLanguage::Korean;
    }
    return std::nullopt;
}

const char* UiText(std::string_view english) noexcept {
    if (CurrentUiLanguage() == UiLanguage::Korean) {
        for (const auto& entry : kTranslations) {
            if (entry.english == english) {
                return entry.korean.data();
            }
        }
    }
    return english.data();
}

std::string UiLabel(
    std::string_view english,
    std::string_view stable_id) {
    const std::string_view visible{UiText(english)};
    std::string label;
    label.reserve(visible.size() + 3U + stable_id.size());
    label.append(visible);
    label.append("###");
    label.append(stable_id);
    return label;
}

}  // namespace kdbg::ui

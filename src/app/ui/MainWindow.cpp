#include "app/ui/MainWindow.h"

#include "app/LocalDiagnostics.h"
#include "app/ui/Localization.h"
#include "core/memory/ProbeEvidencePattern.h"
#include "core/windows/DriverService.h"

#include <imgui.h>
#ifdef IMGUI_HAS_DOCK
#include <imgui_internal.h>
#endif

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <span>
#include <string_view>
#include <utility>

#ifdef _WIN32
#include <Windows.h>
#include <Wincrypt.h>
#endif

namespace kdbg {
using ui::CurrentUiLanguage;
using ui::KoreanFontAvailable;
using ui::SetUiLanguage;
using ui::UiLabel;
using ui::UiLanguage;
using ui::UiText;

namespace {

std::filesystem::path ExecutableDirectory() {
#ifdef _WIN32
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length != 0) {
        buffer.resize(length);
        return std::filesystem::path(buffer).parent_path();
    }
#endif
    return std::filesystem::current_path();
}

std::string PathToUtf8(const std::filesystem::path& path) {
#ifdef _WIN32
    const std::wstring& wide = path.native();
    if (wide.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS,
        wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string utf8(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS,
            wide.data(), static_cast<int>(wide.size()),
            utf8.data(), required, nullptr, nullptr) != required) {
        return {};
    }
    return utf8;
#else
    return path.string();
#endif
}

std::filesystem::path Utf8Path(std::string_view value) {
#ifdef _WIN32
    if (value.empty()) return {};
    const int required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (required <= 0) return {};
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()),
            wide.data(), required) != required) {
        return {};
    }
    return std::filesystem::path(wide);
#else
    return std::filesystem::path(value);
#endif
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

const char* PageStateName(PageSessionState state) noexcept {
    switch (state) {
    case PageSessionState::Empty: return "EMPTY";
    case PageSessionState::Loading: return "LOADING";
    case PageSessionState::Clean: return "CLEAN";
    case PageSessionState::Dirty: return "STAGED / DIRTY";
    case PageSessionState::Preflight: return "PREFLIGHT";
    case PageSessionState::Writing: return "WRITING";
    case PageSessionState::Verifying: return "VERIFYING";
    case PageSessionState::Conflict: return "CONFLICT";
    case PageSessionState::VerificationFailed: return "VERIFICATION FAILED";
    case PageSessionState::Error: return "ERROR";
    }
    return "UNKNOWN";
}

const char* ServiceStateName(const std::optional<bool>& running) noexcept {
    if (!running.has_value()) return "UNKNOWN";
    return *running ? "RUNNING" : "STOPPED / NOT INSTALLED";
}

std::optional<std::filesystem::path> LocalEvidenceRoot() {
#ifdef _WIN32
    std::wstring local_app_data(32768, L'\0');
    const DWORD length = GetEnvironmentVariableW(
        L"LOCALAPPDATA", local_app_data.data(),
        static_cast<DWORD>(local_app_data.size()));
    if (length == 0 || length >= local_app_data.size()) return std::nullopt;
    local_app_data.resize(length);
    return std::filesystem::path(local_app_data) / L"KDBG" / L"evidence";
#else
    return std::nullopt;
#endif
}

enum class RuntimeReadiness {
    SourceOnly,
    Disconnected,
    Mock,
    LiveConnected,
    LiveVerified
};

constexpr RuntimeReadiness ClassifyRuntime(
    bool backend_connected,
    bool backend_is_mock,
    bool packaged_driver_present,
    bool packaged_probe_present,
    bool driver_service_state_known,
    bool driver_service_running,
    bool probe_service_state_known,
    bool probe_service_running,
    bool probe_verified) noexcept {
    if (backend_connected && backend_is_mock) return RuntimeReadiness::Mock;
    if (backend_connected) {
        return probe_verified
            ? RuntimeReadiness::LiveVerified
            : RuntimeReadiness::LiveConnected;
    }
    if (!packaged_driver_present && !packaged_probe_present &&
        driver_service_state_known && probe_service_state_known &&
        !driver_service_running && !probe_service_running) {
        return RuntimeReadiness::SourceOnly;
    }
    return RuntimeReadiness::Disconnected;
}

static_assert(ClassifyRuntime(
    false, false, false, false, true, false, true, false, false) ==
    RuntimeReadiness::SourceOnly);
static_assert(ClassifyRuntime(
    false, false, false, false, true, false, true, true, false) ==
    RuntimeReadiness::Disconnected);
static_assert(ClassifyRuntime(
    false, false, false, false, true, false, false, false, false) ==
    RuntimeReadiness::Disconnected);
static_assert(ClassifyRuntime(
    true, true, false, false, true, false, true, false, false) ==
    RuntimeReadiness::Mock);
static_assert(ClassifyRuntime(
    true, false, true, true, true, true, true, true, true) ==
    RuntimeReadiness::LiveVerified);

const char* RuntimeReadinessName(RuntimeReadiness readiness) noexcept {
    switch (readiness) {
    case RuntimeReadiness::SourceOnly: return "SOURCE-ONLY";
    case RuntimeReadiness::Disconnected: return "DISCONNECTED";
    case RuntimeReadiness::Mock: return "MOCK / SIMULATED";
    case RuntimeReadiness::LiveConnected: return "LIVE CONNECTED";
    case RuntimeReadiness::LiveVerified: return "LIVE / PROBE VERIFIED";
    }
    return "UNKNOWN";
}

ImVec4 RuntimeReadinessColor(RuntimeReadiness readiness) noexcept {
    switch (readiness) {
    case RuntimeReadiness::SourceOnly:
        return ImVec4(0.70F, 0.70F, 0.74F, 1.0F);
    case RuntimeReadiness::Disconnected:
        return ImVec4(1.0F, 0.65F, 0.25F, 1.0F);
    case RuntimeReadiness::Mock:
        return ImVec4(0.45F, 0.75F, 1.0F, 1.0F);
    case RuntimeReadiness::LiveConnected:
        return ImVec4(0.75F, 0.85F, 0.30F, 1.0F);
    case RuntimeReadiness::LiveVerified:
        return ImVec4(0.35F, 0.90F, 0.45F, 1.0F);
    }
    return ImVec4(1.0F, 0.30F, 0.25F, 1.0F);
}

std::string FormatError(const Error& error) {
    std::ostringstream stream;
    stream << error.message;
    if (!error.operation.empty()) stream << " [" << error.operation << ']';
    if (error.native_code != 0) stream << " | native=" << error.native_code;
    if (error.requested != 0 || error.completed != 0) {
        stream << " | requested=" << error.requested
               << " completed=" << error.completed;
    }
    return stream.str();
}

constexpr std::uint32_t PageCrc32(
    std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t crc = 0xFFFFFFFFU;
    for (const std::uint8_t byte : bytes) {
        crc ^= byte;
        for (unsigned bit = 0; bit < 8U; ++bit) {
            const std::uint32_t mask =
                static_cast<std::uint32_t>(
                    -static_cast<std::int32_t>(crc & 1U));
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}

constexpr std::array<std::uint8_t, 9> kCrc32Check{
    '1', '2', '3', '4', '5', '6', '7', '8', '9'};
static_assert(PageCrc32(kCrc32Check) == 0xCBF43926U);

bool PageMatchesProbeCrc(
    const std::optional<std::array<
        std::uint8_t, kPhysicalPageSize>>& page,
    const std::optional<ProbeInfo>& probe) noexcept {
    return page.has_value() && probe.has_value() &&
        PageCrc32(*page) == probe->crc32;
}

bool ProbeIdentityMatchesPage(
    const ProbeInfo& probe,
    const PfnAddress& page,
    std::uint32_t generation) noexcept {
    return probe.byte_count == kPhysicalPageSize &&
        probe.pfn == page.pfn &&
        probe.physical_address == page.physical_address &&
        probe.generation == generation;
}

constexpr const char* kVersion = "1.1.0";
constexpr const char* kBuildId = KDBG_BUILD_ID;

std::string HexValue(std::uint64_t value, int width = 0) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::nouppercase;
    if (width > 0) {
        stream << std::setw(width) << std::setfill('0');
    }
    stream << value;
    return stream.str();
}

std::string WideToUtf8(std::wstring_view value) {
#ifdef _WIN32
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string utf8(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()),
            utf8.data(), required, nullptr, nullptr) != required) {
        return {};
    }
    return utf8;
#else
    return std::string(value.begin(), value.end());
#endif
}

std::string RuntimeHostMachineName() {
#ifdef _WIN32
    std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1U> name{};
    DWORD length = static_cast<DWORD>(name.size());
    if (GetComputerNameW(name.data(), &length) != FALSE && length != 0U) {
        return WideToUtf8(std::wstring_view{name.data(), length});
    }
#endif
    return "unknown-machine";
}

std::string RuntimeHostBootId() {
#ifdef _WIN32
    struct BootEnvironmentInformation {
        GUID boot_identifier{};
        ULONG firmware_type{0};
        ULONGLONG boot_flags{0};
    };
    using NtQuerySystemInformationFn = LONG(NTAPI*)(
        ULONG, PVOID, ULONG, PULONG);
    constexpr ULONG kSystemBootEnvironmentInformation = 90U;
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<NtQuerySystemInformationFn>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
    BootEnvironmentInformation boot{};
    if (query != nullptr &&
        query(
            kSystemBootEnvironmentInformation,
            &boot,
            static_cast<ULONG>(sizeof(boot)),
            nullptr) >= 0) {
        const auto& id = boot.boot_identifier;
        char text[64]{};
        std::snprintf(
            text, sizeof(text),
            "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
            id.Data1, id.Data2, id.Data3,
            id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3],
            id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
        return text;
    }

    // Fallback for a platform that does not expose the boot environment
    // information class: bind the app session to an estimated boot epoch.
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = now.dwLowDateTime;
    ticks.HighPart = now.dwHighDateTime;
    constexpr std::uint64_t kTicksPerMillisecond = 10000U;
    const auto uptime_ticks = GetTickCount64() * kTicksPerMillisecond;
    const auto boot_ticks = ticks.QuadPart >= uptime_ticks
        ? ticks.QuadPart - uptime_ticks
        : 0U;
    // Round the estimate to a second so scheduling jitter between the two
    // clock reads cannot create a different identity inside this process.
    constexpr std::uint64_t kTicksPerSecond = 10000000U;
    return HexValue(boot_ticks / kTicksPerSecond, 16);
#else
    return "unknown-boot";
#endif
}

std::string RuntimeHostProcessSessionId() {
#ifdef _WIN32
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    ULARGE_INTEGER creation_ticks{};
    if (GetProcessTimes(
            GetCurrentProcess(), &creation, &exit, &kernel, &user) != FALSE) {
        creation_ticks.LowPart = creation.dwLowDateTime;
        creation_ticks.HighPart = creation.dwHighDateTime;
    }
    return "pid-" + std::to_string(GetCurrentProcessId()) + "-" +
        HexValue(creation_ticks.QuadPart, 16);
#else
    return "unknown-process-session";
#endif
}

std::string PhysicalTargetProvenance(const PhysicalWriteTarget& target) {
    switch (target.kind) {
    case PhysicalTargetKind::RawPfn:
        return "Manual PFN entry; complete page validated against driver RAM ranges";
    case PhysicalTargetKind::ProbeFixture:
        return "KDbgProbe metadata bound to the loaded PFN/PA and generation";
    case PhysicalTargetKind::ProcessMapping:
        return "PTView writable mapping; PID " +
            std::to_string(target.process_id.value_or(0U)) + " / VA " +
            HexValue(target.virtual_page_address.value_or(0U), 16);
    }
    return "Unknown physical target provenance";
}

std::string EvidenceTimestampUtc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    std::ostringstream stream;
    const auto milliseconds = std::chrono::duration_cast<
        std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
    stream << std::put_time(&utc, "%Y%m%d-%H%M%S") << '-'
           << std::setw(3) << std::setfill('0') << milliseconds;
    return stream.str();
}

bool WritePageFile(
    const std::filesystem::path& path,
    const std::optional<std::array<std::uint8_t, kPhysicalPageSize>>& page) {
    if (!page.has_value()) return false;
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output.write(
        reinterpret_cast<const char*>(page->data()),
        static_cast<std::streamsize>(page->size()));
    output.flush();
    output.close();
    return output.good();
}

void LogResultDiagnostic(
    const Result<void>& result,
    DiagnosticEvent success,
    DiagnosticEvent failure) noexcept {
    if (result) {
        LogDiagnostic(success);
        return;
    }
    LogDiagnostic(
        failure,
        static_cast<std::uint64_t>(result.GetError().code),
        result.GetError().native_code);
}

}  // namespace

MainWindow::MainWindow() {
    kernel_explorer_.Attach(&backend_);
    runtime_host_machine_ = RuntimeHostMachineName();
    runtime_host_boot_id_ = RuntimeHostBootId();
    runtime_host_process_session_id_ = RuntimeHostProcessSessionId();
    const auto directory = ExecutableDirectory();
    const auto driver = directory / "drivers" / "KDbgDriver.sys";
    const auto probe_driver = directory / "drivers" / "KDbgProbe.sys";
    const auto fixture_info = directory / "fixture-info.json";
    const auto driver_utf8 = PathToUtf8(driver);
    const auto probe_driver_utf8 = PathToUtf8(probe_driver);
    std::snprintf(
        driver_path_.data(), driver_path_.size(), "%s", driver_utf8.c_str());
    std::snprintf(
        probe_driver_path_.data(), probe_driver_path_.size(),
        "%s", probe_driver_utf8.c_str());
    const auto fixture_info_utf8 = PathToUtf8(fixture_info);
    std::snprintf(
        fixture_info_path_.data(), fixture_info_path_.size(),
        "%s", fixture_info_utf8.c_str());

    RefreshServiceStates();
    RefreshProcesses();
    const auto opened = backend_.Open();
    if (opened) {
        ++runtime_backend_session_generation_;
        LogDiagnostic(DiagnosticEvent::DriverConnectSucceeded);
        operation_status_ = "KDBG driver connected. Physical and privileged process reads are available.";
        if (probe_service_running_.value_or(false)) {
            QueryAndLoadProbeFixture();
        }
    } else {
        LogDiagnostic(
            DiagnosticEvent::DriverConnectFailed,
            static_cast<std::uint64_t>(opened.GetError().code),
            opened.GetError().native_code);
        operation_status_ =
            "KDBG driver is not connected. Install/start it from the Driver tab; "
            "ordinary user-process scanning can still use Win32 APIs.";
    }
}

MainWindow::~MainWindow() {
    CancelAnalysisEvidenceExport();
    if (analysis_evidence_future_.valid()) {
        try {
            static_cast<void>(analysis_evidence_future_.get());
        } catch (...) {
            // Destruction still closes every memory and driver handle.
        }
    }
    lifecycle_cancel_requested_.store(true, std::memory_order_relaxed);
    if (lifecycle_future_.valid()) {
        try {
            static_cast<void>(lifecycle_future_.get());
        } catch (...) {
            // Destruction must continue so all write gates and device handles
            // are still closed even if a background SCM operation failed.
        }
    }
    process_usage_.CancelAndWait();
    kernel_explorer_.CancelAndWait();
    process_memory_browser_.CancelAndWait();
    disassembly_.CancelAndWait();
    process_scanner_.CancelAndWait();
    pointer_scanner_.CancelAndWait();
    snapshots_.CancelAndWait();
    static_cast<void>(FinishDisconnectProcess());
    probe_.Close();
    backend_.Close();
}

void MainWindow::Draw() {
    if (pending_language_.has_value()) {
        static_cast<void>(SetUiLanguage(*pending_language_));
        pending_language_.reset();
    }
    process_memory_browser_.Poll();
    disassembly_.Poll();
    kernel_explorer_.Poll();
    PollAnalysisEvidenceExport();
    PollDeferredAction();
    PollLifecycleAction();
    if (!ProcessIoBusy()) cached_backend_info_ = backend_.Info();
#ifdef IMGUI_HAS_DOCK
    DrawDockedWorkspace();
#else
    DrawTabbedWorkspace();
#endif
}

void MainWindow::DrawTabbedWorkspace() {
    const auto& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0.0F, 0.0F), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    constexpr auto flags =
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_MenuBar;

    if (!ImGui::Begin("KDBG", nullptr, flags)) {
        ImGui::End();
        return;
    }

    HandleShortcuts();
    DrawMenuBar();
    DrawStatusBar();
    ImGui::Separator();
    DrawProcessSelector();
    ImGui::Separator();

    if (ImGui::BeginTabBar("KDBG-MainTabs", ImGuiTabBarFlags_Reorderable)) {
        const auto driver_flags = select_driver_tab_
            ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem(
                UiLabel("Driver", "Driver").c_str(), nullptr, driver_flags)) {
            select_driver_tab_ = false;
            DrawDriverTab();
            ImGui::EndTabItem();
        }
        const auto physical_flags = select_physical_memory_tab_
            ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem(
                UiLabel("Physical Memory", "Physical Memory").c_str(),
                nullptr, physical_flags)) {
            select_physical_memory_tab_ = false;
            DrawPhysicalMemoryTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(
                UiLabel("Memory Map", "Memory Map").c_str())) {
            DrawMemoryMapTab();
            ImGui::EndTabItem();
        }
        const auto process_memory_flags = select_process_memory_tab_
            ? ImGuiTabItemFlags_SetSelected
            : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem(
                UiLabel("Process Memory", "Process Memory").c_str(), nullptr,
                process_memory_flags)) {
            select_process_memory_tab_ = false;
            DrawProcessMemoryTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(
                UiLabel("Process Scanner", "Process Scanner").c_str())) {
            DrawProcessScannerTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(
                UiLabel("Pointer Scanner", "Pointer Scanner").c_str())) {
            DrawPointerScannerTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(
                UiLabel("Disassembler", "Disassembler").c_str())) {
            DrawDisassemblyTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(
                UiLabel("Kernel Explorer", "Kernel Explorer").c_str())) {
            DrawKernelExplorerTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(
                UiLabel("Snapshots", "Snapshots").c_str())) {
            DrawSnapshotTab();
            ImGui::EndTabItem();
        }
        const auto page_table_flags = select_page_tables_tab_
            ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem(
                UiLabel("Page Tables", "Page Tables").c_str(), nullptr,
                page_table_flags)) {
            select_page_tables_tab_ = false;
            DrawTranslationTab();
            ImGui::EndTabItem();
        }
        const auto ownership_flags = select_pfn_ownership_tab_
            ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem(
                UiLabel("PFN Ownership", "PFN Ownership").c_str(), nullptr,
                ownership_flags)) {
            select_pfn_ownership_tab_ = false;
            DrawPfnOwnershipTab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    if (!operation_status_.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("%s", operation_status_.c_str());
    }
    const auto process_target = CurrentPageProcessTarget();
    const auto target_kind = physical_session_.HasPage()
        ? physical_session_.Target().kind
        : PhysicalTargetKind::RawPfn;
    const auto provenance = physical_session_.HasPage()
        ? PhysicalTargetProvenance(physical_session_.Target())
        : std::string{"No physical page loaded"};
    const auto runtime_host_identity = RuntimeHostIdentityLabel();
    write_modal_.Draw(
        physical_session_,
        target_kind,
        CurrentPageIsVerifiedWriteTarget(),
        runtime_host_identity,
        provenance,
        process_target.has_value() ? process_target->pid : 0,
        process_target.has_value() ? process_target->virtual_address : 0,
        probe_info_.has_value() ? probe_info_->generation : 0,
        probe_info_.has_value() ? probe_info_->crc32 : 0,
        backend_.Info().write_enabled);
    DrawAboutDialog();
    ImGui::End();
}

void MainWindow::DrawDockedWorkspace() {
#ifdef IMGUI_HAS_DOCK
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const ImGuiDockNodeFlags dock_flags =
        ImGuiDockNodeFlags_PassthruCentralNode;
    const ImGuiID dockspace_id = ImGui::DockSpaceOverViewport(
        0, viewport, dock_flags);

    if (!dock_layout_checked_) {
        dock_layout_checked_ = true;
        const ImGuiDockNode* existing =
            ImGui::DockBuilderGetNode(dockspace_id);
        bool saved_layout_fits_viewport = existing != nullptr;
        std::size_t leaf_count = 0;
        if (existing != nullptr) {
            const ImVec2 work_min = viewport->WorkPos;
            const ImVec2 work_max{
                viewport->WorkPos.x + viewport->WorkSize.x,
                viewport->WorkPos.y + viewport->WorkSize.y};
            std::vector<const ImGuiDockNode*> pending{existing};
            while (!pending.empty()) {
                const ImGuiDockNode* node = pending.back();
                pending.pop_back();
                if (node->ChildNodes[0] != nullptr ||
                    node->ChildNodes[1] != nullptr) {
                    if (node->ChildNodes[0] != nullptr) {
                        pending.push_back(node->ChildNodes[0]);
                    }
                    if (node->ChildNodes[1] != nullptr) {
                        pending.push_back(node->ChildNodes[1]);
                    }
                    continue;
                }
                ++leaf_count;
                constexpr float kMinimumPaneWidth = 160.0F;
                constexpr float kMinimumPaneHeight = 120.0F;
                constexpr float kBoundsTolerance = 2.0F;
                const ImVec2 node_max{
                    node->Pos.x + node->Size.x,
                    node->Pos.y + node->Size.y};
                if (node->Size.x < kMinimumPaneWidth ||
                    node->Size.y < kMinimumPaneHeight ||
                    node->Pos.x < work_min.x - kBoundsTolerance ||
                    node->Pos.y < work_min.y - kBoundsTolerance ||
                    node_max.x > work_max.x + kBoundsTolerance ||
                    node_max.y > work_max.y + kBoundsTolerance) {
                    saved_layout_fits_viewport = false;
                }
            }
        }
        const bool has_saved_layout = saved_layout_fits_viewport &&
            leaf_count >= 4 &&
            (existing->ChildNodes[0] != nullptr ||
             existing->ChildNodes[1] != nullptr ||
             existing->Windows.Size > 0);
        if (!has_saved_layout) {
            ImGui::DockBuilderRemoveNode(dockspace_id);
            ImGui::DockBuilderAddNode(
                dockspace_id,
                static_cast<ImGuiDockNodeFlags>(
                    static_cast<int>(ImGuiDockNodeFlags_DockSpace) |
                    static_cast<int>(
                        ImGuiDockNodeFlags_PassthruCentralNode)));
            ImGui::DockBuilderSetNodeSize(
                dockspace_id, viewport->WorkSize);

            ImGuiID remaining = dockspace_id;
            const ImGuiID left = ImGui::DockBuilderSplitNode(
                remaining, ImGuiDir_Left, 0.24F, nullptr, &remaining);
            const ImGuiID right = ImGui::DockBuilderSplitNode(
                remaining, ImGuiDir_Right, 0.30F, nullptr, &remaining);
            const ImGuiID bottom = ImGui::DockBuilderSplitNode(
                remaining, ImGuiDir_Down, 0.36F, nullptr, &remaining);

            ImGui::DockBuilderDockWindow(
                UiLabel("KDBG Control Center", "KDBG Control Center").c_str(),
                left);
            ImGui::DockBuilderDockWindow(
                UiLabel("Driver", "Driver").c_str(), left);
            ImGui::DockBuilderDockWindow(
                UiLabel("Physical Memory", "Physical Memory").c_str(),
                remaining);
            ImGui::DockBuilderDockWindow(
                UiLabel("Process Memory", "Process Memory").c_str(),
                remaining);
            ImGui::DockBuilderDockWindow(
                UiLabel("Memory Map", "Memory Map").c_str(), right);
            ImGui::DockBuilderDockWindow(
                UiLabel("Page Tables", "Page Tables").c_str(), right);
            ImGui::DockBuilderDockWindow(
                UiLabel("PFN Ownership", "PFN Ownership").c_str(), right);
            ImGui::DockBuilderDockWindow(
                UiLabel("Process Scanner", "Process Scanner").c_str(), bottom);
            ImGui::DockBuilderDockWindow(
                UiLabel("Pointer Scanner", "Pointer Scanner").c_str(), bottom);
            ImGui::DockBuilderDockWindow(
                UiLabel("Disassembler", "Disassembler").c_str(), bottom);
            ImGui::DockBuilderDockWindow(
                UiLabel("Kernel Explorer", "Kernel Explorer").c_str(), bottom);
            ImGui::DockBuilderDockWindow(
                UiLabel("Snapshots", "Snapshots").c_str(), bottom);
            ImGui::DockBuilderFinish(dockspace_id);
        }
    }

    const bool control_center_visible = ImGui::Begin(
        UiLabel("KDBG Control Center", "KDBG Control Center").c_str(), nullptr,
        ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoCollapse);
    HandleShortcuts();
    if (control_center_visible) {
        DrawMenuBar();
        DrawStatusBar();
        ImGui::Separator();
        DrawProcessSelector();
        if (!operation_status_.empty()) {
            ImGui::Separator();
            ImGui::TextWrapped("%s", operation_status_.c_str());
        }
    }
    ImGui::End();

    // Popups must keep rendering even when the Control Center is an inactive
    // dock tab. Otherwise a write-review request made from Physical Memory is
    // never submitted and the safety confirmation appears to do nothing.
    const auto process_target = CurrentPageProcessTarget();
    const auto target_kind = physical_session_.HasPage()
        ? physical_session_.Target().kind
        : PhysicalTargetKind::RawPfn;
    const auto provenance = physical_session_.HasPage()
        ? PhysicalTargetProvenance(physical_session_.Target())
        : std::string{"No physical page loaded"};
    const auto runtime_host_identity = RuntimeHostIdentityLabel();
    write_modal_.Draw(
        physical_session_,
        target_kind,
        CurrentPageIsVerifiedWriteTarget(),
        runtime_host_identity,
        provenance,
        process_target.has_value() ? process_target->pid : 0,
        process_target.has_value() ? process_target->virtual_address : 0,
        probe_info_.has_value() ? probe_info_->generation : 0,
        probe_info_.has_value() ? probe_info_->crc32 : 0,
        backend_.Info().write_enabled);
    DrawAboutDialog();

    auto draw_pane = [](const char* name, bool* request_focus, auto&& draw) {
        if (request_focus != nullptr && *request_focus) {
            ImGui::SetNextWindowFocus();
            *request_focus = false;
        }
        if (ImGui::Begin(name, nullptr, ImGuiWindowFlags_NoCollapse)) draw();
        ImGui::End();
    };
    draw_pane(UiLabel("Driver", "Driver").c_str(),
        &select_driver_tab_, [&] { DrawDriverTab(); });
    draw_pane(UiLabel("Physical Memory", "Physical Memory").c_str(),
        &select_physical_memory_tab_,
        [&] { DrawPhysicalMemoryTab(); });
    draw_pane(UiLabel("Memory Map", "Memory Map").c_str(), nullptr,
        [&] { DrawMemoryMapTab(); });
    draw_pane(UiLabel("Process Memory", "Process Memory").c_str(),
        &select_process_memory_tab_,
        [&] { DrawProcessMemoryTab(); });
    draw_pane(UiLabel("Process Scanner", "Process Scanner").c_str(), nullptr,
        [&] { DrawProcessScannerTab(); });
    draw_pane(UiLabel("Pointer Scanner", "Pointer Scanner").c_str(), nullptr,
        [&] { DrawPointerScannerTab(); });
    draw_pane(UiLabel("Disassembler", "Disassembler").c_str(), nullptr,
        [&] { DrawDisassemblyTab(); });
    draw_pane(UiLabel("Kernel Explorer", "Kernel Explorer").c_str(), nullptr,
        [&] { DrawKernelExplorerTab(); });
    draw_pane(UiLabel("Snapshots", "Snapshots").c_str(), nullptr,
        [&] { DrawSnapshotTab(); });
    draw_pane(UiLabel("Page Tables", "Page Tables").c_str(),
        &select_page_tables_tab_,
        [&] { DrawTranslationTab(); });
    draw_pane(UiLabel("PFN Ownership", "PFN Ownership").c_str(),
        &select_pfn_ownership_tab_,
        [&] { DrawPfnOwnershipTab(); });
#else
    DrawTabbedWorkspace();
#endif
}

void MainWindow::DrawMenuBar() {
    if (!ImGui::BeginMenuBar()) return;
    if (ImGui::BeginMenu(UiText("Session"))) {
        if (ImGui::MenuItem(UiText("Refresh process list"), "Ctrl+R")) {
            RefreshProcesses();
        }
        if (ImGui::MenuItem(UiText("Disconnect process"), nullptr, false,
                process_memory_ != nullptr)) {
            DisconnectProcess();
        }
        const bool can_reconnect =
            !process_usage_.Busy() && !physical_session_.CanRollback() &&
            !physical_session_.RecoveryObservationRequired();
        if (ImGui::MenuItem(
                UiText("Reconnect KDBG driver"), nullptr, false,
                can_reconnect)) {
            ConnectBackend();
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu(UiText("Navigate"))) {
        if (ImGui::MenuItem(UiText("Driver"), "Ctrl+D")) {
            select_driver_tab_ = true;
        }
        if (ImGui::MenuItem(UiText("Physical Memory"), "Ctrl+P")) {
            select_physical_memory_tab_ = true;
        }
        if (ImGui::MenuItem(UiText("Page Tables"), "Ctrl+T")) {
            select_page_tables_tab_ = true;
        }
        if (ImGui::MenuItem(UiText("PFN Ownership"), "Ctrl+Shift+P")) {
            select_pfn_ownership_tab_ = true;
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu(UiText("Safety"))) {
        const bool process_io_busy = ProcessIoBusy();
        const bool process_armed = process_memory_ != nullptr &&
            !process_io_busy &&
            (process_memory_->WritesArmed() ||
             process_scanner_.WriteAuthorizationActive());
        if (ImGui::MenuItem(UiText("Lock all writes"), "Ctrl+L", false,
                cached_backend_info_.write_enabled || process_armed ||
                    process_io_busy)) {
            LockAllWrites();
        }
        ImGui::EndMenu();
    }
    const auto language_menu = UiLabel("Language / 언어", "Language");
    if (ImGui::BeginMenu(language_menu.c_str())) {
        const auto language = CurrentUiLanguage();
        if (ImGui::MenuItem(
                "English", nullptr, language == UiLanguage::English)) {
            pending_language_ = UiLanguage::English;
        }
        const bool korean_available = KoreanFontAvailable();
        const char* korean_label = korean_available ? "한국어" : "Korean";
        if (ImGui::MenuItem(korean_label, nullptr,
                language == UiLanguage::Korean, korean_available)) {
            pending_language_ = UiLanguage::Korean;
        }
        if (!korean_available &&
            ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("%s", UiText(
                "Korean UI requires an installed Korean-capable font."));
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu(UiText("Help"))) {
        if (ImGui::MenuItem(UiText("About KDBG"), "F1")) {
            about_open_requested_ = true;
        }
        ImGui::EndMenu();
    }
    ImGui::TextDisabled(
        UiText("KDBG %s | local physical RAM — this Windows instance"),
        kVersion);
    ImGui::EndMenuBar();
}

void MainWindow::HandleShortcuts() {
    constexpr auto global = ImGuiInputFlags_RouteGlobal;
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_L, global)) LockAllWrites();
    if (ImGui::Shortcut(ImGuiKey_F1, global)) about_open_requested_ = true;
    if (ImGui::GetIO().WantTextInput) return;
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_R, global)) RefreshProcesses();
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_D, global)) {
        select_driver_tab_ = true;
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_P, global)) {
        select_physical_memory_tab_ = true;
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_T, global)) {
        select_page_tables_tab_ = true;
    }
    if (ImGui::Shortcut(
            ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_P, global)) {
        select_pfn_ownership_tab_ = true;
    }
}

void MainWindow::DrawStatusBar() {
    const auto info = cached_backend_info_;
    std::error_code driver_error;
    std::error_code probe_error;
    const bool packaged_driver_present = std::filesystem::is_regular_file(
        Utf8Path(driver_path_.data()), driver_error);
    const bool packaged_probe_present = std::filesystem::is_regular_file(
        Utf8Path(probe_driver_path_.data()), probe_error);
    const auto readiness = ClassifyRuntime(
        info.connected,
        info.is_mock,
        packaged_driver_present,
        packaged_probe_present,
        driver_service_running_.has_value(),
        driver_service_running_.value_or(false),
        probe_service_running_.has_value(),
        probe_service_running_.value_or(false),
        CurrentPageIsProbeFixture());
    ImGui::TextColored(
        RuntimeReadinessColor(readiness),
        UiText("Runtime: %s"), RuntimeReadinessName(readiness));
    ImGui::SameLine();
    ImGui::Text(UiText("| Service: %s | ABI: %u | Physical gate: %s"),
        ServiceStateName(driver_service_running_),
        info.abi_version,
        info.write_enabled ? "ARMED" : "LOCKED");
    ImGui::SameLine();
    ImGui::Text(UiText("| Probe: %s / %s"),
        ServiceStateName(probe_service_running_),
        probe_.IsOpen() ? "DEVICE OPEN" : "DEVICE CLOSED");
    if (process_memory_ != nullptr && ProcessIoBusy()) {
        ImGui::SameLine();
        ImGui::TextUnformatted(UiText("| Process I/O: BUSY"));
    } else if (process_memory_ != nullptr) {
        ImGui::SameLine();
        ImGui::Text(UiText(
            "| Process PID %u (%s) | gate: %s | freeze auth: %s"),
            process_memory_->ProcessId(),
            AttachedProcessName().c_str(),
            process_memory_->WritesArmed() ? "ARMED" : "LOCKED",
            process_scanner_.WriteAuthorizationActive()
                ? "ACTIVE" : "LOCKED");
    }
    if (info.write_enabled) {
        ImGui::TextColored(
            ImVec4(1.0F, 0.25F, 0.20F, 1.0F),
            UiText("WARNING: the driver reports its physical write gate ARMED. Ctrl+L locks all writes."));
    }
    const bool writes_available = info.connected && !LifecycleBusy();
    const char* write_reason = LifecycleBusy()
        ? UiText("driver lifecycle operation in progress")
        : (!info.connected
            ? UiText("the KDBG device is disconnected")
            : (info.write_enabled
                ? UiText("one-shot driver gate is ARMED")
                : UiText(
                    "range-validated target and typed PFN confirmation are required")));
    ImGui::TextColored(
        writes_available
            ? ImVec4(0.75F, 0.85F, 0.30F, 1.0F)
            : ImVec4(0.90F, 0.50F, 0.30F, 1.0F),
        UiText("Physical write path: %s | %s"),
        writes_available ? "READY FOR TARGET REVIEW" : "BLOCKED",
        write_reason);
}

struct ProcessFixtureInfo {
    std::string raw_json;
    std::uint32_t pid{0};
    std::uint64_t process_start_id{0};
    std::string nonce;
    std::string image_basename;
    std::uint64_t virtual_address{0};
    std::uint32_t generation{0};
    std::uint32_t baseline_crc32{0};
    std::uint32_t current_crc32{0};
};

std::optional<std::string_view> JsonScalar(
    std::string_view json,
    std::string_view key) {
    const std::string marker = "\"" + std::string(key) + "\"";
    const auto position = json.find(marker);
    if (position == std::string_view::npos ||
        json.find(marker, position + marker.size()) != std::string_view::npos) {
        return std::nullopt;
    }
    auto cursor = position + marker.size();
    while (cursor < json.size() && std::isspace(
               static_cast<unsigned char>(json[cursor]))) {
        ++cursor;
    }
    if (cursor >= json.size() || json[cursor++] != ':') return std::nullopt;
    while (cursor < json.size() && std::isspace(
               static_cast<unsigned char>(json[cursor]))) {
        ++cursor;
    }
    if (cursor >= json.size()) return std::nullopt;
    if (json[cursor] == '"') {
        const auto end = json.find('"', cursor + 1U);
        if (end == std::string_view::npos) return std::nullopt;
        return json.substr(cursor, end - cursor + 1U);
    }
    const auto end = json.find_first_of(",}\r\n\t ", cursor);
    return json.substr(cursor, end == std::string_view::npos
        ? json.size() - cursor
        : end - cursor);
}

std::optional<std::string> JsonString(
    std::string_view json,
    std::string_view key) {
    const auto scalar = JsonScalar(json, key);
    if (!scalar.has_value() || scalar->size() < 2U ||
        scalar->front() != '"' || scalar->back() != '"') {
        return std::nullopt;
    }
    const auto body = scalar->substr(1U, scalar->size() - 2U);
    if (body.find_first_of("\\\"\r\n") != std::string_view::npos) {
        return std::nullopt;
    }
    return std::string(body);
}

std::optional<std::uint64_t> JsonUnsigned(
    std::string_view json,
    std::string_view key) {
    const auto scalar = JsonScalar(json, key);
    if (!scalar.has_value()) return std::nullopt;
    std::string_view value = *scalar;
    if (value.size() >= 2U && value.front() == '"' && value.back() == '"') {
        value.remove_prefix(1U);
        value.remove_suffix(1U);
    }
    int base = 10;
    if (value.starts_with("0x")) {
        value.remove_prefix(2U);
        base = 16;
    }
    if (value.empty() || value.front() == '+' || value.front() == '-') {
        return std::nullopt;
    }
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed, base);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return parsed;
}

bool LowerHex(std::string_view value, std::size_t digits) {
    if (value.size() != digits) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

Result<ProcessFixtureInfo> ReadProcessFixtureInfo(
    const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return Result<ProcessFixtureInfo>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to open fixture INFO JSON",
            "MainWindow::ReadProcessFixtureInfo"));
    }
    std::string json(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    if (json.empty() || json.size() > 64U * 1024U) {
        return Result<ProcessFixtureInfo>::Failure(MakeError(
            ErrorCode::ParseError, "Fixture INFO JSON must be 1..65536 bytes",
            "MainWindow::ReadProcessFixtureInfo"));
    }
    const auto schema = JsonString(json, "schema");
    const auto ok = JsonScalar(json, "ok");
    const auto protocol = JsonUnsigned(json, "protocol_version");
    const auto pid = JsonUnsigned(json, "pid");
    const auto start = JsonUnsigned(json, "process_start_id");
    const auto nonce = JsonString(json, "fixture_nonce");
    const auto image = JsonString(json, "image_basename");
    const auto va = JsonUnsigned(json, "virtual_address");
    const auto bytes = JsonUnsigned(json, "byte_count");
    const auto generation = JsonUnsigned(json, "generation");
    const auto baseline_crc = JsonString(json, "baseline_crc32");
    const auto current_crc = JsonString(json, "current_crc32");
    const auto locked = JsonScalar(json, "virtual_locked");
    if (!schema.has_value() || *schema != "kdbg.process-fixture.v1" ||
        !ok.has_value() || *ok != "true" || !protocol.has_value() ||
        *protocol != 1U || !pid.has_value() || *pid == 0 ||
        *pid > std::numeric_limits<std::uint32_t>::max() ||
        !start.has_value() || *start == 0 || !nonce.has_value() ||
        !LowerHex(*nonce, 32U) || !image.has_value() ||
        *image != "kdbg_process_fixture.exe" || !va.has_value() ||
        *va == 0 || (*va & (kPhysicalPageSize - 1U)) != 0 ||
        (*va >> 47U) != 0 || !bytes.has_value() ||
        *bytes != kPhysicalPageSize || !generation.has_value() ||
        *generation == 0 ||
        *generation > std::numeric_limits<std::uint32_t>::max() ||
        !baseline_crc.has_value() || !baseline_crc->starts_with("0x") ||
        !LowerHex(std::string_view(*baseline_crc).substr(2U), 8U) ||
        !current_crc.has_value() || !current_crc->starts_with("0x") ||
        !LowerHex(std::string_view(*current_crc).substr(2U), 8U) ||
        !locked.has_value() || *locked != "true") {
        return Result<ProcessFixtureInfo>::Failure(MakeError(
            ErrorCode::ParseError,
            "Fixture INFO JSON failed the dedicated locked user-page contract",
            "MainWindow::ReadProcessFixtureInfo"));
    }
    const auto baseline_crc_value = JsonUnsigned(json, "baseline_crc32");
    const auto crc = JsonUnsigned(json, "current_crc32");
    if (!baseline_crc_value.has_value() ||
        *baseline_crc_value > std::numeric_limits<std::uint32_t>::max() ||
        !crc.has_value() || *crc > std::numeric_limits<std::uint32_t>::max()) {
        return Result<ProcessFixtureInfo>::Failure(MakeError(
            ErrorCode::ParseError, "Fixture current CRC32 is invalid",
            "MainWindow::ReadProcessFixtureInfo"));
    }
    ProcessFixtureInfo fixture;
    fixture.raw_json = std::move(json);
    fixture.pid = static_cast<std::uint32_t>(*pid);
    fixture.process_start_id = *start;
    fixture.nonce = *nonce;
    fixture.image_basename = *image;
    fixture.virtual_address = *va;
    fixture.generation = static_cast<std::uint32_t>(*generation);
    fixture.baseline_crc32 = static_cast<std::uint32_t>(*baseline_crc_value);
    fixture.current_crc32 = static_cast<std::uint32_t>(*crc);
    return Result<ProcessFixtureInfo>::Success(std::move(fixture));
}

Result<std::string> Sha256Bytes(std::span<const std::uint8_t> bytes) {
#ifdef _WIN32
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    if (CryptAcquireContextW(
            &provider, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT) == FALSE ||
        CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) == FALSE) {
        const auto native = GetLastError();
        if (hash != 0) CryptDestroyHash(hash);
        if (provider != 0) CryptReleaseContext(provider, 0);
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to initialize SHA-256",
            "MainWindow::Sha256Bytes", native));
    }
    bool ok = true;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = static_cast<DWORD>(std::min<std::size_t>(
            bytes.size() - offset, std::numeric_limits<DWORD>::max()));
        if (CryptHashData(hash, bytes.data() + offset, count, 0) == FALSE) {
            ok = false;
            break;
        }
        offset += count;
    }
    std::array<BYTE, 32> digest{};
    DWORD digest_size = static_cast<DWORD>(digest.size());
    if (!ok || CryptGetHashParam(
            hash, HP_HASHVAL, digest.data(), &digest_size, 0) == FALSE ||
        digest_size != digest.size()) {
        const auto native = GetLastError();
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to finish SHA-256",
            "MainWindow::Sha256Bytes", native));
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    constexpr char digits[] = "0123456789abcdef";
    std::string output(64U, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        output[index * 2U] = digits[digest[index] >> 4U];
        output[index * 2U + 1U] = digits[digest[index] & 0x0FU];
    }
    return Result<std::string>::Success(std::move(output));
#else
    (void)bytes;
    return Result<std::string>::Failure(MakeError(
        ErrorCode::Unsupported, "SHA-256 export is Windows-only",
        "MainWindow::Sha256Bytes"));
#endif
}

Result<std::vector<std::uint8_t>> ReadBoundedFile(
    const std::filesystem::path& path,
    std::size_t cap) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to open evidence input file",
            "MainWindow::ReadBoundedFile"));
    }
    const auto end = input.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) > cap) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::InvalidArgument, "Evidence input file exceeds its cap",
            "MainWindow::ReadBoundedFile"));
    }
    input.seekg(0);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    }
    if (!input && !bytes.empty()) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to read evidence input file",
            "MainWindow::ReadBoundedFile"));
    }
    return Result<std::vector<std::uint8_t>>::Success(std::move(bytes));
}

Result<std::vector<std::uint8_t>> ReadFilePrefix(
    const std::filesystem::path& path,
    std::size_t length) {
    std::ifstream input(path, std::ios::binary);
    if (!input || length == 0) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to open evidence header input",
            "MainWindow::ReadFilePrefix"));
    }
    std::vector<std::uint8_t> bytes(length);
    input.read(reinterpret_cast<char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    const auto completed = static_cast<std::size_t>(input.gcount());
    bytes.resize(completed);
    if (completed < 256U) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ShortRead, "Evidence PE header is shorter than 256 bytes",
            "MainWindow::ReadFilePrefix", 0, length, completed));
    }
    return Result<std::vector<std::uint8_t>>::Success(std::move(bytes));
}

Result<std::string> Sha256File(const std::filesystem::path& path) {
#ifdef _WIN32
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to open evidence file for SHA-256",
            "MainWindow::Sha256File"));
    }
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    if (CryptAcquireContextW(
            &provider, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT) == FALSE ||
        CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) == FALSE) {
        const auto native = GetLastError();
        if (hash != 0) CryptDestroyHash(hash);
        if (provider != 0) CryptReleaseContext(provider, 0);
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to initialize file SHA-256",
            "MainWindow::Sha256File", native));
    }
    std::vector<std::uint8_t> buffer(64U * 1024U);
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        const auto completed = static_cast<std::size_t>(input.gcount());
        if (completed != 0 && CryptHashData(
                hash, buffer.data(), static_cast<DWORD>(completed), 0) == FALSE) {
            const auto native = GetLastError();
            CryptDestroyHash(hash);
            CryptReleaseContext(provider, 0);
            return Result<std::string>::Failure(MakeError(
                ErrorCode::IoFailure, "Unable to update file SHA-256",
                "MainWindow::Sha256File", native));
        }
    }
    if (!input.eof()) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to read evidence file for SHA-256",
            "MainWindow::Sha256File"));
    }
    std::array<BYTE, 32> digest{};
    DWORD digest_size = static_cast<DWORD>(digest.size());
    if (CryptGetHashParam(
            hash, HP_HASHVAL, digest.data(), &digest_size, 0) == FALSE ||
        digest_size != digest.size()) {
        const auto native = GetLastError();
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure, "Unable to finish file SHA-256",
            "MainWindow::Sha256File", native));
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    constexpr char digits[] = "0123456789abcdef";
    std::string output(64U, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        output[index * 2U] = digits[digest[index] >> 4U];
        output[index * 2U + 1U] = digits[digest[index] & 0x0FU];
    }
    return Result<std::string>::Success(std::move(output));
#else
    (void)path;
    return Result<std::string>::Failure(MakeError(
        ErrorCode::Unsupported, "File SHA-256 export is Windows-only",
        "MainWindow::Sha256File"));
#endif
}

std::string IsoTimestampUtc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    std::ostringstream stream;
    stream << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S") << 'Z';
    return stream.str();
}

bool WriteBytes(
    const std::filesystem::path& path,
    std::span<const std::uint8_t> bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    if (!bytes.empty()) {
        output.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    }
    output.flush();
    output.close();
    return output.good();
}

bool SameWalk(const TranslationWalk& left, const TranslationWalk& right) {
    if (left.directory_table_base != right.directory_table_base ||
        left.virtual_address != right.virtual_address ||
        left.physical_address != right.physical_address ||
        left.page_size != right.page_size || left.page_offset != right.page_offset ||
        left.la57 != right.la57 || left.translated != right.translated ||
        left.steps.size() != right.steps.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.steps.size(); ++index) {
        const auto& a = left.steps[index];
        const auto& b = right.steps[index];
        if (a.level != b.level || a.index != b.index ||
            a.entry_physical_address != b.entry_physical_address ||
            a.entry_value != b.entry_value || a.next_pfn != b.next_pfn ||
            a.flags.present != b.flags.present ||
            a.flags.writable != b.flags.writable ||
            a.flags.user != b.flags.user ||
            a.flags.write_through != b.flags.write_through ||
            a.flags.cache_disable != b.flags.cache_disable ||
            a.flags.accessed != b.flags.accessed ||
            a.flags.dirty != b.flags.dirty ||
            a.flags.page_size != b.flags.page_size ||
            a.flags.global != b.flags.global ||
            a.flags.no_execute != b.flags.no_execute ||
            a.flags.protection_key != b.flags.protection_key ||
            a.flags.pfn != b.flags.pfn) {
            return false;
        }
    }
    return true;
}

const char* PagingLevelName(PagingLevel level) noexcept {
    switch (level) {
    case PagingLevel::Pml5: return "PML5";
    case PagingLevel::Pml4: return "PML4";
    case PagingLevel::Pdpt: return "PDPT";
    case PagingLevel::Pd: return "PD";
    case PagingLevel::Pt: return "PT";
    }
    return "UNKNOWN";
}

const char* ConfidenceText(MappingConfidence confidence) noexcept {
    switch (confidence) {
    case MappingConfidence::Unknown: return "unknown";
    case MappingConfidence::Low: return "low";
    case MappingConfidence::Medium: return "medium";
    case MappingConfidence::High: return "high";
    }
    return "unknown";
}

std::string JsonEscape(std::string_view value) {
    std::ostringstream stream;
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': stream << "\\\""; break;
        case '\\': stream << "\\\\"; break;
        case '\b': stream << "\\b"; break;
        case '\f': stream << "\\f"; break;
        case '\n': stream << "\\n"; break;
        case '\r': stream << "\\r"; break;
        case '\t': stream << "\\t"; break;
        default:
            if (ch < 0x20U) {
                stream << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0') << static_cast<unsigned>(ch)
                       << std::dec;
            } else {
                stream << static_cast<char>(ch);
            }
        }
    }
    return stream.str();
}

void MainWindow::DrawProcessSelector() {
    ImGui::TextUnformatted(UiText("Target Process"));
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputTextWithHint(
        "##process-filter", UiText("filter name or PID"),
        process_filter_.data(), process_filter_.size());

    const std::string filter = Lower(process_filter_.data());
    std::vector<std::size_t> visible_processes;
    visible_processes.reserve(processes_.size());
    for (std::size_t index = 0; index < processes_.size(); ++index) {
        const auto& process = processes_[index];
        const auto pid_text = std::to_string(process.pid);
        if (!filter.empty() &&
            Lower(process.name).find(filter) == std::string::npos &&
            Lower(process.path).find(filter) == std::string::npos &&
            pid_text.find(filter) == std::string::npos) {
            continue;
        }
        visible_processes.push_back(index);
    }
    ImGui::SetNextItemWidth(-1.0F);
    const char* preview = selected_process_index_ >= 0 &&
        selected_process_index_ < static_cast<int>(processes_.size())
        ? processes_[static_cast<std::size_t>(selected_process_index_)].name.c_str()
        : UiText("Select a process");
    if (ImGui::BeginCombo("##process-list", preview)) {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            visible_processes.size(), static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const std::size_t index =
                visible_processes[static_cast<std::size_t>(row)];
            const auto& process = processes_[index];
            char label[512]{};
            std::snprintf(label, sizeof(label), "%s | PID %u | PPID %u | %s",
                process.name.c_str(), process.pid, process.parent_pid,
                process.is_64_bit ? "x64" : "x86");
            const bool selected = selected_process_index_ == static_cast<int>(index);
            if (ImGui::Selectable(label, selected)) {
                selected_process_index_ = static_cast<int>(index);
            }
            if (ImGui::IsItemHovered() && !process.path.empty()) {
                ImGui::SetTooltip("%s", process.path.c_str());
            }
            if (selected) ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }
    if (selected_process_index_ < 0) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Attach"))) AttachSelectedProcess();
    if (selected_process_index_ < 0) ImGui::EndDisabled();
    ImGui::SameLine();
    if (process_memory_ == nullptr) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Detach"))) DisconnectProcess();
    if (process_memory_ == nullptr) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button(UiText("Refresh"))) RefreshProcesses();
    if (selected_process_index_ >= 0 &&
        selected_process_index_ < static_cast<int>(processes_.size())) {
        const auto& selected =
            processes_[static_cast<std::size_t>(selected_process_index_)];
        ImGui::TextWrapped(UiText("Selected PID %u | %s | %s"),
            selected.pid,
            selected.is_64_bit ? "x64" : "x86",
            selected.path.empty() ? UiText("path unavailable")
                                  : selected.path.c_str());
    }
}

void MainWindow::DrawDriverTab() {
    if (ProcessIoBusy()) {
        ImGui::TextDisabled(UiText(
            "Process I/O is BUSY; driver lifecycle controls are paused to keep the UI non-blocking."));
        return;
    }
    const auto info = backend_.Info();
    std::error_code driver_path_error;
    std::error_code probe_path_error;
    const bool driver_file_ready = std::filesystem::is_regular_file(
        Utf8Path(driver_path_.data()), driver_path_error);
    const bool probe_file_ready = std::filesystem::is_regular_file(
        Utf8Path(probe_driver_path_.data()), probe_path_error);
    const auto readiness = ClassifyRuntime(
        info.connected,
        info.is_mock,
        driver_file_ready,
        probe_file_ready,
        driver_service_running_.has_value(),
        driver_service_running_.value_or(false),
        probe_service_running_.has_value(),
        probe_service_running_.value_or(false),
        CurrentPageIsProbeFixture());
    const bool lifecycle_busy = LifecycleBusy();
    const bool kernel_read_busy = kernel_explorer_.ReadBusy();
    const bool process_io_busy = ProcessIoBusy();

    ImGui::TextWrapped(UiText(
        "The KDBG and KDBGProbe drivers are installed through the Windows "
        "Service Control Manager. Windows test-signing mode and Administrator "
        "rights are required. The probe owns a deterministic contiguous page "
        "for safe read/edit/write/read-back demonstrations."));

    ImGui::TextColored(
        RuntimeReadinessColor(readiness),
        UiText("Runtime readiness: %s"), RuntimeReadinessName(readiness));
    switch (readiness) {
    case RuntimeReadiness::SourceOnly:
        ImGui::TextWrapped(UiText(
            "Source-only: no packaged KDbgDriver.sys or KDbgProbe.sys was found. "
            "Live memory and all write controls remain unavailable."));
        break;
    case RuntimeReadiness::Disconnected:
        ImGui::TextWrapped(UiText(
            "Runtime components exist, but the KDBG device is not connected and ABI-validated."));
        break;
    case RuntimeReadiness::Mock:
        ImGui::TextWrapped(UiText(
            "Mock backend: operations are simulated; this is not live-driver evidence."));
        break;
    case RuntimeReadiness::LiveConnected:
        ImGui::TextWrapped(UiText(
            "Live driver connected. Load and verify the KDbgProbe page for the default demonstration target."));
        break;
    case RuntimeReadiness::LiveVerified:
        ImGui::TextWrapped(UiText(
            "Live driver and deterministic KDbgProbe page are verified for this session."));
        break;
    }

    if (ImGui::BeginTable(
            "runtime-readiness", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn(
            UiLabel("Prerequisite", "Prerequisite").c_str());
        ImGui::TableSetupColumn(UiLabel("State", "State").c_str());
        ImGui::TableSetupColumn(UiLabel("Effect", "Effect").c_str());
        ImGui::TableHeadersRow();
        const auto row = [](const char* prerequisite, bool ready,
                            const char* ready_text, const char* blocked_text) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(UiText(prerequisite));
            ImGui::TableNextColumn();
            ImGui::TextColored(
                ready ? ImVec4(0.35F, 0.90F, 0.45F, 1.0F)
                      : ImVec4(1.0F, 0.55F, 0.25F, 1.0F),
                "%s", ready ? "READY" : "BLOCKED");
            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", UiText(
                ready ? ready_text : blocked_text));
        };
        row("KDbgDriver.sys", driver_file_ready,
            "Packaged binary found.", "Select an existing packaged .sys file.");
        row("KDbgProbe.sys", probe_file_ready,
            "Packaged probe found.", "Default live demonstration is unavailable.");
        row("KDBG service", driver_service_running_.value_or(false),
            "Service reports running.",
            "Install/start it as Administrator on this Windows instance.");
        row("Probe service", probe_service_running_.value_or(false),
            "Service reports running.", "Start it to expose the deterministic probe page.");
        row("KDBG device / ABI", info.connected && !info.is_mock,
            "Live device is connected and ABI-validated.",
            "Physical and privileged driver operations are unavailable.");
        row("Probe fixture", CurrentPageIsProbeFixture(),
            "Verified 4096-byte page is loaded.",
            "Probe evidence is unavailable; RawPfn writes remain governed by independent RAM-range and session validation.");
        row("Physical gate", info.connected && !info.write_enabled,
            "Connected driver reports LOCKED.",
            info.connected
                ? "Lock all writes before lifecycle changes."
                : "No connected driver gate can be verified.");
        ImGui::EndTable();
    }

    const bool process_gate_locked = process_memory_ == nullptr ||
        (!process_io_busy && !process_memory_->WritesArmed());
    const bool can_bring_online = !lifecycle_busy && driver_file_ready &&
        probe_file_ready && driver_service_running_.has_value() &&
        probe_service_running_.has_value() && !physical_session_.IsDirty() &&
        !physical_session_.CanRollback() &&
        !physical_session_.RecoveryObservationRequired() &&
        !process_usage_.Busy() &&
        !kernel_read_busy && !process_io_busy && !info.write_enabled &&
        process_gate_locked &&
        readiness != RuntimeReadiness::LiveVerified;
    if (!can_bring_online) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Bring Lab Online & Load Probe"))) {
        StartLifecycleAction(LifecycleAction::BringLabOnline);
    }
    if (!can_bring_online) ImGui::EndDisabled();
    if (lifecycle_busy) {
        ImGui::SameLine();
        if (ImGui::Button(UiText("Request Lifecycle Cancel"))) {
            if (deferred_action_ == DeferredAction::StartLifecycle) {
                deferred_action_ = DeferredAction::None;
                deferred_lifecycle_ = LifecycleAction::None;
                operation_status_ =
                    "Deferred lifecycle transition cancelled before any SCM change.";
            } else {
                lifecycle_cancel_requested_.store(
                    true, std::memory_order_relaxed);
            }
        }
        const auto step = lifecycle_step_.load(std::memory_order_relaxed);
        const float fraction = lifecycle_action_ == LifecycleAction::BringLabOnline
            ? static_cast<float>(std::min<std::uint32_t>(step, 6U)) / 6.0F
            : (step == 0 ? 0.05F : 0.75F);
        ImGui::ProgressBar(fraction, ImVec2(-1.0F, 0.0F));
        if (deferred_action_ == DeferredAction::StartLifecycle) {
            ImGui::TextWrapped(UiText(
                "Waiting without blocking the render thread for active process, "
                "PFN, or kernel-read workers to stop before the SCM operation starts."));
        } else {
            ImGui::TextWrapped(UiText(
                "Lifecycle operation is running off the render thread. "
                "Cancellation takes effect between Service Control Manager stages; "
                "the active SCM call is allowed to finish."));
        }
    }

    ImGui::Text(UiText("KDBG service: %s | Probe service: %s"),
        ServiceStateName(driver_service_running_),
        ServiceStateName(probe_service_running_));
    if (lifecycle_busy) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Refresh Service Status"))) {
        RefreshServiceStates();
    }
    if (lifecycle_busy) ImGui::EndDisabled();
    if (!service_status_.empty()) {
        ImGui::SameLine();
        ImGui::TextWrapped("%s", service_status_.c_str());
    }

    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputText(UiText("KDBG driver SYS"), driver_path_.data(),
        driver_path_.size());
    const bool can_install_driver =
        !lifecycle_busy && !kernel_read_busy && !process_io_busy &&
        !physical_session_.RecoveryObservationRequired() &&
        driver_file_ready;
    if (!can_install_driver) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Install/Update KDBG"))) {
        StartLifecycleAction(LifecycleAction::InstallDriver);
    }
    if (!can_install_driver) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_start_driver = !lifecycle_busy && !kernel_read_busy &&
        !process_io_busy && !physical_session_.RecoveryObservationRequired() &&
        !driver_service_running_.value_or(false);
    if (!can_start_driver) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Start KDBG"))) {
        StartLifecycleAction(LifecycleAction::StartDriver);
    }
    if (!can_start_driver) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_stop_driver = !lifecycle_busy && !kernel_read_busy &&
        !process_io_busy &&
        driver_service_running_.value_or(false) &&
        !process_usage_.Busy() && !physical_session_.CanRollback() &&
        !physical_session_.RecoveryObservationRequired();
    if (!can_stop_driver) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Stop KDBG"))) {
        StartLifecycleAction(LifecycleAction::StopDriver);
    }
    if (!can_stop_driver) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_remove_driver =
        !lifecycle_busy && !kernel_read_busy && !process_io_busy &&
        !physical_session_.RecoveryObservationRequired() &&
        !driver_service_running_.value_or(true) &&
        !backend_.Info().connected && !process_usage_.Busy();
    if (!can_remove_driver) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Remove KDBG"))) {
        StartLifecycleAction(LifecycleAction::RemoveDriver);
    }
    if (!can_remove_driver) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_connect_device =
        !lifecycle_busy && !kernel_read_busy && !process_io_busy &&
        !process_usage_.Busy() && !physical_session_.CanRollback() &&
        !physical_session_.RecoveryObservationRequired();
    if (!can_connect_device) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Connect Device"))) ConnectBackend();
    if (!can_connect_device) ImGui::EndDisabled();
    if (process_usage_.Busy()) {
        ImGui::TextDisabled(UiText(
            "Cancel the active PFN ownership query before stopping, removing, or reconnecting KDBG."));
    }
    if (kernel_read_busy) {
        ImGui::TextDisabled(UiText(
            "Cancel or finish the active Kernel Explorer read before changing the KDBG service or device connection."));
    }
    if (process_io_busy) {
        ImGui::TextDisabled(UiText(
            "Process I/O is BUSY; cancel or finish it before changing the KDBG service or device connection."));
    }
    if (!driver_file_ready) {
        ImGui::TextDisabled(UiText(
            "Install is disabled until KDbgDriver.sys points to an existing file."));
    }

    ImGui::Separator();
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputText(UiText("Probe driver SYS"), probe_driver_path_.data(),
        probe_driver_path_.size());
    const bool can_install_probe = !lifecycle_busy && probe_file_ready &&
        !physical_session_.RecoveryObservationRequired();
    if (!can_install_probe) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Install/Update Probe"))) {
        StartLifecycleAction(LifecycleAction::InstallProbe);
    }
    if (!can_install_probe) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_start_probe = !lifecycle_busy &&
        !physical_session_.RecoveryObservationRequired() &&
        !probe_service_running_.value_or(false);
    if (!can_start_probe) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Start Probe"))) {
        StartLifecycleAction(LifecycleAction::StartProbe);
    }
    if (!can_start_probe) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_stop_probe = !lifecycle_busy &&
        probe_service_running_.value_or(false) &&
        !physical_session_.CanRollback() &&
        !physical_session_.RecoveryObservationRequired();
    if (!can_stop_probe) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Stop Probe"))) {
        probe_.Close();
        probe_fixture_loaded_ = false;
        ClearProbeEvidence();
        StartLifecycleAction(LifecycleAction::StopProbe);
        probe_info_.reset();
        probe_status_ = "Probe device stopped; no fixture is currently verified.";
    }
    if (!can_stop_probe) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_remove_probe =
        !lifecycle_busy && !probe_service_running_.value_or(true) &&
        !probe_.IsOpen() &&
        !physical_session_.RecoveryObservationRequired();
    if (!can_remove_probe) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Remove Probe"))) {
        StartLifecycleAction(LifecycleAction::RemoveProbe);
    }
    if (!can_remove_probe) ImGui::EndDisabled();
    if (!probe_file_ready) {
        ImGui::TextDisabled(UiText(
            "Install is disabled until KDbgProbe.sys points to an existing file."));
    }

    ImGui::Separator();
    const bool can_query_fixture = backend_.Info().connected &&
        !lifecycle_busy &&
        probe_service_running_.value_or(false) &&
        !physical_session_.IsDirty() && !physical_session_.CanRollback() &&
        !physical_session_.RecoveryObservationRequired();
    if (!can_query_fixture) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Query & Load Probe Fixture"))) {
        QueryAndLoadProbeFixture();
    }
    if (!can_query_fixture) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_reset_probe = probe_.IsOpen() && probe_info_.has_value() &&
        !physical_session_.IsDirty() && !physical_session_.CanRollback() &&
        !physical_session_.RecoveryObservationRequired();
    if (!can_reset_probe) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Reset Probe Pattern"))) {
        const auto result = probe_.Reset();
        LogResultDiagnostic(
            result,
            DiagnosticEvent::ProbeResetSucceeded,
            DiagnosticEvent::ProbeResetFailed);
        if (!result) {
            SetOperationResult(result, "");
        } else {
            QueryAndLoadProbeFixture();
            if (CurrentPageIsProbeFixture()) {
                operation_status_ =
                    "Probe page reset, re-queried, and loaded as a fresh baseline.";
            }
        }
    }
    if (!can_reset_probe) ImGui::EndDisabled();

    if (probe_info_.has_value()) {
        ImGui::TextColored(ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
            "Probe fixture VERIFIED | generation %u | bytes %u | CRC32 %08X",
            probe_info_->generation,
            probe_info_->byte_count,
            probe_info_->crc32);
        ImGui::Text("VA 0x%016llX | PA 0x%016llX | PFN 0x%llX",
            static_cast<unsigned long long>(probe_info_->virtual_address),
            static_cast<unsigned long long>(probe_info_->physical_address),
            static_cast<unsigned long long>(probe_info_->pfn));
    } else {
        ImGui::TextDisabled(UiText(
            "Probe fixture has not been queried and verified in this session."));
    }
    if (!probe_status_.empty()) ImGui::TextWrapped("%s", probe_status_.c_str());
    if (physical_session_.RecoveryObservationRequired()) {
        ImGui::TextDisabled(UiText(
            "Query & Load is disabled until the uncertain physical transaction is observed."));
    } else if (physical_session_.IsDirty()) {
        ImGui::TextDisabled(UiText(
            "Query & Load is disabled until staged physical edits are reverted or applied."));
    } else if (physical_session_.CanRollback()) {
        ImGui::TextDisabled(UiText(
            "Query & Load is disabled while a verified rollback is pending; use Independent Reload (keep rollback)."));
    }

    if (backend_.Info().connected) {
        ImGui::Separator();
        if (ImGui::Button(UiText("Query Driver Counters"))) {
            const auto session = backend_.QuerySessionStatus();
            if (!session) {
                operation_status_ = session.GetError().message;
            } else {
                char counters[480]{};
                std::snprintf(counters, sizeof(counters),
                    "Controller PID %u | Handles %u | Reads %llu | Writes %llu | Rejected writes %llu | Last physical write stage %u | NTSTATUS 0x%08X | transferred %u",
                    session.Value().owner_pid,
                    session.Value().open_handle_count,
                    static_cast<unsigned long long>(session.Value().successful_reads),
                    static_cast<unsigned long long>(session.Value().successful_writes),
                    static_cast<unsigned long long>(session.Value().rejected_writes),
                    session.Value().last_physical_write_stage,
                    session.Value().last_physical_write_status,
                    session.Value().last_physical_write_transferred);
                operation_status_ = counters;
            }
        }
    }
}

void MainWindow::DrawPhysicalMemoryTab() {
    if (ProcessIoBusy()) {
        ImGui::TextDisabled(UiText(
            "Process I/O is BUSY; physical-memory controls are paused to keep the UI non-blocking."));
        return;
    }
    if (!backend_.Info().connected) {
        ImGui::TextDisabled(UiText(
            "Connect the KDBG driver to access physical memory."));
    }
    if (!backend_.Info().connected) ImGui::BeginDisabled();
    if (ImGui::BeginTable(
            "physical-layout", 3,
            ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("PFN", ImGuiTableColumnFlags_WidthFixed, 270.0F);
        ImGui::TableSetupColumn(
            UiLabel("Hex Editor", "Hex Editor").c_str(),
            ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn(
            UiLabel("Inspector", "Inspector").c_str(),
            ImGuiTableColumnFlags_WidthFixed, 360.0F);
        ImGui::TableNextColumn();
        const bool transaction_pending = physical_session_.CanRollback() ||
            physical_session_.RecoveryObservationRequired();
        if (transaction_pending) ImGui::BeginDisabled();
        const bool loaded_from_navigator =
            pfn_input_.Draw(backend_, physical_session_);
        if (transaction_pending) ImGui::EndDisabled();
        if (loaded_from_navigator) {
            BindCurrentPageToRuntimeHost();
            probe_fixture_loaded_ = false;
            ClearProbeEvidence();
            last_physical_diffs_.clear();
            last_physical_readback_.clear();
            last_physical_readback_status_.clear();
        }
        if (physical_session_.RecoveryObservationRequired()) {
            ImGui::TextDisabled(UiText(
                "PFN navigation is locked until the uncertain transaction is observed."));
        } else if (physical_session_.CanRollback()) {
            ImGui::TextDisabled(UiText(
                "PFN navigation is locked until the pending rollback is completed."));
        }
        ImGui::TableNextColumn();
        hex_editor_.Draw(physical_session_);
        ImGui::TableNextColumn();
        if (physical_session_.HasPage()) {
            const auto target_kind = physical_session_.Target().kind;
            const bool probe_target = CurrentPageIsProbeFixture();
            const auto process_target = CurrentPageProcessTarget();
            ImGui::TextColored(
                ImVec4(0.45F, 0.75F, 1.0F, 1.0F),
                "%s", UiText(
                    "Local physical RAM — this Windows instance"));
            const auto runtime_host_identity = RuntimeHostIdentityLabel();
            ImGui::TextWrapped(
                UiText("Runtime host identity: %s"),
                runtime_host_identity.c_str());
            ImGui::TextColored(
                CurrentPageBoundToRuntimeHost()
                    ? ImVec4(0.35F, 0.90F, 0.45F, 1.0F)
                    : ImVec4(1.0F, 0.35F, 0.30F, 1.0F),
                "%s", CurrentPageBoundToRuntimeHost()
                    ? UiText("Target binding: CURRENT RUNTIME SESSION")
                    : UiText("Target binding: STALE / RELOAD REQUIRED"));
            ImGui::TextUnformatted(UiText(
                "Memory space: PHYSICAL / 4 KiB page"));
            ImGui::Text(UiText("State: %s"),
                PageStateName(physical_session_.State()));
            ImGui::Text(UiText("Revision: %llu"),
                static_cast<unsigned long long>(physical_session_.Revision()));
            ImGui::Text(UiText("Dirty bytes: %llu"),
                static_cast<unsigned long long>(physical_session_.DirtyCount()));
            ImGui::Text(UiText("One-shot write unlock: %s"),
                physical_session_.WriteUnlocked() ? "YES" : "NO");
            ImGui::Text(UiText("Driver physical gate: %s"),
                backend_.Info().write_enabled ? "ARMED" : "LOCKED");
            ImGui::Text(UiText(
                "Conflicts: %llu | Read-back mismatches: %llu"),
                static_cast<unsigned long long>(physical_session_.LastConflictOffsets().size()),
                static_cast<unsigned long long>(physical_session_.LastMismatchOffsets().size()));
            ImGui::Text(UiText(
                "PA range: 0x%016llX - 0x%016llX | size: 4096 bytes"),
                static_cast<unsigned long long>(physical_session_.Address().physical_address),
                static_cast<unsigned long long>(
                    physical_session_.Address().physical_address + 0xFFFU));
            ImGui::Text(
                UiText("Baseline CRC32: %08X | Current CRC32: %08X"),
                PageCrc32(physical_session_.Baseline()),
                PageCrc32(physical_session_.Working()));
            const auto provenance =
                PhysicalTargetProvenance(physical_session_.Target());
            ImGui::TextWrapped(UiText("Provenance: %s"), provenance.c_str());
            if (target_kind == PhysicalTargetKind::RawPfn) {
                ImGui::TextColored(
                    ImVec4(0.95F, 0.75F, 0.25F, 1.0F),
                    "%s", UiText(
                        "WRITE TARGET: RANGE-VALIDATED RAW PFN"));
                ImGui::TextWrapped("%s", UiText(
                    "The complete 4096-byte page is inside a driver-reported RAM range; ownership is not implied."));
            } else if (target_kind == PhysicalTargetKind::ProbeFixture &&
                       probe_target) {
                ImGui::TextColored(
                    ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
                    "WRITE TARGET: VERIFIED KDbgProbe FIXTURE");
            } else if (target_kind == PhysicalTargetKind::ProcessMapping &&
                       process_target.has_value()) {
                ImGui::TextColored(
                    ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
                    "WRITE TARGET: VERIFIED PROCESS PID %u / VA 0x%016llX",
                    process_target->pid,
                    static_cast<unsigned long long>(
                        process_target->virtual_address));
            } else {
                ImGui::TextColored(
                    ImVec4(1.0F, 0.35F, 0.30F, 1.0F),
                    "%s", UiText(
                        "BLOCKED: probe/process provenance must be revalidated before write review"));
            }
            if (ImGui::Button(UiText("Copy PFN"))) {
                char value[32]{};
                std::snprintf(value, sizeof(value), "0x%llX",
                    static_cast<unsigned long long>(physical_session_.Address().pfn));
                ImGui::SetClipboardText(value);
            }
            ImGui::SameLine();
            if (ImGui::Button(UiText("Copy PA"))) {
                char value[32]{};
                std::snprintf(value, sizeof(value), "0x%016llX",
                    static_cast<unsigned long long>(
                        physical_session_.Address().physical_address));
                ImGui::SetClipboardText(value);
            }
            ImGui::SameLine();
            if (ImGui::Button(UiText("View PFN Ownership"))) {
                select_pfn_ownership_tab_ = true;
            }
        } else {
            ImGui::TextDisabled(UiText("No physical page loaded."));
        }
        ImGui::EndTable();
    }
    DrawDiffPanel();
    DrawPhysicalReadback();
    DrawPhysicalActions();
    if (!backend_.Info().connected) ImGui::EndDisabled();
}

void MainWindow::DrawMemoryMapTab() {
    if (ProcessIoBusy() || LifecycleBusy()) {
        ImGui::TextDisabled(UiText(
            "Process I/O is BUSY; the memory map is paused to keep the UI non-blocking."));
        return;
    }
    memory_map_.Draw();
    if (const auto navigation = memory_map_.ConsumeNavigation();
        navigation.has_value()) {
        process_memory_browser_.Navigate(
            navigation->address,
            navigation->length == 0 ? 0x1000U : navigation->length);
        select_process_memory_tab_ = true;
        operation_status_ = "Memory-map selection opened in Process Memory.";
    }
}

void MainWindow::DrawProcessMemoryTab() {
    const bool competing_io = disassembly_.Busy() ||
        process_scanner_.Busy() || pointer_scanner_.Busy() || snapshots_.Busy();
    if ((competing_io || LifecycleBusy()) &&
        !process_memory_browser_.Busy()) {
        ImGui::TextDisabled(UiText(
            "Another process I/O worker is BUSY; this pane is paused to keep the UI non-blocking."));
        return;
    }
    process_memory_browser_.Draw();
}
void MainWindow::DrawProcessScannerTab() {
    const bool competing_io = process_memory_browser_.Busy() ||
        disassembly_.Busy() || pointer_scanner_.Busy() || snapshots_.Busy();
    if ((competing_io || LifecycleBusy()) && !process_scanner_.Busy()) {
        ImGui::TextDisabled(UiText(
            "Another process I/O worker is BUSY; scanning controls are paused to keep the UI non-blocking."));
        return;
    }
    process_scanner_.Draw();
}
void MainWindow::DrawPointerScannerTab() {
    const bool competing_io = process_memory_browser_.Busy() ||
        disassembly_.Busy() || process_scanner_.Busy() || snapshots_.Busy();
    if ((competing_io || LifecycleBusy()) && !pointer_scanner_.Busy()) {
        ImGui::TextDisabled(UiText(
            "Another process I/O worker is BUSY; pointer scanning is paused to keep the UI non-blocking."));
        return;
    }
    pointer_scanner_.Draw();
}
void MainWindow::DrawDisassemblyTab() {
    const bool competing_io = process_memory_browser_.Busy() ||
        process_scanner_.Busy() || pointer_scanner_.Busy() || snapshots_.Busy();
    if ((competing_io || LifecycleBusy()) && !disassembly_.Busy()) {
        ImGui::TextDisabled(UiText(
            "Another process I/O worker is BUSY; disassembly is paused to keep the UI non-blocking."));
        return;
    }
    disassembly_.Draw();
}
void MainWindow::DrawKernelExplorerTab() {
    if (ProcessIoBusy() ||
        (LifecycleBusy() && !kernel_explorer_.Busy())) {
        ImGui::TextDisabled(UiText(
            "Process I/O is BUSY; Kernel Explorer is paused to keep the UI non-blocking."));
        return;
    }
    kernel_explorer_.Draw();
    const auto navigation = kernel_explorer_.ConsumePageTableNavigation();
    if (!navigation.has_value()) return;
    if (ProcessIoBusy()) {
        operation_status_ =
            "Page-table navigation deferred: process I/O is BUSY.";
        return;
    }
    page_table_.SetVirtualAddress(*navigation);
    if (process_memory_ != nullptr) {
        page_table_.SetPid(process_memory_->ProcessId());
        operation_status_ =
            "Kernel VA opened in Page Tables with the attached process CR3.";
    } else {
        operation_status_ =
            "Kernel VA opened in Page Tables; select a process PID to supply a CR3.";
    }
    select_page_tables_tab_ = true;
}
void MainWindow::DrawSnapshotTab() {
    const bool competing_io = process_memory_browser_.Busy() ||
        disassembly_.Busy() || process_scanner_.Busy() ||
        pointer_scanner_.Busy();
    if ((competing_io || LifecycleBusy()) && !snapshots_.Busy()) {
        ImGui::TextDisabled(UiText(
            "Another process I/O worker is BUSY; snapshots are paused to keep the UI non-blocking."));
        return;
    }
    snapshots_.Draw();
}

void MainWindow::DrawTranslationTab() {
    if (ProcessIoBusy() || LifecycleBusy()) {
        ImGui::TextDisabled(UiText(
            "Process I/O is BUSY; page-table operations are paused to keep the UI non-blocking."));
        return;
    }
    page_table_.Draw(
        backend_,
        process_memory_ == nullptr ? 0 : process_memory_->ProcessId());
    if (const auto page = page_table_.ConsumePhysicalNavigation();
        page.has_value()) {
        if (physical_session_.RecoveryObservationRequired()) {
            operation_status_ =
                "Observe the uncertain physical transaction before opening a translated PFN.";
            return;
        }
        if (physical_session_.IsDirty()) {
            operation_status_ =
                "Revert or apply staged physical edits before opening a translated PFN.";
            return;
        }
        if (physical_session_.CanRollback()) {
            operation_status_ =
                "Complete the pending verified rollback before opening a translated PFN.";
            return;
        }
        const auto process_target =
            page_table_.CurrentProcessTarget(*page);
        const auto loaded = process_target.has_value()
            ? physical_session_.Load(
                backend_,
                PhysicalWriteTarget::ProcessMapping(
                    *page,
                    process_target->pid,
                    process_target->virtual_address &
                        ~static_cast<std::uint64_t>(
                            kPhysicalPageSize - 1U)))
            : physical_session_.Load(
                backend_, PhysicalWriteTarget::RawPfn(*page));
        if (loaded) {
            BindCurrentPageToRuntimeHost();
            probe_fixture_loaded_ = false;
            ClearProbeEvidence();
            last_physical_diffs_.clear();
            last_physical_readback_.clear();
            last_physical_readback_status_.clear();
            pfn_input_.SetPfn(page->pfn);
            select_physical_memory_tab_ = true;
            operation_status_ = process_target.has_value()
                ? "Translated writable 4 KiB user page opened in Physical Memory. "
                  "Unlock and Apply will revalidate PID, CR3, VA, and PFN before writing."
                : "Translated page opened in Physical Memory for inspection. "
                  "Advanced writes require a writable 4 KiB user mapping.";
        } else {
            operation_status_ = loaded.GetError().message;
        }
    }
}

void MainWindow::DrawPfnOwnershipTab() {
    DrawAnalysisEvidence();
    if (analysis_evidence_future_.valid()) return;
    if (ProcessIoBusy() ||
        (LifecycleBusy() && !process_usage_.Busy())) {
        ImGui::TextDisabled(UiText(
            "Process I/O is BUSY; PFN ownership is paused to keep the UI non-blocking."));
        return;
    }
    std::optional<PfnAddress> page;
    if (physical_session_.HasPage()) page = physical_session_.Address();
    process_usage_.Draw(
        backend_,
        page,
        process_memory_ == nullptr ? 0 : process_memory_->ProcessId(),
        AttachedProcessName());
    if (const auto navigation = process_usage_.ConsumeNavigation();
        navigation.has_value()) {
        if (navigation->target == PfnUsageNavigationTarget::PageTables) {
            page_table_.SetPid(navigation->pid);
            page_table_.SetVirtualAddress(navigation->virtual_address);
            select_page_tables_tab_ = true;
            operation_status_ = "PFN ownership mapping opened in Page Tables.";
        } else {
            const auto process = std::find_if(
                processes_.begin(), processes_.end(),
                [&](const ProcessInfo& entry) {
                    return entry.pid == navigation->pid;
                });
            if (process == processes_.end()) {
                operation_status_ =
                    "The owner PID is no longer present in the process catalog; refresh and retry.";
            } else {
                selected_process_index_ = static_cast<int>(
                    std::distance(processes_.begin(), process));
                if (process_memory_ == nullptr ||
                    process_memory_->ProcessId() != navigation->pid) {
                    AttachSelectedProcess();
                }
                if (process_memory_ != nullptr &&
                    process_memory_->ProcessId() == navigation->pid) {
                    process_memory_browser_.Navigate(
                        navigation->virtual_address, 0x1000U);
                    select_process_memory_tab_ = true;
                    operation_status_ =
                        "PFN ownership mapping opened in Process Memory.";
                }
            }
        }
    }
}

void MainWindow::DrawDiffPanel() {
    if (!physical_session_.HasPage()) return;
    if (!ImGui::CollapsingHeader(
            UiLabel("Dirty Diff", "Dirty Diff").c_str(),
            ImGuiTreeNodeFlags_DefaultOpen)) {
        return;
    }
    const auto diffs = physical_session_.ByteDiffs();
    if (diffs.empty()) {
        ImGui::TextDisabled(UiText("No local changes."));
        return;
    }
    if (ImGui::BeginTable(
            "physical-diff", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 150.0F))) {
        ImGui::TableSetupColumn(UiLabel("Offset", "Offset").c_str());
        ImGui::TableSetupColumn(
            UiLabel("Physical Address", "Physical Address").c_str());
        ImGui::TableSetupColumn(UiLabel("Before", "Before").c_str());
        ImGui::TableSetupColumn(UiLabel("After", "After").c_str());
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            diffs.size(), static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart;
                 index < clipper.DisplayEnd; ++index) {
                const auto& diff = diffs[static_cast<std::size_t>(index)];
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("0x%03llX", static_cast<unsigned long long>(diff.offset));
                ImGui::TableNextColumn(); ImGui::Text("0x%016llX", static_cast<unsigned long long>(physical_session_.Address().physical_address + diff.offset));
                ImGui::TableNextColumn(); ImGui::Text("%02X", diff.before);
                ImGui::TableNextColumn(); ImGui::Text("%02X", diff.after);
            }
        }
        ImGui::EndTable();
    }
}

void MainWindow::DrawPhysicalReadback() {
    if (last_physical_readback_status_.empty()) return;
    if (!ImGui::CollapsingHeader(
            UiLabel("Last Physical Operation Read-back",
                "Last Physical Operation Read-back").c_str(),
            ImGuiTreeNodeFlags_DefaultOpen)) {
        return;
    }
    ImGui::TextWrapped("%s", last_physical_readback_status_.c_str());
    if (last_physical_readback_.size() != kPhysicalPageSize ||
        last_physical_diffs_.empty()) {
        return;
    }
    if (ImGui::BeginTable(
            "physical-readback", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 180.0F))) {
        ImGui::TableSetupColumn(UiLabel("Offset", "Offset").c_str());
        ImGui::TableSetupColumn(
            UiLabel("Physical Address", "Physical Address").c_str());
        ImGui::TableSetupColumn(UiLabel("Baseline", "Baseline").c_str());
        ImGui::TableSetupColumn(UiLabel("Submitted", "Submitted").c_str());
        ImGui::TableSetupColumn(UiLabel("Read-back", "Read-back").c_str());
        ImGui::TableSetupColumn(UiLabel("Result", "Result").c_str());
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            last_physical_diffs_.size(), static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart;
                 index < clipper.DisplayEnd; ++index) {
                const auto& diff =
                    last_physical_diffs_[static_cast<std::size_t>(index)];
                const auto readback = last_physical_readback_[diff.offset];
                const bool matched = readback == diff.after;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%03llX",
                    static_cast<unsigned long long>(diff.offset));
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(
                    physical_session_.Address().physical_address + diff.offset));
                ImGui::TableNextColumn(); ImGui::Text("%02X", diff.before);
                ImGui::TableNextColumn(); ImGui::Text("%02X", diff.after);
                ImGui::TableNextColumn(); ImGui::Text("%02X", readback);
                ImGui::TableNextColumn();
                ImGui::TextColored(
                    matched
                        ? ImVec4(0.35F, 0.90F, 0.45F, 1.0F)
                        : ImVec4(1.0F, 0.30F, 0.25F, 1.0F),
                    "%s", matched ? "MATCH" : "MISMATCH");
            }
        }
        ImGui::EndTable();
    }
}

void MainWindow::DrawPhysicalActions() {
    if (!physical_session_.HasPage()) return;
    const bool recovery_observation_required =
        physical_session_.RecoveryObservationRequired();
    const bool probe_target = CurrentPageIsProbeFixture() ||
        (physical_session_.CanRollback() &&
         CurrentPageMatchesProbeIdentity());
    const bool write_target = CurrentPageIsVerifiedWriteTarget();
    const bool ownership_idle = !process_usage_.Busy();
    const bool lifecycle_idle = !LifecycleBusy();
    const bool can_stage_probe_pattern = probe_target &&
        !physical_session_.CanRollback() &&
        !recovery_observation_required && ownership_idle && lifecycle_idle;
    if (recovery_observation_required) {
        ImGui::TextColored(
            ImVec4(1.0F, 0.55F, 0.20F, 1.0F),
            "%s", UiText(
                "RECOVERY OBSERVATION REQUIRED: the previous transaction result is uncertain. Reload the exact 4096-byte page before any further write."));
    }
    if (!can_stage_probe_pattern) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Stage Evidence Probe Pattern"))) {
        physical_session_.RevertAll();
        const auto& baseline = physical_session_.Baseline();
        bool staged = true;
        for (std::size_t index = 0;
             index < kProbeEvidenceEditMask.size(); ++index) {
            const auto result = physical_session_.EditByte(
                kProbeEvidenceEditOffset + index,
                static_cast<std::uint8_t>(
                    baseline[kProbeEvidenceEditOffset + index] ^
                    kProbeEvidenceEditMask[index]));
            if (!result) {
                physical_session_.RevertAll();
                SetOperationResult(result, "");
                staged = false;
                break;
            }
        }
        if (staged) {
            probe_evidence_after_write_.reset();
            probe_evidence_after_reload_.reset();
            probe_evidence_after_rollback_.reset();
            last_physical_evidence_path_.clear();
            operation_status_ =
                "Staged the evidence Probe XOR pattern at offset 0x100 (8 bytes); no write was issued.";
        }
    }
    if (!can_stage_probe_pattern) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!physical_session_.CanUndo()) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Undo Byte Edit"))) {
        SetOperationResult(
            physical_session_.Undo(),
            "Last physical-page byte edit undone.");
    }
    if (!physical_session_.CanUndo()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!physical_session_.CanRedo()) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Redo Byte Edit"))) {
        SetOperationResult(
            physical_session_.Redo(),
            "Last physical-page byte edit redone.");
    }
    if (!physical_session_.CanRedo()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!physical_session_.IsDirty()) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Revert Local Edits"))) {
        physical_session_.RevertAll();
        operation_status_ = "Local physical-page edits reverted.";
    }
    if (!physical_session_.IsDirty()) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_unlock = physical_session_.IsDirty() &&
        !recovery_observation_required && write_target && ownership_idle &&
        lifecycle_idle;
    if (!can_unlock) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Unlock One Physical Apply"))) {
        if (ValidateCurrentPhysicalTargetForWrite()) {
            write_modal_.Open(WriteReviewPurpose::Apply);
        }
    }
    if (!can_unlock) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_apply = physical_session_.IsDirty() &&
        !recovery_observation_required &&
        physical_session_.WriteUnlocked() && write_target && ownership_idle &&
        lifecycle_idle;
    if (!can_apply) ImGui::BeginDisabled();
    if (ImGui::Button(UiText(
            "Apply Exact 4 KiB Transaction & Verify"))) {
        if (!ValidateCurrentPhysicalTargetForWrite()) {
            write_modal_.ClearUnlocked();
        } else {
            const auto submitted_diffs = physical_session_.ByteDiffs();
            const auto result = physical_session_.ApplyAndVerify(backend_);
            LogResultDiagnostic(
                result,
                DiagnosticEvent::PhysicalApplySucceeded,
                DiagnosticEvent::PhysicalApplyFailed);
            const auto relock = backend_.SetWriteEnabled(false);
            if (relock && !backend_.Info().write_enabled) {
                LogDiagnostic(DiagnosticEvent::PhysicalGateLockSucceeded);
            } else {
                LogDiagnostic(
                    DiagnosticEvent::PhysicalGateLockFailed,
                    relock ? 1U : static_cast<std::uint64_t>(
                        relock.GetError().code),
                    relock ? 0U : relock.GetError().native_code);
            }
            if (!relock || backend_.Info().write_enabled) {
                operation_status_ = relock
                    ? "CRITICAL: physical operation returned but the driver still reports its write gate ARMED."
                    : "CRITICAL: physical operation returned but the driver write gate could not be confirmed locked: " +
                        relock.GetError().message;
            } else {
                SetOperationResult(
                    result,
                    "Local dirty diff (" +
                        std::to_string(submitted_diffs.size()) +
                        " byte(s)) was reviewed; the driver completed one exact 4096-byte compare/write/read-back transaction and the write gate is LOCKED.");
            }
            if (result && probe_target && probe_.IsOpen()) {
                const auto refreshed = probe_.Query();
                if (refreshed) {
                    probe_evidence_after_reload_.reset();
                    probe_evidence_after_rollback_.reset();
                    last_physical_evidence_path_.clear();
                    const auto expected_generation =
                        probe_info_.has_value()
                            ? probe_info_->generation
                            : 0U;
                    if (!ProbeIdentityMatchesPage(
                            refreshed.Value(),
                            physical_session_.Address(),
                            expected_generation)) {
                        probe_fixture_loaded_ = false;
                        probe_evidence_after_write_.reset();
                        operation_status_ +=
                            " | CRITICAL: Probe identity changed after the physical apply. VERIFIED/evidence was revoked.";
                    } else {
                        probe_info_ = refreshed.Value();
                        const auto& readback =
                            physical_session_.Evidence().readback;
                        if (!PageMatchesProbeCrc(
                                readback, probe_info_)) {
                            probe_evidence_after_write_.reset();
                            operation_status_ +=
                                " | CRITICAL: Probe metadata CRC does not match the physical full-page read-back. Runtime readiness was revoked; rollback remains available.";
                        } else {
                            probe_evidence_after_write_ =
                                refreshed.Value();
                        }
                    }
                } else {
                    probe_evidence_after_write_.reset();
                    operation_status_ +=
                        " | Probe metadata refresh after apply failed: " +
                        refreshed.GetError().message;
                }
            }
            CapturePhysicalReadback(submitted_diffs, "Apply");
            write_modal_.ClearUnlocked();
        }
    }
    if (!can_apply) ImGui::EndDisabled();
    const auto& page_evidence = physical_session_.Evidence();
    const bool reload_page_verified =
        page_evidence.independent_reload.has_value() &&
        page_evidence.expected_after.has_value() &&
        page_evidence.independent_reload == page_evidence.expected_after;
    const bool needs_probe_metadata_retry = probe_target && (
        (physical_session_.CanRollback() &&
         physical_session_.LastApplyVerified() &&
         !probe_evidence_after_write_.has_value()) ||
        (physical_session_.CanRollback() && reload_page_verified &&
         !probe_evidence_after_reload_.has_value()) ||
        (!physical_session_.CanRollback() && page_evidence.Complete() &&
         !probe_evidence_after_rollback_.has_value()));
    if (needs_probe_metadata_retry) {
        if (ImGui::Button(UiText(
                "Retry Probe Metadata (keep evidence)"))) {
            RetryProbeMetadataForEvidence();
        }
    }
    if (physical_session_.CanRollback() || recovery_observation_required) {
        const bool can_reload =
            (!physical_session_.IsDirty() || recovery_observation_required) &&
            write_target && ownership_idle && lifecycle_idle &&
            (recovery_observation_required || !probe_target ||
             probe_evidence_after_write_.has_value());
        if (!can_reload) ImGui::BeginDisabled();
        const char* reload_label = recovery_observation_required
            ? UiText("Observe Live Page (recover rollback state)")
            : UiText("Independent Reload (keep rollback)");
        if (ImGui::Button(reload_label)) {
            probe_evidence_after_reload_.reset();
            probe_evidence_after_rollback_.reset();
            last_physical_evidence_path_.clear();
            const bool observing_recovery = recovery_observation_required;
            const bool target_valid = observing_recovery
                ? ValidateCurrentPhysicalTargetForObservation()
                : ValidateCurrentPhysicalTargetForWrite();
            if (target_valid) {
                const auto result =
                    physical_session_.ReloadPreservingRollback(backend_);
                if (!result) {
                    SetOperationResult(result, "");
                } else if (!probe_target) {
                    const auto& reloaded =
                        *physical_session_.Evidence().independent_reload;
                    last_physical_readback_.assign(
                        reloaded.begin(), reloaded.end());
                    if (observing_recovery) {
                        last_physical_readback_status_ =
                            "Recovery observation captured: exact 4096-byte live page read.";
                        operation_status_ = physical_session_.CanRollback()
                            ? "Recovery observation completed; the observed page differs from the saved baseline and conditional rollback is now available."
                            : "Recovery observation completed; the observed page already matches the saved baseline, so no rollback is required.";
                    } else {
                        last_physical_readback_status_ =
                            "Independent reload captured: 4096 bytes; full-page match; rollback snapshot preserved.";
                        operation_status_ = physical_session_.Target().kind ==
                                PhysicalTargetKind::RawPfn
                            ? "Independent 4096-byte reload matched the RawPfn write; rollback remains available."
                            : "Independent 4096-byte reload matched the verified process-page write; rollback remains available.";
                    }
                } else {
                    const auto refreshed = probe_.Query();
                    if (!refreshed) {
                        probe_evidence_after_reload_.reset();
                        operation_status_ =
                            "Independent 4096-byte reload passed, but the probe metadata re-query failed: " +
                            refreshed.GetError().message;
                    } else if (refreshed.Value().byte_count !=
                                   kPhysicalPageSize ||
                               refreshed.Value().pfn !=
                                   physical_session_.Address().pfn ||
                               refreshed.Value().physical_address !=
                                   physical_session_.Address().physical_address ||
                               !probe_info_.has_value() ||
                               refreshed.Value().generation !=
                                   probe_info_->generation) {
                        probe_fixture_loaded_ = false;
                        probe_evidence_after_reload_.reset();
                        operation_status_ =
                            "Independent reload completed, but the probe identity changed; rollback remains locked.";
                    } else {
                        probe_info_ = refreshed.Value();
                        const auto& reloaded =
                            *physical_session_.Evidence().independent_reload;
                        last_physical_readback_.assign(
                            reloaded.begin(), reloaded.end());
                        if (PageCrc32(reloaded) != probe_info_->crc32) {
                            probe_evidence_after_reload_.reset();
                            last_physical_readback_status_ =
                                "Independent reload matched the physical write, but its CRC does not match Probe metadata.";
                            operation_status_ =
                                "CRITICAL: independent physical reload and Probe metadata disagree; evidence remains blocked and rollback remains available.";
                        } else {
                            probe_evidence_after_reload_ = refreshed.Value();
                            if (observing_recovery) {
                                last_physical_readback_status_ =
                                    "Recovery observation captured: 4096 bytes; Probe identity and CRC match the observed page.";
                                operation_status_ =
                                    physical_session_.CanRollback()
                                    ? "Recovery observation completed; conditional rollback is now available."
                                    : "Recovery observation completed; the page already matches the saved baseline and no rollback is required.";
                            } else {
                                last_physical_readback_status_ =
                                    "Independent reload evidence captured: 4096 bytes; full-page and Probe CRC match; rollback snapshot preserved.";
                                operation_status_ =
                                    "Independent 4096-byte reload matched the verified write and Probe CRC; rollback snapshot remains available.";
                            }
                        }
                    }
                }
            }
        }
        if (!can_reload) ImGui::EndDisabled();
    }
    if (physical_session_.CanRollback()) {
        ImGui::SameLine();
        if (!physical_session_.WriteUnlocked()) {
            const bool independent_reload_required =
                physical_session_.LastApplyVerified() &&
                CurrentPageIsProbeFixture();
            const bool independent_reload_complete =
                physical_session_.Evidence().independent_reload.has_value() &&
                (!probe_target || probe_evidence_after_reload_.has_value());
            const bool can_unlock_rollback = write_target && ownership_idle &&
                lifecycle_idle &&
                (!independent_reload_required || independent_reload_complete);
            if (!can_unlock_rollback) ImGui::BeginDisabled();
            if (ImGui::Button(UiText("Unlock Rollback"))) {
                if (ValidateCurrentPhysicalTargetForRollback()) {
                    write_modal_.Open(WriteReviewPurpose::Rollback);
                }
            }
            if (!can_unlock_rollback) ImGui::EndDisabled();
        } else {
            const bool can_rollback = write_target && ownership_idle &&
                lifecycle_idle;
            if (!can_rollback) ImGui::BeginDisabled();
            if (ImGui::Button(UiText("Rollback Previous Apply"))) {
                if (!ValidateCurrentPhysicalTargetForRollback()) {
                    write_modal_.ClearUnlocked();
                } else {
                    const auto before_rollback = physical_session_.Baseline();
                    const auto result = physical_session_.RollbackBaseline(backend_);
                    LogResultDiagnostic(
                        result,
                        DiagnosticEvent::PhysicalRollbackSucceeded,
                        DiagnosticEvent::PhysicalRollbackFailed);
                    const auto relock = backend_.SetWriteEnabled(false);
                    if (relock && !backend_.Info().write_enabled) {
                        LogDiagnostic(
                            DiagnosticEvent::PhysicalGateLockSucceeded);
                    } else {
                        LogDiagnostic(
                            DiagnosticEvent::PhysicalGateLockFailed,
                            relock ? 1U : static_cast<std::uint64_t>(
                                relock.GetError().code),
                            relock ? 0U : relock.GetError().native_code);
                    }
                    if (!relock || backend_.Info().write_enabled) {
                        operation_status_ = relock
                            ? "CRITICAL: rollback returned but the physical write gate still reports ARMED."
                            : "CRITICAL: rollback returned but relocking failed: " +
                                relock.GetError().message;
                    } else {
                        SetOperationResult(
                            result,
                            "Previous physical-page baseline restored, read back, and the write gate is LOCKED.");
                    }
                    if (result && probe_target && probe_.IsOpen()) {
                        const auto refreshed = probe_.Query();
                        if (refreshed) {
                            const auto expected_generation =
                                probe_evidence_baseline_.has_value()
                                    ? probe_evidence_baseline_->generation
                                    : 0U;
                            if (!ProbeIdentityMatchesPage(
                                    refreshed.Value(),
                                    physical_session_.Address(),
                                    expected_generation)) {
                                probe_fixture_loaded_ = false;
                                probe_evidence_after_rollback_.reset();
                                operation_status_ +=
                                    " | CRITICAL: Probe identity changed after rollback; VERIFIED/evidence remains blocked.";
                            } else {
                                probe_info_ = refreshed.Value();
                                const auto& rollback_page =
                                    physical_session_.Evidence().rollback;
                                if (!PageMatchesProbeCrc(
                                        rollback_page, probe_info_)) {
                                    probe_evidence_after_rollback_.reset();
                                    operation_status_ +=
                                        " | CRITICAL: rollback physical page CRC does not match Probe metadata; VERIFIED/evidence remains blocked.";
                                } else {
                                    probe_evidence_after_rollback_ =
                                        refreshed.Value();
                                }
                            }
                        } else {
                            probe_evidence_after_rollback_.reset();
                            operation_status_ +=
                                " | Probe metadata refresh after rollback failed: " +
                                refreshed.GetError().message;
                        }
                    }
                    std::vector<ByteDiff> rollback_diffs;
                    if (result) {
                        const auto& restored = physical_session_.Baseline();
                        for (std::size_t offset = 0;
                             offset < restored.size(); ++offset) {
                            if (before_rollback[offset] != restored[offset]) {
                                rollback_diffs.push_back(ByteDiff{
                                    offset,
                                    before_rollback[offset],
                                    restored[offset]});
                            }
                        }
                    }
                    CapturePhysicalReadback(
                        std::move(rollback_diffs), "Rollback");
                    write_modal_.ClearUnlocked();
                }
            }
            if (!can_rollback) ImGui::EndDisabled();
        }
    }
    const bool can_export_evidence =
        physical_session_.Evidence().Complete() &&
        probe_evidence_baseline_.has_value() &&
        probe_evidence_after_write_.has_value() &&
        probe_evidence_after_reload_.has_value() &&
        probe_evidence_after_rollback_.has_value() && probe_target;
    if (!can_export_evidence) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Export Live Evidence Bundle"))) {
        ExportPhysicalEvidence();
    }
    if (!can_export_evidence) ImGui::EndDisabled();
    if (!last_physical_evidence_path_.empty()) {
        ImGui::SameLine();
        if (ImGui::Button(UiText("Copy Evidence Path"))) {
            ImGui::SetClipboardText(last_physical_evidence_path_.c_str());
        }
        ImGui::TextWrapped(UiText("Evidence bundle: %s"),
            last_physical_evidence_path_.c_str());
    }
    if (!write_target) {
        ImGui::TextDisabled(UiText(
            "Physical apply/rollback is disabled until the RawPfn RAM range or "
            "the selected Probe/ProcessMapping provenance is revalidated."));
    } else if (!ownership_idle) {
        ImGui::TextDisabled(UiText(
            "Physical apply/rollback is disabled while PFN ownership analysis uses the backend."));
    } else if (!lifecycle_idle) {
        ImGui::TextDisabled(UiText(
            "Physical apply/rollback is disabled while a driver lifecycle operation is running."));
    } else if (physical_session_.CanRollback() &&
               physical_session_.LastApplyVerified() &&
               !physical_session_.Evidence().independent_reload.has_value()) {
        ImGui::TextDisabled(UiText(
            "Run Independent Reload (keep rollback) before unlocking rollback."));
    }
}

void MainWindow::DrawAnalysisEvidence() {
    ImGui::SeparatorText(UiText(
        "Analysis live evidence (dedicated user fixture)"));
    ImGui::TextWrapped(UiText(
        "Exports a separate hash-bound user VA -> page walk -> physical page "
        "proof plus the current Kernel Explorer read. This never substitutes "
        "the Probe physical-write transaction."));
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputText(
        UiText("Fixture INFO JSON"), fixture_info_path_.data(),
        fixture_info_path_.size());

    const bool running = analysis_evidence_future_.valid();
    const bool coarse_ready = !running && cached_backend_info_.connected &&
        !cached_backend_info_.is_mock && process_memory_ != nullptr &&
        process_memory_->IsOpen() && !process_memory_->WritesArmed() &&
        !cached_backend_info_.write_enabled && physical_session_.HasPage() &&
        !physical_session_.RecoveryObservationRequired() &&
        physical_session_.ByteDiffs().empty() && !process_usage_.Busy() &&
        !kernel_explorer_.Busy();
    ImGui::BeginDisabled(!coarse_ready);
    if (ImGui::Button(UiText("Export Analysis Evidence"))) {
        StartAnalysisEvidenceExport();
    }
    ImGui::EndDisabled();
    if (running) {
        ImGui::SameLine();
        if (ImGui::Button(UiText("Cancel Analysis Export"))) {
            CancelAnalysisEvidenceExport();
        }
        const auto progress = analysis_evidence_progress_.load(
            std::memory_order_relaxed);
        ImGui::ProgressBar(
            std::min(1.0F, static_cast<float>(progress) / 10.0F),
            ImVec2(-1.0F, 0.0F));
    }
    if (!analysis_evidence_status_.empty()) {
        ImGui::TextWrapped("%s", analysis_evidence_status_.c_str());
    }
    if (!last_analysis_evidence_path_.empty()) {
        if (ImGui::Button(UiText("Copy Analysis Evidence Path"))) {
            ImGui::SetClipboardText(last_analysis_evidence_path_.c_str());
        }
        ImGui::TextWrapped(UiText("Analysis evidence: %s"),
            last_analysis_evidence_path_.c_str());
    }
    if (!coarse_ready && !running) {
        ImGui::TextDisabled(UiText(
            "Requires LIVE backend, attached fixture, clean loaded 4 KiB page, "
            "LOCKED physical/process gates, completed ownership/PTView, and an "
            "exact-signature Kernel Explorer read."));
    }
    ImGui::Separator();
}

void MainWindow::StartAnalysisEvidenceExport() {
    if (analysis_evidence_future_.valid()) return;
    const auto fixture_result = ReadProcessFixtureInfo(
        Utf8Path(fixture_info_path_.data()));
    if (!fixture_result) {
        analysis_evidence_status_ = FormatError(fixture_result.GetError());
        return;
    }
    const auto fixture = fixture_result.Value();
    if (process_memory_ == nullptr || !process_memory_->IsOpen() ||
        process_memory_->ProcessId() != fixture.pid ||
        process_memory_->ProcessIdentityToken() != fixture.process_start_id ||
        process_memory_->WritesArmed() || cached_backend_info_.write_enabled) {
        analysis_evidence_status_ =
            "Analysis export blocked: attach the exact INFO process identity and lock both write gates.";
        return;
    }
    if (!physical_session_.HasPage() ||
        !physical_session_.ByteDiffs().empty()) {
        analysis_evidence_status_ =
            "Analysis export blocked: load the fixture physical page with no staged edits.";
        return;
    }
    const auto pfn = physical_session_.Address().pfn;
    const auto ownership = process_usage_.CurrentEvidence(
        pfn, fixture.pid, fixture.virtual_address);
    const auto page_table = page_table_.CurrentEvidence(
        fixture.pid, fixture.virtual_address, pfn);
    const auto kernel = kernel_explorer_.CurrentEvidence();
    if (!ownership.has_value() || !page_table.has_value() ||
        !kernel.has_value()) {
        analysis_evidence_status_ =
            "Analysis export blocked: ownership, PTView, and Kernel Explorer proofs must all match the current targets.";
        return;
    }
    const auto module_name_raw =
        std::filesystem::path(kernel->module.name).filename().string();
    const auto module_lower = Lower(module_name_raw);
    if ((module_lower != "kdbgdriver.sys" &&
         module_lower != "kdbgprobe.sys") ||
        module_name_raw != kernel->module.name) {
        analysis_evidence_status_ =
            "Analysis export blocked: Kernel Explorer must target KDbgDriver.sys or KDbgProbe.sys.";
        return;
    }
    const std::string module_basename = module_lower == "kdbgdriver.sys"
        ? "KDbgDriver.sys"
        : "KDbgProbe.sys";
    const auto expected_pdb_basename =
        std::filesystem::path(module_basename).stem().string() + ".pdb";
    if (Lower(kernel->symbol_proof.loaded_pdb_basename) !=
        Lower(expected_pdb_basename)) {
        analysis_evidence_status_ =
            "Analysis export blocked: loaded PDB basename does not match the selected KDBG driver.";
        return;
    }
    const auto& mapping = ownership->mapping;
    if (ownership->provider != "selected-process-page-table-scan" ||
        mapping.source != "selected-process-page-table-scan" ||
        mapping.mapping_type != "4 KiB page" ||
        mapping.confidence != MappingConfidence::High || mapping.shared ||
        !mapping.writable || !mapping.user_accessible ||
        page_table->walk.steps.empty() || page_table->walk.page_size != 4096U ||
        page_table->walk.page_offset != 0 ||
        page_table->walk.physical_address != (pfn << 12U) ||
        mapping.pte_address !=
            page_table->walk.steps.back().entry_physical_address ||
        (probe_info_.has_value() && probe_info_->pfn == pfn)) {
        analysis_evidence_status_ =
            "Analysis export blocked: the fixture must be a unique high-confidence writable user 4 KiB reverse mapping.";
        return;
    }
    const auto process = std::find_if(
        processes_.begin(), processes_.end(), [&](const ProcessInfo& value) {
            return value.pid == fixture.pid;
        });
    if (process == processes_.end() || process->path.empty()) {
        analysis_evidence_status_ =
            "Analysis export blocked: refresh the process catalog to bind the fixture image path.";
        return;
    }
    const auto expected_fixture =
        ExecutableDirectory() / "tools" / "kdbg_process_fixture.exe";
    const auto expected_driver =
        ExecutableDirectory() / "drivers" / module_basename;
    std::error_code path_error;
    const auto actual_canonical = std::filesystem::weakly_canonical(
        Utf8Path(process->path), path_error);
    if (path_error) {
        analysis_evidence_status_ =
            "Analysis export blocked: unable to canonicalize the attached process image path.";
        return;
    }
    const auto expected_canonical = std::filesystem::weakly_canonical(
        expected_fixture, path_error);
    if (path_error || actual_canonical != expected_canonical) {
        analysis_evidence_status_ =
            "Analysis export blocked: attached image is not the packaged process fixture.";
        return;
    }
    const auto expected_driver_canonical = std::filesystem::weakly_canonical(
        expected_driver, path_error);
    if (path_error) {
        analysis_evidence_status_ =
            "Analysis export blocked: packaged KDBG driver image is unavailable.";
        return;
    }
    const auto evidence_root = LocalEvidenceRoot();
    if (!evidence_root.has_value()) {
        analysis_evidence_status_ =
            "Analysis export blocked: LOCALAPPDATA evidence root is unavailable.";
        return;
    }

    analysis_evidence_cancel_.store(false, std::memory_order_relaxed);
    analysis_evidence_progress_.store(0, std::memory_order_relaxed);
    analysis_evidence_status_ = "Capturing analysis evidence...";
    last_analysis_evidence_path_.clear();
    auto* const memory = process_memory_.get();
    auto* const backend = &backend_;
    const auto driver_abi_version = cached_backend_info_.abi_version;
    const auto captured_utc = IsoTimestampUtc();
    const auto directory_name = "analysis-" + EvidenceTimestampUtc();
    analysis_evidence_future_ = std::async(
        std::launch::async,
        [this, memory, backend, fixture, ownership = *ownership,
         page_table = *page_table, kernel = *kernel,
         expected_canonical, root = *evidence_root,
         expected_driver_canonical, module_basename, expected_pdb_basename,
         captured_utc, directory_name, driver_abi_version]() mutable {
            AnalysisEvidenceOutcome outcome;
            const auto fail = [&](Error error) {
                outcome.error = std::move(error);
                outcome.message = outcome.error.message;
                return outcome;
            };
            const auto cancelled = [&]() {
                return analysis_evidence_cancel_.load(std::memory_order_relaxed);
            };
            const auto cancel_outcome = [&]() {
                outcome.cancelled = true;
                outcome.message = "Analysis evidence export cancelled";
                return outcome;
            };
            try {
                if (cancelled()) return cancel_outcome();
                const auto fixture_image_hash = Sha256File(expected_canonical);
                if (!fixture_image_hash) return fail(fixture_image_hash.GetError());
                const auto packaged_driver_hash = Sha256File(
                    expected_driver_canonical);
                if (!packaged_driver_hash) {
                    return fail(packaged_driver_hash.GetError());
                }
                if (packaged_driver_hash.Value() !=
                    kernel.symbol_proof.image_sha256) {
                    return fail(MakeError(
                        ErrorCode::VerificationMismatch,
                        "Loaded KDBG driver image hash does not match the packaged candidate",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                analysis_evidence_progress_.store(1, std::memory_order_relaxed);

                const auto identity_before = memory->ProcessIdentityToken();
                const auto context_before = backend->GetProcessContext(fixture.pid);
                if (!context_before) return fail(context_before.GetError());
                const auto walk_before = backend->TranslateVirtual(
                    context_before.Value().directory_table_base,
                    fixture.virtual_address);
                if (!walk_before) return fail(walk_before.GetError());
                if (identity_before != fixture.process_start_id ||
                    context_before.Value().directory_table_base !=
                        page_table.context.directory_table_base ||
                    !SameWalk(walk_before.Value(), page_table.walk)) {
                    return fail(MakeError(
                        ErrorCode::ConcurrentModification,
                        "Fixture identity or page walk changed before capture",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                analysis_evidence_progress_.store(2, std::memory_order_relaxed);
                if (cancelled()) return cancel_outcome();

                const auto process_page = memory->Read(
                    fixture.virtual_address, kPhysicalPageSize);
                if (!process_page) return fail(process_page.GetError());
                const auto physical_page = backend->ReadPhysical(
                    page_table.walk.physical_address, kPhysicalPageSize);
                if (!physical_page) return fail(physical_page.GetError());
                if (process_page.Value().size() != kPhysicalPageSize ||
                    physical_page.Value().size() != kPhysicalPageSize ||
                    process_page.Value() != physical_page.Value() ||
                    PageCrc32(process_page.Value()) != fixture.current_crc32) {
                    return fail(MakeError(
                        ErrorCode::VerificationMismatch,
                        "Process and physical fixture pages did not match the INFO CRC",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                const auto process_hash = Sha256Bytes(process_page.Value());
                const auto physical_hash = Sha256Bytes(physical_page.Value());
                const auto fixture_info_hash = Sha256Bytes(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(fixture.raw_json.data()),
                        fixture.raw_json.size()));
                if (!process_hash || !physical_hash || !fixture_info_hash) {
                    return fail(!process_hash ? process_hash.GetError() :
                        (!physical_hash ? physical_hash.GetError() :
                         fixture_info_hash.GetError()));
                }
                analysis_evidence_progress_.store(4, std::memory_order_relaxed);
                if (cancelled()) return cancel_outcome();

                const auto live_header = backend->ReadKernelVirtual(
                    kernel.module.base, 4096U);
                if (!live_header || live_header.Value().size() != 4096U) {
                    return fail(live_header
                        ? MakeError(ErrorCode::ShortRead,
                            "Kernel live PE header was not exactly 4096 bytes",
                            "MainWindow::StartAnalysisEvidenceExport", 0, 4096,
                            live_header.Value().size())
                        : live_header.GetError());
                }
                const auto local_header = ReadFilePrefix(
                    kernel.symbol_proof.image_path, 4096U);
                if (!local_header) return fail(local_header.GetError());
                const auto live_header_span = PeHeaderSpanForEvidence(
                    live_header.Value());
                const auto local_header_span = PeHeaderSpanForEvidence(
                    local_header.Value());
                if (!live_header_span.has_value() ||
                    live_header_span != local_header_span) {
                    return fail(MakeError(
                        ErrorCode::VerificationMismatch,
                        "Live and local PE SizeOfHeaders did not match",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                auto live_header_bytes = live_header.Value();
                auto local_header_bytes = local_header.Value();
                live_header_bytes.resize(*live_header_span);
                local_header_bytes.resize(*local_header_span);
                const auto header_comparison =
                    CompareLoadedPeHeadersForEvidence(
                        live_header_bytes,
                        local_header_bytes,
                        kernel.module.base);
                if (!header_comparison.has_value()) {
                    return fail(MakeError(
                        ErrorCode::VerificationMismatch,
                        "Live/local PE headers differ beyond the loader-applied ImageBase or the live ImageBase does not match the selected module",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                const auto live_pe = ParsePe64ImageMetadata(live_header_bytes);
                const auto local_pe = ParsePe64ImageMetadata(local_header_bytes);
                if (!live_pe || !local_pe ||
                    live_pe.Value().machine != local_pe.Value().machine ||
                    live_pe.Value().timestamp != kernel.module.timestamp ||
                    live_pe.Value().image_size != kernel.module.image_size) {
                    return fail(MakeError(
                        ErrorCode::VerificationMismatch,
                        "Kernel live/local PE metadata did not match the selected module",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                const auto live_header_hash = Sha256Bytes(live_header_bytes);
                const auto local_header_hash = Sha256Bytes(local_header_bytes);
                const auto kernel_read_hash = Sha256Bytes(kernel.read_bytes);
                const auto local_image_hash = Sha256File(
                    kernel.symbol_proof.image_path);
                const auto pdb_hash = Sha256File(
                    kernel.symbol_proof.loaded_pdb_path);
                if (!live_header_hash || !local_header_hash ||
                    !kernel_read_hash || !local_image_hash || !pdb_hash ||
                    local_image_hash.Value() != kernel.symbol_proof.image_sha256 ||
                    pdb_hash.Value() != kernel.symbol_proof.loaded_pdb_sha256) {
                    return fail(MakeError(
                        ErrorCode::VerificationMismatch,
                        "Kernel image or PDB hash proof changed during capture",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                analysis_evidence_progress_.store(6, std::memory_order_relaxed);
                if (cancelled()) return cancel_outcome();

                const auto context_after = backend->GetProcessContext(fixture.pid);
                if (!context_after) return fail(context_after.GetError());
                const auto walk_after = backend->TranslateVirtual(
                    context_after.Value().directory_table_base,
                    fixture.virtual_address);
                if (!walk_after) return fail(walk_after.GetError());
                const auto identity_after = memory->ProcessIdentityToken();
                if (identity_after != identity_before ||
                    context_after.Value().directory_table_base !=
                        context_before.Value().directory_table_base ||
                    !SameWalk(walk_before.Value(), walk_after.Value())) {
                    return fail(MakeError(
                        ErrorCode::ConcurrentModification,
                        "Fixture identity or full page walk changed after capture",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                analysis_evidence_progress_.store(7, std::memory_order_relaxed);
                if (cancelled()) return cancel_outcome();

                std::error_code io_error;
                std::filesystem::create_directories(root, io_error);
                if (io_error) return fail(MakeError(
                    ErrorCode::IoFailure, "Unable to create evidence root",
                    "MainWindow::StartAnalysisEvidenceExport", io_error.value()));
                const auto partial = root / (".partial-" + directory_name);
                const auto final = root / directory_name;
                std::filesystem::create_directory(partial, io_error);
                if (io_error) return fail(MakeError(
                    ErrorCode::IoFailure, "Unable to create partial analysis directory",
                    "MainWindow::StartAnalysisEvidenceExport", io_error.value()));
                const auto cleanup = [&]() {
                    std::error_code ignored;
                    std::filesystem::remove_all(partial, ignored);
                };
                const auto fixture_bytes = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(fixture.raw_json.data()),
                    fixture.raw_json.size());
                const auto pdb_name = expected_pdb_basename;
                if (pdb_name.empty() ||
                    std::filesystem::path(pdb_name).filename().string() != pdb_name ||
                    !WriteBytes(partial / "fixture-info.json", fixture_bytes) ||
                    !WriteBytes(partial / "process-read.bin", process_page.Value()) ||
                    !WriteBytes(partial / "physical-read.bin", physical_page.Value()) ||
                    !WriteBytes(partial / "module-live-header.bin", live_header_bytes) ||
                    !WriteBytes(partial / "module-local-header.bin", local_header_bytes) ||
                    !WriteBytes(partial / "kernel-read.bin", kernel.read_bytes)) {
                    cleanup();
                    return fail(MakeError(
                        ErrorCode::IoFailure, "Unable to write analysis evidence artifacts",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                std::filesystem::copy_file(
                    kernel.symbol_proof.loaded_pdb_path, partial / pdb_name,
                    std::filesystem::copy_options::none, io_error);
                if (io_error) {
                    cleanup();
                    return fail(MakeError(
                        ErrorCode::IoFailure, "Unable to copy exact loaded PDB",
                        "MainWindow::StartAnalysisEvidenceExport", io_error.value()));
                }

                auto guid_hex = [](std::string value) {
                    value.erase(std::remove(value.begin(), value.end(), '-'), value.end());
                    return value;
                };
                const auto& map = ownership.mapping;
                const auto& walk = walk_after.Value();
                const auto& leaf = walk.steps.back();
                const bool effective_writable = std::all_of(
                    walk.steps.begin(), walk.steps.end(),
                    [](const TranslationStep& step) { return step.flags.writable; });
                const bool effective_user = std::all_of(
                    walk.steps.begin(), walk.steps.end(),
                    [](const TranslationStep& step) { return step.flags.user; });
                const bool effective_nx = std::any_of(
                    walk.steps.begin(), walk.steps.end(),
                    [](const TranslationStep& step) { return step.flags.no_execute; });
                std::ostringstream json;
                json << "{\n"
                     << "  \"schema\": \"kdbg-analysis-live-evidence-v1\",\n"
                     << "  \"captured_utc\": \"" << captured_utc << "\",\n"
                     << "  \"driver_abi_version\": "
                     << driver_abi_version << ",\n"
                     << "  \"process\": {\"pid\": " << fixture.pid
                     << ", \"process_start_id\": " << fixture.process_start_id
                     << ", \"image_basename\": \"" << JsonEscape(fixture.image_basename)
                     << "\", \"image_sha256\": \"" << fixture_image_hash.Value()
                     << "\", \"protocol_version\": 1, \"fixture_nonce\": \""
                     << fixture.nonce << "\", \"virtual_address\": "
                     << fixture.virtual_address << ", \"byte_count\": 4096"
                     << ", \"virtual_locked\": true, \"generation\": "
                     << fixture.generation << ", \"baseline_crc32\": \""
                     << std::hex << std::setw(8) << std::setfill('0')
                     << fixture.baseline_crc32 << "\", \"current_crc32\": \""
                     << std::setw(8) << fixture.current_crc32 << std::dec
                     << "\", \"fixture_info_file\": \"fixture-info.json\""
                     << ", \"fixture_info_sha256\": \"" << fixture_info_hash.Value()
                     << "\"},\n"
                     << "  \"ownership\": {\"pid\": " << map.pid
                     << ", \"virtual_address\": " << map.virtual_address
                     << ", \"physical_address\": " << (ownership.pfn << 12U)
                     << ", \"pfn\": " << ownership.pfn
                     << ", \"pte_address\": " << map.pte_address
                     << ", \"pte_value\": " << leaf.entry_value
                     << ", \"page_size\": 4096, \"mapping_type\": \""
                     << JsonEscape(map.mapping_type) << "\", \"shared\": false"
                     << ", \"writable\": true, \"user_accessible\": true"
                     << ", \"no_execute\": " << (map.no_execute ? "true" : "false")
                     << ", \"provider\": \"" << JsonEscape(ownership.provider)
                     << "\", \"source\": \"" << JsonEscape(map.source)
                     << "\", \"confidence\": \"" << ConfidenceText(map.confidence)
                     << "\", \"query_generation\": " << ownership.query_generation << "},\n"
                     << "  \"page_table\": {\"pid\": " << fixture.pid
                     << ", \"directory_table_base\": " << walk.directory_table_base
                     << ", \"virtual_address\": " << walk.virtual_address
                     << ", \"physical_address\": " << walk.physical_address
                     << ", \"pfn\": " << (walk.physical_address >> 12U)
                     << ", \"translated\": true, \"page_size\": 4096"
                     << ", \"page_offset\": 0, \"la57\": "
                     << (walk.la57 ? "true" : "false")
                     << ", \"effective_writable\": " << (effective_writable ? "true" : "false")
                     << ", \"effective_user\": " << (effective_user ? "true" : "false")
                     << ", \"effective_nx\": " << (effective_nx ? "true" : "false")
                     << ", \"steps\": [";
                for (std::size_t index = 0; index < walk.steps.size(); ++index) {
                    const auto& step = walk.steps[index];
                    if (index != 0) json << ',';
                    json << "{\"level\":\"" << PagingLevelName(step.level)
                         << "\",\"index\":" << step.index
                         << ",\"entry_physical_address\":" << step.entry_physical_address
                         << ",\"entry_value\":" << step.entry_value
                         << ",\"next_pfn\":" << step.next_pfn
                         << ",\"present\":" << (step.flags.present ? "true" : "false")
                         << ",\"writable\":" << (step.flags.writable ? "true" : "false")
                         << ",\"user\":" << (step.flags.user ? "true" : "false")
                         << ",\"page_size\":" << (step.flags.page_size ? "true" : "false")
                         << ",\"no_execute\":" << (step.flags.no_execute ? "true" : "false")
                         << '}';
                }
                json << "]},\n"
                     << "  \"revalidation\": {\"process_identity_unchanged\": true"
                     << ", \"dtb_unchanged\": true, \"walk_unchanged\": true"
                     << ", \"process_start_id_before\": " << identity_before
                     << ", \"process_start_id_after\": " << identity_after
                     << ", \"dtb_before\": " << context_before.Value().directory_table_base
                     << ", \"dtb_after\": " << context_after.Value().directory_table_base
                     << ", \"translated_before_pa\": " << walk_before.Value().physical_address
                     << ", \"translated_after_pa\": " << walk_after.Value().physical_address
                     << "},\n"
                     << "  \"page_files\": {\"process_read\": \"process-read.bin\", \"physical_read\": \"physical-read.bin\"},\n"
                     << "  \"page_sha256\": {\"process_read\": \"" << process_hash.Value()
                     << "\", \"physical_read\": \"" << physical_hash.Value() << "\"},\n"
                     << "  \"page_bytes\": 4096, \"page_match\": true,\n"
                     << "  \"kernel_explorer\": {\n"
                     << "    \"module\": {\"name\": \""
                     << JsonEscape(module_basename)
                     << "\", \"package_relative_path\": \"drivers/"
                     << JsonEscape(module_basename)
                     << "\", \"base\": " << kernel.module.base
                     << ", \"size\": " << kernel.module.image_size
                     << ", \"machine\": " << live_pe.Value().machine
                     << ", \"pe_timestamp\": " << live_pe.Value().timestamp
                     << ", \"image_size\": " << live_pe.Value().image_size
                     << ", \"image_sha256\": \"" << local_image_hash.Value()
                     << "\", \"local_image_sha256\": \""
                     << packaged_driver_hash.Value()
                     << "\", \"header_bytes\": " << live_header_bytes.size()
                     << ", \"live_header_file\": \"module-live-header.bin\""
                     << ", \"live_header_sha256\": \"" << live_header_hash.Value()
                     << "\", \"local_header_file\": \"module-local-header.bin\""
                     << ", \"local_header_sha256\": \"" << local_header_hash.Value()
                     << "\", \"headers_match\": true"
                     << ", \"header_match_mode\": \"exact-except-loader-image-base\""
                     << ", \"image_base_offset\": "
                     << header_comparison->image_base_offset
                     << ", \"live_image_base\": "
                     << header_comparison->live_image_base
                     << ", \"local_preferred_image_base\": "
                     << header_comparison->local_preferred_image_base << "},\n"
                     << "    \"symbol\": {\"pdb_name\": \"" << JsonEscape(pdb_name)
                     << "\", \"pdb_file\": \"" << JsonEscape(pdb_name)
                     << "\", \"package_relative_path\": \"drivers/"
                     << JsonEscape(expected_pdb_basename)
                     << "\", \"pdb_sha256\": \"" << pdb_hash.Value()
                     << "\", \"pe_guid\": \"" << guid_hex(kernel.symbol_proof.image_codeview_guid)
                     << "\", \"pdb_guid\": \"" << guid_hex(kernel.symbol_proof.loaded_pdb_guid)
                     << "\", \"pe_age\": " << kernel.symbol_proof.image_codeview_age
                     << ", \"pdb_age\": " << kernel.symbol_proof.loaded_pdb_age
                     << ", \"exact_match\": true, \"symbol_name\": \""
                     << JsonEscape(kernel.symbol.name) << "\", \"symbol_address\": "
                     << kernel.symbol.address << ", \"displacement\": "
                     << kernel.symbol.displacement << "},\n"
                     << "    \"read\": {\"address\": " << kernel.read_address
                     << ", \"module_offset\": " << (kernel.read_address - kernel.module.base)
                     << ", \"requested_bytes\": " << kernel.requested_bytes
                     << ", \"completed_bytes\": " << kernel.read_bytes.size()
                     << ", \"file\": \"kernel-read.bin\", \"sha256\": \""
                     << kernel_read_hash.Value() << "\"},\n"
                     << "    \"disassembly\": {\"architecture\": \"x64\", \"formatter\": \"intel\""
                     << ", \"start_address\": " << kernel.read_address
                     << ", \"consumed_bytes\": " << kernel.disassembly.consumed_bytes
                     << ", \"instruction_count\": " << kernel.disassembly.instructions.size()
                     << ", \"truncated\": " << (kernel.disassembly.truncated ? "true" : "false")
                     << "}\n  }\n}\n";
                const auto metadata_text = json.str();
                if (!WriteBytes(
                        partial / "analysis_metadata.json",
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(metadata_text.data()),
                            metadata_text.size()))) {
                    cleanup();
                    return fail(MakeError(
                        ErrorCode::IoFailure, "Unable to write analysis metadata JSON",
                        "MainWindow::StartAnalysisEvidenceExport"));
                }
                analysis_evidence_progress_.store(9, std::memory_order_relaxed);
                if (cancelled()) {
                    cleanup();
                    return cancel_outcome();
                }
                std::filesystem::rename(partial, final, io_error);
                if (io_error) {
                    cleanup();
                    return fail(MakeError(
                        ErrorCode::IoFailure, "Unable to publish analysis evidence atomically",
                        "MainWindow::StartAnalysisEvidenceExport", io_error.value()));
                }
                analysis_evidence_progress_.store(10, std::memory_order_relaxed);
                outcome.succeeded = true;
                outcome.path = PathToUtf8(final);
                outcome.message = "Analysis evidence exported with exact page, walk, image, and PDB hashes.";
                return outcome;
            } catch (const std::exception& exception) {
                return fail(MakeError(
                    ErrorCode::InternalInvariant,
                    "Analysis export worker failed: " + std::string(exception.what()),
                    "MainWindow::StartAnalysisEvidenceExport"));
            } catch (...) {
                return fail(MakeError(
                    ErrorCode::InternalInvariant,
                    "Analysis export worker failed with an unknown exception",
                    "MainWindow::StartAnalysisEvidenceExport"));
            }
        });
}

void MainWindow::PollAnalysisEvidenceExport() {
    using namespace std::chrono_literals;
    if (!analysis_evidence_future_.valid() ||
        analysis_evidence_future_.wait_for(0ms) != std::future_status::ready) {
        return;
    }
    const auto outcome = analysis_evidence_future_.get();
    if (outcome.succeeded) {
        last_analysis_evidence_path_ = outcome.path;
        analysis_evidence_status_ = outcome.message;
    } else if (outcome.cancelled) {
        analysis_evidence_status_ = outcome.message;
    } else {
        analysis_evidence_status_ = FormatError(outcome.error);
    }
}

void MainWindow::CancelAnalysisEvidenceExport() noexcept {
    analysis_evidence_cancel_.store(true, std::memory_order_relaxed);
}

void MainWindow::StartLifecycleAction(LifecycleAction action) {
    if (action == LifecycleAction::None || LifecycleBusy()) return;
    if (physical_session_.RecoveryObservationRequired()) {
        operation_status_ =
            "Driver/probe lifecycle changes are blocked until the uncertain physical transaction is observed.";
        return;
    }
    const bool changes_kdbg_service =
        action == LifecycleAction::BringLabOnline ||
        action == LifecycleAction::InstallDriver ||
        action == LifecycleAction::StartDriver ||
        action == LifecycleAction::StopDriver ||
        action == LifecycleAction::RemoveDriver;
    if (changes_kdbg_service) {
        QueueDeferredAction(DeferredAction::StartLifecycle, action);
        return;
    }
    LaunchLifecycleAction(action);
}

void MainWindow::QueueDeferredAction(
    DeferredAction action,
    LifecycleAction lifecycle,
    std::optional<ProcessInfo> process) {
    if (action == DeferredAction::None) return;
    if (action == DeferredAction::LockAllWrites) {
        RequestBackendIoCancellation();
        deferred_lock_requested_ = true;
        operation_status_ =
            "Write-lock requested; active I/O was asked to cancel and the "
            "gates will close from a later UI poll without joining workers.";
        if (process_scanner_.Busy()) {
            operation_status_ +=
                " Use the Process Scanner cancel control to stop its active scan/freeze pass.";
        }
        return;
    }
    if (deferred_action_ != DeferredAction::None) {
        operation_status_ =
            "A deferred safety/lifecycle transition is already pending.";
        return;
    }
    deferred_action_ = action;
    deferred_lifecycle_ = lifecycle;
    deferred_process_ = std::move(process);
    if (action == DeferredAction::LockAllWrites ||
        action == DeferredAction::DisconnectProcess ||
        action == DeferredAction::AttachProcess) {
        RequestProcessIoCancellation();
    } else {
        RequestBackendIoCancellation();
    }
    operation_status_ =
        "Cancellation requested; the transition will complete after active "
        "workers publish or discard their final result.";
    if (process_scanner_.Busy()) {
        operation_status_ +=
            " Use the Process Scanner cancel control to stop its active scan/freeze pass.";
    }
}

void MainWindow::RequestProcessIoCancellation() noexcept {
    CancelAnalysisEvidenceExport();
    process_memory_browser_.RequestCancel();
    disassembly_.RequestCancel();
    pointer_scanner_.RequestCancel();
    snapshots_.RequestCancel();
}

void MainWindow::RequestBackendIoCancellation() noexcept {
    RequestProcessIoCancellation();
    process_usage_.RequestCancel();
    kernel_explorer_.RequestReadCancel();
}

void MainWindow::PollDeferredAction() {
    if (deferred_lock_requested_ && !BackendIoBusy()) {
        deferred_lock_requested_ = false;
        static_cast<void>(FinishLockAllWrites());
    }
    const auto action = deferred_action_;
    if (action == DeferredAction::None) return;
    const bool waits_for_backend =
        action == DeferredAction::ConnectBackend ||
        action == DeferredAction::StartLifecycle;
    if ((waits_for_backend && BackendIoBusy()) ||
        (!waits_for_backend && ProcessIoBusy())) {
        return;
    }

    if (action == DeferredAction::DisconnectProcess ||
        action == DeferredAction::AttachProcess) {
        const auto process = deferred_process_;
        deferred_action_ = DeferredAction::None;
        deferred_process_.reset();
        if (!FinishDisconnectProcess() ||
            action == DeferredAction::DisconnectProcess ||
            !process.has_value()) {
            return;
        }
        auto attached = Win32ProcessMemory::Attach(process->pid, &backend_);
        if (!attached) {
            operation_status_ = FormatError(attached.GetError());
            return;
        }
        process_memory_ = attached.TakeValue();
        memory_map_.Attach(process_memory_.get());
        process_memory_browser_.Attach(process_memory_.get());
        process_scanner_.Attach(process_memory_.get());
        pointer_scanner_.Attach(process_memory_.get());
        disassembly_.Attach(process_memory_.get());
        snapshots_.Attach(process_memory_.get());
        page_table_.SetPid(process->pid);
        operation_status_ = "Attached to " + process->name + " (PID " +
            std::to_string(process->pid) + ").";
        return;
    }

    if (action == DeferredAction::ConnectBackend) {
        deferred_action_ = DeferredAction::None;
        if (!FinishLockAllWrites()) return;
        FinishConnectBackend();
        return;
    }

    const auto lifecycle = deferred_lifecycle_;
    deferred_action_ = DeferredAction::None;
    deferred_lifecycle_ = LifecycleAction::None;
    if (!FinishLockAllWrites()) {
        operation_status_ += " | Driver lifecycle transition was blocked.";
        return;
    }
    process_usage_.CancelAndWait();
    const bool closes_backend =
        lifecycle == LifecycleAction::BringLabOnline ||
        lifecycle == LifecycleAction::InstallDriver ||
        lifecycle == LifecycleAction::StopDriver ||
        lifecycle == LifecycleAction::RemoveDriver;
    if (closes_backend) {
        probe_.Close();
        backend_.Close();
        probe_fixture_loaded_ = false;
        ClearProbeEvidence();
    }
    LaunchLifecycleAction(lifecycle);
}

void MainWindow::LaunchLifecycleAction(LifecycleAction action) {
    if (lifecycle_future_.valid() || action == LifecycleAction::None) return;

    lifecycle_cancel_requested_.store(false, std::memory_order_relaxed);
    lifecycle_step_.store(0, std::memory_order_relaxed);
    lifecycle_action_ = action;
    const auto driver_path = Utf8Path(driver_path_.data());
    const auto probe_path = Utf8Path(probe_driver_path_.data());
    const bool driver_running = driver_service_running_.value_or(false);
    const bool probe_running = probe_service_running_.value_or(false);
    operation_status_ =
        "Driver lifecycle operation started; the GUI remains responsive.";

    lifecycle_future_ = std::async(
        std::launch::async,
        [this, action, driver_path, probe_path, driver_running, probe_running]() {
            const auto cancelled = [action]() {
                LifecycleOutcome outcome{};
                outcome.action = action;
                outcome.cancelled = true;
                outcome.error = MakeError(
                    ErrorCode::Cancelled,
                    "Driver lifecycle operation cancelled before the next stage; "
                    "service state was refreshed",
                    "MainWindow::StartLifecycleAction");
                return outcome;
            };
            const auto finish = [action](
                const Result<void>& result,
                std::string success) {
                LifecycleOutcome outcome{};
                outcome.action = action;
                outcome.succeeded = result.Ok();
                if (result) {
                    outcome.message = std::move(success);
                } else {
                    outcome.error = result.GetError();
                }
                return outcome;
            };
            const auto is_cancelled = [this]() {
                return lifecycle_cancel_requested_.load(
                    std::memory_order_relaxed);
            };

            if (is_cancelled()) return cancelled();
            switch (action) {
            case LifecycleAction::BringLabOnline: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto driver_before =
                    DriverService::QueryConfiguration(L"KDBG");
                if (!driver_before) {
                    return finish(
                        Result<void>::Failure(driver_before.GetError()), {});
                }
                const auto probe_before =
                    DriverService::QueryConfiguration(L"KDBGProbe");
                if (!probe_before) {
                    return finish(
                        Result<void>::Failure(probe_before.GetError()), {});
                }
                if ((driver_before.Value().exists &&
                     driver_before.Value().service_type != SERVICE_KERNEL_DRIVER) ||
                    (probe_before.Value().exists &&
                     probe_before.Value().service_type != SERVICE_KERNEL_DRIVER)) {
                    return finish(
                        Result<void>::Failure(MakeError(
                            ErrorCode::AccessDenied,
                            "A KDBG service name belongs to a non-kernel service; no configuration was changed",
                            "MainWindow::StartLifecycleAction/BringLabOnline")),
                        {});
                }

                const auto rollback = [action, &driver_before, &probe_before](
                    Error failure,
                    bool cancellation) {
                    std::vector<std::string> rollback_errors;
                    const auto restore_probe =
                        DriverService::RestoreConfiguration(
                            L"KDBGProbe", probe_before.Value());
                    if (!restore_probe) {
                        rollback_errors.push_back(
                            "KDBGProbe: " + restore_probe.GetError().message);
                    }
                    const auto restore_driver =
                        DriverService::RestoreConfiguration(
                            L"KDBG", driver_before.Value());
                    if (!restore_driver) {
                        rollback_errors.push_back(
                            "KDBG: " + restore_driver.GetError().message);
                    }
                    LifecycleOutcome outcome{};
                    outcome.action = action;
                    outcome.cancelled = cancellation;
                    outcome.error = std::move(failure);
                    if (rollback_errors.empty()) {
                        outcome.error.message +=
                            "; prior KDBG service configuration and running state were restored";
                    } else {
                        outcome.error.message += "; rollback errors: ";
                        for (std::size_t index = 0;
                             index < rollback_errors.size(); ++index) {
                            if (index != 0) outcome.error.message += " | ";
                            outcome.error.message += rollback_errors[index];
                        }
                    }
                    return outcome;
                };
                const auto cancel_with_rollback = [&]() {
                    return rollback(
                        MakeError(
                            ErrorCode::Cancelled,
                            "Bring Online was cancelled between transactional stages",
                            "MainWindow::StartLifecycleAction/BringLabOnline"),
                        true);
                };
                const auto fail_with_rollback = [&](const Error& error) {
                    return rollback(error, false);
                };

                if (is_cancelled()) return cancel_with_rollback();
                lifecycle_step_.store(2, std::memory_order_relaxed);
                if (probe_before.Value().running) {
                    const auto stopped = DriverService::Stop(L"KDBGProbe");
                    if (!stopped) {
                        return fail_with_rollback(stopped.GetError());
                    }
                }
                if (driver_before.Value().running) {
                    const auto stopped = DriverService::Stop(L"KDBG");
                    if (!stopped) {
                        return fail_with_rollback(stopped.GetError());
                    }
                }
                if (is_cancelled()) return cancel_with_rollback();

                lifecycle_step_.store(3, std::memory_order_relaxed);
                const auto installed_driver = DriverService::InstallOrUpdate(
                    L"KDBG", L"KDBG Physical Memory Driver", driver_path);
                LogResultDiagnostic(
                    installed_driver,
                    DiagnosticEvent::DriverServiceInstallSucceeded,
                    DiagnosticEvent::DriverServiceInstallFailed);
                if (!installed_driver) {
                    return fail_with_rollback(installed_driver.GetError());
                }
                const auto installed_probe = DriverService::InstallOrUpdate(
                    L"KDBGProbe", L"KDBG Probe Fixture Driver", probe_path);
                LogResultDiagnostic(
                    installed_probe,
                    DiagnosticEvent::ProbeServiceInstallSucceeded,
                    DiagnosticEvent::ProbeServiceInstallFailed);
                if (!installed_probe) {
                    return fail_with_rollback(installed_probe.GetError());
                }
                if (is_cancelled()) return cancel_with_rollback();

                lifecycle_step_.store(4, std::memory_order_relaxed);
                const auto started_driver = DriverService::Start(L"KDBG");
                LogResultDiagnostic(
                    started_driver,
                    DiagnosticEvent::DriverServiceStartSucceeded,
                    DiagnosticEvent::DriverServiceStartFailed);
                if (!started_driver) {
                    return fail_with_rollback(started_driver.GetError());
                }
                const auto started_probe = DriverService::Start(L"KDBGProbe");
                LogResultDiagnostic(
                    started_probe,
                    DiagnosticEvent::ProbeServiceStartSucceeded,
                    DiagnosticEvent::ProbeServiceStartFailed);
                if (!started_probe) {
                    return fail_with_rollback(started_probe.GetError());
                }
                if (is_cancelled()) return cancel_with_rollback();

                lifecycle_step_.store(5, std::memory_order_relaxed);
                KDbgBackend verification_backend;
                const auto backend_opened = verification_backend.Open();
                if (!backend_opened) {
                    return fail_with_rollback(backend_opened.GetError());
                }
                ProbeClient verification_probe;
                const auto probe_opened = verification_probe.Open();
                if (!probe_opened) {
                    return fail_with_rollback(probe_opened.GetError());
                }
                const auto probe_info = verification_probe.Query();
                if (!probe_info) {
                    return fail_with_rollback(probe_info.GetError());
                }
                const auto probe_address =
                    PfnAddress::FromPfn(probe_info.Value().pfn);
                if (!probe_address ||
                    probe_address.Value().physical_address !=
                        probe_info.Value().physical_address) {
                    return fail_with_rollback(
                        probe_address
                            ? MakeError(
                                ErrorCode::VerificationMismatch,
                                "Probe PFN and physical address disagree",
                                "MainWindow::StartLifecycleAction/BringLabOnline")
                            : probe_address.GetError());
                }
                auto verification_session =
                    std::make_unique<PhysicalPageSession>();
                const auto loaded = verification_session->Load(
                    verification_backend, probe_address.Value());
                if (!loaded) {
                    return fail_with_rollback(loaded.GetError());
                }
                const auto session_status =
                    verification_backend.QuerySessionStatus();
                if (!session_status || session_status.Value().write_enabled) {
                    return fail_with_rollback(
                        session_status
                            ? MakeError(
                                ErrorCode::WriteLocked,
                                "Verification backend did not report the default-locked write gate",
                                "MainWindow::StartLifecycleAction/BringLabOnline")
                            : session_status.GetError());
                }
                if (is_cancelled()) return cancel_with_rollback();

                lifecycle_step_.store(6, std::memory_order_relaxed);
                return finish(
                    Result<void>::Success(),
                    "KDBG services were transactionally repaired, started, and verified against the Probe 4 KiB page.");
            }
            case LifecycleAction::InstallDriver: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto result = DriverService::InstallOrUpdate(
                    L"KDBG", L"KDBG Physical Memory Driver", driver_path);
                LogResultDiagnostic(
                    result,
                    DiagnosticEvent::DriverServiceInstallSucceeded,
                    DiagnosticEvent::DriverServiceInstallFailed);
                return finish(result, "KDBG driver service installed/updated.");
            }
            case LifecycleAction::StartDriver: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto result = DriverService::Start(L"KDBG");
                LogResultDiagnostic(
                    result,
                    DiagnosticEvent::DriverServiceStartSucceeded,
                    DiagnosticEvent::DriverServiceStartFailed);
                return finish(result, "KDBG driver started.");
            }
            case LifecycleAction::StopDriver: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto result = DriverService::Stop(L"KDBG");
                LogResultDiagnostic(
                    result,
                    DiagnosticEvent::DriverServiceStopSucceeded,
                    DiagnosticEvent::DriverServiceStopFailed);
                return finish(result, "KDBG driver stopped.");
            }
            case LifecycleAction::RemoveDriver: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto result = DriverService::Remove(L"KDBG");
                LogResultDiagnostic(
                    result,
                    DiagnosticEvent::DriverServiceRemoveSucceeded,
                    DiagnosticEvent::DriverServiceRemoveFailed);
                return finish(result, "KDBG driver service removed.");
            }
            case LifecycleAction::InstallProbe: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto result = DriverService::InstallOrUpdate(
                    L"KDBGProbe", L"KDBG Probe Fixture Driver", probe_path);
                LogResultDiagnostic(
                    result,
                    DiagnosticEvent::ProbeServiceInstallSucceeded,
                    DiagnosticEvent::ProbeServiceInstallFailed);
                return finish(result, "KDBGProbe service installed/updated.");
            }
            case LifecycleAction::StartProbe: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto result = DriverService::Start(L"KDBGProbe");
                LogResultDiagnostic(
                    result,
                    DiagnosticEvent::ProbeServiceStartSucceeded,
                    DiagnosticEvent::ProbeServiceStartFailed);
                return finish(result, "KDBGProbe started.");
            }
            case LifecycleAction::StopProbe: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto result = DriverService::Stop(L"KDBGProbe");
                LogResultDiagnostic(
                    result,
                    DiagnosticEvent::ProbeServiceStopSucceeded,
                    DiagnosticEvent::ProbeServiceStopFailed);
                return finish(result, "KDBGProbe stopped.");
            }
            case LifecycleAction::RemoveProbe: {
                lifecycle_step_.store(1, std::memory_order_relaxed);
                const auto result = DriverService::Remove(L"KDBGProbe");
                LogResultDiagnostic(
                    result,
                    DiagnosticEvent::ProbeServiceRemoveSucceeded,
                    DiagnosticEvent::ProbeServiceRemoveFailed);
                return finish(result, "KDBGProbe service removed.");
            }
            case LifecycleAction::None:
                break;
            }
            LifecycleOutcome outcome{};
            outcome.action = action;
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Unknown driver lifecycle action",
                "MainWindow::StartLifecycleAction");
            return outcome;
        });
}

void MainWindow::PollLifecycleAction() {
    if (!lifecycle_future_.valid() ||
        lifecycle_future_.wait_for(std::chrono::seconds(0)) !=
            std::future_status::ready) {
        return;
    }

    LifecycleOutcome outcome{};
    try {
        outcome = lifecycle_future_.get();
    } catch (const std::exception& exception) {
        operation_status_ =
            "Driver lifecycle task failed unexpectedly: " +
            std::string(exception.what());
        lifecycle_action_ = LifecycleAction::None;
        lifecycle_step_.store(0, std::memory_order_relaxed);
        lifecycle_cancel_requested_.store(false, std::memory_order_relaxed);
        return;
    } catch (...) {
        operation_status_ =
            "Driver lifecycle task failed with an unknown exception.";
        lifecycle_action_ = LifecycleAction::None;
        lifecycle_step_.store(0, std::memory_order_relaxed);
        lifecycle_cancel_requested_.store(false, std::memory_order_relaxed);
        return;
    }

    lifecycle_action_ = LifecycleAction::None;
    lifecycle_step_.store(0, std::memory_order_relaxed);
    lifecycle_cancel_requested_.store(false, std::memory_order_relaxed);
    RefreshServiceStates();

    if (outcome.cancelled) {
        operation_status_ = FormatError(outcome.error);
        return;
    }
    if (!outcome.succeeded) {
        operation_status_ = "Driver lifecycle failed: " +
            FormatError(outcome.error);
        return;
    }

    operation_status_ = std::move(outcome.message);
    if (outcome.action == LifecycleAction::StartDriver ||
        outcome.action == LifecycleAction::BringLabOnline) {
        FinishConnectBackend();
        if (!backend_.Info().connected) return;
    }
    if (outcome.action == LifecycleAction::StartProbe) {
        probe_.Close();
        const auto opened = probe_.Open();
        LogResultDiagnostic(
            opened,
            DiagnosticEvent::ProbeDeviceOpenSucceeded,
            DiagnosticEvent::ProbeDeviceOpenFailed);
        SetOperationResult(
            opened,
            "KDBGProbe started and its device was opened. Load the probe fixture to verify the target.");
        return;
    }
    if (outcome.action == LifecycleAction::BringLabOnline) {
        QueryAndLoadProbeFixture();
    }
}

void MainWindow::RefreshProcesses() {
    const auto result = ProcessCatalog::Enumerate();
    if (!result) {
        operation_status_ = result.GetError().message;
        return;
    }
    processes_ = result.Value();
    selected_process_index_ = processes_.empty() ? -1 : 0;
    operation_status_ = "Process list refreshed: " + std::to_string(processes_.size()) + " entries.";
}

void MainWindow::RefreshServiceStates() {
    const auto driver = DriverService::IsRunning(L"KDBG");
    const auto probe = DriverService::IsRunning(L"KDBGProbe");
    driver_service_running_ = driver
        ? std::optional<bool>(driver.Value()) : std::nullopt;
    probe_service_running_ = probe
        ? std::optional<bool>(probe.Value()) : std::nullopt;
    if (!driver) {
        service_status_ = "KDBG service status failed: " +
            FormatError(driver.GetError());
    } else if (!probe) {
        service_status_ = "Probe service status failed: " +
            FormatError(probe.GetError());
    } else {
        service_status_ = "Service state refreshed.";
    }
}

void MainWindow::AttachSelectedProcess() {
    if (selected_process_index_ < 0 ||
        selected_process_index_ >= static_cast<int>(processes_.size())) return;
    if (physical_session_.CanRollback() ||
        physical_session_.RecoveryObservationRequired()) {
        operation_status_ =
            "Process switch blocked until physical recovery observation and any pending rollback are complete.";
        return;
    }
    QueueDeferredAction(
        DeferredAction::AttachProcess,
        LifecycleAction::None,
        processes_[static_cast<std::size_t>(selected_process_index_)]);
}

void MainWindow::DisconnectProcess() {
    if (process_memory_ == nullptr) return;
    if (physical_session_.CanRollback() ||
        physical_session_.RecoveryObservationRequired()) {
        operation_status_ =
            "Process detach blocked until physical recovery observation and any pending rollback are complete.";
        return;
    }
    QueueDeferredAction(DeferredAction::DisconnectProcess);
}

bool MainWindow::FinishDisconnectProcess() {
    if (ProcessIoBusy()) return false;
    if (process_memory_ != nullptr && process_memory_->WritesArmed()) {
        const auto locked = process_memory_->SetWritesArmed(false);
        if (!locked || process_memory_->WritesArmed()) {
            operation_status_ = locked
                ? "Process detach blocked because the process write gate still reports ARMED."
                : "Process detach blocked because the write gate could not be locked: " +
                    FormatError(locked.GetError());
            return false;
        }
    }
    process_memory_browser_.CancelAndWait();
    disassembly_.CancelAndWait();
    memory_map_.Reset();
    process_memory_browser_.Reset();
    process_scanner_.Reset();
    pointer_scanner_.Reset();
    disassembly_.Attach(nullptr);
    snapshots_.Reset();
    process_memory_.reset();
    operation_status_ = "Process detached; all process workers are idle and the write gate is locked.";
    return true;
}

void MainWindow::ConnectBackend() {
    if (physical_session_.CanRollback() ||
        physical_session_.RecoveryObservationRequired()) {
        operation_status_ =
            "Reconnect blocked until physical recovery observation and any pending rollback are completed.";
        return;
    }
    QueueDeferredAction(DeferredAction::ConnectBackend);
}

void MainWindow::FinishConnectBackend() {
    if (BackendIoBusy()) return;
    if (backend_.Info().connected && backend_.Info().write_enabled) {
        const auto locked = backend_.SetWriteEnabled(false);
        if (!locked) {
            operation_status_ =
                "Reconnect blocked because the current driver write gate could not be locked: " +
                locked.GetError().message;
            return;
        }
    }
    backend_.Close();
    probe_fixture_loaded_ = false;
    ClearProbeEvidence();
    const auto result = backend_.Open();
    if (result) {
        ++runtime_backend_session_generation_;
    }
    LogResultDiagnostic(
        result,
        DiagnosticEvent::DriverConnectSucceeded,
        DiagnosticEvent::DriverConnectFailed);
    SetOperationResult(result, "KDBG device connected and ABI validated.");
}

void MainWindow::QueryAndLoadProbeFixture() {
    if (physical_session_.RecoveryObservationRequired()) {
        operation_status_ =
            "Observe the uncertain physical transaction before loading another fixture.";
        return;
    }
    if (physical_session_.IsDirty()) {
        operation_status_ =
            "Revert or apply staged physical edits before loading the probe fixture.";
        return;
    }
    if (physical_session_.CanRollback()) {
        operation_status_ =
            "A verified rollback is pending. Use Independent Reload (keep rollback), then complete rollback before loading a new baseline.";
        return;
    }
    if (!backend_.Info().connected) {
        operation_status_ =
            "Connect the KDBG driver before querying and loading the probe fixture.";
        return;
    }
    if (!probe_.IsOpen()) {
        const auto opened = probe_.Open();
        LogResultDiagnostic(
            opened,
            DiagnosticEvent::ProbeDeviceOpenSucceeded,
            DiagnosticEvent::ProbeDeviceOpenFailed);
        if (!opened) {
            probe_fixture_loaded_ = false;
            probe_info_.reset();
            probe_status_ = opened.GetError().message;
            operation_status_ = probe_status_;
            return;
        }
    }
    const auto queried = probe_.Query();
    if (!queried) {
        LogDiagnostic(
            DiagnosticEvent::ProbeQueryFailed,
            static_cast<std::uint64_t>(queried.GetError().code),
            queried.GetError().native_code);
        probe_fixture_loaded_ = false;
        probe_info_.reset();
        probe_status_ = queried.GetError().message;
        operation_status_ = probe_status_;
        return;
    }
    if (queried.Value().byte_count != kPhysicalPageSize) {
        probe_fixture_loaded_ = false;
        probe_info_.reset();
        probe_status_ =
            "Probe query returned an unexpected fixture size; physical write review remains blocked.";
        operation_status_ = probe_status_;
        return;
    }
    const auto address = PfnAddress::FromPfn(queried.Value().pfn);
    if (!address ||
        address.Value().physical_address != queried.Value().physical_address) {
        probe_fixture_loaded_ = false;
        probe_info_.reset();
        probe_status_ = address
            ? "Probe PFN and physical address are inconsistent."
            : address.GetError().message;
        operation_status_ = probe_status_;
        return;
    }
    const auto loaded = physical_session_.Load(
        backend_, PhysicalWriteTarget::ProbeFixture(address.Value()));
    if (!loaded) {
        probe_fixture_loaded_ = false;
        probe_info_.reset();
        probe_status_ = loaded.GetError().message;
        operation_status_ = probe_status_;
        return;
    }
    BindCurrentPageToRuntimeHost();
    const auto physical_crc = PageCrc32(physical_session_.Baseline());
    if (physical_crc != queried.Value().crc32) {
        probe_fixture_loaded_ = false;
        probe_info_.reset();
        ClearProbeEvidence();
        char mismatch[320]{};
        std::snprintf(
            mismatch,
            sizeof(mismatch),
            "Probe metadata CRC32 %08X does not match the physical 4096-byte baseline CRC32 %08X. The page remains read-only and runtime readiness is not VERIFIED.",
            queried.Value().crc32,
            physical_crc);
        probe_status_ = mismatch;
        operation_status_ = mismatch;
        return;
    }
    probe_info_ = queried.Value();
    ClearProbeEvidence();
    probe_evidence_baseline_ = queried.Value();
    LogDiagnostic(DiagnosticEvent::ProbeQuerySucceeded);
    probe_fixture_loaded_ = true;
    last_physical_diffs_.clear();
    last_physical_readback_.clear();
    last_physical_readback_status_.clear();
    pfn_input_.SetPfn(probe_info_->pfn);
    select_physical_memory_tab_ = true;
    char message[320]{};
    std::snprintf(message, sizeof(message),
        "Probe fixture loaded: generation %u, 4096 bytes, CRC32 %08X, PFN 0x%llX.",
        probe_info_->generation,
        probe_info_->crc32,
        static_cast<unsigned long long>(probe_info_->pfn));
    probe_status_ = message;
    operation_status_ = message;
}

void MainWindow::RetryProbeMetadataForEvidence() {
    if (!physical_session_.HasPage() ||
        !probe_evidence_baseline_.has_value()) {
        operation_status_ =
            "Probe metadata retry requires the original verified fixture baseline.";
        return;
    }
    if (!probe_service_running_.value_or(false)) {
        operation_status_ =
            "Probe metadata retry requires the KDBGProbe service to remain running.";
        return;
    }
    if (!probe_.IsOpen()) {
        const auto opened = probe_.Open();
        LogResultDiagnostic(
            opened,
            DiagnosticEvent::ProbeDeviceOpenSucceeded,
            DiagnosticEvent::ProbeDeviceOpenFailed);
        if (!opened) {
            operation_status_ =
                "Probe metadata retry could not reopen the device: " +
                opened.GetError().message;
            return;
        }
    }

    const auto refreshed = probe_.Query();
    if (!refreshed) {
        LogDiagnostic(
            DiagnosticEvent::ProbeQueryFailed,
            static_cast<std::uint64_t>(refreshed.GetError().code),
            refreshed.GetError().native_code);
        operation_status_ =
            "Probe metadata retry failed; the rollback snapshot remains preserved: " +
            refreshed.GetError().message;
        return;
    }

    const auto& baseline = *probe_evidence_baseline_;
    const auto& actual = refreshed.Value();
    if (actual.byte_count != kPhysicalPageSize ||
        actual.pfn != physical_session_.Address().pfn ||
        actual.physical_address !=
            physical_session_.Address().physical_address ||
        actual.pfn != baseline.pfn ||
        actual.physical_address != baseline.physical_address ||
        actual.generation != baseline.generation) {
        probe_fixture_loaded_ = false;
        operation_status_ =
            "Probe metadata retry detected a changed fixture identity or generation; no write was attempted.";
        return;
    }

    probe_info_ = actual;
    probe_fixture_loaded_ = true;
    const auto& evidence = physical_session_.Evidence();
    const bool reload_verified =
        evidence.independent_reload.has_value() &&
        evidence.expected_after.has_value() &&
        evidence.independent_reload == evidence.expected_after;
    if (physical_session_.CanRollback() && reload_verified) {
        if (!PageMatchesProbeCrc(
                evidence.independent_reload, probe_info_)) {
            probe_evidence_after_reload_.reset();
            operation_status_ =
                "Probe metadata retry still disagrees with the independent physical reload CRC; evidence remains blocked and rollback remains available.";
            return;
        }
        probe_evidence_after_reload_ = actual;
        operation_status_ =
            "Probe metadata after independent reload was recovered; rollback remains available.";
    } else if (physical_session_.CanRollback() &&
               physical_session_.LastApplyVerified()) {
        if (!PageMatchesProbeCrc(evidence.readback, probe_info_)) {
            probe_evidence_after_write_.reset();
            operation_status_ =
                "Probe metadata retry still disagrees with the physical read-back CRC; evidence remains blocked and rollback remains available.";
            return;
        }
        probe_evidence_after_write_ = actual;
        operation_status_ =
            "Probe metadata after verified apply was recovered; independent reload is now available.";
    } else if (!physical_session_.CanRollback() && evidence.Complete()) {
        if (!PageMatchesProbeCrc(evidence.rollback, probe_info_)) {
            probe_evidence_after_rollback_.reset();
            operation_status_ =
                "Probe metadata retry still disagrees with the rollback page CRC; VERIFIED/evidence remains blocked.";
            return;
        }
        probe_evidence_after_rollback_ = actual;
        operation_status_ =
            "Probe metadata after rollback was recovered; evidence export is now available.";
    } else {
        operation_status_ =
            "Probe identity is valid, but no pending evidence phase requires metadata recovery.";
    }
    LogDiagnostic(DiagnosticEvent::ProbeQuerySucceeded);
}

void MainWindow::ClearProbeEvidence() noexcept {
    probe_evidence_baseline_.reset();
    probe_evidence_after_write_.reset();
    probe_evidence_after_reload_.reset();
    probe_evidence_after_rollback_.reset();
    last_physical_evidence_path_.clear();
}

void MainWindow::ExportPhysicalEvidence() {
    const auto& evidence = physical_session_.Evidence();
    if (!CurrentPageIsProbeFixture() || !evidence.Complete() ||
        !probe_evidence_baseline_.has_value() ||
        !probe_evidence_after_write_.has_value() ||
        !probe_evidence_after_reload_.has_value() ||
        !probe_evidence_after_rollback_.has_value()) {
        operation_status_ =
            "Evidence export requires a complete probe apply, independent reload, and verified rollback.";
        return;
    }
    if (backend_.Info().write_enabled) {
        operation_status_ =
            "Evidence export blocked because the physical write gate is not confirmed LOCKED.";
        return;
    }
    if (evidence.preflight != evidence.baseline ||
        evidence.readback != evidence.expected_after ||
        evidence.independent_reload != evidence.expected_after ||
        evidence.rollback != evidence.baseline) {
        operation_status_ =
            "Evidence export blocked because one or more full-page comparisons do not match.";
        return;
    }
    if (probe_evidence_after_rollback_->crc32 !=
        probe_evidence_baseline_->crc32) {
        operation_status_ =
            "Evidence export blocked because the rollback probe CRC does not match the baseline CRC.";
        return;
    }

    const auto evidence_root = LocalEvidenceRoot();
    if (!evidence_root.has_value()) {
        operation_status_ =
            "Unable to resolve %LOCALAPPDATA% for evidence export; the package directory was not modified.";
        return;
    }
    if (!PageMatchesProbeCrc(
            evidence.baseline, probe_evidence_baseline_) ||
        !PageMatchesProbeCrc(
            evidence.preflight, probe_evidence_baseline_) ||
        !PageMatchesProbeCrc(
            evidence.expected_after, probe_evidence_after_write_) ||
        !PageMatchesProbeCrc(
            evidence.readback, probe_evidence_after_write_) ||
        !PageMatchesProbeCrc(
            evidence.independent_reload,
            probe_evidence_after_reload_) ||
        !PageMatchesProbeCrc(
            evidence.rollback, probe_evidence_after_rollback_)) {
        operation_status_ =
            "Evidence export blocked because Probe metadata CRC does not match one or more physical 4096-byte pages.";
        return;
    }
    bool exact_evidence_pattern = true;
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        std::uint8_t expected = (*evidence.baseline)[offset];
        if (offset >= kProbeEvidenceEditOffset &&
            offset < kProbeEvidenceEditOffset +
                kProbeEvidenceEditMask.size()) {
            expected = static_cast<std::uint8_t>(expected ^
                kProbeEvidenceEditMask[offset - kProbeEvidenceEditOffset]);
        }
        if ((*evidence.expected_after)[offset] != expected) {
            exact_evidence_pattern = false;
            break;
        }
    }
    if (!exact_evidence_pattern) {
        operation_status_ =
            "Evidence export blocked: use Stage Evidence Probe Pattern so the GUI raw pages match the packaged verifier contract.";
        return;
    }
    const auto timestamp_utc = EvidenceTimestampUtc();
    const auto evidence_id = timestamp_utc + "-" +
        std::to_string(::GetCurrentProcessId()) + "-" +
        std::to_string(::GetTickCount64());
    const auto directory = *evidence_root /
        (".partial-live-" + evidence_id);
    const auto published_directory = *evidence_root /
        ("live-" + evidence_id);
    std::error_code error;
    if (!std::filesystem::create_directories(directory, error) || error) {
        operation_status_ =
            "Unable to create the live evidence directory: " +
            error.message();
        return;
    }
    const auto discard_partial = [&]() noexcept {
        std::error_code cleanup_error;
        std::filesystem::remove_all(directory, cleanup_error);
    };

    const bool pages_written =
        WritePageFile(directory / "baseline.bin", evidence.baseline) &&
        WritePageFile(directory / "preflight.bin", evidence.preflight) &&
        WritePageFile(
            directory / "expected-after.bin", evidence.expected_after) &&
        WritePageFile(directory / "readback.bin", evidence.readback) &&
        WritePageFile(
            directory / "independent-reload.bin",
            evidence.independent_reload) &&
        WritePageFile(directory / "rollback.bin", evidence.rollback);
    if (!pages_written) {
        discard_partial();
        operation_status_ =
            "Unable to write all six 4096-byte evidence pages.";
        return;
    }

    std::ofstream metadata(
        directory / "metadata.json", std::ios::out | std::ios::trunc);
    if (!metadata) {
        discard_partial();
        operation_status_ = "Unable to create evidence metadata.json.";
        return;
    }

    const auto write_probe = [&](const char* label, const ProbeInfo& info,
                                 bool trailing_comma) {
        metadata << "    \"" << label << "\": {"
                 << "\"generation\": " << info.generation << ", "
                 << "\"byte_count\": " << info.byte_count << ", "
                 << "\"virtual_address\": \""
                 << HexValue(info.virtual_address, 16) << "\", "
                 << "\"physical_address\": \""
                 << HexValue(info.physical_address, 16) << "\", "
                 << "\"pfn\": \"" << HexValue(info.pfn) << "\", "
                 << "\"crc32\": \"" << HexValue(info.crc32, 8)
                 << "\"}" << (trailing_comma ? "," : "") << "\n";
    };

    metadata << "{\n"
             << "  \"schema\": \"kdbg-physical-live-evidence-v1\",\n"
             << "  \"timestamp_utc\": \""
             << timestamp_utc << "Z\",\n"
             << "  \"page_size\": 4096,\n"
             << "  \"driver_abi_version\": "
             << backend_.Info().abi_version << ",\n"
             << "  \"pfn\": \""
             << HexValue(physical_session_.Address().pfn) << "\",\n"
             << "  \"physical_address\": \""
             << HexValue(
                    physical_session_.Address().physical_address, 16)
             << "\",\n"
             << "  \"edit_offset\": " << kProbeEvidenceEditOffset << ",\n"
             << "  \"edit_length\": "
             << kProbeEvidenceEditMask.size() << ",\n"
             << "  \"edit_xor_mask\": \"";
    for (const std::uint8_t value : kProbeEvidenceEditMask) {
        metadata << std::hex << std::setfill('0') << std::setw(2)
                 << static_cast<unsigned int>(value);
    }
    metadata << std::dec << std::setfill(' ')
             << "\",\n"
             << "  \"page_files\": {\n"
             << "    \"baseline\": \"baseline.bin\",\n"
             << "    \"preflight\": \"preflight.bin\",\n"
             << "    \"expected_after\": \"expected-after.bin\",\n"
             << "    \"readback\": \"readback.bin\",\n"
             << "    \"independent_reload\": \"independent-reload.bin\",\n"
             << "    \"rollback\": \"rollback.bin\"\n"
             << "  },\n"
             << "  \"dirty_runs\": [";

    bool first_run = true;
    std::size_t offset = 0;
    while (offset < kPhysicalPageSize) {
        if ((*evidence.baseline)[offset] ==
            (*evidence.expected_after)[offset]) {
            ++offset;
            continue;
        }
        const auto start = offset;
        while (offset < kPhysicalPageSize &&
               (*evidence.baseline)[offset] !=
                   (*evidence.expected_after)[offset]) {
            ++offset;
        }
        if (!first_run) metadata << ", ";
        metadata << "{\"offset\": " << start
                 << ", \"length\": " << (offset - start) << "}";
        first_run = false;
    }
    metadata << "],\n"
             << "  \"write_gate_relocked\": true,\n"
             << "  \"preflight_match\": true,\n"
             << "  \"full_readback_match\": true,\n"
             << "  \"independent_reload_match\": true,\n"
             << "  \"rollback_match\": true,\n"
             << "  \"probe\": {\n";
    write_probe("baseline", *probe_evidence_baseline_, true);
    write_probe("after_write", *probe_evidence_after_write_, true);
    write_probe("after_reload", *probe_evidence_after_reload_, true);
    write_probe("after_rollback", *probe_evidence_after_rollback_, false);
    metadata << "  }\n}\n";
    metadata.close();
    if (!metadata) {
        discard_partial();
        operation_status_ = "Writing evidence metadata.json failed.";
        return;
    }

    std::filesystem::rename(directory, published_directory, error);
    if (error) {
        discard_partial();
        operation_status_ =
            "Unable to atomically publish the live evidence directory: " +
            error.message();
        return;
    }

    last_physical_evidence_path_ = PathToUtf8(published_directory);
    operation_status_ =
        "Live evidence bundle exported: six exact 4096-byte pages plus metadata; write gate LOCKED.";
}

void MainWindow::LockAllWrites() {
    QueueDeferredAction(DeferredAction::LockAllWrites);
}

bool MainWindow::FinishLockAllWrites() {
    std::vector<std::string> failures;
    process_scanner_.RevokeWriteAuthorization();
    if (process_memory_ != nullptr && process_memory_->WritesArmed()) {
        const auto process_lock = process_memory_->SetWritesArmed(false);
        if (!process_lock) failures.push_back(process_lock.GetError().message);
    }
    if (backend_.Info().connected) {
        const auto driver_lock = backend_.SetWriteEnabled(false);
        if (!driver_lock) failures.push_back(driver_lock.GetError().message);
    }
    if (failures.empty() && !backend_.Info().write_enabled &&
        (process_memory_ == nullptr || !process_memory_->WritesArmed())) {
        LogDiagnostic(DiagnosticEvent::PhysicalGateLockSucceeded);
        operation_status_ = ProcessIoBusy()
            ? "All write gates report LOCKED; active process workers were asked to cancel and remain visible until they finish."
            : "All process and physical write gates report LOCKED.";
        return true;
    }
    LogDiagnostic(DiagnosticEvent::PhysicalGateLockFailed);
    operation_status_ = "CRITICAL: not every write gate could be confirmed locked";
    for (const auto& failure : failures) operation_status_ += " | " + failure;
    return false;
}

bool MainWindow::CurrentPageBoundToRuntimeHost() const noexcept {
    return physical_session_.HasPage() &&
        runtime_backend_session_generation_ != 0U &&
        physical_target_backend_session_ ==
            runtime_backend_session_generation_;
}

std::string MainWindow::RuntimeHostIdentityLabel() const {
    return "machine=" + runtime_host_machine_ + " | boot=" +
        runtime_host_boot_id_ + " | app-session=" +
        runtime_host_process_session_id_ + " | backend-session=" +
        std::to_string(runtime_backend_session_generation_);
}

void MainWindow::BindCurrentPageToRuntimeHost() noexcept {
    physical_target_backend_session_ = physical_session_.HasPage()
        ? runtime_backend_session_generation_
        : 0U;
}

bool MainWindow::CurrentPageMatchesProbeIdentity() const noexcept {
    return probe_fixture_loaded_ && probe_.IsOpen() &&
        probe_service_running_.value_or(false) &&
        probe_info_.has_value() && physical_session_.HasPage() &&
        CurrentPageBoundToRuntimeHost() &&
        physical_session_.Target().kind ==
            PhysicalTargetKind::ProbeFixture &&
        probe_info_->byte_count == kPhysicalPageSize &&
        physical_session_.Address().pfn == probe_info_->pfn &&
        physical_session_.Address().physical_address ==
             probe_info_->physical_address;
}

bool MainWindow::CurrentPageIsProbeFixture() const noexcept {
    return CurrentPageMatchesProbeIdentity() &&
        PageCrc32(physical_session_.Baseline()) == probe_info_->crc32;
}

std::optional<VerifiedProcessPhysicalTarget>
MainWindow::CurrentPageProcessTarget() const noexcept {
    if (ProcessIoBusy() || !physical_session_.HasPage() ||
        !CurrentPageBoundToRuntimeHost() ||
        physical_session_.Target().kind !=
            PhysicalTargetKind::ProcessMapping ||
        process_memory_ == nullptr) {
        return std::nullopt;
    }
    const auto& provenance = physical_session_.Target();
    const auto target =
        page_table_.CurrentProcessTarget(physical_session_.Address());
    if (!target.has_value() ||
        target->pid != process_memory_->ProcessId() ||
        !provenance.process_id.has_value() ||
        !provenance.virtual_page_address.has_value() ||
        target->pid != *provenance.process_id ||
        (target->virtual_address &
         ~static_cast<std::uint64_t>(kPhysicalPageSize - 1U)) !=
            *provenance.virtual_page_address ||
        target->pfn != provenance.address.pfn) {
        return std::nullopt;
    }
    return target;
}

bool MainWindow::CurrentPageIsVerifiedWriteTarget() const noexcept {
    if (!backend_.Info().connected || !physical_session_.HasPage() ||
        !CurrentPageBoundToRuntimeHost() ||
        !physical_session_.Target().IsConsistent()) {
        return false;
    }
    switch (physical_session_.Target().kind) {
    case PhysicalTargetKind::RawPfn:
        // PhysicalPageSession::Load accepted this page only after verifying
        // that all 4096 bytes fit one driver-reported physical RAM range.
        return true;
    case PhysicalTargetKind::ProbeFixture:
        return CurrentPageIsProbeFixture() ||
            (physical_session_.CanRollback() &&
             CurrentPageMatchesProbeIdentity());
    case PhysicalTargetKind::ProcessMapping:
        return CurrentPageProcessTarget().has_value();
    }
    return false;
}

bool MainWindow::LifecycleBusy() const noexcept {
    return lifecycle_future_.valid() ||
        deferred_action_ == DeferredAction::StartLifecycle;
}

bool MainWindow::ProcessIoBusy() const noexcept {
    return process_memory_browser_.Busy() || disassembly_.Busy() ||
        process_scanner_.Busy() || pointer_scanner_.Busy() ||
        snapshots_.Busy() || analysis_evidence_future_.valid();
}

bool MainWindow::BackendIoBusy() const noexcept {
    return ProcessIoBusy() || process_usage_.Busy() ||
        kernel_explorer_.ReadBusy();
}

bool MainWindow::ValidateCurrentPhysicalTargetForObservation() {
    if (!physical_session_.RecoveryObservationRequired()) {
        operation_status_ =
            "Recovery observation is not required for the current page.";
        return false;
    }
    if (!physical_session_.HasPage()) {
        operation_status_ =
            "Recovery observation blocked: no physical page is loaded.";
        return false;
    }
    if (physical_session_.Target().kind == PhysicalTargetKind::RawPfn) {
        return ValidateRawPfnTarget(false);
    }
    // Probe rollback validation checks the exact PFN/PA/generation identity
    // without assuming the page CRC, which is intentionally unknown here.
    // Process rollback validation likewise re-walks the exact PID/VA/PFN
    // provenance before the observation read.
    return ValidateCurrentPhysicalTargetForRollback();
}

bool MainWindow::ValidateCurrentPhysicalTargetForWrite() {
    if (!physical_session_.HasPage()) {
        operation_status_ =
            "Physical write review blocked: no physical page is loaded.";
        return false;
    }
    if (physical_session_.Target().kind == PhysicalTargetKind::RawPfn) {
        return ValidateRawPfnTarget(false);
    }
    if (physical_session_.Target().kind ==
        PhysicalTargetKind::ProbeFixture) {
        return ValidateProbeTargetForWrite();
    }
    const auto target = CurrentPageProcessTarget();
    if (!target.has_value()) {
        operation_status_ =
            "Physical write review blocked: translate an attached process writable 4 KiB user VA in PTView and open its final PA first.";
        return false;
    }
    const auto revalidated = page_table_.RevalidateProcessTarget(
        backend_, physical_session_.Address());
    if (!revalidated) {
        operation_status_ =
            "Physical write review blocked: process mapping revalidation failed: " +
            revalidated.GetError().message;
        return false;
    }
    const auto& provenance = physical_session_.Target();
    if (process_memory_ == nullptr ||
        revalidated.Value().pid != process_memory_->ProcessId() ||
        !provenance.process_id.has_value() ||
        !provenance.virtual_page_address.has_value() ||
        revalidated.Value().pid != *provenance.process_id ||
        (revalidated.Value().virtual_address &
         ~static_cast<std::uint64_t>(kPhysicalPageSize - 1U)) !=
            *provenance.virtual_page_address ||
        revalidated.Value().pfn != provenance.address.pfn) {
        operation_status_ =
            "Physical write review blocked: the attached process or its PID/VA/PFN provenance changed.";
        return false;
    }
    operation_status_ =
        "Verified process physical target revalidated: PID " +
        std::to_string(revalidated.Value().pid) + " / PFN " +
        HexValue(revalidated.Value().pfn) + ".";
    return true;
}

bool MainWindow::ValidateCurrentPhysicalTargetForRollback() {
    if (!physical_session_.HasPage()) {
        operation_status_ =
            "Physical rollback blocked: no physical page is loaded.";
        return false;
    }
    if (physical_session_.Target().kind == PhysicalTargetKind::RawPfn) {
        return ValidateRawPfnTarget(true);
    }
    if (physical_session_.Target().kind ==
        PhysicalTargetKind::ProbeFixture) {
        return ValidateProbeTargetForRollback();
    }
    const auto target = CurrentPageProcessTarget();
    if (!target.has_value()) {
        operation_status_ =
            "Physical rollback blocked: the verified process mapping is no longer selected.";
        return false;
    }
    const auto revalidated = page_table_.RevalidateProcessTarget(
        backend_, physical_session_.Address());
    if (!revalidated) {
        operation_status_ =
            "Physical rollback blocked: process mapping revalidation failed: " +
            revalidated.GetError().message;
        return false;
    }
    const auto& provenance = physical_session_.Target();
    return process_memory_ != nullptr &&
        revalidated.Value().pid == process_memory_->ProcessId() &&
        provenance.process_id.has_value() &&
        provenance.virtual_page_address.has_value() &&
        revalidated.Value().pid == *provenance.process_id &&
        (revalidated.Value().virtual_address &
         ~static_cast<std::uint64_t>(kPhysicalPageSize - 1U)) ==
            *provenance.virtual_page_address &&
        revalidated.Value().pfn == provenance.address.pfn;
}

bool MainWindow::ValidateRawPfnTarget(bool rollback) {
    const char* operation = rollback ? "rollback" : "write review";
    if (!backend_.Info().connected || !physical_session_.HasPage() ||
        !CurrentPageBoundToRuntimeHost() ||
        physical_session_.Target().kind != PhysicalTargetKind::RawPfn ||
        !physical_session_.Target().IsConsistent()) {
        operation_status_ = std::string{"Physical "} + operation +
            " blocked: the RawPfn session is not valid for this backend.";
        return false;
    }
    if (rollback && !physical_session_.CanRollback()) {
        operation_status_ =
            "Physical rollback blocked: no verified RawPfn apply is pending.";
        return false;
    }

    const auto ranges = backend_.GetPhysicalRanges();
    if (!ranges) {
        operation_status_ = std::string{"Physical "} + operation +
            " blocked: RAM range revalidation failed: " +
            ranges.GetError().message;
        return false;
    }
    const auto& address = physical_session_.Address();
    const bool contained = std::any_of(
        ranges.Value().begin(), ranges.Value().end(),
        [&](const PhysicalRange& range) {
            return range.Contains(
                address.physical_address, kPhysicalPageSize);
        });
    if (!contained) {
        operation_status_ = std::string{"Physical "} + operation +
            " blocked: the complete RawPfn page is no longer inside one "
            "driver-reported physical RAM range.";
        return false;
    }

    operation_status_ = "RawPfn target range revalidated for this Windows "
        "instance: PFN " + HexValue(address.pfn) + " / PA " +
        HexValue(address.physical_address, 16) + " / 4096 bytes.";
    return true;
}

bool MainWindow::ValidateProbeTargetForWrite() {
    if (!CurrentPageIsProbeFixture()) {
        operation_status_ =
            "Physical write review blocked: load and verify the live probe fixture first.";
        return false;
    }
    const auto current = probe_.Query();
    if (!current) {
        LogDiagnostic(
            DiagnosticEvent::ProbeQueryFailed,
            static_cast<std::uint64_t>(current.GetError().code),
            current.GetError().native_code);
        probe_fixture_loaded_ = false;
        probe_status_ = "Probe revalidation failed: " + current.GetError().message;
        operation_status_ = probe_status_;
        return false;
    }
    const auto& expected = *probe_info_;
    const auto& actual = current.Value();
    if (actual.byte_count != kPhysicalPageSize ||
        actual.pfn != expected.pfn ||
        actual.physical_address != expected.physical_address ||
        actual.generation != expected.generation ||
        actual.crc32 != expected.crc32) {
        probe_fixture_loaded_ = false;
        probe_status_ =
            "Probe identity/content changed since the page baseline was loaded. "
            "Query & Load Probe Fixture again; no physical write was attempted.";
        operation_status_ = probe_status_;
        return false;
    }
    LogDiagnostic(DiagnosticEvent::ProbeQuerySucceeded);
    return true;
}

bool MainWindow::ValidateProbeTargetForRollback() {
    if (!CurrentPageMatchesProbeIdentity()) {
        operation_status_ =
            "Physical rollback blocked: the live probe fixture is no longer selected.";
        return false;
    }
    const auto current = probe_.Query();
    if (!current) {
        LogDiagnostic(
            DiagnosticEvent::ProbeQueryFailed,
            static_cast<std::uint64_t>(current.GetError().code),
            current.GetError().native_code);
        probe_status_ =
            "Probe identity revalidation for rollback failed: " +
            current.GetError().message;
        operation_status_ = probe_status_;
        return false;
    }
    const auto& expected = *probe_info_;
    const auto& actual = current.Value();
    if (actual.byte_count != kPhysicalPageSize ||
        actual.pfn != expected.pfn ||
        actual.physical_address != expected.physical_address ||
        actual.generation != expected.generation) {
        probe_fixture_loaded_ = false;
        probe_status_ =
            "Probe identity changed before rollback. No rollback write was attempted.";
        operation_status_ = probe_status_;
        return false;
    }
    probe_info_ = actual;
    LogDiagnostic(DiagnosticEvent::ProbeQuerySucceeded);
    return true;
}

void MainWindow::CapturePhysicalReadback(
    std::vector<ByteDiff> submitted_diffs,
    std::string operation_name) {
    last_physical_diffs_ = std::move(submitted_diffs);
    last_physical_readback_.clear();
    const auto readback = backend_.ReadPhysical(
        physical_session_.Address().physical_address,
        static_cast<std::uint32_t>(kPhysicalPageSize));
    if (!readback) {
        last_physical_readback_status_ = operation_name +
            " evidence read failed: " + readback.GetError().message;
        operation_status_ += " | " + last_physical_readback_status_;
        return;
    }
    if (readback.Value().size() != kPhysicalPageSize) {
        last_physical_readback_status_ = operation_name +
            " evidence read returned " +
            std::to_string(readback.Value().size()) +
            " bytes instead of 4096.";
        operation_status_ += " | " + last_physical_readback_status_;
        return;
    }
    last_physical_readback_ = readback.Value();
    const auto mismatch_count = static_cast<std::size_t>(std::count_if(
        last_physical_diffs_.begin(), last_physical_diffs_.end(),
        [&](const ByteDiff& diff) {
            return last_physical_readback_[diff.offset] != diff.after;
        }));
    last_physical_readback_status_ = operation_name +
        " evidence captured: driver transfer/read-back contract 4096 bytes; " +
        std::to_string(last_physical_diffs_.size()) +
        " locally dirty/submitted byte(s), " + std::to_string(mismatch_count) +
        " mismatch(es).";
    if (mismatch_count != 0) {
        operation_status_ +=
            " | CRITICAL: the independent UI read-back found " +
            std::to_string(mismatch_count) + " submitted-byte mismatch(es).";
    }
}

void MainWindow::DrawAboutDialog() {
    if (about_open_requested_) {
        ImGui::OpenPopup(UiLabel("About KDBG", "About KDBG").c_str());
        about_open_requested_ = false;
    }
    if (!ImGui::BeginPopupModal(
            UiLabel("About KDBG", "About KDBG").c_str(), nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    ImGui::Text("KDBG %s", kVersion);
    ImGui::Text(UiText("Build ID: %s"), kBuildId);
    ImGui::Separator();
    ImGui::TextWrapped(UiText(
        "Windows x64 physical/process-memory research UI. Physical PFN "
        "operations address local physical RAM exposed by KDbgDriver in this "
        "Windows instance. KDBG never transmits memory externally by itself."));
    ImGui::Text(UiText("Backend: %s | ABI %u | physical gate %s"),
        cached_backend_info_.connected
            ? cached_backend_info_.name.c_str()
            : "disconnected",
        cached_backend_info_.abi_version,
        cached_backend_info_.write_enabled ? "ARMED" : "LOCKED");
    ImGui::Separator();
    ImGui::TextUnformatted(UiText("Licenses / attribution"));
    ImGui::BulletText("%s", UiText(
        "KDBG original code: repository license and attribution files"));
    ImGui::BulletText("%s", UiText(
        "Dear ImGui and imgui_memory_editor: MIT License"));
    ImGui::BulletText("%s", UiText("Zydis and Zycore: MIT License"));
    ImGui::BulletText("%s", UiText(
        "Optional MemProcFS integration remains out-of-process (AGPL-3.0)"));
    ImGui::TextDisabled(UiText(
        "See THIRD_PARTY.lock.json and the packaged licenses directory for full notices."));
    ImGui::Separator();
    ImGui::TextWrapped(UiText(
        "Local diagnostics: %%LOCALAPPDATA%%\\KDBG\\logs. The event log "
        "rotates at 1 MiB across three files and excludes memory bytes, "
        "credentials, and user paths. MiniDumpNormal crash dumps stay local; "
        "KDBG does not transmit them."));
    if (ImGui::Button(UiText("Copy build ID"))) {
        ImGui::SetClipboardText(kBuildId);
    }
    ImGui::SameLine();
    if (ImGui::Button(UiText("Close"))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void MainWindow::SetOperationResult(
    const Result<void>& result,
    std::string success) {
    if (result) {
        operation_status_ = std::move(success);
        return;
    }
    operation_status_ = FormatError(result.GetError());
}

std::string MainWindow::AttachedProcessName() const {
    if (process_memory_ == nullptr) return {};
    if (ProcessIoBusy()) return "busy";
    const auto it = std::find_if(
        processes_.begin(), processes_.end(),
        [&](const ProcessInfo& process) {
            return process.pid == process_memory_->ProcessId();
        });
    return it == processes_.end() ? std::string("unknown") : it->name;
}

}  // namespace kdbg

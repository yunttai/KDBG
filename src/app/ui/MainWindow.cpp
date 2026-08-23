#include "app/ui/MainWindow.h"

#include "app/LocalDiagnostics.h"
#include "core/windows/DriverService.h"

#include <imgui.h>
#ifdef IMGUI_HAS_DOCK
#include <imgui_internal.h>
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string_view>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace kdbg {
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

constexpr const char* kVersion = "1.0.0";
constexpr const char* kBuildId = __DATE__ " " __TIME__;

std::string HexValue(std::uint64_t value, int width = 0) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::nouppercase;
    if (width > 0) {
        stream << std::setw(width) << std::setfill('0');
    }
    stream << value;
    return stream.str();
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
    const auto directory = ExecutableDirectory();
    const auto driver = directory / "drivers" / "KDbgDriver.sys";
    const auto probe_driver = directory / "drivers" / "KDbgProbe.sys";
    const auto driver_utf8 = PathToUtf8(driver);
    const auto probe_driver_utf8 = PathToUtf8(probe_driver);
    std::snprintf(
        driver_path_.data(), driver_path_.size(), "%s", driver_utf8.c_str());
    std::snprintf(
        probe_driver_path_.data(), probe_driver_path_.size(),
        "%s", probe_driver_utf8.c_str());

    RefreshServiceStates();
    RefreshProcesses();
    const auto opened = backend_.Open();
    if (opened) {
        LogDiagnostic(DiagnosticEvent::DriverConnectSucceeded);
        operation_status_ = "KDBG driver connected. Physical and privileged process reads are available.";
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
    process_usage_.CancelAndWait();
    DisconnectProcess();
    probe_.Close();
    backend_.Close();
}

void MainWindow::Draw() {
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
        if (ImGui::BeginTabItem("Driver", nullptr, driver_flags)) {
            select_driver_tab_ = false;
            DrawDriverTab();
            ImGui::EndTabItem();
        }
        const auto physical_flags = select_physical_memory_tab_
            ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem("Physical Memory", nullptr, physical_flags)) {
            select_physical_memory_tab_ = false;
            DrawPhysicalMemoryTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Memory Map")) {
            DrawMemoryMapTab();
            ImGui::EndTabItem();
        }
        const auto process_memory_flags = select_process_memory_tab_
            ? ImGuiTabItemFlags_SetSelected
            : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem(
                "Process Memory", nullptr, process_memory_flags)) {
            select_process_memory_tab_ = false;
            DrawProcessMemoryTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Process Scanner")) {
            DrawProcessScannerTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Pointer Scanner")) {
            DrawPointerScannerTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Disassembler")) {
            DrawDisassemblyTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Snapshots")) {
            DrawSnapshotTab();
            ImGui::EndTabItem();
        }
        const auto page_table_flags = select_page_tables_tab_
            ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem("Page Tables", nullptr, page_table_flags)) {
            select_page_tables_tab_ = false;
            DrawTranslationTab();
            ImGui::EndTabItem();
        }
        const auto ownership_flags = select_pfn_ownership_tab_
            ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem("PFN Ownership", nullptr, ownership_flags)) {
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
    const bool probe_target = CurrentPageIsProbeFixture();
    const auto process_target = CurrentPageProcessTarget();
    write_modal_.Draw(
        physical_session_,
        probe_target,
        process_target.has_value(),
        process_target.has_value() ? process_target->pid : 0,
        process_target.has_value() ? process_target->virtual_address : 0,
        probe_info_.has_value() ? probe_info_->generation : 0,
        probe_info_.has_value() ? probe_info_->crc32 : 0);
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

            ImGui::DockBuilderDockWindow("KDBG Control Center", left);
            ImGui::DockBuilderDockWindow("Driver", left);
            ImGui::DockBuilderDockWindow("Physical Memory", remaining);
            ImGui::DockBuilderDockWindow("Process Memory", remaining);
            ImGui::DockBuilderDockWindow("Memory Map", right);
            ImGui::DockBuilderDockWindow("Page Tables", right);
            ImGui::DockBuilderDockWindow("PFN Ownership", right);
            ImGui::DockBuilderDockWindow("Process Scanner", bottom);
            ImGui::DockBuilderDockWindow("Pointer Scanner", bottom);
            ImGui::DockBuilderDockWindow("Disassembler", bottom);
            ImGui::DockBuilderDockWindow("Snapshots", bottom);
            ImGui::DockBuilderFinish(dockspace_id);
        }
    }

    const bool control_center_visible = ImGui::Begin(
        "KDBG Control Center", nullptr,
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
    const bool probe_target = CurrentPageIsProbeFixture();
    const auto process_target = CurrentPageProcessTarget();
    write_modal_.Draw(
        physical_session_,
        probe_target,
        process_target.has_value(),
        process_target.has_value() ? process_target->pid : 0,
        process_target.has_value() ? process_target->virtual_address : 0,
        probe_info_.has_value() ? probe_info_->generation : 0,
        probe_info_.has_value() ? probe_info_->crc32 : 0);
    DrawAboutDialog();

    auto draw_pane = [](const char* name, bool* request_focus, auto&& draw) {
        if (request_focus != nullptr && *request_focus) {
            ImGui::SetNextWindowFocus();
            *request_focus = false;
        }
        if (ImGui::Begin(name, nullptr, ImGuiWindowFlags_NoCollapse)) draw();
        ImGui::End();
    };
    draw_pane("Driver", &select_driver_tab_, [&] { DrawDriverTab(); });
    draw_pane("Physical Memory", &select_physical_memory_tab_,
        [&] { DrawPhysicalMemoryTab(); });
    draw_pane("Memory Map", nullptr, [&] { DrawMemoryMapTab(); });
    draw_pane("Process Memory", &select_process_memory_tab_,
        [&] { DrawProcessMemoryTab(); });
    draw_pane("Process Scanner", nullptr,
        [&] { DrawProcessScannerTab(); });
    draw_pane("Pointer Scanner", nullptr,
        [&] { DrawPointerScannerTab(); });
    draw_pane("Disassembler", nullptr, [&] { DrawDisassemblyTab(); });
    draw_pane("Snapshots", nullptr, [&] { DrawSnapshotTab(); });
    draw_pane("Page Tables", &select_page_tables_tab_,
        [&] { DrawTranslationTab(); });
    draw_pane("PFN Ownership", &select_pfn_ownership_tab_,
        [&] { DrawPfnOwnershipTab(); });
#else
    DrawTabbedWorkspace();
#endif
}

void MainWindow::DrawMenuBar() {
    if (!ImGui::BeginMenuBar()) return;
    if (ImGui::BeginMenu("Session")) {
        if (ImGui::MenuItem("Refresh process list", "Ctrl+R")) RefreshProcesses();
        if (ImGui::MenuItem("Disconnect process", nullptr, false, process_memory_ != nullptr)) {
            DisconnectProcess();
        }
        const bool can_reconnect =
            !process_usage_.Busy() && !physical_session_.CanRollback();
        if (ImGui::MenuItem(
                "Reconnect KDBG driver", nullptr, false, can_reconnect)) {
            ConnectBackend();
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Navigate")) {
        if (ImGui::MenuItem("Driver", "Ctrl+D")) {
            select_driver_tab_ = true;
        }
        if (ImGui::MenuItem("Physical Memory", "Ctrl+P")) {
            select_physical_memory_tab_ = true;
        }
        if (ImGui::MenuItem("Page Tables", "Ctrl+T")) {
            select_page_tables_tab_ = true;
        }
        if (ImGui::MenuItem("PFN Ownership", "Ctrl+Shift+P")) {
            select_pfn_ownership_tab_ = true;
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Safety")) {
        const bool process_armed = process_memory_ != nullptr && process_memory_->WritesArmed();
        if (ImGui::MenuItem("Lock all writes", "Ctrl+L", false,
                backend_.Info().write_enabled || process_armed)) {
            LockAllWrites();
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("About KDBG", "F1")) {
            about_open_requested_ = true;
        }
        ImGui::EndMenu();
    }
    ImGui::TextDisabled("KDBG %s | authorized disposable VM research", kVersion);
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
    const auto info = backend_.Info();
    const ImVec4 driver_color = info.connected
        ? ImVec4(0.35F, 0.90F, 0.45F, 1.0F)
        : ImVec4(1.0F, 0.65F, 0.25F, 1.0F);
    ImGui::TextColored(driver_color, "Driver: %s",
        info.connected ? (info.is_mock ? "MOCK" : "LIVE CONNECTED")
                       : "DISCONNECTED / SOURCE-ONLY");
    ImGui::SameLine();
    ImGui::Text("| Service: %s | ABI: %u | Physical gate: %s",
        ServiceStateName(driver_service_running_),
        info.abi_version,
        info.write_enabled ? "ARMED" : "LOCKED");
    ImGui::SameLine();
    ImGui::Text("| Probe: %s / %s",
        ServiceStateName(probe_service_running_),
        probe_.IsOpen() ? "DEVICE OPEN" : "DEVICE CLOSED");
    if (process_memory_ != nullptr) {
        ImGui::SameLine();
        ImGui::Text("| Process PID %u (%s) | gate: %s",
            process_memory_->ProcessId(),
            AttachedProcessName().c_str(),
            process_memory_->WritesArmed() ? "ARMED" : "LOCKED");
    }
    if (info.write_enabled) {
        ImGui::TextColored(
            ImVec4(1.0F, 0.25F, 0.20F, 1.0F),
            "WARNING: the driver reports its physical write gate ARMED. Ctrl+L locks all writes.");
    }
}

void MainWindow::DrawProcessSelector() {
    ImGui::TextUnformatted("Target Process");
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputTextWithHint(
        "##process-filter", "filter name or PID",
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
        : "Select a process";
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
    if (ImGui::Button("Attach")) AttachSelectedProcess();
    if (selected_process_index_ < 0) ImGui::EndDisabled();
    ImGui::SameLine();
    if (process_memory_ == nullptr) ImGui::BeginDisabled();
    if (ImGui::Button("Detach")) DisconnectProcess();
    if (process_memory_ == nullptr) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) RefreshProcesses();
    if (selected_process_index_ >= 0 &&
        selected_process_index_ < static_cast<int>(processes_.size())) {
        const auto& selected =
            processes_[static_cast<std::size_t>(selected_process_index_)];
        ImGui::TextWrapped("Selected PID %u | %s | %s",
            selected.pid,
            selected.is_64_bit ? "x64" : "x86",
            selected.path.empty() ? "path unavailable" : selected.path.c_str());
    }
}

void MainWindow::DrawDriverTab() {
    ImGui::TextWrapped(
        "The KDBG and KDBGProbe drivers are installed through the Windows "
        "Service Control Manager. Windows test-signing mode and Administrator "
        "rights are required. The probe owns a deterministic contiguous page "
        "for safe read/edit/write/read-back demonstrations.");

    ImGui::Text("KDBG service: %s | Probe service: %s",
        ServiceStateName(driver_service_running_),
        ServiceStateName(probe_service_running_));
    if (ImGui::Button("Refresh Service Status")) RefreshServiceStates();
    if (!service_status_.empty()) {
        ImGui::SameLine();
        ImGui::TextWrapped("%s", service_status_.c_str());
    }

    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputText("KDBG driver SYS", driver_path_.data(), driver_path_.size());
    std::error_code driver_path_error;
    const bool driver_file_ready = std::filesystem::is_regular_file(
        Utf8Path(driver_path_.data()), driver_path_error);
    if (!driver_file_ready) ImGui::BeginDisabled();
    if (ImGui::Button("Install/Update KDBG")) {
        const auto result = DriverService::InstallOrUpdate(
            L"KDBG", L"KDBG Physical Memory Driver",
            Utf8Path(driver_path_.data()));
        LogResultDiagnostic(
            result,
            DiagnosticEvent::DriverServiceInstallSucceeded,
            DiagnosticEvent::DriverServiceInstallFailed);
        SetOperationResult(result, "KDBG driver service installed/updated.");
        RefreshServiceStates();
    }
    if (!driver_file_ready) ImGui::EndDisabled();
    ImGui::SameLine();
    if (driver_service_running_.value_or(false)) ImGui::BeginDisabled();
    if (ImGui::Button("Start KDBG")) {
        const auto result = DriverService::Start(L"KDBG");
        LogResultDiagnostic(
            result,
            DiagnosticEvent::DriverServiceStartSucceeded,
            DiagnosticEvent::DriverServiceStartFailed);
        SetOperationResult(result, "KDBG driver started.");
        if (result) ConnectBackend();
        RefreshServiceStates();
    }
    if (driver_service_running_.value_or(false)) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_stop_driver = driver_service_running_.value_or(false) &&
        !process_usage_.Busy() && !physical_session_.CanRollback();
    if (!can_stop_driver) ImGui::BeginDisabled();
    if (ImGui::Button("Stop KDBG")) {
        LockAllWrites();
        const bool gates_locked = !backend_.Info().write_enabled &&
            (process_memory_ == nullptr || !process_memory_->WritesArmed());
        if (!gates_locked) {
            operation_status_ += " | Driver stop was blocked.";
        } else {
            backend_.Close();
            probe_fixture_loaded_ = false;
            ClearProbeEvidence();
            const auto result = DriverService::Stop(L"KDBG");
            LogResultDiagnostic(
                result,
                DiagnosticEvent::DriverServiceStopSucceeded,
                DiagnosticEvent::DriverServiceStopFailed);
            SetOperationResult(result, "KDBG driver stopped.");
        }
        RefreshServiceStates();
    }
    if (!can_stop_driver) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_remove_driver =
        !driver_service_running_.value_or(true) &&
        !backend_.Info().connected && !process_usage_.Busy();
    if (!can_remove_driver) ImGui::BeginDisabled();
    if (ImGui::Button("Remove KDBG")) {
        const auto result = DriverService::Remove(L"KDBG");
        LogResultDiagnostic(
            result,
            DiagnosticEvent::DriverServiceRemoveSucceeded,
            DiagnosticEvent::DriverServiceRemoveFailed);
        SetOperationResult(result, "KDBG driver service removed.");
        RefreshServiceStates();
    }
    if (!can_remove_driver) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_connect_device =
        !process_usage_.Busy() && !physical_session_.CanRollback();
    if (!can_connect_device) ImGui::BeginDisabled();
    if (ImGui::Button("Connect Device")) ConnectBackend();
    if (!can_connect_device) ImGui::EndDisabled();
    if (process_usage_.Busy()) {
        ImGui::TextDisabled(
            "Cancel the active PFN ownership query before stopping, removing, or reconnecting KDBG.");
    }
    if (!driver_file_ready) {
        ImGui::TextDisabled("Install is disabled until KDbgDriver.sys points to an existing file.");
    }

    ImGui::Separator();
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputText("Probe driver SYS", probe_driver_path_.data(), probe_driver_path_.size());
    std::error_code probe_path_error;
    const bool probe_file_ready = std::filesystem::is_regular_file(
        Utf8Path(probe_driver_path_.data()), probe_path_error);
    if (!probe_file_ready) ImGui::BeginDisabled();
    if (ImGui::Button("Install/Update Probe")) {
        const auto result = DriverService::InstallOrUpdate(
            L"KDBGProbe", L"KDBG Probe Fixture Driver",
            Utf8Path(probe_driver_path_.data()));
        LogResultDiagnostic(
            result,
            DiagnosticEvent::ProbeServiceInstallSucceeded,
            DiagnosticEvent::ProbeServiceInstallFailed);
        SetOperationResult(result, "KDBGProbe service installed/updated.");
        RefreshServiceStates();
    }
    if (!probe_file_ready) ImGui::EndDisabled();
    ImGui::SameLine();
    if (probe_service_running_.value_or(false)) ImGui::BeginDisabled();
    if (ImGui::Button("Start Probe")) {
        const auto result = DriverService::Start(L"KDBGProbe");
        LogResultDiagnostic(
            result,
            DiagnosticEvent::ProbeServiceStartSucceeded,
            DiagnosticEvent::ProbeServiceStartFailed);
        if (result) {
            probe_.Close();
            const auto opened = probe_.Open();
            LogResultDiagnostic(
                opened,
                DiagnosticEvent::ProbeDeviceOpenSucceeded,
                DiagnosticEvent::ProbeDeviceOpenFailed);
            SetOperationResult(opened, "KDBGProbe started and its device was opened.");
        } else {
            SetOperationResult(result, "");
        }
        RefreshServiceStates();
    }
    if (probe_service_running_.value_or(false)) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_stop_probe = probe_service_running_.value_or(false) &&
        !physical_session_.CanRollback();
    if (!can_stop_probe) ImGui::BeginDisabled();
    if (ImGui::Button("Stop Probe")) {
        probe_.Close();
        probe_fixture_loaded_ = false;
        ClearProbeEvidence();
        const auto result = DriverService::Stop(L"KDBGProbe");
        LogResultDiagnostic(
            result,
            DiagnosticEvent::ProbeServiceStopSucceeded,
            DiagnosticEvent::ProbeServiceStopFailed);
        SetOperationResult(result, "KDBGProbe stopped.");
        probe_info_.reset();
        probe_status_ = "Probe device stopped; no fixture is currently verified.";
        RefreshServiceStates();
    }
    if (!can_stop_probe) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_remove_probe =
        !probe_service_running_.value_or(true) && !probe_.IsOpen();
    if (!can_remove_probe) ImGui::BeginDisabled();
    if (ImGui::Button("Remove Probe")) {
        const auto result = DriverService::Remove(L"KDBGProbe");
        LogResultDiagnostic(
            result,
            DiagnosticEvent::ProbeServiceRemoveSucceeded,
            DiagnosticEvent::ProbeServiceRemoveFailed);
        SetOperationResult(result, "KDBGProbe service removed.");
        RefreshServiceStates();
    }
    if (!can_remove_probe) ImGui::EndDisabled();
    if (!probe_file_ready) {
        ImGui::TextDisabled("Install is disabled until KDbgProbe.sys points to an existing file.");
    }

    ImGui::Separator();
    const bool can_query_fixture = backend_.Info().connected &&
        probe_service_running_.value_or(false) &&
        !physical_session_.IsDirty() && !physical_session_.CanRollback();
    if (!can_query_fixture) ImGui::BeginDisabled();
    if (ImGui::Button("Query & Load Probe Fixture")) QueryAndLoadProbeFixture();
    if (!can_query_fixture) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_reset_probe = probe_.IsOpen() && probe_info_.has_value() &&
        !physical_session_.IsDirty() && !physical_session_.CanRollback();
    if (!can_reset_probe) ImGui::BeginDisabled();
    if (ImGui::Button("Reset Probe Pattern")) {
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
        ImGui::TextDisabled("Probe fixture has not been queried and verified in this session.");
    }
    if (!probe_status_.empty()) ImGui::TextWrapped("%s", probe_status_.c_str());
    if (physical_session_.IsDirty()) {
        ImGui::TextDisabled(
            "Query & Load is disabled until staged physical edits are reverted or applied.");
    } else if (physical_session_.CanRollback()) {
        ImGui::TextDisabled(
            "Query & Load is disabled while a verified rollback is pending; use Independent Reload (keep rollback).");
    }

    if (backend_.Info().connected) {
        ImGui::Separator();
        if (ImGui::Button("Query Driver Counters")) {
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
    if (!backend_.Info().connected) {
        ImGui::TextDisabled("Connect the KDBG driver to access physical memory.");
    }
    if (!backend_.Info().connected) ImGui::BeginDisabled();
    if (ImGui::BeginTable(
            "physical-layout", 3,
            ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("PFN", ImGuiTableColumnFlags_WidthFixed, 270.0F);
        ImGui::TableSetupColumn("Hex Editor", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Inspector", ImGuiTableColumnFlags_WidthFixed, 360.0F);
        ImGui::TableNextColumn();
        const bool rollback_pending = physical_session_.CanRollback();
        if (rollback_pending) ImGui::BeginDisabled();
        const bool loaded_from_navigator =
            pfn_input_.Draw(backend_, physical_session_);
        if (rollback_pending) ImGui::EndDisabled();
        if (loaded_from_navigator) {
            probe_fixture_loaded_ = false;
            ClearProbeEvidence();
            last_physical_diffs_.clear();
            last_physical_readback_.clear();
            last_physical_readback_status_.clear();
        }
        if (rollback_pending) {
            ImGui::TextDisabled(
                "PFN navigation is locked until the pending rollback is completed.");
        }
        ImGui::TableNextColumn();
        hex_editor_.Draw(physical_session_);
        ImGui::TableNextColumn();
        if (physical_session_.HasPage()) {
            const bool probe_target = CurrentPageIsProbeFixture();
            const auto process_target = CurrentPageProcessTarget();
            ImGui::Text("Memory space: PHYSICAL / 4 KiB page");
            ImGui::Text("State: %s", PageStateName(physical_session_.State()));
            ImGui::Text("Revision: %llu", static_cast<unsigned long long>(physical_session_.Revision()));
            ImGui::Text("Dirty bytes: %llu", static_cast<unsigned long long>(physical_session_.DirtyCount()));
            ImGui::Text("One-shot write unlock: %s", physical_session_.WriteUnlocked() ? "YES" : "NO");
            ImGui::Text("Conflicts: %llu | Read-back mismatches: %llu",
                static_cast<unsigned long long>(physical_session_.LastConflictOffsets().size()),
                static_cast<unsigned long long>(physical_session_.LastMismatchOffsets().size()));
            ImGui::Text("PA range: 0x%016llX - 0x%016llX | size: 4096 bytes",
                static_cast<unsigned long long>(physical_session_.Address().physical_address),
                static_cast<unsigned long long>(
                    physical_session_.Address().physical_address + 0xFFFU));
            if (probe_target) {
                ImGui::TextColored(
                    ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
                    "WRITE TARGET: VERIFIED KDbgProbe FIXTURE");
            } else if (process_target.has_value()) {
                ImGui::TextColored(
                    ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
                    "WRITE TARGET: VERIFIED PROCESS PID %u / VA 0x%016llX",
                    process_target->pid,
                    static_cast<unsigned long long>(
                        process_target->virtual_address));
            } else {
                ImGui::TextColored(
                    ImVec4(1.0F, 0.35F, 0.30F, 1.0F),
                    "READ-ONLY: translate a writable 4 KiB user VA in PTView "
                    "and open its final PA to verify this PFN");
            }
            if (ImGui::Button("Copy PFN")) {
                char value[32]{};
                std::snprintf(value, sizeof(value), "0x%llX",
                    static_cast<unsigned long long>(physical_session_.Address().pfn));
                ImGui::SetClipboardText(value);
            }
            ImGui::SameLine();
            if (ImGui::Button("Copy PA")) {
                char value[32]{};
                std::snprintf(value, sizeof(value), "0x%016llX",
                    static_cast<unsigned long long>(
                        physical_session_.Address().physical_address));
                ImGui::SetClipboardText(value);
            }
            ImGui::SameLine();
            if (ImGui::Button("View PFN Ownership")) {
                select_pfn_ownership_tab_ = true;
            }
        } else {
            ImGui::TextDisabled("No physical page loaded.");
        }
        ImGui::EndTable();
    }
    DrawDiffPanel();
    DrawPhysicalReadback();
    DrawPhysicalActions();
    if (!backend_.Info().connected) ImGui::EndDisabled();
}

void MainWindow::DrawMemoryMapTab() {
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

void MainWindow::DrawProcessMemoryTab() { process_memory_browser_.Draw(); }
void MainWindow::DrawProcessScannerTab() { process_scanner_.Draw(); }
void MainWindow::DrawPointerScannerTab() { pointer_scanner_.Draw(); }
void MainWindow::DrawDisassemblyTab() { disassembly_.Draw(); }
void MainWindow::DrawSnapshotTab() { snapshots_.Draw(); }

void MainWindow::DrawTranslationTab() {
    page_table_.Draw(
        backend_,
        process_memory_ == nullptr ? 0 : process_memory_->ProcessId());
    if (const auto page = page_table_.ConsumePhysicalNavigation();
        page.has_value()) {
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
        const auto loaded = physical_session_.Load(backend_, *page);
        if (loaded) {
            probe_fixture_loaded_ = false;
            ClearProbeEvidence();
            last_physical_diffs_.clear();
            last_physical_readback_.clear();
            last_physical_readback_status_.clear();
            pfn_input_.SetPfn(page->pfn);
            select_physical_memory_tab_ = true;
            operation_status_ =
                "Translated writable user page opened in Physical Memory. "
                "Unlock and Apply will revalidate PID, CR3, VA, and PFN before writing.";
        } else {
            operation_status_ = loaded.GetError().message;
        }
    }
}

void MainWindow::DrawPfnOwnershipTab() {
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
    if (!ImGui::CollapsingHeader("Dirty Diff", ImGuiTreeNodeFlags_DefaultOpen)) return;
    const auto diffs = physical_session_.ByteDiffs();
    if (diffs.empty()) {
        ImGui::TextDisabled("No local changes.");
        return;
    }
    if (ImGui::BeginTable(
            "physical-diff", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 150.0F))) {
        ImGui::TableSetupColumn("Offset");
        ImGui::TableSetupColumn("Physical Address");
        ImGui::TableSetupColumn("Before");
        ImGui::TableSetupColumn("After");
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
            "Last Physical Operation Read-back",
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
        ImGui::TableSetupColumn("Offset");
        ImGui::TableSetupColumn("Physical Address");
        ImGui::TableSetupColumn("Baseline");
        ImGui::TableSetupColumn("Submitted");
        ImGui::TableSetupColumn("Read-back");
        ImGui::TableSetupColumn("Result");
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
    const bool probe_target = CurrentPageIsProbeFixture();
    const bool write_target = CurrentPageIsVerifiedWriteTarget();
    const bool ownership_idle = !process_usage_.Busy();
    if (!physical_session_.CanUndo()) ImGui::BeginDisabled();
    if (ImGui::Button("Undo Byte Edit")) {
        SetOperationResult(
            physical_session_.Undo(),
            "Last physical-page byte edit undone.");
    }
    if (!physical_session_.CanUndo()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!physical_session_.CanRedo()) ImGui::BeginDisabled();
    if (ImGui::Button("Redo Byte Edit")) {
        SetOperationResult(
            physical_session_.Redo(),
            "Last physical-page byte edit redone.");
    }
    if (!physical_session_.CanRedo()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!physical_session_.IsDirty()) ImGui::BeginDisabled();
    if (ImGui::Button("Revert Local Edits")) {
        physical_session_.RevertAll();
        operation_status_ = "Local physical-page edits reverted.";
    }
    if (!physical_session_.IsDirty()) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_unlock = physical_session_.IsDirty() &&
        write_target && ownership_idle;
    if (!can_unlock) ImGui::BeginDisabled();
    if (ImGui::Button("Unlock One Physical Apply")) {
        if (ValidateCurrentPhysicalTargetForWrite()) {
            write_modal_.Open(WriteReviewPurpose::Apply);
        }
    }
    if (!can_unlock) ImGui::EndDisabled();
    ImGui::SameLine();
    const bool can_apply = physical_session_.IsDirty() &&
        physical_session_.WriteUnlocked() && write_target && ownership_idle;
    if (!can_apply) ImGui::BeginDisabled();
    if (ImGui::Button("Apply Changed Runs & Verify")) {
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
                    "Physical dirty runs were applied; the current core read-back comparison passed and the write gate is LOCKED.");
            }
            if (result && probe_target && probe_.IsOpen()) {
                const auto refreshed = probe_.Query();
                if (refreshed) {
                    probe_info_ = refreshed.Value();
                    probe_evidence_after_write_ = refreshed.Value();
                    probe_evidence_after_reload_.reset();
                    probe_evidence_after_rollback_.reset();
                    last_physical_evidence_path_.clear();
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
    const bool needs_probe_metadata_retry = probe_target &&
        (physical_session_.CanRollback() &&
         physical_session_.LastApplyVerified() &&
         !probe_evidence_after_write_.has_value()) ||
        (physical_session_.CanRollback() && reload_page_verified &&
         !probe_evidence_after_reload_.has_value()) ||
        (!physical_session_.CanRollback() && page_evidence.Complete() &&
         !probe_evidence_after_rollback_.has_value());
    if (needs_probe_metadata_retry) {
        if (ImGui::Button("Retry Probe Metadata (keep evidence)")) {
            RetryProbeMetadataForEvidence();
        }
    }
    if (physical_session_.CanRollback()) {
        const bool can_reload = !physical_session_.IsDirty() &&
            write_target && ownership_idle &&
            (!probe_target || probe_evidence_after_write_.has_value());
        if (!can_reload) ImGui::BeginDisabled();
        if (ImGui::Button("Independent Reload (keep rollback)")) {
            probe_evidence_after_reload_.reset();
            probe_evidence_after_rollback_.reset();
            last_physical_evidence_path_.clear();
            if (ValidateCurrentPhysicalTargetForWrite()) {
                const auto result =
                    physical_session_.ReloadPreservingRollback(backend_);
                if (!result) {
                    SetOperationResult(result, "");
                } else if (!probe_target) {
                    const auto& reloaded =
                        *physical_session_.Evidence().independent_reload;
                    last_physical_readback_.assign(
                        reloaded.begin(), reloaded.end());
                    last_physical_readback_status_ =
                        "Independent reload captured: 4096 bytes; full-page match; rollback snapshot preserved.";
                    operation_status_ =
                        "Independent 4096-byte reload matched the verified process-page write; rollback remains available.";
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
                                   physical_session_.Address().physical_address) {
                        probe_fixture_loaded_ = false;
                        probe_evidence_after_reload_.reset();
                        operation_status_ =
                            "Independent reload completed, but the probe identity changed; rollback remains locked.";
                    } else {
                        probe_info_ = refreshed.Value();
                        probe_evidence_after_reload_ = refreshed.Value();
                        const auto& reloaded =
                            *physical_session_.Evidence().independent_reload;
                        last_physical_readback_.assign(
                            reloaded.begin(), reloaded.end());
                        last_physical_readback_status_ =
                            "Independent reload evidence captured: 4096 bytes; full-page match; rollback snapshot preserved.";
                        operation_status_ =
                            "Independent 4096-byte reload matched the verified write; rollback snapshot remains available.";
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
                physical_session_.LastApplyVerified();
            const bool independent_reload_complete =
                physical_session_.Evidence().independent_reload.has_value() &&
                (!probe_target || probe_evidence_after_reload_.has_value());
            const bool can_unlock_rollback = write_target && ownership_idle &&
                (!independent_reload_required || independent_reload_complete);
            if (!can_unlock_rollback) ImGui::BeginDisabled();
            if (ImGui::Button("Unlock Rollback")) {
                if (ValidateCurrentPhysicalTargetForRollback()) {
                    write_modal_.Open(WriteReviewPurpose::Rollback);
                }
            }
            if (!can_unlock_rollback) ImGui::EndDisabled();
        } else {
            const bool can_rollback = write_target && ownership_idle;
            if (!can_rollback) ImGui::BeginDisabled();
            if (ImGui::Button("Rollback Previous Apply")) {
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
                            probe_info_ = refreshed.Value();
                            probe_evidence_after_rollback_ = refreshed.Value();
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
    if (ImGui::Button("Export Live Evidence Bundle")) {
        ExportPhysicalEvidence();
    }
    if (!can_export_evidence) ImGui::EndDisabled();
    if (!last_physical_evidence_path_.empty()) {
        ImGui::SameLine();
        if (ImGui::Button("Copy Evidence Path")) {
            ImGui::SetClipboardText(last_physical_evidence_path_.c_str());
        }
        ImGui::TextWrapped(
            "Evidence bundle: %s", last_physical_evidence_path_.c_str());
    }
    if (!write_target) {
        ImGui::TextDisabled(
            "Physical apply/rollback is disabled until a probe fixture or a "
            "writable 4 KiB PTView process mapping verifies this PFN.");
    } else if (!ownership_idle) {
        ImGui::TextDisabled(
            "Physical apply/rollback is disabled while PFN ownership analysis uses the backend.");
    } else if (physical_session_.CanRollback() &&
               physical_session_.LastApplyVerified() &&
               !physical_session_.Evidence().independent_reload.has_value()) {
        ImGui::TextDisabled(
            "Run Independent Reload (keep rollback) before unlocking rollback.");
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
            driver.GetError().message;
    } else if (!probe) {
        service_status_ = "Probe service status failed: " +
            probe.GetError().message;
    } else {
        service_status_ = "Service state refreshed.";
    }
}

void MainWindow::AttachSelectedProcess() {
    if (selected_process_index_ < 0 ||
        selected_process_index_ >= static_cast<int>(processes_.size())) return;
    DisconnectProcess();
    const auto& selected = processes_[static_cast<std::size_t>(selected_process_index_)];
    auto attached = Win32ProcessMemory::Attach(selected.pid, &backend_);
    if (!attached) {
        operation_status_ = attached.GetError().message;
        return;
    }
    process_memory_ = attached.TakeValue();
    memory_map_.Attach(process_memory_.get());
    process_memory_browser_.Attach(process_memory_.get());
    process_scanner_.Attach(process_memory_.get());
    pointer_scanner_.Attach(process_memory_.get());
    disassembly_.Attach(process_memory_.get());
    snapshots_.Attach(process_memory_.get());
    page_table_.SetPid(selected.pid);
    operation_status_ = "Attached to " + selected.name + " (PID " +
        std::to_string(selected.pid) + ").";
}

void MainWindow::DisconnectProcess() {
    memory_map_.Reset();
    process_memory_browser_.Reset();
    process_scanner_.Reset();
    pointer_scanner_.Reset();
    disassembly_.Attach(nullptr);
    snapshots_.Reset();
    if (process_memory_ != nullptr && process_memory_->WritesArmed()) {
        const auto locked = process_memory_->SetWritesArmed(false);
        if (!locked) {
            operation_status_ =
                "Process detach requested; explicit write-gate lock failed before handle close: " +
                locked.GetError().message;
        }
    }
    process_memory_.reset();
}

void MainWindow::ConnectBackend() {
    if (physical_session_.CanRollback()) {
        operation_status_ =
            "Reconnect blocked until the pending physical rollback is completed.";
        return;
    }
    if (process_usage_.Busy()) {
        operation_status_ =
            "Cancel the active PFN ownership query before reconnecting the driver.";
        return;
    }
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
    const auto result = backend_.Open();
    LogResultDiagnostic(
        result,
        DiagnosticEvent::DriverConnectSucceeded,
        DiagnosticEvent::DriverConnectFailed);
    SetOperationResult(result, "KDBG device connected and ABI validated.");
}

void MainWindow::QueryAndLoadProbeFixture() {
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
    const auto loaded = physical_session_.Load(backend_, address.Value());
    if (!loaded) {
        probe_fixture_loaded_ = false;
        probe_info_.reset();
        probe_status_ = loaded.GetError().message;
        operation_status_ = probe_status_;
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
        probe_evidence_after_reload_ = actual;
        operation_status_ =
            "Probe metadata after independent reload was recovered; rollback remains available.";
    } else if (physical_session_.CanRollback() &&
               physical_session_.LastApplyVerified()) {
        probe_evidence_after_write_ = actual;
        operation_status_ =
            "Probe metadata after verified apply was recovered; independent reload is now available.";
    } else if (!physical_session_.CanRollback() && evidence.Complete()) {
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

    const auto directory = ExecutableDirectory() / "evidence" /
        ("live-" + EvidenceTimestampUtc());
    std::error_code error;
    if (!std::filesystem::create_directories(directory, error) || error) {
        operation_status_ =
            "Unable to create the live evidence directory: " +
            error.message();
        return;
    }

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
        operation_status_ =
            "Unable to write all six 4096-byte evidence pages.";
        return;
    }

    std::ofstream metadata(
        directory / "metadata.json", std::ios::out | std::ios::trunc);
    if (!metadata) {
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
             << EvidenceTimestampUtc() << "Z\",\n"
             << "  \"page_size\": 4096,\n"
             << "  \"driver_abi_version\": "
             << backend_.Info().abi_version << ",\n"
             << "  \"pfn\": \""
             << HexValue(physical_session_.Address().pfn) << "\",\n"
             << "  \"physical_address\": \""
             << HexValue(
                    physical_session_.Address().physical_address, 16)
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
        operation_status_ = "Writing evidence metadata.json failed.";
        return;
    }

    last_physical_evidence_path_ = PathToUtf8(directory);
    operation_status_ =
        "Live evidence bundle exported: six exact 4096-byte pages plus metadata; write gate LOCKED.";
}

void MainWindow::LockAllWrites() {
    std::vector<std::string> failures;
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
        operation_status_ = "All process and physical write gates report LOCKED.";
        return;
    }
    LogDiagnostic(DiagnosticEvent::PhysicalGateLockFailed);
    operation_status_ = "CRITICAL: not every write gate could be confirmed locked";
    for (const auto& failure : failures) operation_status_ += " | " + failure;
}

bool MainWindow::CurrentPageIsProbeFixture() const noexcept {
    return probe_fixture_loaded_ && probe_.IsOpen() &&
        probe_service_running_.value_or(false) &&
        probe_info_.has_value() && physical_session_.HasPage() &&
        probe_info_->byte_count == kPhysicalPageSize &&
        physical_session_.Address().pfn == probe_info_->pfn &&
        physical_session_.Address().physical_address ==
             probe_info_->physical_address;
}

std::optional<VerifiedProcessPhysicalTarget>
MainWindow::CurrentPageProcessTarget() const noexcept {
    if (!physical_session_.HasPage() || process_memory_ == nullptr) {
        return std::nullopt;
    }
    const auto target =
        page_table_.CurrentProcessTarget(physical_session_.Address());
    if (!target.has_value() ||
        target->pid != process_memory_->ProcessId()) {
        return std::nullopt;
    }
    return target;
}

bool MainWindow::CurrentPageIsVerifiedWriteTarget() const noexcept {
    return CurrentPageIsProbeFixture() ||
        CurrentPageProcessTarget().has_value();
}

bool MainWindow::ValidateCurrentPhysicalTargetForWrite() {
    if (CurrentPageIsProbeFixture()) {
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
    if (process_memory_ == nullptr ||
        revalidated.Value().pid != process_memory_->ProcessId()) {
        operation_status_ =
            "Physical write review blocked: the attached process changed.";
        return false;
    }
    operation_status_ =
        "Verified process physical target revalidated: PID " +
        std::to_string(revalidated.Value().pid) + " / PFN " +
        HexValue(revalidated.Value().pfn) + ".";
    return true;
}

bool MainWindow::ValidateCurrentPhysicalTargetForRollback() {
    if (CurrentPageIsProbeFixture()) {
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
    return process_memory_ != nullptr &&
        revalidated.Value().pid == process_memory_->ProcessId();
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
    if (!CurrentPageIsProbeFixture()) {
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
        " evidence captured: 4096 read-back bytes; " +
        std::to_string(last_physical_diffs_.size()) +
        " submitted byte(s), " + std::to_string(mismatch_count) +
        " mismatch(es).";
    if (mismatch_count != 0) {
        operation_status_ +=
            " | CRITICAL: the independent UI read-back found " +
            std::to_string(mismatch_count) + " submitted-byte mismatch(es).";
    }
}

void MainWindow::DrawAboutDialog() {
    if (about_open_requested_) {
        ImGui::OpenPopup("About KDBG");
        about_open_requested_ = false;
    }
    if (!ImGui::BeginPopupModal(
            "About KDBG", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    ImGui::Text("KDBG %s", kVersion);
    ImGui::Text("Build ID: %s", kBuildId);
    ImGui::Separator();
    ImGui::TextWrapped(
        "Windows x64 physical/process-memory research UI for an authorized, "
        "snapshot-capable disposable assignment VM. KDBG never transmits "
        "memory externally by itself.");
    ImGui::Text("Backend: %s | ABI %u | physical gate %s",
        backend_.Info().connected ? backend_.Info().name.c_str() : "disconnected",
        backend_.Info().abi_version,
        backend_.Info().write_enabled ? "ARMED" : "LOCKED");
    ImGui::Separator();
    ImGui::TextUnformatted("Licenses / attribution");
    ImGui::BulletText("KDBG original code: repository license and attribution files");
    ImGui::BulletText("Dear ImGui and imgui_memory_editor: MIT License");
    ImGui::BulletText("Zydis and Zycore: MIT License");
    ImGui::BulletText("Optional MemProcFS integration remains out-of-process (AGPL-3.0)");
    ImGui::TextDisabled(
        "See THIRD_PARTY.lock.json and the packaged licenses directory for full notices.");
    ImGui::Separator();
    ImGui::TextWrapped(
        "Local diagnostics: %%LOCALAPPDATA%%\\KDBG\\logs. The event log "
        "rotates at 1 MiB across three files and excludes memory bytes, "
        "credentials, and user paths. MiniDumpNormal crash dumps stay local; "
        "KDBG does not transmit them.");
    if (ImGui::Button("Copy build ID")) ImGui::SetClipboardText(kBuildId);
    ImGui::SameLine();
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void MainWindow::SetOperationResult(
    const Result<void>& result,
    std::string success) {
    if (result) {
        operation_status_ = std::move(success);
        return;
    }
    const auto& error = result.GetError();
    operation_status_ = error.message;
    if (!error.operation.empty()) {
        operation_status_ += " [" + error.operation + "]";
    }
    if (error.native_code != 0) {
        operation_status_ += " | native=" +
            std::to_string(error.native_code);
    }
}

std::string MainWindow::AttachedProcessName() const {
    if (process_memory_ == nullptr) return {};
    const auto it = std::find_if(
        processes_.begin(), processes_.end(),
        [&](const ProcessInfo& process) {
            return process.pid == process_memory_->ProcessId();
        });
    return it == processes_.end() ? std::string("unknown") : it->name;
}

}  // namespace kdbg

#pragma once

#include "app/ui/DisassemblyPanel.h"
#include "app/ui/HexEditorPanel.h"
#include "app/ui/KernelExplorerPanel.h"
#include "app/ui/MemoryMapPanel.h"
#include "app/ui/PageTablePanel.h"
#include "app/ui/PfnInputPanel.h"
#include "app/ui/PointerScanPanel.h"
#include "app/ui/ProcessMemoryPanel.h"
#include "app/ui/ProcessScannerPanel.h"
#include "app/ui/ProcessUsagePanel.h"
#include "app/ui/SnapshotPanel.h"
#include "app/ui/WriteReviewModal.h"
#include "core/memory/KDbgBackend.h"
#include "core/memory/PhysicalPageSession.h"
#include "core/process/ProcessCatalog.h"
#include "core/process/Win32ProcessMemory.h"
#include "core/memory/ProbeClient.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace kdbg {

class MainWindow {
public:
    MainWindow();
    ~MainWindow();

    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

    void Draw();

private:
    enum class LifecycleAction {
        None,
        BringLabOnline,
        InstallDriver,
        StartDriver,
        StopDriver,
        RemoveDriver,
        InstallProbe,
        StartProbe,
        StopProbe,
        RemoveProbe
    };

    enum class DeferredAction {
        None,
        LockAllWrites,
        DisconnectProcess,
        ConnectBackend,
        AttachProcess,
        StartLifecycle
    };

    struct LifecycleOutcome {
        LifecycleAction action{LifecycleAction::None};
        bool succeeded{false};
        bool cancelled{false};
        std::string message;
        Error error;
    };

    struct AnalysisEvidenceOutcome {
        bool succeeded{false};
        bool cancelled{false};
        std::string path;
        std::string message;
        Error error;
    };

    void DrawTabbedWorkspace();
    void DrawDockedWorkspace();
    void DrawMenuBar();
    void DrawStatusBar();
    void DrawDriverTab();
    void DrawProcessSelector();
    void DrawPhysicalMemoryTab();
    void DrawMemoryMapTab();
    void DrawProcessMemoryTab();
    void DrawProcessScannerTab();
    void DrawPointerScannerTab();
    void DrawDisassemblyTab();
    void DrawKernelExplorerTab();
    void DrawSnapshotTab();
    void DrawTranslationTab();
    void DrawPfnOwnershipTab();
    void DrawAnalysisEvidence();
    void DrawDiffPanel();
    void DrawPhysicalReadback();
    void DrawPhysicalActions();
    void DrawAboutDialog();
    void HandleShortcuts();
    void StartLifecycleAction(LifecycleAction action);
    void LaunchLifecycleAction(LifecycleAction action);
    void PollLifecycleAction();
    void QueueDeferredAction(
        DeferredAction action,
        LifecycleAction lifecycle = LifecycleAction::None,
        std::optional<ProcessInfo> process = std::nullopt);
    void PollDeferredAction();
    void RequestProcessIoCancellation() noexcept;
    void RequestBackendIoCancellation() noexcept;
    [[nodiscard]] bool FinishDisconnectProcess();
    void FinishConnectBackend();
    [[nodiscard]] bool FinishLockAllWrites();

    void RefreshProcesses();
    void RefreshServiceStates();
    void AttachSelectedProcess();
    void DisconnectProcess();
    void ConnectBackend();
    void QueryAndLoadProbeFixture();
    void RetryProbeMetadataForEvidence();
    void ClearProbeEvidence() noexcept;
    void ExportPhysicalEvidence();
    void StartAnalysisEvidenceExport();
    void PollAnalysisEvidenceExport();
    void CancelAnalysisEvidenceExport() noexcept;
    void LockAllWrites();
    bool ValidateProbeTargetForWrite();
    bool ValidateProbeTargetForRollback();
    bool ValidateCurrentPhysicalTargetForWrite();
    bool ValidateCurrentPhysicalTargetForRollback();
    void CapturePhysicalReadback(
        std::vector<ByteDiff> submitted_diffs,
        std::string operation_name);
    void SetOperationResult(const Result<void>& result, std::string success);
    [[nodiscard]] std::string AttachedProcessName() const;
    [[nodiscard]] bool CurrentPageMatchesProbeIdentity() const noexcept;
    [[nodiscard]] bool CurrentPageIsProbeFixture() const noexcept;
    [[nodiscard]] std::optional<VerifiedProcessPhysicalTarget>
    CurrentPageProcessTarget() const noexcept;
    [[nodiscard]] bool CurrentPageIsVerifiedWriteTarget() const noexcept;
    [[nodiscard]] bool LifecycleBusy() const noexcept;
    [[nodiscard]] bool ProcessIoBusy() const noexcept;
    [[nodiscard]] bool BackendIoBusy() const noexcept;

    KDbgBackend backend_;
    BackendInfo cached_backend_info_;
    ProbeClient probe_;
    std::vector<ProcessInfo> processes_;
    int selected_process_index_{-1};
    std::unique_ptr<Win32ProcessMemory> process_memory_;
    std::array<char, 128> process_filter_{};

    PhysicalPageSession physical_session_;
    PfnInputPanel pfn_input_;
    HexEditorPanel hex_editor_;
    PageTablePanel page_table_;
    ProcessUsagePanel process_usage_;
    WriteReviewModal write_modal_;
    MemoryMapPanel memory_map_;
    ProcessMemoryPanel process_memory_browser_;
    ProcessScannerPanel process_scanner_;
    PointerScanPanel pointer_scanner_;
    DisassemblyPanel disassembly_;
    KernelExplorerPanel kernel_explorer_;
    SnapshotPanel snapshots_;

    std::array<char, 512> driver_path_{};
    std::array<char, 512> probe_driver_path_{};
    std::future<LifecycleOutcome> lifecycle_future_;
    std::atomic_bool lifecycle_cancel_requested_{false};
    std::atomic_uint32_t lifecycle_step_{0};
    LifecycleAction lifecycle_action_{LifecycleAction::None};
    DeferredAction deferred_action_{DeferredAction::None};
    LifecycleAction deferred_lifecycle_{LifecycleAction::None};
    std::optional<ProcessInfo> deferred_process_;
    bool deferred_lock_requested_{false};
    std::optional<bool> driver_service_running_;
    std::optional<bool> probe_service_running_;
    std::optional<ProbeInfo> probe_info_;
    std::optional<ProbeInfo> probe_evidence_baseline_;
    std::optional<ProbeInfo> probe_evidence_after_write_;
    std::optional<ProbeInfo> probe_evidence_after_reload_;
    std::optional<ProbeInfo> probe_evidence_after_rollback_;
    bool probe_fixture_loaded_{false};
    std::string service_status_;
    std::string probe_status_;
    std::string operation_status_;
    std::vector<ByteDiff> last_physical_diffs_;
    std::vector<std::uint8_t> last_physical_readback_;
    std::string last_physical_readback_status_;
    std::string last_physical_evidence_path_;
    std::array<char, 512> fixture_info_path_{};
    std::future<AnalysisEvidenceOutcome> analysis_evidence_future_;
    std::atomic_bool analysis_evidence_cancel_{false};
    std::atomic_uint32_t analysis_evidence_progress_{0};
    std::string analysis_evidence_status_;
    std::string last_analysis_evidence_path_;
    bool select_driver_tab_{false};
    bool select_process_memory_tab_{false};
    bool select_physical_memory_tab_{false};
    bool select_page_tables_tab_{false};
    bool select_pfn_ownership_tab_{false};
    bool about_open_requested_{false};
    bool dock_layout_checked_{false};
};

}  // namespace kdbg

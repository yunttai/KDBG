#pragma once

#include "app/ui/DisassemblyPanel.h"
#include "app/ui/HexEditorPanel.h"
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
#include <cstdint>
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
    void DrawSnapshotTab();
    void DrawTranslationTab();
    void DrawPfnOwnershipTab();
    void DrawDiffPanel();
    void DrawPhysicalReadback();
    void DrawPhysicalActions();
    void DrawAboutDialog();
    void HandleShortcuts();

    void RefreshProcesses();
    void RefreshServiceStates();
    void AttachSelectedProcess();
    void DisconnectProcess();
    void ConnectBackend();
    void QueryAndLoadProbeFixture();
    void RetryProbeMetadataForEvidence();
    void ClearProbeEvidence() noexcept;
    void ExportPhysicalEvidence();
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
    [[nodiscard]] bool CurrentPageIsProbeFixture() const noexcept;
    [[nodiscard]] std::optional<VerifiedProcessPhysicalTarget>
    CurrentPageProcessTarget() const noexcept;
    [[nodiscard]] bool CurrentPageIsVerifiedWriteTarget() const noexcept;

    KDbgBackend backend_;
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
    SnapshotPanel snapshots_;

    std::array<char, 512> driver_path_{};
    std::array<char, 512> probe_driver_path_{};
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
    bool select_driver_tab_{false};
    bool select_process_memory_tab_{false};
    bool select_physical_memory_tab_{false};
    bool select_page_tables_tab_{false};
    bool select_pfn_ownership_tab_{false};
    bool about_open_requested_{false};
    bool dock_layout_checked_{false};
};

}  // namespace kdbg

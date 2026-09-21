#pragma once

#include "core/process/IProcessMemory.h"
#include "core/scanner/MemoryScanner.h"
#include "core/scanner/WatchList.h"
#include "app/ui/ProcessScannerState.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace kdbg {

class ProcessScannerPanel {
public:
    ProcessScannerPanel();
    ~ProcessScannerPanel();

    void Attach(IProcessMemory* memory);
    void Draw();
    void Reset();
    void CancelAndWait() noexcept;
    void RevokeWriteAuthorization() noexcept;
    [[nodiscard]] bool Busy() const noexcept;
    [[nodiscard]] bool WriteAuthorizationActive() const noexcept;

private:
    struct PublishedScanSnapshot {
        std::uint64_t generation{0};
        ScanValueType type{ScanValueType::Int32};
        bool hexadecimal{false};
        ScanSummary summary{};
        ScanReadReport read_report{};
        ScanPublicationState publication_state{ScanPublicationState::Failed};
        std::vector<ScanCandidate> candidates;
    };

    struct WatchBatchOutcome {
        std::uint64_t generation{0};
        std::size_t begin{0};
        std::size_t completed{0};
        std::size_t total{0};
        std::vector<WatchEntry> rows;
        std::optional<Error> error;
        bool cancelled{false};
        bool freeze_mode{false};
        bool freeze_fail_closed{false};
        bool gate_locked{false};
        bool gate_lock_retry_used{false};
        std::size_t disarmed_entries{0};
        std::optional<Error> gate_lock_error;
    };

    ScanQuery BuildQuery() const;
    void StartScan(bool first);
    void StopScanWorker();
    void ResetScan();
    void PublishScanCompletion(
        std::uint64_t generation,
        const ScanQuery& query,
        const Result<ScanSummary>& result,
        const ScanReadReport& read_report);
    [[nodiscard]] std::shared_ptr<const PublishedScanSnapshot>
    ScanSnapshot() const;
    [[nodiscard]] ScanProgress CurrentScanProgress() const;
    [[nodiscard]] std::optional<Error> CurrentScanError() const;

    void StartWatchBatch(bool include_freeze, bool manual_pass);
    void PollWatchWorker();
    void StopWatchWorker();
    void PublishAllWatches();
    void RequestFullWatchRefresh();
    [[nodiscard]] bool WatchActionsBusy() const noexcept;
    void DrawScanControls();
    void DrawResults();
    void DrawWatchList();
    void DrawWriteGateModal();
    void SetStatus(const Result<void>& result, std::string success);

    IProcessMemory* memory_{nullptr};
    std::unique_ptr<MemoryScanner> scanner_;
    std::unique_ptr<WatchList> watches_;
    std::jthread scan_worker_;
    std::atomic_bool scan_running_{false};
    std::atomic_uint64_t scan_generation_{0};
    std::atomic_uint64_t scan_telemetry_id_{0};
    mutable std::mutex scan_mutex_;
    ScanProgress scan_progress_{};
    std::optional<Error> scan_error_;
    std::shared_ptr<const PublishedScanSnapshot> published_scan_;

    std::jthread watch_worker_;
    std::atomic_bool watch_running_{false};
    std::atomic_bool watch_cancel_requested_{false};
    std::atomic_uint64_t watch_generation_{0};
    std::atomic_size_t watch_batch_completed_{0};
    mutable std::mutex watch_mutex_;
    std::optional<WatchBatchOutcome> watch_outcome_;
    std::vector<WatchEntry> published_watches_;
    std::size_t watch_cursor_{0};
    std::size_t watch_cycle_completed_{0};
    std::size_t watch_cycle_total_{0};
    std::size_t watch_failures_{0};
    std::optional<Error> watch_last_error_;
    std::string freeze_fail_closed_status_;
    bool watch_full_refresh_requested_{false};
    bool watch_manual_pass_active_{false};
    bool watch_last_overrun_{false};
    bool write_authorization_active_{false};
    std::chrono::steady_clock::time_point next_watch_refresh_{};

    int value_type_index_{4};
    int compare_index_{0};
    std::array<char, 256> value_{};
    std::array<char, 256> second_value_{};
    bool hexadecimal_{false};
    bool writable_only_{false};
    bool include_executable_{true};
    int alignment_{4};
    int max_results_{250000};

    std::uint64_t selected_watch_id_{0};
    std::array<char, 256> watch_value_{};
    std::array<char, 32> manual_address_{};
    std::array<char, 128> manual_description_{};
    std::array<char, 512> address_list_path_{};
    int manual_type_index_{4};
    bool manual_hexadecimal_{false};
    std::array<char, 32> write_confirmation_{};
    std::string status_;
};

}  // namespace kdbg

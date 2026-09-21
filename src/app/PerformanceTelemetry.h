#pragma once

#include "core/scanner/MemoryScanner.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace kdbg {

enum class TelemetryStartStatus : std::uint64_t {
    NotRequested = 0,
    Started = 1,
    InvalidConfiguration = 2,
    PathNotAbsolute = 3,
    PathNotLocalFixedDrive = 4,
    DirectoryCreationFailed = 5,
    ParentResolutionFailed = 6,
    InitialSnapshotWriteFailed = 7,
    WriterStartFailed = 8,
    UnsupportedPlatform = 9
};

class PerformanceTelemetry {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    struct Config {
        std::filesystem::path output_path;
        std::chrono::microseconds frame_stall_threshold{
            std::chrono::milliseconds(50)};
        std::chrono::milliseconds flush_interval{
            std::chrono::seconds(1)};
        std::size_t max_scan_records{64};
    };

    PerformanceTelemetry() = default;
    ~PerformanceTelemetry();

    PerformanceTelemetry(const PerformanceTelemetry&) = delete;
    PerformanceTelemetry& operator=(const PerformanceTelemetry&) = delete;

    [[nodiscard]] bool Start(Config config);
    [[nodiscard]] bool StartFromEnvironment();
    void Stop() noexcept;
    [[nodiscard]] bool Enabled() const noexcept;
    [[nodiscard]] TelemetryStartStatus LastStartStatus() const noexcept;
    [[nodiscard]] std::uint64_t LastStartNativeCode() const noexcept;

    void RecordFrame(TimePoint now = Clock::now()) noexcept;
    void RecordFrameInterval(std::chrono::microseconds interval) noexcept;

    [[nodiscard]] std::uint64_t BeginProcessScan(
        bool first,
        TimePoint now = Clock::now()) noexcept;
    [[nodiscard]] std::uint64_t BeginProcessScanAt(
        bool first,
        std::chrono::microseconds session_elapsed) noexcept;
    void RecordProcessScanProgress(
        std::uint64_t scan_id,
        const ScanProgress& progress) noexcept;
    void RequestProcessScanCancellation(
        std::uint64_t scan_id,
        TimePoint now = Clock::now()) noexcept;
    void RequestProcessScanCancellationAt(
        std::uint64_t scan_id,
        std::chrono::microseconds session_elapsed) noexcept;
    void FinishProcessScan(
        std::uint64_t scan_id,
        const ScanProgress& final_progress,
        const ScanReadReport& read_report,
        bool succeeded,
        bool cancelled,
        TimePoint now = Clock::now()) noexcept;
    void FinishProcessScanAt(
        std::uint64_t scan_id,
        const ScanProgress& final_progress,
        const ScanReadReport& read_report,
        bool succeeded,
        bool cancelled,
        std::chrono::microseconds session_elapsed) noexcept;

private:
    struct ScanRecord {
        std::uint64_t id{0};
        bool first{false};
        std::uint64_t started_us{0};
        std::uint64_t finished_us{0};
        std::uint64_t regions_requested{0};
        std::uint64_t regions_completed{0};
        std::uint64_t requested_bytes{0};
        std::uint64_t completed_bytes{0};
        std::uint64_t io_requests{0};
        std::uint64_t io_completed{0};
        std::uint64_t read_failures{0};
        std::uint64_t short_reads{0};
        std::uint64_t cancellation_latency_us{0};
        bool cancellation_requested{false};
        bool partial{false};
        bool succeeded{false};
        bool cancelled{false};
    };

    [[nodiscard]] std::chrono::microseconds Elapsed(TimePoint now) const noexcept;
    void WriterMain(std::stop_token stop_token) noexcept;
    [[nodiscard]] std::uint64_t WriteSnapshot(bool count_failure) noexcept;
    [[nodiscard]] std::filesystem::path NextTemporaryPath() noexcept;
    [[nodiscard]] std::string BuildJson() const;
    void ResetCounters() noexcept;

    Config config_{};
    TimePoint session_start_{};
    std::jthread writer_;
    mutable std::mutex writer_mutex_;
    std::condition_variable_any writer_cv_;
    std::atomic_bool enabled_{false};
    std::atomic<TelemetryStartStatus> last_start_status_{
        TelemetryStartStatus::NotRequested};
    std::atomic_uint64_t last_start_native_code_{0};
    std::uint64_t process_id_{0};
    std::uint64_t process_session_nonce_{0};
    std::atomic_uint64_t temporary_sequence_{0};

    std::atomic<std::int64_t> last_frame_tick_us_{-1};
    std::atomic_uint64_t frames_observed_{0};
    std::atomic_uint64_t frame_intervals_observed_{0};
    std::atomic_uint64_t frame_stalls_{0};
    std::atomic_uint64_t max_frame_interval_us_{0};

    std::atomic_uint64_t next_scan_id_{1};
    std::atomic_uint64_t active_scan_id_{0};
    std::atomic_bool active_scan_first_{false};
    std::atomic_uint64_t active_scan_started_us_{0};
    std::atomic_uint64_t active_regions_requested_{0};
    std::atomic_uint64_t active_regions_completed_{0};
    std::atomic_uint64_t active_progress_bytes_{0};
    std::atomic<std::int64_t> active_cancel_requested_us_{-1};

    std::atomic_uint64_t scans_started_{0};
    std::atomic_uint64_t scans_succeeded_{0};
    std::atomic_uint64_t scans_partial_{0};
    std::atomic_uint64_t scans_failed_{0};
    std::atomic_uint64_t scans_cancelled_{0};
    std::atomic_uint64_t total_regions_requested_{0};
    std::atomic_uint64_t total_regions_completed_{0};
    std::atomic_uint64_t total_requested_bytes_{0};
    std::atomic_uint64_t total_completed_bytes_{0};
    std::atomic_uint64_t total_io_requests_{0};
    std::atomic_uint64_t total_io_completed_{0};
    std::atomic_uint64_t total_read_failures_{0};
    std::atomic_uint64_t total_short_reads_{0};
    std::atomic_uint64_t max_cancellation_latency_us_{0};
    std::atomic_uint64_t records_evicted_{0};
    std::atomic_uint64_t writer_errors_{0};

    mutable std::mutex records_mutex_;
    std::vector<ScanRecord> records_;
};

[[nodiscard]] PerformanceTelemetry& RuntimePerformanceTelemetry();

}  // namespace kdbg

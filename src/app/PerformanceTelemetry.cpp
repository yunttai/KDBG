#include "app/PerformanceTelemetry.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cwctype>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <Windows.h>
#endif

namespace kdbg {
namespace {

constexpr std::size_t kMaximumScanRecords = 256;
std::atomic_uint64_t g_process_session_sequence{0};

struct PathValidation {
    TelemetryStartStatus status{TelemetryStartStatus::Started};
    std::uint64_t native_code{0};
};

void UpdateMaximum(
    std::atomic_uint64_t& destination,
    std::uint64_t candidate) noexcept {
    auto current = destination.load(std::memory_order_relaxed);
    while (current < candidate &&
           !destination.compare_exchange_weak(
               current,
               candidate,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

std::uint64_t NonNegativeMicroseconds(
    std::chrono::microseconds value) noexcept {
    return value.count() <= 0
        ? 0
        : static_cast<std::uint64_t>(value.count());
}

std::optional<std::filesystem::path> EnvironmentOutputPath() {
#if defined(_WIN32)
    wchar_t* value = nullptr;
    std::size_t length = 0;
    if (_wdupenv_s(&value, &length, L"KDBG_RUNTIME_TELEMETRY") != 0 ||
        value == nullptr) {
        std::free(value);
        return std::nullopt;
    }
    const std::wstring copy(value);
    std::free(value);
    if (copy.empty()) return std::nullopt;
    return std::filesystem::path(copy);
#else
    const char* value = std::getenv("KDBG_RUNTIME_TELEMETRY");
    if (value == nullptr || *value == '\0') return std::nullopt;
    return std::filesystem::path(value);
#endif
}

#if defined(_WIN32)

bool HasForbiddenWindowsPrefix(std::wstring value) {
    std::replace(value.begin(), value.end(), L'/', L'\\');
    return value.starts_with(L"\\\\") ||
        value.starts_with(L"\\??\\") ||
        value.starts_with(L"\\Device\\");
}

PathValidation ValidateLocalFixedPath(
    const std::filesystem::path& path,
    bool require_filename) {
    if (HasForbiddenWindowsPrefix(path.native())) {
        return {TelemetryStartStatus::PathNotLocalFixedDrive, 0};
    }
    if (!path.is_absolute() || !path.has_root_name() ||
        !path.has_root_directory()) {
        return {TelemetryStartStatus::PathNotAbsolute, 0};
    }
    const auto root_name = path.root_name().native();
    if (root_name.size() != 2 || root_name[1] != L':' ||
        std::iswalpha(root_name[0]) == 0) {
        return {TelemetryStartStatus::PathNotLocalFixedDrive, 0};
    }
    if (require_filename &&
        (!path.has_filename() || path.filename() == L"." ||
         path.filename() == L"..")) {
        return {TelemetryStartStatus::InvalidConfiguration, 0};
    }
    const auto relative = path.relative_path().native();
    if (relative.find(L':') != std::wstring::npos) {
        return {TelemetryStartStatus::PathNotLocalFixedDrive, 0};
    }
    std::wstring root;
    root.push_back(static_cast<wchar_t>(std::towupper(root_name[0])));
    root.append(L":\\");
    const UINT drive_type = GetDriveTypeW(root.c_str());
    if (drive_type != DRIVE_FIXED) {
        return {
            TelemetryStartStatus::PathNotLocalFixedDrive,
            static_cast<std::uint64_t>(drive_type)};
    }
    return {};
}

PathValidation ValidateResolvedParent(
    const std::filesystem::path& parent) {
    HANDLE directory = CreateFileW(
        parent.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (directory == INVALID_HANDLE_VALUE) {
        return {
            TelemetryStartStatus::ParentResolutionFailed,
            static_cast<std::uint64_t>(GetLastError())};
    }
    std::vector<wchar_t> resolved(32768);
    const DWORD length = GetFinalPathNameByHandleW(
        directory,
        resolved.data(),
        static_cast<DWORD>(resolved.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    DWORD final_error = ERROR_SUCCESS;
    if (length == 0) {
        final_error = GetLastError();
    } else if (length >= resolved.size()) {
        final_error = ERROR_BUFFER_OVERFLOW;
    }
    CloseHandle(directory);
    if (final_error != ERROR_SUCCESS) {
        return {
            TelemetryStartStatus::ParentResolutionFailed,
            static_cast<std::uint64_t>(final_error)};
    }
    std::wstring final_path(resolved.data(), length);
    constexpr std::wstring_view extended_prefix = L"\\\\?\\";
    constexpr std::wstring_view extended_unc_prefix = L"\\\\?\\UNC\\";
    if (final_path.starts_with(extended_unc_prefix)) {
        return {TelemetryStartStatus::PathNotLocalFixedDrive, DRIVE_REMOTE};
    }
    if (final_path.starts_with(extended_prefix)) {
        final_path.erase(0, extended_prefix.size());
    }
    return ValidateLocalFixedPath(std::filesystem::path(final_path), false);
}

std::pair<std::uint64_t, std::uint64_t> ProcessIdentity() noexcept {
    const auto process_id = static_cast<std::uint64_t>(GetCurrentProcessId());
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    std::uint64_t nonce = GetProcessTimes(
            GetCurrentProcess(), &creation, &exit, &kernel, &user) != FALSE
        ? (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) |
            static_cast<std::uint64_t>(creation.dwLowDateTime)
        : static_cast<std::uint64_t>(GetTickCount64());
    const auto sequence = g_process_session_sequence.fetch_add(
        1, std::memory_order_relaxed) + 1;
    nonce ^= sequence * 0x9E3779B97F4A7C15ULL;
    return {process_id, nonce};
}

#endif

}  // namespace

PerformanceTelemetry::~PerformanceTelemetry() { Stop(); }

bool PerformanceTelemetry::Start(Config config) {
    Stop();
    last_start_native_code_.store(0, std::memory_order_relaxed);
    if (config.output_path.empty() ||
        config.frame_stall_threshold.count() <= 0 ||
        config.flush_interval.count() <= 0 ||
        config.max_scan_records == 0) {
        last_start_status_.store(
            TelemetryStartStatus::InvalidConfiguration,
            std::memory_order_release);
        return false;
    }
#if !defined(_WIN32)
    last_start_status_.store(
        TelemetryStartStatus::UnsupportedPlatform,
        std::memory_order_release);
    return false;
#else
    try {
    const auto syntax = ValidateLocalFixedPath(config.output_path, true);
    if (syntax.status != TelemetryStartStatus::Started) {
        last_start_native_code_.store(
            syntax.native_code, std::memory_order_relaxed);
        last_start_status_.store(syntax.status, std::memory_order_release);
        return false;
    }
    config.output_path = config.output_path.lexically_normal();
    std::error_code directory_error;
    const auto parent = config.output_path.parent_path();
    auto existing_parent = parent;
    while (!std::filesystem::exists(existing_parent, directory_error)) {
        if (directory_error) {
            last_start_native_code_.store(
                static_cast<std::uint64_t>(directory_error.value()),
                std::memory_order_relaxed);
            last_start_status_.store(
                TelemetryStartStatus::ParentResolutionFailed,
                std::memory_order_release);
            return false;
        }
        const auto next = existing_parent.parent_path();
        if (next.empty() || next == existing_parent) {
            last_start_status_.store(
                TelemetryStartStatus::ParentResolutionFailed,
                std::memory_order_release);
            return false;
        }
        existing_parent = next;
    }
    const auto existing_resolved = ValidateResolvedParent(existing_parent);
    if (existing_resolved.status != TelemetryStartStatus::Started) {
        last_start_native_code_.store(
            existing_resolved.native_code, std::memory_order_relaxed);
        last_start_status_.store(
            existing_resolved.status, std::memory_order_release);
        return false;
    }
    directory_error.clear();
    std::filesystem::create_directories(parent, directory_error);
    if (directory_error) {
        last_start_native_code_.store(
            static_cast<std::uint64_t>(directory_error.value()),
            std::memory_order_relaxed);
        last_start_status_.store(
            TelemetryStartStatus::DirectoryCreationFailed,
            std::memory_order_release);
        return false;
    }
    const auto resolved = ValidateResolvedParent(parent);
    if (resolved.status != TelemetryStartStatus::Started) {
        last_start_native_code_.store(
            resolved.native_code, std::memory_order_relaxed);
        last_start_status_.store(resolved.status, std::memory_order_release);
        return false;
    }

    config.max_scan_records = std::min(
        config.max_scan_records, kMaximumScanRecords);
    config_ = std::move(config);
    const auto [process_id, session_nonce] = ProcessIdentity();
    process_id_ = process_id;
    process_session_nonce_ = session_nonce;
    ResetCounters();
    session_start_ = Clock::now();

    const auto initial_write = WriteSnapshot(false);
    if (initial_write != ERROR_SUCCESS) {
        last_start_native_code_.store(
            initial_write, std::memory_order_relaxed);
        last_start_status_.store(
            TelemetryStartStatus::InitialSnapshotWriteFailed,
            std::memory_order_release);
        return false;
    }
    try {
        writer_ = std::jthread(
            [this](std::stop_token token) { WriterMain(token); });
    } catch (...) {
        last_start_status_.store(
            TelemetryStartStatus::WriterStartFailed,
            std::memory_order_release);
        return false;
    }
    enabled_.store(true, std::memory_order_release);
    last_start_status_.store(
        TelemetryStartStatus::Started, std::memory_order_release);
    return true;
    } catch (...) {
        last_start_native_code_.store(
            ERROR_NOT_ENOUGH_MEMORY, std::memory_order_relaxed);
        last_start_status_.store(
            TelemetryStartStatus::InvalidConfiguration,
            std::memory_order_release);
        return false;
    }
#endif
}

bool PerformanceTelemetry::StartFromEnvironment() {
    const auto output = EnvironmentOutputPath();
    if (!output.has_value()) {
        last_start_native_code_.store(0, std::memory_order_relaxed);
        last_start_status_.store(
            TelemetryStartStatus::NotRequested,
            std::memory_order_release);
        return false;
    }
    Config config{};
    config.output_path = *output;
    return Start(std::move(config));
}

void PerformanceTelemetry::Stop() noexcept {
    enabled_.store(false, std::memory_order_release);
    if (writer_.joinable()) {
        writer_.request_stop();
        writer_cv_.notify_all();
        writer_.join();
    }
}

bool PerformanceTelemetry::Enabled() const noexcept {
    return enabled_.load(std::memory_order_acquire);
}

TelemetryStartStatus PerformanceTelemetry::LastStartStatus() const noexcept {
    return last_start_status_.load(std::memory_order_acquire);
}

std::uint64_t PerformanceTelemetry::LastStartNativeCode() const noexcept {
    return last_start_native_code_.load(std::memory_order_relaxed);
}

std::chrono::microseconds PerformanceTelemetry::Elapsed(
    TimePoint now) const noexcept {
    if (now <= session_start_) return std::chrono::microseconds::zero();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now - session_start_);
}

void PerformanceTelemetry::RecordFrame(TimePoint now) noexcept {
    if (!Enabled()) return;
    frames_observed_.fetch_add(1, std::memory_order_relaxed);
    const auto tick = static_cast<std::int64_t>(
        NonNegativeMicroseconds(Elapsed(now)));
    const auto previous = last_frame_tick_us_.exchange(
        tick, std::memory_order_relaxed);
    if (previous >= 0 && tick >= previous) {
        RecordFrameInterval(std::chrono::microseconds(tick - previous));
        frames_observed_.fetch_sub(1, std::memory_order_relaxed);
    }
}

void PerformanceTelemetry::RecordFrameInterval(
    std::chrono::microseconds interval) noexcept {
    if (!Enabled()) return;
    frames_observed_.fetch_add(1, std::memory_order_relaxed);
    const auto interval_us = NonNegativeMicroseconds(interval);
    frame_intervals_observed_.fetch_add(1, std::memory_order_relaxed);
    UpdateMaximum(max_frame_interval_us_, interval_us);
    if (interval_us >= static_cast<std::uint64_t>(
            config_.frame_stall_threshold.count())) {
        frame_stalls_.fetch_add(1, std::memory_order_relaxed);
    }
}

std::uint64_t PerformanceTelemetry::BeginProcessScan(
    bool first,
    TimePoint now) noexcept {
    return BeginProcessScanAt(first, Elapsed(now));
}

std::uint64_t PerformanceTelemetry::BeginProcessScanAt(
    bool first,
    std::chrono::microseconds session_elapsed) noexcept {
    if (!Enabled()) return 0;
    const auto id = next_scan_id_.fetch_add(1, std::memory_order_relaxed);
    active_scan_first_.store(first, std::memory_order_relaxed);
    active_scan_started_us_.store(
        NonNegativeMicroseconds(session_elapsed), std::memory_order_relaxed);
    active_regions_requested_.store(0, std::memory_order_relaxed);
    active_regions_completed_.store(0, std::memory_order_relaxed);
    active_progress_bytes_.store(0, std::memory_order_relaxed);
    active_cancel_requested_us_.store(-1, std::memory_order_relaxed);
    active_scan_id_.store(id, std::memory_order_release);
    scans_started_.fetch_add(1, std::memory_order_relaxed);
    return id;
}

void PerformanceTelemetry::RecordProcessScanProgress(
    std::uint64_t scan_id,
    const ScanProgress& progress) noexcept {
    if (scan_id == 0 ||
        active_scan_id_.load(std::memory_order_acquire) != scan_id) {
        return;
    }
    active_regions_requested_.store(
        static_cast<std::uint64_t>(progress.regions_total),
        std::memory_order_relaxed);
    active_regions_completed_.store(
        static_cast<std::uint64_t>(progress.regions_scanned),
        std::memory_order_relaxed);
    active_progress_bytes_.store(
        progress.bytes_scanned, std::memory_order_relaxed);
}

void PerformanceTelemetry::RequestProcessScanCancellation(
    std::uint64_t scan_id,
    TimePoint now) noexcept {
    RequestProcessScanCancellationAt(scan_id, Elapsed(now));
}

void PerformanceTelemetry::RequestProcessScanCancellationAt(
    std::uint64_t scan_id,
    std::chrono::microseconds session_elapsed) noexcept {
    if (scan_id == 0 ||
        active_scan_id_.load(std::memory_order_acquire) != scan_id) {
        return;
    }
    std::int64_t expected = -1;
    const auto requested = static_cast<std::int64_t>(
        std::min<std::uint64_t>(
            NonNegativeMicroseconds(session_elapsed),
            static_cast<std::uint64_t>(
                std::numeric_limits<std::int64_t>::max())));
    static_cast<void>(active_cancel_requested_us_.compare_exchange_strong(
        expected,
        requested,
        std::memory_order_relaxed,
        std::memory_order_relaxed));
}

void PerformanceTelemetry::FinishProcessScan(
    std::uint64_t scan_id,
    const ScanProgress& final_progress,
    const ScanReadReport& read_report,
    bool succeeded,
    bool cancelled,
    TimePoint now) noexcept {
    FinishProcessScanAt(
        scan_id,
        final_progress,
        read_report,
        succeeded,
        cancelled,
        Elapsed(now));
}

void PerformanceTelemetry::FinishProcessScanAt(
    std::uint64_t scan_id,
    const ScanProgress& final_progress,
    const ScanReadReport& read_report,
    bool succeeded,
    bool cancelled,
    std::chrono::microseconds session_elapsed) noexcept {
    if (scan_id == 0 ||
        active_scan_id_.load(std::memory_order_acquire) != scan_id) {
        return;
    }

    ScanRecord record{};
    record.id = scan_id;
    record.first = active_scan_first_.load(std::memory_order_relaxed);
    record.started_us = active_scan_started_us_.load(
        std::memory_order_relaxed);
    record.finished_us = NonNegativeMicroseconds(session_elapsed);
    if (record.finished_us < record.started_us) {
        record.finished_us = record.started_us;
    }
    record.regions_requested = std::max(
        active_regions_requested_.load(std::memory_order_relaxed),
        static_cast<std::uint64_t>(final_progress.regions_total));
    record.regions_completed = std::max(
        active_regions_completed_.load(std::memory_order_relaxed),
        static_cast<std::uint64_t>(final_progress.regions_scanned));
    record.requested_bytes = read_report.requested_bytes;
    record.completed_bytes = read_report.completed_bytes;
    record.io_requests = read_report.items_attempted;
    record.io_completed = read_report.items_completed;
    record.read_failures = read_report.failed_reads;
    record.short_reads = read_report.short_reads;
    record.partial = read_report.partial;
    record.succeeded = succeeded;
    record.cancelled = cancelled || read_report.cancelled;
    const auto cancellation_requested = active_cancel_requested_us_.load(
        std::memory_order_relaxed);
    if (cancellation_requested >= 0) {
        record.cancellation_requested = true;
        const auto requested_us = static_cast<std::uint64_t>(
            cancellation_requested);
        if (record.finished_us >= requested_us) {
            record.cancellation_latency_us =
                record.finished_us - requested_us;
        }
        UpdateMaximum(
            max_cancellation_latency_us_,
            record.cancellation_latency_us);
    }

    if (record.cancelled) {
        scans_cancelled_.fetch_add(1, std::memory_order_relaxed);
    } else if (!record.succeeded) {
        scans_failed_.fetch_add(1, std::memory_order_relaxed);
    } else if (record.partial) {
        scans_partial_.fetch_add(1, std::memory_order_relaxed);
    } else {
        scans_succeeded_.fetch_add(1, std::memory_order_relaxed);
    }
    total_regions_requested_.fetch_add(
        record.regions_requested, std::memory_order_relaxed);
    total_regions_completed_.fetch_add(
        record.regions_completed, std::memory_order_relaxed);
    total_requested_bytes_.fetch_add(
        record.requested_bytes, std::memory_order_relaxed);
    total_completed_bytes_.fetch_add(
        record.completed_bytes, std::memory_order_relaxed);
    total_io_requests_.fetch_add(
        record.io_requests, std::memory_order_relaxed);
    total_io_completed_.fetch_add(
        record.io_completed, std::memory_order_relaxed);
    total_read_failures_.fetch_add(
        record.read_failures, std::memory_order_relaxed);
    total_short_reads_.fetch_add(
        record.short_reads, std::memory_order_relaxed);

    {
        std::scoped_lock lock(records_mutex_);
        if (records_.size() == config_.max_scan_records) {
            records_.erase(records_.begin());
            records_evicted_.fetch_add(1, std::memory_order_relaxed);
        }
        records_.push_back(record);
    }
    active_scan_id_.store(0, std::memory_order_release);
}

void PerformanceTelemetry::WriterMain(std::stop_token stop_token) noexcept {
    while (!stop_token.stop_requested()) {
        std::unique_lock lock(writer_mutex_);
        writer_cv_.wait_for(lock, stop_token, config_.flush_interval, [] {
            return false;
        });
        lock.unlock();
        if (!stop_token.stop_requested()) {
            static_cast<void>(WriteSnapshot(true));
        }
    }
    static_cast<void>(WriteSnapshot(true));
}

std::filesystem::path PerformanceTelemetry::NextTemporaryPath() noexcept {
    try {
        auto name = config_.output_path.filename().native();
#if defined(_WIN32)
        name.append(L".tmp-");
        name.append(std::to_wstring(process_id_));
        name.push_back(L'-');
        name.append(std::to_wstring(process_session_nonce_));
        name.push_back(L'-');
        name.append(std::to_wstring(temporary_sequence_.fetch_add(
            1, std::memory_order_relaxed) + 1));
#else
        name.append(".tmp-");
        name.append(std::to_string(process_id_));
        name.push_back('-');
        name.append(std::to_string(process_session_nonce_));
        name.push_back('-');
        name.append(std::to_string(temporary_sequence_.fetch_add(
            1, std::memory_order_relaxed) + 1));
#endif
        return config_.output_path.parent_path() / name;
    } catch (...) {
        return {};
    }
}

std::uint64_t PerformanceTelemetry::WriteSnapshot(bool count_failure) noexcept {
#if !defined(_WIN32)
    if (count_failure) {
        writer_errors_.fetch_add(1, std::memory_order_relaxed);
    }
    return static_cast<std::uint64_t>(ENOTSUP);
#else
    std::uint64_t failure = ERROR_SUCCESS;
    std::filesystem::path temporary;
    bool owns_temporary = false;
    try {
        const auto json = BuildJson();
        HANDLE file = INVALID_HANDLE_VALUE;
        for (unsigned int attempt = 0; attempt < 8; ++attempt) {
            temporary = NextTemporaryPath();
            if (temporary.empty()) {
                failure = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }
            file = CreateFileW(
                temporary.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file != INVALID_HANDLE_VALUE) {
                owns_temporary = true;
                break;
            }
            failure = GetLastError();
            if (failure != ERROR_FILE_EXISTS &&
                failure != ERROR_ALREADY_EXISTS) {
                break;
            }
        }
        if (file != INVALID_HANDLE_VALUE) {
            failure = ERROR_SUCCESS;
            std::size_t offset = 0;
            while (offset < json.size()) {
                const auto remaining = json.size() - offset;
                const DWORD requested = static_cast<DWORD>(
                    std::min<std::size_t>(
                        remaining,
                        static_cast<std::size_t>(
                            std::numeric_limits<DWORD>::max())));
                DWORD written = 0;
                if (WriteFile(
                        file,
                        json.data() + offset,
                        requested,
                        &written,
                        nullptr) == FALSE ||
                    written != requested) {
                    failure = GetLastError();
                    if (failure == ERROR_SUCCESS) failure = ERROR_WRITE_FAULT;
                    break;
                }
                offset += written;
            }
            if (failure == ERROR_SUCCESS && FlushFileBuffers(file) == FALSE) {
                failure = GetLastError();
            }
            CloseHandle(file);
            if (failure == ERROR_SUCCESS &&
                MoveFileExW(
                    temporary.c_str(),
                    config_.output_path.c_str(),
                    MOVEFILE_REPLACE_EXISTING |
                        MOVEFILE_WRITE_THROUGH) == FALSE) {
                failure = GetLastError();
            }
        }
    } catch (...) {
        failure = ERROR_NOT_ENOUGH_MEMORY;
    }
    if (failure != ERROR_SUCCESS && owns_temporary && !temporary.empty()) {
        static_cast<void>(DeleteFileW(temporary.c_str()));
    }
    if (failure != ERROR_SUCCESS && count_failure) {
        writer_errors_.fetch_add(1, std::memory_order_relaxed);
    }
    return failure;
#endif
}

std::string PerformanceTelemetry::BuildJson() const {
    std::vector<ScanRecord> records;
    {
        std::scoped_lock lock(records_mutex_);
        records = records_;
    }
    std::ostringstream json;
    json << "{\n"
         << "  \"schema\":\"kdbg.runtime-telemetry.v1\",\n"
         << "  \"privacy\":{\"target_memory_contents\":false,"
            "\"filesystem_paths\":false,\"process_names\":false},\n"
         << "  \"session\":{\"clock\":\"steady_monotonic\","
            "\"writer_errors\":"
         << writer_errors_.load(std::memory_order_relaxed)
         << "},\n"
         << "  \"gui\":{\"frames_observed\":"
         << frames_observed_.load(std::memory_order_relaxed)
         << ",\"interval_samples\":"
         << frame_intervals_observed_.load(std::memory_order_relaxed)
         << ",\"stall_threshold_us\":"
         << config_.frame_stall_threshold.count()
         << ",\"stall_count\":"
         << frame_stalls_.load(std::memory_order_relaxed)
         << ",\"max_interval_us\":"
         << max_frame_interval_us_.load(std::memory_order_relaxed)
         << "},\n"
         << "  \"process_scans\":{\"started\":"
         << scans_started_.load(std::memory_order_relaxed)
         << ",\"succeeded\":"
         << scans_succeeded_.load(std::memory_order_relaxed)
         << ",\"partial\":"
         << scans_partial_.load(std::memory_order_relaxed)
         << ",\"failed\":"
         << scans_failed_.load(std::memory_order_relaxed)
         << ",\"cancelled\":"
         << scans_cancelled_.load(std::memory_order_relaxed)
         << ",\"records_evicted\":"
         << records_evicted_.load(std::memory_order_relaxed)
         << ",\"max_cancellation_latency_us\":"
         << max_cancellation_latency_us_.load(std::memory_order_relaxed)
         << ",\"totals\":{\"regions_requested\":"
         << total_regions_requested_.load(std::memory_order_relaxed)
         << ",\"regions_completed\":"
         << total_regions_completed_.load(std::memory_order_relaxed)
         << ",\"requested_bytes\":"
         << total_requested_bytes_.load(std::memory_order_relaxed)
         << ",\"completed_bytes\":"
         << total_completed_bytes_.load(std::memory_order_relaxed)
         << ",\"io_requests\":"
         << total_io_requests_.load(std::memory_order_relaxed)
         << ",\"io_completed\":"
         << total_io_completed_.load(std::memory_order_relaxed)
         << ",\"read_failures\":"
         << total_read_failures_.load(std::memory_order_relaxed)
         << ",\"short_reads\":"
         << total_short_reads_.load(std::memory_order_relaxed)
         << "},\"records\":[";
    for (std::size_t index = 0; index < records.size(); ++index) {
        if (index != 0) json << ',';
        const auto& record = records[index];
        const char* const outcome = record.cancelled
            ? "cancelled"
            : (!record.succeeded
                ? "failed"
                : (record.partial ? "partial" : "completed"));
        json << "{\"id\":" << record.id
             << ",\"kind\":\"" << (record.first ? "first" : "next")
             << "\",\"outcome\":\"" << outcome
             << "\",\"started_us\":" << record.started_us
             << ",\"finished_us\":" << record.finished_us
             << ",\"regions_requested\":" << record.regions_requested
             << ",\"regions_completed\":" << record.regions_completed
             << ",\"requested_bytes\":" << record.requested_bytes
             << ",\"completed_bytes\":" << record.completed_bytes
             << ",\"io_requests\":" << record.io_requests
             << ",\"io_completed\":" << record.io_completed
             << ",\"read_failures\":" << record.read_failures
             << ",\"short_reads\":" << record.short_reads
             << ",\"partial\":" << (record.partial ? "true" : "false")
             << ",\"cancellation_requested\":"
             << (record.cancellation_requested ? "true" : "false")
             << ",\"cancellation_latency_us\":"
             << record.cancellation_latency_us << '}';
    }
    json << "]}\n}\n";
    return json.str();
}

void PerformanceTelemetry::ResetCounters() noexcept {
    last_frame_tick_us_.store(-1, std::memory_order_relaxed);
    frames_observed_.store(0, std::memory_order_relaxed);
    frame_intervals_observed_.store(0, std::memory_order_relaxed);
    frame_stalls_.store(0, std::memory_order_relaxed);
    max_frame_interval_us_.store(0, std::memory_order_relaxed);
    next_scan_id_.store(1, std::memory_order_relaxed);
    active_scan_id_.store(0, std::memory_order_relaxed);
    active_cancel_requested_us_.store(-1, std::memory_order_relaxed);
    scans_started_.store(0, std::memory_order_relaxed);
    scans_succeeded_.store(0, std::memory_order_relaxed);
    scans_partial_.store(0, std::memory_order_relaxed);
    scans_failed_.store(0, std::memory_order_relaxed);
    scans_cancelled_.store(0, std::memory_order_relaxed);
    total_regions_requested_.store(0, std::memory_order_relaxed);
    total_regions_completed_.store(0, std::memory_order_relaxed);
    total_requested_bytes_.store(0, std::memory_order_relaxed);
    total_completed_bytes_.store(0, std::memory_order_relaxed);
    total_io_requests_.store(0, std::memory_order_relaxed);
    total_io_completed_.store(0, std::memory_order_relaxed);
    total_read_failures_.store(0, std::memory_order_relaxed);
    total_short_reads_.store(0, std::memory_order_relaxed);
    max_cancellation_latency_us_.store(0, std::memory_order_relaxed);
    records_evicted_.store(0, std::memory_order_relaxed);
    writer_errors_.store(0, std::memory_order_relaxed);
    temporary_sequence_.store(0, std::memory_order_relaxed);
    std::scoped_lock lock(records_mutex_);
    records_.clear();
    records_.reserve(config_.max_scan_records);
}

PerformanceTelemetry& RuntimePerformanceTelemetry() {
    static PerformanceTelemetry telemetry;
    return telemetry;
}

}  // namespace kdbg

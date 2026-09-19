#include "app/ui/ProcessScannerPanel.h"

#include "app/PerformanceTelemetry.h"
#include "app/ui/Localization.h"
#include "core/scanner/ValueCodec.h"

#include <imgui.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <exception>
#include <limits>
#include <utility>
#include <string_view>

namespace kdbg {
namespace {

constexpr const char* kTypeLabels[] = {
    "Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
    "Int64", "UInt64", "Float", "Double", "UTF-8", "UTF-16", "AOB"};
constexpr ScanValueType kTypes[] = {
    ScanValueType::Int8, ScanValueType::UInt8,
    ScanValueType::Int16, ScanValueType::UInt16,
    ScanValueType::Int32, ScanValueType::UInt32,
    ScanValueType::Int64, ScanValueType::UInt64,
    ScanValueType::Float, ScanValueType::Double,
    ScanValueType::Utf8, ScanValueType::Utf16,
    ScanValueType::ByteArray};

constexpr const char* kCompareLabels[] = {
    "Exact", "Not Equal", "Greater Than", "Less Than", "Between",
    "Unknown Initial", "Changed", "Unchanged", "Increased", "Decreased",
    "Increased By", "Decreased By"};
constexpr ScanCompare kComparisons[] = {
    ScanCompare::Exact, ScanCompare::NotEqual,
    ScanCompare::GreaterThan, ScanCompare::LessThan,
    ScanCompare::Between, ScanCompare::UnknownInitial,
    ScanCompare::Changed, ScanCompare::Unchanged,
    ScanCompare::Increased, ScanCompare::Decreased,
    ScanCompare::IncreasedBy, ScanCompare::DecreasedBy};

bool NeedsSecond(ScanCompare compare) noexcept {
    return compare == ScanCompare::Between;
}

bool NeedsValue(ScanCompare compare) noexcept {
    return compare != ScanCompare::UnknownInitial &&
        compare != ScanCompare::Changed &&
        compare != ScanCompare::Unchanged &&
        compare != ScanCompare::Increased &&
        compare != ScanCompare::Decreased;
}

bool ParseAddress(std::string_view text, std::uint64_t* address) {
    if (address == nullptr) return false;
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    if (text.empty() || text.front() == '+' || text.front() == '-') return false;
    int base = 10;
    if (text.size() > 2 && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return false;
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(
        text.data(), text.data() + text.size(), parsed, base);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return false;
    }
    *address = parsed;
    return true;
}

constexpr std::size_t WatchBatchCount(
    std::size_t total,
    std::size_t begin,
    std::size_t cap = 64) noexcept {
    return begin >= total || cap == 0
        ? 0
        : std::min(cap, total - begin);
}

static_assert(WatchBatchCount(0, 0) == 0);
static_assert(WatchBatchCount(1, 0) == 1);
static_assert(WatchBatchCount(65, 0) == 64);
static_assert(WatchBatchCount(65, 64) == 1);
static_assert(WatchBatchCount(65, 65) == 0);

Result<void> RefreshAndMaybeFreezeEntry(
    IProcessMemory& memory,
    WatchEntry& entry,
    bool include_freeze) {
    return RefreshAndMaybeFreezeEntryOneShot(
        memory, entry, include_freeze);
}

}  // namespace

ProcessScannerPanel::ProcessScannerPanel() {
    std::snprintf(manual_address_.data(), manual_address_.size(), "0x0");
    std::snprintf(
        address_list_path_.data(), address_list_path_.size(),
        "kdbg-address-list.kdbgal");
}

ProcessScannerPanel::~ProcessScannerPanel() { Reset(); }

bool ProcessScannerPanel::Busy() const noexcept {
    return scan_running_.load(std::memory_order_acquire) ||
        watch_running_.load(std::memory_order_acquire);
}

bool ProcessScannerPanel::WriteAuthorizationActive() const noexcept {
    return write_authorization_active_;
}

void ProcessScannerPanel::RevokeWriteAuthorization() noexcept {
    write_authorization_active_ = false;
}

void ProcessScannerPanel::CancelAndWait() noexcept {
    watch_full_refresh_requested_ = false;
    watch_manual_pass_active_ = false;
    try {
        StopScanWorker();
        StopWatchWorker();
    } catch (...) {
        scan_running_.store(false, std::memory_order_release);
        watch_running_.store(false, std::memory_order_release);
    }
}

void ProcessScannerPanel::Attach(IProcessMemory* memory) {
    Reset();
    memory_ = memory;
    if (memory_ != nullptr) {
        scanner_ = std::make_unique<MemoryScanner>(*memory_);
        watches_ = std::make_unique<WatchList>(*memory_);
        PublishAllWatches();
        next_watch_refresh_ = std::chrono::steady_clock::now();
        status_ = ui::UiText("Process scanner ready.");
    }
}

void ProcessScannerPanel::Reset() {
    CancelAndWait();
    scan_generation_.fetch_add(1, std::memory_order_acq_rel);
    watch_generation_.fetch_add(1, std::memory_order_acq_rel);
    scanner_.reset();
    watches_.reset();
    memory_ = nullptr;
    {
        std::scoped_lock lock(scan_mutex_);
        scan_progress_ = {};
        scan_error_.reset();
        published_scan_.reset();
    }
    {
        std::scoped_lock lock(watch_mutex_);
        watch_outcome_.reset();
    }
    published_watches_.clear();
    watch_cursor_ = 0;
    watch_cycle_completed_ = 0;
    watch_cycle_total_ = 0;
    watch_failures_ = 0;
    watch_last_error_.reset();
    freeze_fail_closed_status_.clear();
    watch_full_refresh_requested_ = false;
    watch_manual_pass_active_ = false;
    watch_last_overrun_ = false;
    write_authorization_active_ = false;
    selected_watch_id_ = 0;
    status_.clear();
}

ScanQuery ProcessScannerPanel::BuildQuery() const {
    ScanQuery query{};
    query.type = kTypes[std::clamp(value_type_index_, 0, 12)];
    query.comparison = kComparisons[std::clamp(compare_index_, 0, 11)];
    query.value = value_.data();
    query.second_value = second_value_.data();
    query.hexadecimal = hexadecimal_;
    query.require_writable = writable_only_;
    query.include_executable = include_executable_;
    query.alignment = alignment_ > 0 ? static_cast<std::size_t>(alignment_) : 1U;
    query.max_results = static_cast<std::size_t>(std::max(max_results_, 1));
    query.chunk_size = 1024U * 1024U;
    return query;
}

void ProcessScannerPanel::StopScanWorker() {
    if (scan_worker_.joinable()) {
        RuntimePerformanceTelemetry().RequestProcessScanCancellation(
            scan_telemetry_id_.load(std::memory_order_acquire));
        scan_worker_.request_stop();
        scan_worker_.join();
    }
    scan_running_.store(false, std::memory_order_release);
}

void ProcessScannerPanel::StartScan(bool first) {
    if (scanner_ == nullptr || scan_running_.load(std::memory_order_acquire)) {
        return;
    }
    StopScanWorker();
    StopWatchWorker();
    const auto generation =
        scan_generation_.fetch_add(1, std::memory_order_acq_rel) + 1U;
    if (first) {
        scanner_->Reset();
        std::scoped_lock lock(scan_mutex_);
        published_scan_.reset();
    }
    const auto query = BuildQuery();
    {
        std::scoped_lock lock(scan_mutex_);
        scan_progress_ = {};
        scan_error_.reset();
    }
    scan_running_.store(true, std::memory_order_release);
    const auto telemetry_id =
        RuntimePerformanceTelemetry().BeginProcessScan(first);
    scan_telemetry_id_.store(telemetry_id, std::memory_order_release);
    scan_worker_ = std::jthread(
        [this, generation, query, first, telemetry_id](std::stop_token token) {
            Result<ScanSummary> result = Result<ScanSummary>::Failure(MakeError(
                ErrorCode::InternalInvariant,
                "Scan worker did not run",
                "ProcessScannerPanel::StartScan"));
            ScanReadReport read_report{};
            try {
                const auto progress = [this, generation, telemetry_id](
                                          const ScanProgress& value) {
                    if (scan_generation_.load(std::memory_order_acquire) != generation) {
                        return;
                    }
                    {
                        std::scoped_lock lock(scan_mutex_);
                        scan_progress_ = value;
                    }
                    RuntimePerformanceTelemetry().RecordProcessScanProgress(
                        telemetry_id, value);
                };
                result = first
                    ? scanner_->FirstScan(query, progress, token)
                    : scanner_->NextScan(query, progress, token);
                read_report = scanner_->LastReadReport();
            } catch (const std::exception& exception) {
                result = Result<ScanSummary>::Failure(MakeError(
                    ErrorCode::InternalInvariant,
                    "Scan worker failed: " + std::string(exception.what()),
                    "ProcessScannerPanel::StartScan"));
            } catch (...) {
                result = Result<ScanSummary>::Failure(MakeError(
                    ErrorCode::InternalInvariant,
                    "Scan worker failed with an unknown exception",
                    "ProcessScannerPanel::StartScan"));
            }
            const auto final_progress = CurrentScanProgress();
            const bool cancelled = read_report.cancelled ||
                (!result && result.GetError().code == ErrorCode::Cancelled);
            RuntimePerformanceTelemetry().FinishProcessScan(
                telemetry_id,
                final_progress,
                read_report,
                result.Ok(),
                cancelled);
            scan_telemetry_id_.store(0, std::memory_order_release);
            PublishScanCompletion(generation, query, result, read_report);
            if (scan_generation_.load(std::memory_order_acquire) == generation) {
                scan_running_.store(false, std::memory_order_release);
            }
        });
}

void ProcessScannerPanel::PublishScanCompletion(
    std::uint64_t generation,
    const ScanQuery& query,
    const Result<ScanSummary>& result,
    const ScanReadReport& read_report) {
    if (scan_generation_.load(std::memory_order_acquire) != generation) return;
    std::shared_ptr<const PublishedScanSnapshot> published;
    std::optional<Error> error;
    if (result) {
        try {
            auto snapshot = std::make_shared<PublishedScanSnapshot>();
            snapshot->generation = generation;
            snapshot->type = query.type;
            snapshot->hexadecimal = query.hexadecimal;
            snapshot->summary = result.Value();
            snapshot->read_report = read_report;
            snapshot->publication_state =
                ClassifyScanPublication(true, read_report);
            snapshot->candidates = scanner_->Candidates();
            published = std::move(snapshot);
        } catch (const std::exception& exception) {
            error = MakeError(
                ErrorCode::InternalInvariant,
                "Unable to publish scan results: " +
                    std::string(exception.what()),
                "ProcessScannerPanel::PublishScanCompletion");
        } catch (...) {
            error = MakeError(
                ErrorCode::InternalInvariant,
                "Unable to publish scan results",
                "ProcessScannerPanel::PublishScanCompletion");
        }
    } else {
        error = result.GetError();
    }
    std::scoped_lock lock(scan_mutex_);
    if (scan_generation_.load(std::memory_order_acquire) != generation) return;
    if (published != nullptr) published_scan_ = std::move(published);
    scan_error_ = std::move(error);
}

void ProcessScannerPanel::ResetScan() {
    StopScanWorker();
    scan_generation_.fetch_add(1, std::memory_order_acq_rel);
    if (scanner_ != nullptr) scanner_->Reset();
    std::scoped_lock lock(scan_mutex_);
    scan_progress_ = {};
    scan_error_.reset();
    published_scan_.reset();
}

std::shared_ptr<const ProcessScannerPanel::PublishedScanSnapshot>
ProcessScannerPanel::ScanSnapshot() const {
    std::scoped_lock lock(scan_mutex_);
    return published_scan_;
}

ScanProgress ProcessScannerPanel::CurrentScanProgress() const {
    std::scoped_lock lock(scan_mutex_);
    return scan_progress_;
}

std::optional<Error> ProcessScannerPanel::CurrentScanError() const {
    std::scoped_lock lock(scan_mutex_);
    return scan_error_;
}

void ProcessScannerPanel::StopWatchWorker() {
    const bool was_running = watch_running_.load(std::memory_order_acquire);
    if (watch_worker_.joinable()) {
        if (was_running) {
            watch_cancel_requested_.store(true, std::memory_order_release);
        }
        watch_worker_.request_stop();
        watch_worker_.join();
    }
    watch_running_.store(false, std::memory_order_release);
    if (was_running && memory_ != nullptr && watches_ != nullptr &&
        HasFrozenEntries(watches_->Entries())) {
        write_authorization_active_ = false;
        const auto cleanup = FailCloseFreeze(*memory_, watches_->Entries());
        PublishAllWatches();
        freeze_fail_closed_status_ = cleanup.gate_locked
            ? "Freeze cancelled; all frozen entries were disarmed and the process write gate is locked."
            : "Freeze cancelled and all frozen entries were disarmed, but the process write gate lock could not be verified.";
        if (cleanup.cleanup_error.has_value()) {
            watch_last_error_ = cleanup.cleanup_error;
            freeze_fail_closed_status_ += " " + cleanup.cleanup_error->message;
        }
    }
}

bool ProcessScannerPanel::WatchActionsBusy() const noexcept {
    return watch_running_.load(std::memory_order_acquire) ||
        scan_running_.load(std::memory_order_acquire);
}

void ProcessScannerPanel::PublishAllWatches() {
    published_watches_ = watches_ == nullptr
        ? std::vector<WatchEntry>{}
        : watches_->Entries();
    if (watch_cursor_ > published_watches_.size()) watch_cursor_ = 0;
}

void ProcessScannerPanel::StartWatchBatch(
    bool include_freeze,
    bool manual_pass) {
    if (watches_ == nullptr || memory_ == nullptr || WatchActionsBusy()) return;
    if (watch_worker_.joinable()) watch_worker_.join();
    const auto total = watches_->Entries().size();
    if (total == 0) {
        watch_cursor_ = 0;
        watch_cycle_completed_ = 0;
        watch_cycle_total_ = 0;
        watch_manual_pass_active_ = false;
        watch_full_refresh_requested_ = false;
        return;
    }
    if (watch_cursor_ >= total) watch_cursor_ = 0;
    const auto begin = watch_cursor_;
    const auto count = WatchBatchCount(total, begin);
    const auto generation =
        watch_generation_.fetch_add(1, std::memory_order_acq_rel) + 1U;
    if (begin == 0) {
        watch_cycle_completed_ = 0;
        watch_cycle_total_ = total;
        watch_failures_ = 0;
        watch_last_error_.reset();
    }
    watch_manual_pass_active_ = manual_pass;
    watch_cancel_requested_.store(false, std::memory_order_release);
    watch_batch_completed_.store(0, std::memory_order_release);
    watch_running_.store(true, std::memory_order_release);
    IProcessMemory* const memory = memory_;
    watch_worker_ = std::jthread(
        [this, memory, generation, begin, count, total,
         include_freeze](std::stop_token token) {
            WatchBatchOutcome outcome;
            outcome.generation = generation;
            outcome.begin = begin;
            outcome.total = total;
            outcome.rows.reserve(count);
            std::size_t failures = 0;
            try {
                auto& entries = watches_->Entries();
                outcome.freeze_mode = include_freeze && HasFrozenEntries(entries);
                const auto fail_close_freeze = [&]() {
                    if (!outcome.freeze_mode || outcome.freeze_fail_closed) return;
                    const auto cleanup = FailCloseFreeze(*memory, entries);
                    outcome.freeze_fail_closed = true;
                    outcome.gate_locked = cleanup.gate_locked;
                    outcome.gate_lock_retry_used = cleanup.cleanup_retry_used;
                    outcome.disarmed_entries = cleanup.disarmed_entries;
                    outcome.gate_lock_error = cleanup.cleanup_error;
                };
                for (std::size_t offset = 0; offset < count; ++offset) {
                    if (token.stop_requested() ||
                        watch_cancel_requested_.load(std::memory_order_acquire) ||
                        watch_generation_.load(std::memory_order_acquire) != generation) {
                        outcome.cancelled = true;
                        fail_close_freeze();
                        break;
                    }
                    auto& entry = entries[begin + offset];
                    const bool frozen_operation = include_freeze && entry.frozen;
                    const auto refreshed = RefreshAndMaybeFreezeEntry(
                        *memory, entry, include_freeze);
                    if (!refreshed) {
                        ++failures;
                        outcome.error = refreshed.GetError();
                        if (frozen_operation) {
                            fail_close_freeze();
                        }
                    }
                    outcome.rows.push_back(entry);
                    ++outcome.completed;
                    watch_batch_completed_.store(
                        outcome.completed, std::memory_order_release);
                    if (outcome.freeze_fail_closed) break;
                }
                if ((token.stop_requested() ||
                     watch_cancel_requested_.load(std::memory_order_acquire)) &&
                    !outcome.cancelled) {
                    outcome.cancelled = true;
                    fail_close_freeze();
                }
                if (failures != 0 && !outcome.freeze_fail_closed) {
                    outcome.error = MakeError(
                        ErrorCode::VerificationMismatch,
                        "One or more scheduled watch operations failed",
                        "ProcessScannerPanel::StartWatchBatch",
                        0,
                        outcome.completed,
                        failures);
                }
            } catch (const std::exception& exception) {
                outcome.error = MakeError(
                    ErrorCode::InternalInvariant,
                    "Watch worker failed: " + std::string(exception.what()),
                    "ProcessScannerPanel::StartWatchBatch");
                if (outcome.freeze_mode && !outcome.freeze_fail_closed) {
                    try {
                        const auto cleanup = FailCloseFreeze(
                            *memory, watches_->Entries());
                        outcome.freeze_fail_closed = true;
                        outcome.gate_locked = cleanup.gate_locked;
                        outcome.gate_lock_retry_used = cleanup.cleanup_retry_used;
                        outcome.disarmed_entries = cleanup.disarmed_entries;
                        outcome.gate_lock_error = cleanup.cleanup_error;
                    } catch (...) {
                        outcome.freeze_fail_closed = true;
                        outcome.gate_locked = false;
                        outcome.gate_lock_error = MakeError(
                            ErrorCode::InternalInvariant,
                            "Freeze fail-closed cleanup threw an exception",
                            "ProcessScannerPanel::StartWatchBatch/fail_closed");
                    }
                }
            } catch (...) {
                outcome.error = MakeError(
                    ErrorCode::InternalInvariant,
                    "Watch worker failed with an unknown exception",
                    "ProcessScannerPanel::StartWatchBatch");
                if (outcome.freeze_mode && !outcome.freeze_fail_closed) {
                    try {
                        const auto cleanup = FailCloseFreeze(
                            *memory, watches_->Entries());
                        outcome.freeze_fail_closed = true;
                        outcome.gate_locked = cleanup.gate_locked;
                        outcome.gate_lock_retry_used = cleanup.cleanup_retry_used;
                        outcome.disarmed_entries = cleanup.disarmed_entries;
                        outcome.gate_lock_error = cleanup.cleanup_error;
                    } catch (...) {
                        outcome.freeze_fail_closed = true;
                        outcome.gate_locked = false;
                        outcome.gate_lock_error = MakeError(
                            ErrorCode::InternalInvariant,
                            "Freeze fail-closed cleanup threw an exception",
                            "ProcessScannerPanel::StartWatchBatch/fail_closed");
                    }
                }
            }
            {
                std::scoped_lock lock(watch_mutex_);
                if (watch_generation_.load(std::memory_order_acquire) == generation) {
                    watch_outcome_ = std::move(outcome);
                }
            }
            if (watch_generation_.load(std::memory_order_acquire) == generation) {
                watch_running_.store(false, std::memory_order_release);
            }
        });
}

void ProcessScannerPanel::PollWatchWorker() {
    if (watch_running_.load(std::memory_order_acquire)) return;
    if (watch_worker_.joinable()) watch_worker_.join();
    std::optional<WatchBatchOutcome> outcome;
    {
        std::scoped_lock lock(watch_mutex_);
        outcome = std::move(watch_outcome_);
        watch_outcome_.reset();
    }
    if (!outcome.has_value() ||
        outcome->generation != watch_generation_.load(std::memory_order_acquire)) {
        watch_cancel_requested_.store(false, std::memory_order_release);
        return;
    }
    const bool cancellation_requested =
        watch_cancel_requested_.exchange(false, std::memory_order_acq_rel);
    if (cancellation_requested && outcome->freeze_mode &&
        !outcome->freeze_fail_closed && memory_ != nullptr && watches_ != nullptr) {
        const auto cleanup = FailCloseFreeze(*memory_, watches_->Entries());
        outcome->cancelled = true;
        outcome->freeze_fail_closed = true;
        outcome->gate_locked = cleanup.gate_locked;
        outcome->gate_lock_retry_used = cleanup.cleanup_retry_used;
        outcome->disarmed_entries = cleanup.disarmed_entries;
        outcome->gate_lock_error = cleanup.cleanup_error;
    }
    for (std::size_t offset = 0; offset < outcome->rows.size(); ++offset) {
        const auto index = outcome->begin + offset;
        if (index < published_watches_.size()) {
            published_watches_[index] = std::move(outcome->rows[offset]);
        }
    }
    watch_cycle_completed_ += outcome->completed;
    if (outcome->error.has_value()) {
        watch_last_error_ = outcome->error;
        watch_failures_ += static_cast<std::size_t>(
            std::max<std::uint64_t>(outcome->error->completed, 1U));
    }
    if (outcome->freeze_fail_closed) {
        write_authorization_active_ = false;
        PublishAllWatches();
        watch_cursor_ = 0;
        watch_full_refresh_requested_ = false;
        watch_manual_pass_active_ = false;
        watch_last_overrun_ = false;
        next_watch_refresh_ = std::chrono::steady_clock::now() +
            std::chrono::seconds(1);
        if (outcome->gate_locked) {
            freeze_fail_closed_status_ =
                "Freeze stopped after a failed or cancelled operation; "
                "all frozen entries were disarmed and the process write gate is locked.";
        } else {
            freeze_fail_closed_status_ =
                "Freeze stopped and all frozen entries were disarmed, but "
                "the process write gate lock could not be verified.";
            if (outcome->gate_lock_error.has_value()) {
                watch_last_error_ = outcome->gate_lock_error;
                freeze_fail_closed_status_ +=
                    " " + outcome->gate_lock_error->message;
            }
        }
        status_ = freeze_fail_closed_status_;
        return;
    }
    if (outcome->cancelled) {
        watch_full_refresh_requested_ = false;
        watch_manual_pass_active_ = false;
        status_ = ui::UiText("Watch refresh cancellation completed.");
        return;
    }
    watch_cursor_ = outcome->begin + outcome->completed;
    if (watch_cursor_ >= outcome->total) {
        watch_cursor_ = 0;
        watch_full_refresh_requested_ = false;
        watch_manual_pass_active_ = false;
        watch_last_overrun_ = watch_cycle_total_ > outcome->completed;
        next_watch_refresh_ =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    }
}

void ProcessScannerPanel::RequestFullWatchRefresh() {
    if (WatchActionsBusy() || published_watches_.empty()) return;
    watch_cursor_ = 0;
    watch_full_refresh_requested_ = true;
    watch_manual_pass_active_ = true;
    StartWatchBatch(false, true);
}

void ProcessScannerPanel::Draw() {
    if (memory_ == nullptr || !memory_->IsOpen() || scanner_ == nullptr) {
        ImGui::TextDisabled(
            "%s", ui::UiText("Attach to a process to use the memory scanner."));
        return;
    }
    if (!scan_running_.load(std::memory_order_acquire) &&
        scan_worker_.joinable()) {
        scan_worker_.join();
    }
    PollWatchWorker();

    ImGui::Text(ui::UiText(
        "Attached PID: %u | Pointer width: %u-bit | Gate: %s | Freeze authorization: %s"),
        memory_->ProcessId(),
        static_cast<unsigned>(memory_->PointerSize() * 8U),
        memory_->WritesArmed() ? "ARMED" : "LOCKED",
        write_authorization_active_ ? "ACTIVE" : "LOCKED");
    DrawScanControls();
    ImGui::Separator();
    DrawResults();
    ImGui::Separator();
    DrawWatchList();
    DrawWriteGateModal();

    if (!status_.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("%s", status_.c_str());
    }
}

void ProcessScannerPanel::DrawScanControls() {
    ImGui::SetNextItemWidth(150.0F);
    ImGui::Combo(
        ui::UiLabel("Value Type", "Value Type").c_str(),
        &value_type_index_, kTypeLabels, IM_ARRAYSIZE(kTypeLabels));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160.0F);
    ImGui::Combo(
        ui::UiLabel("Scan Type", "Scan Type").c_str(),
        &compare_index_, kCompareLabels, IM_ARRAYSIZE(kCompareLabels));

    const auto compare = kComparisons[std::clamp(compare_index_, 0, 11)];
    if (NeedsValue(compare)) {
        ImGui::SetNextItemWidth(300.0F);
        ImGui::InputText(
            ui::UiLabel("Value", "Value").c_str(),
            value_.data(), value_.size());
    } else {
        ImGui::TextDisabled(
            "%s", ui::UiText(
                "This comparison uses the previous snapshot and does not require a value."));
    }
    if (NeedsSecond(compare)) {
        ImGui::SetNextItemWidth(300.0F);
        ImGui::InputText(
            ui::UiLabel("Second Value", "Second Value").c_str(),
            second_value_.data(), second_value_.size());
    }

    ImGui::Checkbox(
        ui::UiLabel("Hexadecimal", "Hexadecimal").c_str(), &hexadecimal_);
    ImGui::SameLine();
    ImGui::Checkbox(
        ui::UiLabel("Writable only", "Writable only").c_str(),
        &writable_only_);
    ImGui::SameLine();
    ImGui::Checkbox(
        ui::UiLabel("Include executable", "Include executable").c_str(),
        &include_executable_);
    ImGui::SetNextItemWidth(120.0F);
    ImGui::InputInt(
        ui::UiLabel("Alignment", "Alignment").c_str(), &alignment_);
    alignment_ = std::clamp(alignment_, 1, 4096);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0F);
    ImGui::InputInt(
        ui::UiLabel("Max results", "Max results").c_str(), &max_results_);
    max_results_ = std::clamp(max_results_, 1, 2'000'000);

    const bool running = scan_running_.load(std::memory_order_acquire);
    const auto snapshot = ScanSnapshot();
    const auto scan_error = CurrentScanError();
    const bool next_scan_allowed = snapshot != nullptr &&
        snapshot->publication_state == ScanPublicationState::Complete &&
        !scan_error.has_value();
    if (running) ImGui::BeginDisabled();
    const char* const first_scan_text =
        snapshot != nullptr ? "New First Scan" : "First Scan";
    if (ImGui::Button(ui::UiLabel(first_scan_text, first_scan_text).c_str())) {
        StartScan(true);
        status_ = ui::UiText("First scan started.");
    }
    ImGui::SameLine();
    if (!next_scan_allowed) ImGui::BeginDisabled();
    if (ImGui::Button(ui::UiLabel("Next Scan", "Next Scan").c_str())) {
        StartScan(false);
        status_ = ui::UiText("Next scan started.");
    }
    if (!next_scan_allowed) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button(ui::UiLabel("Reset", "Reset").c_str())) {
        ResetScan();
        status_ = ui::UiText("Scan results cleared.");
    }
    if (running) ImGui::EndDisabled();
    if (running) {
        ImGui::SameLine();
        if (ImGui::Button(ui::UiLabel("Cancel", "Cancel").c_str())) {
            RuntimePerformanceTelemetry().RequestProcessScanCancellation(
                scan_telemetry_id_.load(std::memory_order_acquire));
            scan_worker_.request_stop();
        }
        const auto progress = CurrentScanProgress();
        const float fraction = progress.bytes_total == 0
            ? 0.0F
            : static_cast<float>(
                static_cast<double>(progress.bytes_scanned) /
                static_cast<double>(progress.bytes_total));
        ImGui::ProgressBar(
            std::clamp(fraction, 0.0F, 1.0F),
            ImVec2(-1.0F, 0.0F),
            progress.phase.c_str());
        ImGui::Text(ui::UiText(
            "Regions %llu/%llu | Bytes 0x%llX/0x%llX | Candidates %llu"),
            static_cast<unsigned long long>(progress.regions_scanned),
            static_cast<unsigned long long>(progress.regions_total),
            static_cast<unsigned long long>(progress.bytes_scanned),
            static_cast<unsigned long long>(progress.bytes_total),
            static_cast<unsigned long long>(progress.candidates));
    } else if (scan_error.has_value()) {
        status_ = scan_error->message + " " +
            ui::UiText("Next Scan is blocked; start a new First Scan.");
    } else if (snapshot != nullptr) {
        if (snapshot->publication_state == ScanPublicationState::Partial) {
            const auto& report = snapshot->read_report;
            status_ = "PARTIAL/INCOMPLETE scan: " +
                std::to_string(snapshot->summary.result_count) +
                " result(s); " + std::to_string(report.items_skipped) +
                " item(s) skipped, " + std::to_string(report.failed_reads) +
                " failed read(s), " + std::to_string(report.short_reads) +
                " short read(s), " + std::to_string(report.completed_bytes) +
                "/" + std::to_string(report.requested_bytes) +
                " bytes completed. Next Scan is blocked; start a new First Scan.";
            if (!report.first_error.message.empty()) {
                status_ += std::string(" ") + ui::UiText("First error:") +
                    " " + report.first_error.message;
            }
        } else {
            char buffer[192]{};
            std::snprintf(buffer, sizeof(buffer), ui::UiText(
                "Scan generation %llu complete: %llu result(s), 0x%llX bytes%s."),
                static_cast<unsigned long long>(snapshot->generation),
                static_cast<unsigned long long>(snapshot->summary.result_count),
                static_cast<unsigned long long>(snapshot->summary.bytes_scanned),
                snapshot->summary.truncated
                    ? ui::UiText(" (result limit reached)")
                    : "");
            status_ = buffer;
        }
    }
}

void ProcessScannerPanel::DrawResults() {
    const auto snapshot = ScanSnapshot();
    const auto result_count = snapshot == nullptr
        ? 0U
        : snapshot->candidates.size();
    ImGui::Text(ui::UiText("Published Scan Results: %llu"),
        static_cast<unsigned long long>(result_count));
    if (snapshot != nullptr &&
        snapshot->publication_state == ScanPublicationState::Partial) {
        const auto& report = snapshot->read_report;
        ImGui::PushStyleColor(
            ImGuiCol_Text, ImVec4(1.0F, 0.65F, 0.15F, 1.0F));
        ImGui::TextWrapped(
            ui::UiText(
                "PARTIAL / INCOMPLETE: skipped %llu, failed %llu, short %llu, bytes %llu/%llu. Next Scan disabled."),
            static_cast<unsigned long long>(report.items_skipped),
            static_cast<unsigned long long>(report.failed_reads),
            static_cast<unsigned long long>(report.short_reads),
            static_cast<unsigned long long>(report.completed_bytes),
            static_cast<unsigned long long>(report.requested_bytes));
        ImGui::PopStyleColor();
        if (!report.first_error.message.empty()) {
            ImGui::TextWrapped(
                ui::UiText("First read error: %s"),
                report.first_error.message.c_str());
        }
    }
    if (scan_running_.load(std::memory_order_acquire) && snapshot != nullptr) {
        ImGui::TextDisabled(
            ui::UiText(
                "Showing immutable generation %llu while the worker builds the next generation."),
            static_cast<unsigned long long>(snapshot->generation));
    }
    if (snapshot == nullptr || snapshot->candidates.empty()) {
        ImGui::TextDisabled("%s", ui::UiText("No scan results."));
        return;
    }

    if (ImGui::BeginTable(
            "scan-results", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
            ImVec2(0.0F, 260.0F))) {
        ImGui::TableSetupColumn(ui::UiLabel("Address", "Address").c_str());
        ImGui::TableSetupColumn(ui::UiLabel("Previous", "Previous").c_str());
        ImGui::TableSetupColumn(ui::UiLabel("Current", "Current").c_str());
        ImGui::TableSetupColumn(ui::UiLabel("Delta", "Delta").c_str());
        ImGui::TableSetupColumn(ui::UiLabel("Watch", "Watch").c_str());
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            snapshot->candidates.size(),
            static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                const auto& candidate =
                    snapshot->candidates[static_cast<std::size_t>(index)];
                ImGui::PushID(index);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(candidate.address));
                ImGui::TableNextColumn();
                const auto previous = FormatValue(
                    snapshot->type, candidate.previous, snapshot->hexadecimal);
                ImGui::TextUnformatted(previous.c_str());
                ImGui::TableNextColumn();
                const auto current = FormatValue(
                    snapshot->type, candidate.current, snapshot->hexadecimal);
                ImGui::TextUnformatted(current.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(
                    candidate.previous == candidate.current
                        ? "="
                        : ui::UiText("changed"));
                ImGui::TableNextColumn();
                if (FixedValueWidth(snapshot->type) == 0) {
                    ImGui::TextDisabled("N/A");
                } else if (ImGui::SmallButton(
                               ui::UiLabel("Add", "Add").c_str())) {
                    if (WatchActionsBusy()) {
                        status_ =
                            "Wait for the current scan/watch batch before adding a watch.";
                        ImGui::PopID();
                        continue;
                    }
                    const auto added = watches_->Add(
                        candidate.address,
                        snapshot->type,
                        "scan result",
                        snapshot->hexadecimal);
                    if (added) PublishAllWatches();
                    status_ = added
                        ? ui::UiText("Address added to watch list.")
                        : added.GetError().message;
                }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
}

void ProcessScannerPanel::DrawWatchList() {
    ImGui::TextUnformatted(ui::UiText("Address List / Freeze"));
    const auto now = std::chrono::steady_clock::now();
    if (!watch_running_.load(std::memory_order_acquire) &&
        !scan_running_.load(std::memory_order_acquire)) {
        if (watch_full_refresh_requested_) {
            StartWatchBatch(false, true);
        } else if (now >= next_watch_refresh_) {
            StartWatchBatch(write_authorization_active_, false);
            next_watch_refresh_ = now + std::chrono::milliseconds(200);
        }
    }

    const bool watch_busy = WatchActionsBusy();
    if (watch_running_.load(std::memory_order_acquire)) {
        const auto completed = watch_cycle_completed_ +
            watch_batch_completed_.load(std::memory_order_acquire);
        const auto total = std::max(watch_cycle_total_, published_watches_.size());
        const float fraction = total == 0
            ? 0.0F
            : static_cast<float>(completed) / static_cast<float>(total);
        ImGui::ProgressBar(
            std::clamp(fraction, 0.0F, 1.0F),
            ImVec2(-1.0F, 0.0F),
            watch_manual_pass_active_
                ? ui::UiText("manual watch refresh")
                : ui::UiText("bounded refresh/freeze batch"));
        ImGui::Text(
            ui::UiText(
                "Cycle progress %llu/%llu | batch cap 64 | failures %llu"),
            static_cast<unsigned long long>(completed),
            static_cast<unsigned long long>(total),
            static_cast<unsigned long long>(watch_failures_));
        if (ImGui::Button(
                ui::UiLabel("Cancel Watch I/O", "Cancel Watch I/O").c_str())) {
            watch_cancel_requested_.store(true, std::memory_order_release);
            watch_worker_.request_stop();
            watch_full_refresh_requested_ = false;
        }
    } else {
        ImGui::TextDisabled(
            ui::UiText("Published rows: %llu | scheduler batch cap: 64%s"),
            static_cast<unsigned long long>(published_watches_.size()),
            watch_last_overrun_
                ? ui::UiText(" | cycle spans multiple 200 ms slices")
                : "");
    }
    if (watch_last_error_.has_value()) {
        ImGui::TextWrapped(
            ui::UiText(
                "Last watch worker error: %s [requested=%llu completed=%llu]"),
            watch_last_error_->message.c_str(),
            static_cast<unsigned long long>(watch_last_error_->requested),
            static_cast<unsigned long long>(watch_last_error_->completed));
    }
    if (!freeze_fail_closed_status_.empty()) {
        ImGui::PushStyleColor(
            ImGuiCol_Text, ImVec4(1.0F, 0.55F, 0.15F, 1.0F));
        ImGui::TextWrapped(
            "%s", freeze_fail_closed_status_.c_str());
        ImGui::PopStyleColor();
    }

    ImGui::BeginDisabled(watch_busy);
    if (!write_authorization_active_ && !memory_->WritesArmed()) {
        if (ImGui::Button(
                ui::UiLabel(
                    "Arm Process Writes", "Arm Process Writes").c_str())) {
            write_confirmation_.fill('\0');
            const auto popup_label = ui::UiLabel(
                "Arm Process Writes", "Arm Process Writes##KDBG");
            ImGui::OpenPopup(popup_label.c_str());
        }
    } else if (ImGui::Button(
                   ui::UiLabel(
                       "Lock Process Writes", "Lock Process Writes").c_str())) {
        write_authorization_active_ = false;
        const auto result = memory_->SetWritesArmed(false);
        SetStatus(result, ui::UiText("Process writes locked."));
    }
    ImGui::SameLine();
    if (ImGui::Button(
            ui::UiLabel("Refresh Values", "Refresh Values").c_str())) {
        RequestFullWatchRefresh();
    }
    ImGui::EndDisabled();

    ImGui::SetNextItemWidth(390.0F);
    ImGui::InputText(
        ui::UiLabel("Address-list file", "Address-list file").c_str(),
        address_list_path_.data(), address_list_path_.size());
    ImGui::SameLine();
    ImGui::BeginDisabled(watch_busy);
    if (ImGui::Button(ui::UiLabel("Save Table", "Save Table").c_str())) {
        const auto result = watches_->Save(address_list_path_.data());
        SetStatus(result, ui::UiText("Address list saved."));
    }
    ImGui::SameLine();
    if (ImGui::Button(ui::UiLabel("Load Table", "Load Table").c_str())) {
        const auto result = watches_->Load(address_list_path_.data());
        selected_watch_id_ = 0;
        if (result) {
            watch_cursor_ = 0;
            PublishAllWatches();
        }
        SetStatus(result, ui::UiText(
            "Address list loaded. Saved frozen entries were intentionally disarmed."));
    }
    ImGui::EndDisabled();

    ImGui::SetNextItemWidth(180.0F);
    ImGui::InputText(
        ui::UiLabel("Manual Address", "Manual Address").c_str(),
        manual_address_.data(), manual_address_.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(125.0F);
    ImGui::Combo(
        ui::UiLabel("Manual Type", "Manual Type").c_str(),
        &manual_type_index_,
        kTypeLabels, 10);
    ImGui::SameLine();
    ImGui::Checkbox(
        ui::UiLabel("Manual Hex", "Manual Hex").c_str(),
        &manual_hexadecimal_);
    ImGui::SetNextItemWidth(300.0F);
    ImGui::InputTextWithHint(
        ui::UiLabel("Description", "Description").c_str(),
        ui::UiText("optional label"),
        manual_description_.data(), manual_description_.size());
    ImGui::SameLine();
    ImGui::BeginDisabled(watch_busy);
    if (ImGui::Button(
            ui::UiLabel("Add Address", "Add Address").c_str())) {
        std::uint64_t address = 0;
        if (!ParseAddress(manual_address_.data(), &address) || address == 0) {
            status_ = ui::UiText(
                "Manual address must be a non-zero decimal or 0x-prefixed value.");
        } else {
            const auto added = watches_->Add(
                address,
                kTypes[std::clamp(manual_type_index_, 0, 9)],
                manual_description_.data(),
                manual_hexadecimal_);
            if (added) PublishAllWatches();
            status_ = added
                ? ui::UiText("Manual address added to the address list.")
                : added.GetError().message;
        }
    }
    ImGui::EndDisabled();

    if (published_watches_.empty()) {
        ImGui::TextDisabled(
            "%s", ui::UiText("Add an address from scan results."));
        return;
    }
    if (ImGui::BeginTable(
            "watch-list", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 220.0F))) {
        ImGui::TableSetupColumn(ui::UiLabel("Freeze", "Freeze").c_str());
        ImGui::TableSetupColumn(
            ui::UiLabel("Description", "Description").c_str());
        ImGui::TableSetupColumn(ui::UiLabel("Address", "Address").c_str());
        ImGui::TableSetupColumn(ui::UiLabel("Type", "Type").c_str());
        ImGui::TableSetupColumn(ui::UiLabel("Value", "Value").c_str());
        ImGui::TableSetupColumn(ui::UiLabel("Action", "Action").c_str());
        ImGui::TableHeadersRow();
        std::uint64_t remove_id = 0;
        std::optional<std::pair<std::uint64_t, bool>> freeze_change;
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            published_watches_.size(), static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart;
                 index < clipper.DisplayEnd; ++index) {
                const auto& entry =
                    published_watches_[static_cast<std::size_t>(index)];
                ImGui::PushID(static_cast<int>(entry.id));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                bool frozen = entry.frozen;
                const bool cannot_enable_freeze =
                    watch_busy ||
                    (!write_authorization_active_ && !entry.frozen);
                if (cannot_enable_freeze) ImGui::BeginDisabled();
                if (ImGui::Checkbox("##freeze", &frozen)) {
                    freeze_change = std::pair{entry.id, frozen};
                }
                if (cannot_enable_freeze) ImGui::EndDisabled();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(entry.description.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(entry.address));
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(kTypeLabels[static_cast<int>(entry.type)]);
                ImGui::TableNextColumn();
                const auto formatted = FormatValue(entry.type, entry.value, entry.hexadecimal);
                ImGui::TextUnformatted(formatted.c_str());
                if (!entry.last_error.empty()) ImGui::SetItemTooltip("%s", entry.last_error.c_str());
                ImGui::TableNextColumn();
                if (ImGui::SmallButton(
                        ui::UiLabel("Edit", "Edit").c_str())) {
                    selected_watch_id_ = entry.id;
                    std::snprintf(watch_value_.data(), watch_value_.size(), "%s", formatted.c_str());
                }
                ImGui::SameLine();
                ImGui::BeginDisabled(watch_busy);
                if (ImGui::SmallButton(
                        ui::UiLabel("Remove", "Remove").c_str())) {
                    remove_id = entry.id;
                }
                ImGui::EndDisabled();
                ImGui::PopID();
            }
        }
        if (remove_id != 0) {
            const auto removed = watches_->Remove(remove_id);
            if (removed) {
                if (selected_watch_id_ == remove_id) selected_watch_id_ = 0;
                PublishAllWatches();
            }
            SetStatus(
                removed, ui::UiText("Address removed from the watch list."));
        } else if (freeze_change.has_value()) {
            const auto result = [&]() -> Result<void> {
                if (!freeze_change->second) {
                    return watches_->SetFrozen(freeze_change->first, false);
                }
                const auto armed = memory_->SetWritesArmed(true);
                if (!armed) return armed;
                const auto frozen = watches_->SetFrozen(
                    freeze_change->first, true);
                const auto locked = memory_->SetWritesArmed(false);
                if (!locked) {
                    write_authorization_active_ = false;
                    const auto cleanup = FailCloseFreeze(
                        *memory_, watches_->Entries());
                    PublishAllWatches();
                    return Result<void>::Failure(
                        cleanup.cleanup_error.has_value()
                            ? *cleanup.cleanup_error
                            : locked.GetError());
                }
                return frozen;
            }();
            if (result) PublishAllWatches();
            SetStatus(
                result,
                freeze_change->second
                    ? ui::UiText("Address frozen.")
                    : ui::UiText("Address unfrozen."));
        }
        ImGui::EndTable();
    }

    if (selected_watch_id_ != 0) {
        ImGui::SetNextItemWidth(300.0F);
        ImGui::InputText(
            ui::UiLabel("New Value", "New Value").c_str(),
            watch_value_.data(), watch_value_.size());
        ImGui::SameLine();
        if (!memory_->WritesArmed() || watch_busy) ImGui::BeginDisabled();
        if (ImGui::Button(
                ui::UiLabel("Write & Verify", "Write & Verify").c_str())) {
            const auto result = watches_->WriteValue(selected_watch_id_, watch_value_.data());
            write_authorization_active_ = false;
            if (result) PublishAllWatches();
            SetStatus(
                result, ui::UiText("Process value written and verified."));
        }
        if (!memory_->WritesArmed() || watch_busy) ImGui::EndDisabled();
    }
}

void ProcessScannerPanel::DrawWriteGateModal() {
    const auto popup_label = ui::UiLabel(
        "Arm Process Writes", "Arm Process Writes##KDBG");
    if (ImGui::BeginPopupModal(
            popup_label.c_str(), nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped(
            ui::UiText(
                "Writes affect the attached process on this Windows instance. "
                "Enter the attached PID (%u) to arm writes."),
            memory_->ProcessId());
        ImGui::InputText(
            ui::UiLabel("PID confirmation", "PID confirmation").c_str(),
            write_confirmation_.data(), write_confirmation_.size());
        std::uint32_t confirmed = 0;
        const auto parsed = std::from_chars(
            write_confirmation_.data(),
            write_confirmation_.data() + std::strlen(write_confirmation_.data()),
            confirmed,
            10);
        const char* confirmation_end =
            write_confirmation_.data() + std::strlen(write_confirmation_.data());
        const bool valid = parsed.ec == std::errc{} &&
            parsed.ptr == confirmation_end &&
            confirmed == memory_->ProcessId();
        const bool arm_blocked = !valid || WatchActionsBusy();
        if (arm_blocked) ImGui::BeginDisabled();
        if (ImGui::Button(ui::UiLabel("Arm", "Arm").c_str())) {
            const auto result = memory_->SetWritesArmed(true);
            SetStatus(result, ui::UiText("Process writes armed."));
            if (result) {
                write_authorization_active_ = true;
                freeze_fail_closed_status_.clear();
                ImGui::CloseCurrentPopup();
            }
        }
        if (arm_blocked) ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button(ui::UiLabel("Cancel", "Cancel").c_str())) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void ProcessScannerPanel::SetStatus(
    const Result<void>& result,
    std::string success) {
    status_ = result ? std::move(success) : result.GetError().message;
}

}  // namespace kdbg

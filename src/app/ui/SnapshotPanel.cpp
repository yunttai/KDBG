#include "app/ui/SnapshotPanel.h"

#include <imgui.h>

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace kdbg {
namespace {

bool ParseUnsigned(std::string_view text, std::uint64_t* value) {
    if (value == nullptr) return false;
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    if (text.empty() || text.front() == '+' || text.front() == '-') return false;
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
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
    *value = parsed;
    return true;
}

std::string Preview(std::span<const std::uint8_t> bytes) {
    constexpr std::size_t kPreviewBytes = 16;
    std::ostringstream output;
    output << std::hex << std::uppercase << std::setfill('0');
    const auto count = std::min(bytes.size(), kPreviewBytes);
    for (std::size_t index = 0; index < count; ++index) {
        if (index != 0) output << ' ';
        output << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }
    if (bytes.size() > count) output << " ...";
    return output.str();
}

const char* PhaseName(SnapshotProgressPhase phase) {
    switch (phase) {
    case SnapshotProgressPhase::CaptureRead: return "Reading memory";
    case SnapshotProgressPhase::CaptureChecksum: return "Checksumming capture";
    case SnapshotProgressPhase::Diff: return "Comparing snapshots";
    case SnapshotProgressPhase::Save: return "Saving snapshot";
    case SnapshotProgressPhase::LoadRead: return "Loading snapshot";
    case SnapshotProgressPhase::LoadChecksum: return "Verifying checksum";
    }
    return "Working";
}

}  // namespace

SnapshotPanel::SnapshotPanel() {
    std::snprintf(address_.data(), address_.size(), "0x0");
    std::snprintf(size_.data(), size_.size(), "0x1000");
    std::snprintf(
        baseline_path_.data(), baseline_path_.size(),
        "kdbg-baseline.kdbgmem");
    std::snprintf(
        current_path_.data(), current_path_.size(),
        "kdbg-current.kdbgmem");
}

SnapshotPanel::~SnapshotPanel() { StopWorker(); }

void SnapshotPanel::RequestCancel() noexcept {
    if (worker_.joinable()) worker_.request_stop();
}

void SnapshotPanel::CancelAndWait() { StopWorker(); }

bool SnapshotPanel::Busy() const noexcept {
    return running_.load(std::memory_order_acquire);
}

void SnapshotPanel::Attach(IProcessMemory* memory) {
    Reset();
    memory_ = memory;
    if (memory_ != nullptr) {
        status_ = "Snapshot workspace ready for PID " +
            std::to_string(memory_->ProcessId()) + ".";
    }
}

void SnapshotPanel::Reset() {
    StopWorker();
    memory_ = nullptr;
    baseline_.reset();
    current_.reset();
    diffs_.clear();
    {
        std::scoped_lock lock(result_mutex_);
        pending_result_.reset();
        progress_ = {};
    }
    status_.clear();
}

void SnapshotPanel::StopWorker() {
    generation_.fetch_add(1, std::memory_order_acq_rel);
    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    running_.store(false, std::memory_order_release);
    std::scoped_lock lock(result_mutex_);
    pending_result_.reset();
    progress_ = {};
}

void SnapshotPanel::StartWorker(
    WorkerOperation operation,
    std::string status,
    WorkerTask task) {
    ConsumeWorkerResult();
    if (running_.load(std::memory_order_acquire)) return;
    if (worker_.joinable()) worker_.join();

    const auto generation =
        generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
    {
        std::scoped_lock lock(result_mutex_);
        pending_result_.reset();
        progress_ = {};
    }
    status_ = std::move(status);
    running_.store(true, std::memory_order_release);
    worker_ = std::jthread(
        [this, generation, operation, task = std::move(task)](
            std::stop_token stop_token) mutable {
            const SnapshotProgressCallback progress =
                [this, generation](const SnapshotProgress& update) {
                    if (generation_.load(std::memory_order_acquire) != generation) {
                        return;
                    }
                    std::scoped_lock lock(result_mutex_);
                    progress_ = update;
                };

            WorkerResult result{};
            try {
                result = task(stop_token, progress);
            } catch (const std::bad_alloc&) {
                result.error = MakeError(
                    ErrorCode::LimitReached,
                    "Snapshot worker exhausted the allocation budget",
                    "SnapshotPanel");
            } catch (const std::length_error&) {
                result.error = MakeError(
                    ErrorCode::LimitReached,
                    "Snapshot worker requested an invalid allocation",
                    "SnapshotPanel");
            } catch (const std::exception& error) {
                result.error = MakeError(
                    ErrorCode::InternalInvariant,
                    error.what(),
                    "SnapshotPanel");
            }
            result.generation = generation;
            result.operation = operation;
            {
                std::scoped_lock lock(result_mutex_);
                if (generation_.load(std::memory_order_acquire) == generation) {
                    pending_result_ = std::move(result);
                }
            }
            running_.store(false, std::memory_order_release);
        });
}

void SnapshotPanel::StartCapture(CaptureTarget target) {
    if (memory_ == nullptr || !memory_->IsOpen() ||
        running_.load(std::memory_order_acquire)) {
        return;
    }

    std::uint64_t address = 0;
    std::uint64_t size = 0;
    if (!ParseUnsigned(address_.data(), &address) ||
        !ParseUnsigned(size_.data(), &size) ||
        address == 0 || size == 0) {
        status_ = "Enter a non-zero address and size in decimal or 0x-prefixed hexadecimal.";
        return;
    }
    if (size > MemorySnapshot::kMaxSnapshotBytes ||
        address > std::numeric_limits<std::uint64_t>::max() - size) {
        status_ = "Snapshot range is invalid or exceeds the 512 MiB UI limit.";
        return;
    }

    IProcessMemory* const memory = memory_;
    const auto operation = target == CaptureTarget::Baseline
        ? WorkerOperation::CaptureBaseline
        : WorkerOperation::CaptureCurrent;
    StartWorker(
        operation,
        target == CaptureTarget::Baseline
            ? "Capturing baseline snapshot..."
            : "Capturing current snapshot...",
        [memory, address, size, target](
            std::stop_token stop_token,
            const SnapshotProgressCallback& progress) {
            WorkerResult completed{};
            auto result = MemorySnapshot::Capture(
                *memory,
                address,
                size,
                1024U * 1024U,
                stop_token,
                progress);
            if (result) {
                completed.snapshot = result.TakeValue();
                completed.success_status = target == CaptureTarget::Baseline
                    ? "Baseline snapshot captured."
                    : "Current snapshot captured.";
            } else {
                completed.error = result.GetError();
            }
            return completed;
        });
}

void SnapshotPanel::ConsumeWorkerResult() {
    if (running_.load(std::memory_order_acquire) || !worker_.joinable()) return;
    worker_.join();

    std::optional<WorkerResult> result;
    {
        std::scoped_lock lock(result_mutex_);
        result = std::move(pending_result_);
        pending_result_.reset();
    }
    if (!result.has_value() ||
        result->generation != generation_.load(std::memory_order_acquire)) {
        return;
    }
    if (result->error.has_value()) {
        status_ = result->error->message;
        return;
    }

    switch (result->operation) {
    case WorkerOperation::CaptureBaseline:
        baseline_ = std::move(result->snapshot);
        current_.reset();
        diffs_.clear();
        break;
    case WorkerOperation::CaptureCurrent:
        current_ = std::move(result->snapshot);
        diffs_.clear();
        break;
    case WorkerOperation::LoadBaseline:
        baseline_ = std::move(result->snapshot);
        diffs_.clear();
        break;
    case WorkerOperation::LoadCurrent:
        current_ = std::move(result->snapshot);
        diffs_.clear();
        break;
    case WorkerOperation::Diff:
        if (result->diffs.has_value()) {
            diffs_ = std::move(*result->diffs);
        }
        break;
    case WorkerOperation::SaveBaseline:
    case WorkerOperation::SaveCurrent:
    case WorkerOperation::None:
        break;
    }
    if (!result->success_status.empty()) {
        status_ = std::move(result->success_status);
    } else if (result->operation == WorkerOperation::Diff) {
        status_ = "Snapshot diff complete: " + std::to_string(diffs_.size()) +
            " changed run(s).";
    }
}

void SnapshotPanel::DrawSnapshotSummary(
    const char* label,
    const std::optional<MemorySnapshot>& snapshot) const {
    ImGui::TextUnformatted(label);
    if (!snapshot.has_value()) {
        ImGui::TextDisabled("Not captured or loaded.");
        return;
    }
    ImGui::Text("PID: %u", snapshot->Space().pid);
    ImGui::Text(
        "Range: 0x%016llX - 0x%016llX",
        static_cast<unsigned long long>(snapshot->Address()),
        static_cast<unsigned long long>(
            snapshot->Address() + snapshot->Bytes().size()));
    ImGui::Text(
        "Bytes: %llu | CRC32: %08X",
        static_cast<unsigned long long>(snapshot->Bytes().size()),
        snapshot->Checksum());
}

void SnapshotPanel::SaveSnapshot(CaptureTarget target, const char* path) {
    const auto& snapshot = target == CaptureTarget::Baseline ? baseline_ : current_;
    if (!snapshot.has_value()) {
        status_ = "There is no snapshot to save.";
        return;
    }
    const MemorySnapshot* const source = &*snapshot;
    const auto destination = std::filesystem::path(path);
    const auto operation = target == CaptureTarget::Baseline
        ? WorkerOperation::SaveBaseline
        : WorkerOperation::SaveCurrent;
    StartWorker(
        operation,
        "Saving snapshot...",
        [source, destination](
            std::stop_token stop_token,
            const SnapshotProgressCallback& progress) {
            WorkerResult completed{};
            const auto result = source->Save(destination, stop_token, progress);
            if (result) {
                completed.success_status = "Snapshot saved.";
            } else {
                completed.error = result.GetError();
            }
            return completed;
        });
}

void SnapshotPanel::LoadSnapshot(CaptureTarget target, const char* path) {
    const auto source = std::filesystem::path(path);
    const auto operation = target == CaptureTarget::Baseline
        ? WorkerOperation::LoadBaseline
        : WorkerOperation::LoadCurrent;
    StartWorker(
        operation,
        "Loading snapshot...",
        [source](
            std::stop_token stop_token,
            const SnapshotProgressCallback& progress) {
            WorkerResult completed{};
            auto result = MemorySnapshot::Load(source, stop_token, progress);
            if (result) {
                completed.snapshot = result.TakeValue();
                completed.success_status =
                    "Snapshot loaded and checksum verified.";
            } else {
                completed.error = result.GetError();
            }
            return completed;
        });
}

void SnapshotPanel::ComputeDiff() {
    if (!baseline_.has_value() || !current_.has_value()) {
        status_ = "Capture or load both baseline and current snapshots first.";
        return;
    }
    const MemorySnapshot* const baseline = &*baseline_;
    const MemorySnapshot* const current = &*current_;
    const auto max_runs =
        static_cast<std::size_t>(std::max(max_diff_runs_, 1));
    StartWorker(
        WorkerOperation::Diff,
        "Comparing snapshots...",
        [baseline, current, max_runs](
            std::stop_token stop_token,
            const SnapshotProgressCallback& progress) {
            WorkerResult completed{};
            auto result = baseline->Diff(
                *current,
                max_runs,
                MemorySnapshot::kMaxSnapshotBytes,
                stop_token,
                progress);
            if (result) {
                completed.diffs = result.TakeValue();
            } else {
                completed.error = result.GetError();
            }
            return completed;
        });
}

void SnapshotPanel::Draw() {
    ConsumeWorkerResult();
    if (memory_ == nullptr || !memory_->IsOpen()) {
        ImGui::TextDisabled("Attach to a process to capture live snapshots.");
        ImGui::TextWrapped(
            "Previously saved .kdbgmem files are loaded only after a process is attached, "
            "so PID and range mismatches remain visible before comparison.");
        return;
    }

    ImGui::Text(
        "Attached PID: %u | Snapshot reads do not require the process write gate.",
        memory_->ProcessId());
    ImGui::SetNextItemWidth(220.0F);
    ImGui::InputText("Start Address", address_.data(), address_.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180.0F);
    ImGui::InputText("Byte Count", size_.data(), size_.size());

    const bool running = running_.load(std::memory_order_acquire);
    if (running) ImGui::BeginDisabled();
    if (ImGui::Button("Capture Baseline")) StartCapture(CaptureTarget::Baseline);
    ImGui::SameLine();
    if (ImGui::Button("Capture Current")) StartCapture(CaptureTarget::Current);
    if (running) ImGui::EndDisabled();
    if (running) {
        ImGui::SameLine();
        if (ImGui::Button("Cancel Operation")) worker_.request_stop();
        SnapshotProgress progress;
        {
            std::scoped_lock lock(result_mutex_);
            progress = progress_;
        }
        const float fraction = progress.total == 0
            ? 0.0F
            : std::clamp(
                static_cast<float>(progress.completed) /
                    static_cast<float>(progress.total),
                0.0F,
                1.0F);
        const std::string overlay =
            std::string(PhaseName(progress.phase)) + " " +
            std::to_string(progress.completed) + " / " +
            std::to_string(progress.total);
        ImGui::ProgressBar(fraction, ImVec2(-1.0F, 0.0F), overlay.c_str());
    }

    if (running) ImGui::BeginDisabled();
    ImGui::Separator();
    if (ImGui::BeginTable(
            "snapshot-summary", 2,
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable)) {
        ImGui::TableNextColumn();
        DrawSnapshotSummary("Baseline", baseline_);
        ImGui::InputText(
            "Baseline File", baseline_path_.data(), baseline_path_.size());
        if (ImGui::Button("Save Baseline")) {
            SaveSnapshot(CaptureTarget::Baseline, baseline_path_.data());
        }
        ImGui::SameLine();
        if (ImGui::Button("Load Baseline")) {
            LoadSnapshot(CaptureTarget::Baseline, baseline_path_.data());
        }

        ImGui::TableNextColumn();
        DrawSnapshotSummary("Current", current_);
        ImGui::InputText(
            "Current File", current_path_.data(), current_path_.size());
        if (ImGui::Button("Save Current")) {
            SaveSnapshot(CaptureTarget::Current, current_path_.data());
        }
        ImGui::SameLine();
        if (ImGui::Button("Load Current")) {
            LoadSnapshot(CaptureTarget::Current, current_path_.data());
        }
        ImGui::EndTable();
    }

    ImGui::Separator();
    ImGui::SetNextItemWidth(160.0F);
    ImGui::InputInt("Max diff runs", &max_diff_runs_);
    max_diff_runs_ = std::clamp(max_diff_runs_, 1, 1'000'000);
    ImGui::SameLine();
    if (ImGui::Button("Compare Snapshots")) ComputeDiff();
    ImGui::SameLine();
    if (ImGui::Button("Clear Snapshots")) {
        baseline_.reset();
        current_.reset();
        diffs_.clear();
        status_ = "Snapshot workspace cleared.";
    }
    if (running) ImGui::EndDisabled();

    ImGui::Text(
        "Changed runs: %llu",
        static_cast<unsigned long long>(diffs_.size()));
    if (!diffs_.empty() && ImGui::BeginTable(
            "snapshot-diffs", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 330.0F))) {
        ImGui::TableSetupColumn("Offset");
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Length");
        ImGui::TableSetupColumn("Before");
        ImGui::TableSetupColumn("After");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            diffs_.size(),
            static_cast<std::size_t>(std::numeric_limits<int>::max()))));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                const auto& diff = diffs_[static_cast<std::size_t>(index)];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(diff.offset));
                ImGui::TableNextColumn();
                ImGui::Text(
                    "0x%016llX",
                    static_cast<unsigned long long>(
                        baseline_->Address() + diff.offset));
                ImGui::TableNextColumn();
                ImGui::Text("%llu", static_cast<unsigned long long>(diff.length));
                ImGui::TableNextColumn();
                const auto offset = static_cast<std::size_t>(diff.offset);
                const auto length = static_cast<std::size_t>(diff.length);
                const bool descriptor_valid =
                    baseline_.has_value() && current_.has_value() &&
                    offset <= baseline_->Bytes().size() &&
                    length <= baseline_->Bytes().size() - offset &&
                    offset <= current_->Bytes().size() &&
                    length <= current_->Bytes().size() - offset;
                const auto before = descriptor_valid
                    ? Preview(std::span<const std::uint8_t>(
                        baseline_->Bytes()).subspan(offset, length))
                    : std::string("<invalid descriptor>");
                ImGui::TextUnformatted(before.c_str());
                ImGui::TableNextColumn();
                const auto after = descriptor_valid
                    ? Preview(std::span<const std::uint8_t>(
                        current_->Bytes()).subspan(offset, length))
                    : std::string("<invalid descriptor>");
                ImGui::TextUnformatted(after.c_str());
            }
        }
        ImGui::EndTable();
    }

    if (!status_.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("%s", status_.c_str());
    }
}

}  // namespace kdbg

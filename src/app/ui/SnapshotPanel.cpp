#include "app/ui/SnapshotPanel.h"

#include <imgui.h>

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>
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
    pending_snapshot_.reset();
    pending_error_.reset();
    status_.clear();
}

void SnapshotPanel::StopWorker() {
    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    running_.store(false, std::memory_order_release);
}

void SnapshotPanel::StartCapture(CaptureTarget target) {
    if (memory_ == nullptr || !memory_->IsOpen() || running_.load()) return;

    std::uint64_t address = 0;
    std::uint64_t size = 0;
    if (!ParseUnsigned(address_.data(), &address) ||
        !ParseUnsigned(size_.data(), &size) ||
        address == 0 || size == 0) {
        status_ = "Enter a non-zero address and size in decimal or 0x-prefixed hexadecimal.";
        return;
    }
    constexpr std::uint64_t kMaxSnapshotBytes = 512ULL * 1024ULL * 1024ULL;
    if (size > kMaxSnapshotBytes ||
        address > std::numeric_limits<std::uint64_t>::max() - size) {
        status_ = "Snapshot range is invalid or exceeds the 512 MiB UI limit.";
        return;
    }

    StopWorker();
    {
        std::scoped_lock lock(result_mutex_);
        pending_snapshot_.reset();
        pending_error_.reset();
        pending_target_ = target;
    }
    IProcessMemory* const memory = memory_;
    running_.store(true, std::memory_order_release);
    status_ = target == CaptureTarget::Baseline
        ? "Capturing baseline snapshot..."
        : "Capturing current snapshot...";
    worker_ = std::jthread(
        [this, memory, address, size, target](std::stop_token stop_token) {
            auto result = MemorySnapshot::Capture(
                *memory,
                address,
                size,
                1024U * 1024U,
                stop_token);
            std::scoped_lock lock(result_mutex_);
            pending_target_ = target;
            if (result) {
                pending_snapshot_ = result.TakeValue();
                pending_error_.reset();
            } else {
                pending_snapshot_.reset();
                pending_error_ = result.GetError();
            }
            running_.store(false, std::memory_order_release);
        });
}

void SnapshotPanel::ConsumeWorkerResult() {
    if (running_.load(std::memory_order_acquire) || !worker_.joinable()) return;
    worker_.join();

    std::optional<MemorySnapshot> snapshot;
    std::optional<Error> error;
    CaptureTarget target = CaptureTarget::Baseline;
    {
        std::scoped_lock lock(result_mutex_);
        snapshot = std::move(pending_snapshot_);
        error = std::move(pending_error_);
        target = pending_target_;
        pending_snapshot_.reset();
        pending_error_.reset();
    }
    if (error.has_value()) {
        status_ = error->message;
        return;
    }
    if (!snapshot.has_value()) return;

    if (target == CaptureTarget::Baseline) {
        baseline_ = std::move(snapshot);
        current_.reset();
        diffs_.clear();
        status_ = "Baseline snapshot captured.";
    } else {
        current_ = std::move(snapshot);
        diffs_.clear();
        status_ = "Current snapshot captured.";
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
    const auto result = snapshot->Save(std::filesystem::path(path));
    status_ = result ? "Snapshot saved." : result.GetError().message;
}

void SnapshotPanel::LoadSnapshot(CaptureTarget target, const char* path) {
    const auto result = MemorySnapshot::Load(std::filesystem::path(path));
    if (!result) {
        status_ = result.GetError().message;
        return;
    }
    if (target == CaptureTarget::Baseline) {
        baseline_ = result.Value();
    } else {
        current_ = result.Value();
    }
    diffs_.clear();
    status_ = "Snapshot loaded and checksum verified.";
}

void SnapshotPanel::ComputeDiff() {
    if (!baseline_.has_value() || !current_.has_value()) {
        status_ = "Capture or load both baseline and current snapshots first.";
        return;
    }
    const auto result = baseline_->Diff(
        *current_,
        static_cast<std::size_t>(std::max(max_diff_runs_, 1)));
    if (!result) {
        status_ = result.GetError().message;
        return;
    }
    diffs_ = result.Value();
    status_ = "Snapshot diff complete: " + std::to_string(diffs_.size()) +
        " changed run(s).";
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
        if (ImGui::Button("Cancel Capture")) worker_.request_stop();
        ImGui::SameLine();
        ImGui::TextDisabled("Reading in a cancellable worker...");
    }

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
                ImGui::Text("%llu", static_cast<unsigned long long>(diff.before.size()));
                ImGui::TableNextColumn();
                const auto before = Preview(diff.before);
                ImGui::TextUnformatted(before.c_str());
                ImGui::TableNextColumn();
                const auto after = Preview(diff.after);
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

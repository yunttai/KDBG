#include "app/ui/PointerScanPanel.h"

#include <imgui.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <sstream>

namespace kdbg {
namespace {

bool ParseAddress(const char* input, std::uint64_t& value) {
    std::string_view text(input == nullptr ? "" : input);
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return false;
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), value, base);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

std::string FormatPath(const PointerPath& path) {
    std::ostringstream stream;
    if (!path.module_name.empty()) {
        stream << path.module_name << "+0x" << std::hex << std::uppercase
               << path.module_offset;
    } else {
        stream << "0x" << std::hex << std::uppercase << path.root_address;
    }
    for (const auto offset : path.offsets) {
        stream << " -> +0x" << std::hex << std::uppercase << offset;
    }
    return stream.str();
}

}  // namespace

PointerScanPanel::~PointerScanPanel() { Reset(); }

void PointerScanPanel::Attach(IProcessMemory* memory) {
    Reset();
    memory_ = memory;
    if (memory_ != nullptr) {
        scanner_ = std::make_unique<PointerScanner>(*memory_);
    }
}

void PointerScanPanel::Reset() {
    Cancel();
    if (worker_.joinable()) worker_.join();
    scanner_.reset();
    memory_ = nullptr;
    std::scoped_lock lock(mutex_);
    results_.clear();
    error_.reset();
    progress_ = {};
}

void PointerScanPanel::Cancel() {
    if (worker_.joinable()) worker_.request_stop();
}

void PointerScanPanel::Start() {
    if (scanner_ == nullptr || running_.load()) return;
    if (worker_.joinable()) worker_.join();
    std::uint64_t target = 0;
    std::uint64_t max_offset = 0;
    if (!ParseAddress(target_.data(), target) ||
        !ParseAddress(max_offset_.data(), max_offset)) {
        status_ = "Target or max offset is invalid.";
        return;
    }
    PointerScanOptions options{};
    options.max_depth = static_cast<std::uint32_t>(std::clamp(max_depth_, 1, 8));
    options.max_offset = max_offset;
    options.max_results = static_cast<std::size_t>(std::clamp(max_results_, 1, 1'000'000));
    options.aligned_only = aligned_only_;
    options.writable_only = writable_only_;
    options.static_roots_only = static_only_;
    {
        std::scoped_lock lock(mutex_);
        results_.clear();
        error_.reset();
        progress_ = {};
    }
    running_.store(true);
    status_ = "Pointer scan started.";
    worker_ = std::jthread(
        [this, target, options](std::stop_token token) {
            const auto result = scanner_->Scan(
                target,
                options,
                [this](const ScanProgress& value) {
                    std::scoped_lock lock(mutex_);
                    progress_ = value;
                },
                token);
            {
                std::scoped_lock lock(mutex_);
                if (result) results_ = result.Value();
                else error_ = result.GetError();
            }
            running_.store(false);
        });
}

void PointerScanPanel::Draw() {
    if (memory_ == nullptr || !memory_->IsOpen() || scanner_ == nullptr) {
        ImGui::TextDisabled("Attach to a process to scan pointer paths.");
        return;
    }
    ImGui::TextWrapped(
        "Pointer scan searches readable regions backwards from a target. "
        "Static roots restrict displayed roots to loaded modules.");
    ImGui::SetNextItemWidth(260.0F);
    ImGui::InputText("Target Address", target_.data(), target_.size());
    ImGui::SetNextItemWidth(180.0F);
    ImGui::InputText("Maximum Offset", max_offset_.data(), max_offset_.size());
    ImGui::SetNextItemWidth(120.0F);
    ImGui::InputInt("Maximum Depth", &max_depth_);
    max_depth_ = std::clamp(max_depth_, 1, 8);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0F);
    ImGui::InputInt("Result Limit", &max_results_);
    max_results_ = std::clamp(max_results_, 1, 1'000'000);
    ImGui::Checkbox("Pointer-size aligned", &aligned_only_);
    ImGui::SameLine();
    ImGui::Checkbox("Writable regions only", &writable_only_);
    ImGui::SameLine();
    ImGui::Checkbox("Static roots only", &static_only_);

    if (!running_.load()) {
        if (ImGui::Button("Start Pointer Scan")) Start();
    } else {
        if (ImGui::Button("Cancel Pointer Scan")) Cancel();
        ScanProgress current{};
        {
            std::scoped_lock lock(mutex_);
            current = progress_;
        }
        const float fraction = current.bytes_total == 0
            ? 0.0F
            : static_cast<float>(
                static_cast<double>(current.bytes_scanned) /
                static_cast<double>(current.bytes_total));
        ImGui::ProgressBar(std::clamp(fraction, 0.0F, 1.0F), ImVec2(-1.0F, 0.0F));
        ImGui::Text("%s | candidates: %llu",
            current.phase.c_str(),
            static_cast<unsigned long long>(current.candidates));
    }

    std::optional<Error> error;
    if (!running_.load()) {
        std::scoped_lock lock(mutex_);
        error = error_;
    }
    if (error.has_value()) status_ = error->message;
    if (!running_.load() && !results_.empty()) {
        status_ = "Pointer scan complete: " + std::to_string(results_.size()) + " path(s).";
    }
    if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());

    if (results_.empty()) return;
    if (ImGui::BeginTable(
            "pointer-results", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 520.0F))) {
        ImGui::TableSetupColumn("Depth");
        ImGui::TableSetupColumn("Root");
        ImGui::TableSetupColumn("Path");
        ImGui::TableSetupColumn("Target");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(results_.size(), 2'000'000)));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto& path = results_[static_cast<std::size_t>(i)];
                const auto formatted = FormatPath(path);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%llu", static_cast<unsigned long long>(path.offsets.size()));
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(path.root_address));
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(formatted.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(path.resolved_address));
            }
        }
        ImGui::EndTable();
    }
}

}  // namespace kdbg

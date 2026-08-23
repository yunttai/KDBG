#include "app/ui/ProcessScannerPanel.h"

#include "core/scanner/ValueCodec.h"

#include <imgui.h>

#include <algorithm>
#include <charconv>
#include <climits>
#include <cstdio>
#include <cstring>
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

}  // namespace

ProcessScannerPanel::ProcessScannerPanel() {
    std::snprintf(manual_address_.data(), manual_address_.size(), "0x0");
    std::snprintf(
        address_list_path_.data(), address_list_path_.size(),
        "kdbg-address-list.kdbgal");
}

ProcessScannerPanel::~ProcessScannerPanel() { Reset(); }

void ProcessScannerPanel::Attach(IProcessMemory* memory) {
    Reset();
    memory_ = memory;
    if (memory_ != nullptr) {
        scanner_ = std::make_unique<MemoryScanner>(*memory_);
        watches_ = std::make_unique<WatchList>(*memory_);
        status_ = "Process scanner ready.";
    }
}

void ProcessScannerPanel::Reset() {
    async_.Cancel();
    async_.Wait();
    scanner_.reset();
    watches_.reset();
    memory_ = nullptr;
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

void ProcessScannerPanel::Draw() {
    if (memory_ == nullptr || !memory_->IsOpen() || scanner_ == nullptr) {
        ImGui::TextDisabled("Attach to a process to use the memory scanner.");
        return;
    }

    ImGui::Text("Attached PID: %u | Pointer width: %u-bit | Writes: %s",
        memory_->ProcessId(),
        static_cast<unsigned>(memory_->PointerSize() * 8U),
        memory_->WritesArmed() ? "ARMED" : "LOCKED");
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
    ImGui::Combo("Value Type", &value_type_index_, kTypeLabels, IM_ARRAYSIZE(kTypeLabels));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160.0F);
    ImGui::Combo("Scan Type", &compare_index_, kCompareLabels, IM_ARRAYSIZE(kCompareLabels));

    const auto compare = kComparisons[std::clamp(compare_index_, 0, 11)];
    if (NeedsValue(compare)) {
        ImGui::SetNextItemWidth(300.0F);
        ImGui::InputText("Value", value_.data(), value_.size());
    } else {
        ImGui::TextDisabled("This comparison uses the previous snapshot and does not require a value.");
    }
    if (NeedsSecond(compare)) {
        ImGui::SetNextItemWidth(300.0F);
        ImGui::InputText("Second Value", second_value_.data(), second_value_.size());
    }

    ImGui::Checkbox("Hexadecimal", &hexadecimal_);
    ImGui::SameLine();
    ImGui::Checkbox("Writable only", &writable_only_);
    ImGui::SameLine();
    ImGui::Checkbox("Include executable", &include_executable_);
    ImGui::SetNextItemWidth(120.0F);
    ImGui::InputInt("Alignment", &alignment_);
    alignment_ = std::clamp(alignment_, 1, 4096);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0F);
    ImGui::InputInt("Max results", &max_results_);
    max_results_ = std::clamp(max_results_, 1, 2'000'000);

    const bool running = async_.Running();
    if (running) ImGui::BeginDisabled();
    if (ImGui::Button(scanner_->HasScan() ? "New First Scan" : "First Scan")) {
        scanner_->Reset();
        async_.StartFirst(*scanner_, BuildQuery());
        status_ = "First scan started.";
    }
    ImGui::SameLine();
    if (!scanner_->HasScan()) ImGui::BeginDisabled();
    if (ImGui::Button("Next Scan")) {
        async_.StartNext(*scanner_, BuildQuery());
        status_ = "Next scan started.";
    }
    if (!scanner_->HasScan()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Reset")) {
        scanner_->Reset();
        status_ = "Scan results cleared.";
    }
    if (running) ImGui::EndDisabled();
    if (running) {
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) async_.Cancel();
        const auto progress = async_.Progress();
        const float fraction = progress.bytes_total == 0
            ? 0.0F
            : static_cast<float>(
                static_cast<double>(progress.bytes_scanned) /
                static_cast<double>(progress.bytes_total));
        ImGui::ProgressBar(
            std::clamp(fraction, 0.0F, 1.0F),
            ImVec2(-1.0F, 0.0F),
            progress.phase.c_str());
        ImGui::Text("Regions %llu/%llu | Bytes 0x%llX/0x%llX | Candidates %llu",
            static_cast<unsigned long long>(progress.regions_scanned),
            static_cast<unsigned long long>(progress.regions_total),
            static_cast<unsigned long long>(progress.bytes_scanned),
            static_cast<unsigned long long>(progress.bytes_total),
            static_cast<unsigned long long>(progress.candidates));
    } else if (const auto error = async_.LastError(); error.has_value()) {
        status_ = error->message;
    } else if (const auto summary = async_.Summary(); summary.has_value()) {
        char buffer[192]{};
        std::snprintf(buffer, sizeof(buffer),
            "Scan complete: %llu result(s), 0x%llX bytes%s.",
            static_cast<unsigned long long>(summary->result_count),
            static_cast<unsigned long long>(summary->bytes_scanned),
            summary->truncated ? " (result limit reached)" : "");
        status_ = buffer;
    }
}

void ProcessScannerPanel::DrawResults() {
    ImGui::Text("Scan Results: %llu",
        static_cast<unsigned long long>(scanner_->Candidates().size()));
    if (async_.Running()) {
        ImGui::TextDisabled("Results are hidden while the worker updates the candidate set.");
        return;
    }
    const auto* active = scanner_->ActiveQuery();
    if (active == nullptr || scanner_->Candidates().empty()) {
        ImGui::TextDisabled("No scan results.");
        return;
    }

    if (ImGui::BeginTable(
            "scan-results", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
            ImVec2(0.0F, 260.0F))) {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Previous");
        ImGui::TableSetupColumn("Current");
        ImGui::TableSetupColumn("Delta");
        ImGui::TableSetupColumn("Watch");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            scanner_->Candidates().size(),
            static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                const auto& candidate = scanner_->Candidates()[static_cast<std::size_t>(index)];
                ImGui::PushID(index);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(candidate.address));
                ImGui::TableNextColumn();
                const auto previous = FormatValue(active->query.type, candidate.previous, active->query.hexadecimal);
                ImGui::TextUnformatted(previous.c_str());
                ImGui::TableNextColumn();
                const auto current = FormatValue(active->query.type, candidate.current, active->query.hexadecimal);
                ImGui::TextUnformatted(current.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(candidate.previous == candidate.current ? "=" : "changed");
                ImGui::TableNextColumn();
                if (FixedValueWidth(active->query.type) == 0) {
                    ImGui::TextDisabled("N/A");
                } else if (ImGui::SmallButton("Add")) {
                    const auto added = watches_->Add(
                        candidate.address,
                        active->query.type,
                        "scan result",
                        active->query.hexadecimal);
                    status_ = added ? "Address added to watch list." : added.GetError().message;
                }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
}

void ProcessScannerPanel::DrawWatchList() {
    ImGui::TextUnformatted("Address List / Freeze");
    const double now = ImGui::GetTime();
    if (now >= next_refresh_time_) {
        static_cast<void>(watches_->Refresh());
        if (memory_->WritesArmed()) static_cast<void>(watches_->FreezeTick());
        next_refresh_time_ = now + 0.20;
    }

    if (!memory_->WritesArmed()) {
        if (ImGui::Button("Arm Process Writes")) {
            write_confirmation_.fill('\0');
            ImGui::OpenPopup("Arm Process Writes##KDBG");
        }
    } else {
        if (ImGui::Button("Lock Process Writes")) {
            const auto result = memory_->SetWritesArmed(false);
            SetStatus(result, "Process writes locked.");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh Values")) {
        const auto result = watches_->Refresh();
        SetStatus(result, "Watch values refreshed.");
    }

    ImGui::SetNextItemWidth(390.0F);
    ImGui::InputText(
        "Address-list file",
        address_list_path_.data(), address_list_path_.size());
    ImGui::SameLine();
    if (ImGui::Button("Save Table")) {
        const auto result = watches_->Save(address_list_path_.data());
        SetStatus(result, "Address list saved.");
    }
    ImGui::SameLine();
    if (ImGui::Button("Load Table")) {
        const auto result = watches_->Load(address_list_path_.data());
        selected_watch_id_ = 0;
        SetStatus(result,
            "Address list loaded. Saved frozen entries were intentionally disarmed.");
    }

    ImGui::SetNextItemWidth(180.0F);
    ImGui::InputText(
        "Manual Address", manual_address_.data(), manual_address_.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(125.0F);
    ImGui::Combo(
        "Manual Type", &manual_type_index_,
        kTypeLabels, 10);
    ImGui::SameLine();
    ImGui::Checkbox("Manual Hex", &manual_hexadecimal_);
    ImGui::SetNextItemWidth(300.0F);
    ImGui::InputTextWithHint(
        "Description", "optional label",
        manual_description_.data(), manual_description_.size());
    ImGui::SameLine();
    if (ImGui::Button("Add Address")) {
        std::uint64_t address = 0;
        if (!ParseAddress(manual_address_.data(), &address) || address == 0) {
            status_ = "Manual address must be a non-zero decimal or 0x-prefixed value.";
        } else {
            const auto added = watches_->Add(
                address,
                kTypes[std::clamp(manual_type_index_, 0, 9)],
                manual_description_.data(),
                manual_hexadecimal_);
            status_ = added
                ? "Manual address added to the address list."
                : added.GetError().message;
        }
    }

    if (watches_->Entries().empty()) {
        ImGui::TextDisabled("Add an address from scan results.");
        return;
    }
    if (ImGui::BeginTable(
            "watch-list", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 220.0F))) {
        ImGui::TableSetupColumn("Freeze");
        ImGui::TableSetupColumn("Description");
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Value");
        ImGui::TableSetupColumn("Action");
        ImGui::TableHeadersRow();
        std::uint64_t remove_id = 0;
        auto& entries = watches_->Entries();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            entries.size(), static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart;
                 index < clipper.DisplayEnd; ++index) {
                auto& entry = entries[static_cast<std::size_t>(index)];
                ImGui::PushID(static_cast<int>(entry.id));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                bool frozen = entry.frozen;
                const bool cannot_enable_freeze =
                    !memory_->WritesArmed() && !entry.frozen;
                if (cannot_enable_freeze) ImGui::BeginDisabled();
                if (ImGui::Checkbox("##freeze", &frozen)) {
                    const auto result = watches_->SetFrozen(entry.id, frozen);
                    SetStatus(result, frozen ? "Address frozen." : "Address unfrozen.");
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
                if (ImGui::SmallButton("Edit")) {
                    selected_watch_id_ = entry.id;
                    std::snprintf(watch_value_.data(), watch_value_.size(), "%s", formatted.c_str());
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("Remove")) remove_id = entry.id;
                ImGui::PopID();
            }
        }
        if (remove_id != 0) static_cast<void>(watches_->Remove(remove_id));
        ImGui::EndTable();
    }

    if (selected_watch_id_ != 0) {
        ImGui::SetNextItemWidth(300.0F);
        ImGui::InputText("New Value", watch_value_.data(), watch_value_.size());
        ImGui::SameLine();
        if (!memory_->WritesArmed()) ImGui::BeginDisabled();
        if (ImGui::Button("Write & Verify")) {
            const auto result = watches_->WriteValue(selected_watch_id_, watch_value_.data());
            SetStatus(result, "Process value written and verified.");
        }
        if (!memory_->WritesArmed()) ImGui::EndDisabled();
    }
}

void ProcessScannerPanel::DrawWriteGateModal() {
    if (ImGui::BeginPopupModal(
            "Arm Process Writes##KDBG", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped(
            "Writes can destabilize the target. Use only in the assignment VM. "
            "Enter the attached PID (%u) to arm writes.",
            memory_->ProcessId());
        ImGui::InputText("PID confirmation", write_confirmation_.data(), write_confirmation_.size());
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
        if (!valid) ImGui::BeginDisabled();
        if (ImGui::Button("Arm")) {
            const auto result = memory_->SetWritesArmed(true);
            SetStatus(result, "Process writes armed.");
            if (result) ImGui::CloseCurrentPopup();
        }
        if (!valid) ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void ProcessScannerPanel::SetStatus(
    const Result<void>& result,
    std::string success) {
    status_ = result ? std::move(success) : result.GetError().message;
}

}  // namespace kdbg

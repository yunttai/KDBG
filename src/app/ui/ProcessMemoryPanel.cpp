#include "app/ui/ProcessMemoryPanel.h"

#include <algorithm>
#include <charconv>
#include <climits>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string_view>
#include <utility>

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
    *value = parsed;
    return true;
}

const char* StateText(ProcessMemorySessionState state) noexcept {
    switch (state) {
    case ProcessMemorySessionState::Empty: return "EMPTY";
    case ProcessMemorySessionState::Clean: return "CLEAN";
    case ProcessMemorySessionState::Dirty: return "DIRTY";
    case ProcessMemorySessionState::Conflict: return "CONFLICT";
    case ProcessMemorySessionState::VerificationFailed:
        return "VERIFICATION FAILED";
    case ProcessMemorySessionState::Error: return "ERROR";
    }
    return "UNKNOWN";
}

bool ContainsOffset(
    const std::vector<std::size_t>& offsets,
    std::size_t offset) {
    return std::find(offsets.begin(), offsets.end(), offset) != offsets.end();
}

}  // namespace

ProcessMemoryPanel::ProcessMemoryPanel() {
    std::snprintf(address_.data(), address_.size(), "0x0");
    editor_.Cols = 16;
    editor_.OptShowAscii = true;
    editor_.OptShowDataPreview = true;
    editor_.OptUpperCaseHex = true;
    editor_.ReadFn = &ProcessMemoryPanel::ReadByte;
    editor_.WriteFn = &ProcessMemoryPanel::WriteByte;
    editor_.BgColorFn = &ProcessMemoryPanel::ByteBackground;
}

void ProcessMemoryPanel::Attach(IProcessMemory* memory) {
    Reset();
    memory_ = memory;
    if (memory_ != nullptr) {
        status_ = "Process memory browser ready for PID " +
            std::to_string(memory_->ProcessId()) + ".";
    }
}

void ProcessMemoryPanel::Reset() {
    session_.Reset();
    memory_ = nullptr;
    write_confirmation_.fill('\0');
    status_.clear();
}

void ProcessMemoryPanel::Navigate(
    std::uint64_t address,
    std::uint32_t length) {
    std::snprintf(
        address_.data(), address_.size(),
        "0x%llX", static_cast<unsigned long long>(address));
    length_ = static_cast<int>(std::clamp<std::uint32_t>(
        length,
        1U,
        ProcessMemorySession::kMaximumViewSize));
    if (memory_ != nullptr && memory_->IsOpen()) {
        const auto result = session_.Load(
            *memory_, address, static_cast<std::uint32_t>(length_));
        SetStatus(result, "Process memory view loaded.");
    }
}

bool ProcessMemoryPanel::ParseRange(
    std::uint64_t* address,
    std::uint32_t* length) const {
    std::uint64_t parsed = 0;
    if (!ParseUnsigned(address_.data(), &parsed) || parsed == 0 ||
        length_ <= 0 ||
        length_ > static_cast<int>(ProcessMemorySession::kMaximumViewSize)) {
        return false;
    }
    if (parsed > std::numeric_limits<std::uint64_t>::max() -
        static_cast<std::uint64_t>(length_ - 1)) {
        return false;
    }
    *address = parsed;
    *length = static_cast<std::uint32_t>(length_);
    return true;
}

void ProcessMemoryPanel::Draw() {
    if (memory_ == nullptr || !memory_->IsOpen()) {
        ImGui::TextDisabled("Attach to a process to browse and edit its memory.");
        return;
    }

    ImGui::Text(
        "Attached PID: %u | Process write gate: %s",
        memory_->ProcessId(),
        memory_->WritesArmed() ? "ARMED" : "LOCKED");
    ImGui::SetNextItemWidth(220.0F);
    ImGui::InputText("Address", address_.data(), address_.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0F);
    ImGui::InputInt("Length", &length_);
    length_ = std::clamp(
        length_, 1,
        static_cast<int>(ProcessMemorySession::kMaximumViewSize));
    ImGui::SameLine();
    if (ImGui::Button("Read View")) {
        std::uint64_t address = 0;
        std::uint32_t length = 0;
        if (!ParseRange(&address, &length)) {
            status_ = "Enter a valid non-zero address and a length up to 1 MiB.";
        } else {
            const auto result = session_.Load(*memory_, address, length);
            SetStatus(result, "Process memory view loaded.");
        }
    }
    ImGui::SameLine();
    if (!session_.HasBuffer()) ImGui::BeginDisabled();
    if (ImGui::Button("Reload Live")) {
        const auto result = session_.Load(
            *memory_, session_.Address(),
            static_cast<std::uint32_t>(session_.Working().size()));
        SetStatus(result, "Process memory view reloaded from the target.");
    }
    if (!session_.HasBuffer()) ImGui::EndDisabled();

    if (!session_.HasBuffer()) {
        ImGui::Separator();
        ImGui::TextDisabled(
            "Load a committed readable range from the Memory Map or enter an address.");
        if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());
        DrawWriteGateModal();
        return;
    }

    ImGui::Separator();
    ImGui::Text(
        "State: %s | Range: 0x%016llX + 0x%llX | Dirty bytes: %llu",
        StateText(session_.State()),
        static_cast<unsigned long long>(session_.Address()),
        static_cast<unsigned long long>(session_.Working().size()),
        static_cast<unsigned long long>(session_.DirtyCount()));

    editor_.UserData = &session_;
    auto* bytes = const_cast<std::uint8_t*>(session_.Working().data());
    editor_.DrawContents(
        bytes,
        session_.Working().size(),
        static_cast<std::size_t>(session_.Address()));

    if (!session_.CanUndo()) ImGui::BeginDisabled();
    if (ImGui::Button("Undo Byte Edit")) {
        SetStatus(session_.Undo(), "Last process-memory byte edit undone.");
    }
    if (!session_.CanUndo()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!session_.CanRedo()) ImGui::BeginDisabled();
    if (ImGui::Button("Redo Byte Edit")) {
        SetStatus(session_.Redo(), "Last process-memory byte edit redone.");
    }
    if (!session_.CanRedo()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Revert Staged Edits")) {
        session_.RevertAll();
        status_ = "Staged process-memory edits reverted.";
    }
    ImGui::SameLine();
    if (!memory_->WritesArmed()) {
        if (ImGui::Button("Arm Process Writes")) {
            write_confirmation_.fill('\0');
            ImGui::OpenPopup("Arm Process Browser Writes##KDBG");
        }
    } else if (ImGui::Button("Lock Process Writes")) {
        const auto result = memory_->SetWritesArmed(false);
        SetStatus(result, "Process writes locked.");
    }
    ImGui::SameLine();
    const bool can_apply = session_.IsDirty() && memory_->WritesArmed();
    if (!can_apply) ImGui::BeginDisabled();
    if (ImGui::Button("Apply Changed Runs & Verify")) {
        const auto result = session_.ApplyAndVerify(*memory_);
        SetStatus(result,
            "Process-memory changes were written and the full view matched on read-back.");
    }
    if (!can_apply) ImGui::EndDisabled();
    if (session_.CanRollback()) {
        ImGui::SameLine();
        if (!memory_->WritesArmed()) ImGui::BeginDisabled();
        if (ImGui::Button("Rollback Previous Apply")) {
            const auto result = session_.Rollback(*memory_);
            SetStatus(result,
                "The previous process-memory baseline was restored and verified.");
        }
        if (!memory_->WritesArmed()) ImGui::EndDisabled();
    }

    const auto diffs = session_.ByteDiffs();
    if (!diffs.empty() && ImGui::CollapsingHeader(
            "Staged Byte Diff", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable(
                "process-memory-diffs", 4,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY,
                ImVec2(0.0F, 150.0F))) {
            ImGui::TableSetupColumn("Offset");
            ImGui::TableSetupColumn("Virtual Address");
            ImGui::TableSetupColumn("Before");
            ImGui::TableSetupColumn("After");
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(std::min<std::size_t>(
                diffs.size(), static_cast<std::size_t>(INT_MAX))));
            while (clipper.Step()) {
                for (int index = clipper.DisplayStart;
                     index < clipper.DisplayEnd; ++index) {
                    const auto& diff = diffs[static_cast<std::size_t>(index)];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%llX", static_cast<unsigned long long>(diff.offset));
                    ImGui::TableNextColumn();
                    ImGui::Text(
                        "0x%016llX",
                        static_cast<unsigned long long>(session_.Address() + diff.offset));
                    ImGui::TableNextColumn();
                    ImGui::Text("%02X", diff.before);
                    ImGui::TableNextColumn();
                    ImGui::Text("%02X", diff.after);
                }
            }
            ImGui::EndTable();
        }
    }

    if (!status_.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("%s", status_.c_str());
    }
    DrawWriteGateModal();
}

void ProcessMemoryPanel::DrawWriteGateModal() {
    if (memory_ == nullptr) return;
    if (ImGui::BeginPopupModal(
            "Arm Process Browser Writes##KDBG", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped(
            "Process writes can destabilize the target. Use only in the assignment VM. "
            "Enter the attached PID (%u) to open the shared process write gate.",
            memory_->ProcessId());
        ImGui::InputText(
            "PID confirmation",
            write_confirmation_.data(),
            write_confirmation_.size());
        std::uint32_t confirmed = 0;
        const auto parsed = std::from_chars(
            write_confirmation_.data(),
            write_confirmation_.data() +
                std::strlen(write_confirmation_.data()),
            confirmed,
            10);
        const bool valid = parsed.ec == std::errc{} &&
            parsed.ptr == write_confirmation_.data() +
                std::strlen(write_confirmation_.data()) &&
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

void ProcessMemoryPanel::SetStatus(
    const Result<void>& result,
    std::string success) {
    status_ = result ? std::move(success) : result.GetError().message;
}

ImU8 ProcessMemoryPanel::ReadByte(
    const ImU8*,
    std::size_t offset,
    void* user_data) {
    const auto* session = static_cast<const ProcessMemorySession*>(user_data);
    return session->Working().at(offset);
}

void ProcessMemoryPanel::WriteByte(
    ImU8*,
    std::size_t offset,
    ImU8 value,
    void* user_data) {
    auto* session = static_cast<ProcessMemorySession*>(user_data);
    static_cast<void>(session->EditByte(offset, value));
}

ImU32 ProcessMemoryPanel::ByteBackground(
    const ImU8*,
    std::size_t offset,
    void* user_data) {
    const auto* session = static_cast<const ProcessMemorySession*>(user_data);
    if (ContainsOffset(session->MismatchOffsets(), offset)) {
        return IM_COL32(190, 35, 35, 160);
    }
    if (ContainsOffset(session->ConflictOffsets(), offset)) {
        return IM_COL32(210, 125, 20, 150);
    }
    if (offset < session->DirtyBitmap().size() &&
        session->DirtyBitmap()[offset]) {
        return IM_COL32(40, 120, 210, 110);
    }
    return 0;
}

}  // namespace kdbg

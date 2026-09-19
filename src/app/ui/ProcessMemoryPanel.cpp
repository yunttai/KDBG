#include "app/ui/ProcessMemoryPanel.h"

#include "app/ui/Localization.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <exception>
#include <limits>
#include <string_view>
#include <utility>

namespace kdbg {

using ui::UiLabel;
using ui::UiText;

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

ProcessMemoryPanel::~ProcessMemoryPanel() {
    CancelAndWait();
}

bool ProcessMemoryPanel::Busy() const noexcept {
    return operation_future_.valid();
}

void ProcessMemoryPanel::Poll() {
    PollOperation();
}

void ProcessMemoryPanel::RequestCancel() noexcept {
    cancel_requested_.store(true, std::memory_order_relaxed);
}

void ProcessMemoryPanel::CancelAndWait() noexcept {
    RequestCancel();
    try {
        if (operation_future_.valid()) {
            PublishOperation(operation_future_.get());
        }
    } catch (...) {
        // Teardown still clears the session and releases the process pointer.
    }
    pending_navigation_.reset();
}

void ProcessMemoryPanel::Attach(IProcessMemory* memory) {
    Reset();
    memory_ = memory;
    if (memory_ != nullptr) {
        attached_pid_ = memory_->ProcessId();
        cached_writes_armed_ = memory_->WritesArmed();
        char status[128]{};
        std::snprintf(
            status,
            sizeof(status),
            UiText("Process memory browser ready for PID %u."),
            attached_pid_);
        status_ = status;
    }
}

void ProcessMemoryPanel::Reset() {
    CancelAndWait();
    ++generation_;
    pending_navigation_.reset();
    session_.Reset();
    memory_ = nullptr;
    attached_pid_ = 0;
    cached_writes_armed_ = false;
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
    if (memory_ != nullptr && (Busy() || memory_->IsOpen())) {
        const auto bounded_length = static_cast<std::uint32_t>(length_);
        if (Busy()) {
            ++generation_;
            pending_navigation_ = std::pair{address, bounded_length};
            cancel_requested_.store(true, std::memory_order_relaxed);
            status_ = UiText(
                "Navigation queued; cancelling the superseded process-memory operation.");
        } else {
            StartLoad(address, bounded_length, Operation::Load);
        }
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

void ProcessMemoryPanel::StartLoad(
    std::uint64_t address,
    std::uint32_t length,
    Operation operation) {
    if (Busy() || memory_ == nullptr || !memory_->IsOpen()) return;
    cancel_requested_.store(false, std::memory_order_relaxed);
    operation_progress_.store(0, std::memory_order_relaxed);
    const auto generation = ++generation_;
    IProcessMemory* const memory = memory_;
    status_ = operation == Operation::Reload
        ? UiText("Reloading the process-memory view asynchronously...")
        : UiText("Reading the process-memory view asynchronously...");
    operation_future_ = std::async(
        std::launch::async,
        [this, memory, address, length, operation, generation] {
            OperationOutcome outcome;
            outcome.generation = generation;
            outcome.operation = operation;
            try {
                if (cancel_requested_.load(std::memory_order_relaxed)) {
                    outcome.cancel_observed = true;
                    outcome.error = MakeError(
                        ErrorCode::Cancelled,
                        "Process-memory read was cancelled before starting",
                        "ProcessMemoryPanel::StartLoad");
                    return outcome;
                }
                operation_progress_.store(1, std::memory_order_relaxed);
                const auto result = outcome.session.Load(*memory, address, length);
                operation_progress_.store(2, std::memory_order_relaxed);
                if (!result) {
                    outcome.error = result.GetError();
                    return outcome;
                }
                if (cancel_requested_.load(std::memory_order_relaxed)) {
                    outcome.cancel_observed = true;
                    outcome.error = MakeError(
                        ErrorCode::Cancelled,
                        "Completed process-memory read was discarded after cancellation",
                        "ProcessMemoryPanel::StartLoad");
                    return outcome;
                }
                outcome.succeeded = true;
            } catch (const std::exception& exception) {
                outcome.error = MakeError(
                    ErrorCode::InternalInvariant,
                    "Process-memory read worker failed: " +
                        std::string(exception.what()),
                    "ProcessMemoryPanel::StartLoad");
            } catch (...) {
                outcome.error = MakeError(
                    ErrorCode::InternalInvariant,
                    "Process-memory read worker failed with an unknown exception",
                    "ProcessMemoryPanel::StartLoad");
            }
            return outcome;
        });
}

void ProcessMemoryPanel::StartSessionOperation(Operation operation) {
    if (Busy() || memory_ == nullptr || !memory_->IsOpen() ||
        !session_.HasBuffer()) {
        return;
    }
    cancel_requested_.store(false, std::memory_order_relaxed);
    operation_progress_.store(0, std::memory_order_relaxed);
    const auto generation = ++generation_;
    IProcessMemory* const memory = memory_;
    ProcessMemorySession snapshot = session_;
    status_ = operation == Operation::Apply
        ? UiText(
            "Applying staged process-memory changes and verifying read-back asynchronously...")
        : UiText(
            "Rolling back process-memory changes and verifying read-back asynchronously...");
    operation_future_ = std::async(
        std::launch::async,
        [this, memory, operation, generation, snapshot = std::move(snapshot)]() mutable {
            OperationOutcome outcome;
            outcome.generation = generation;
            outcome.operation = operation;
            outcome.session = std::move(snapshot);
            try {
                if (cancel_requested_.load(std::memory_order_relaxed)) {
                    outcome.cancel_observed = true;
                    outcome.error = MakeError(
                        ErrorCode::Cancelled,
                        "Process-memory write operation was cancelled before starting",
                        "ProcessMemoryPanel::StartSessionOperation");
                    return outcome;
                }
                operation_progress_.store(1, std::memory_order_relaxed);
                const auto result = operation == Operation::Apply
                    ? outcome.session.ApplyAndVerify(*memory)
                    : outcome.session.Rollback(*memory);
                operation_progress_.store(2, std::memory_order_relaxed);
                outcome.cancel_observed =
                    cancel_requested_.load(std::memory_order_relaxed);
                outcome.succeeded = result.Ok();
                if (!result) outcome.error = result.GetError();
            } catch (const std::exception& exception) {
                outcome.error = MakeError(
                    ErrorCode::InternalInvariant,
                    "Process-memory write worker failed: " +
                        std::string(exception.what()),
                    "ProcessMemoryPanel::StartSessionOperation");
            } catch (...) {
                outcome.error = MakeError(
                    ErrorCode::InternalInvariant,
                    "Process-memory write worker failed with an unknown exception",
                    "ProcessMemoryPanel::StartSessionOperation");
            }
            return outcome;
        });
}

void ProcessMemoryPanel::PollOperation() {
    using namespace std::chrono_literals;
    if (!operation_future_.valid() ||
        operation_future_.wait_for(0ms) != std::future_status::ready) {
        return;
    }
    std::optional<OperationOutcome> completed;
    try {
        completed = operation_future_.get();
    } catch (const std::exception& exception) {
        status_ = "Process-memory operation publication failed: " +
            std::string(exception.what());
    } catch (...) {
        status_ =
            "Process-memory operation publication failed with an unknown exception.";
    }
    if (completed.has_value()) PublishOperation(std::move(*completed));
    if (pending_navigation_.has_value() && memory_ != nullptr &&
        memory_->IsOpen()) {
        const auto [address, length] = *pending_navigation_;
        pending_navigation_.reset();
        StartLoad(address, length, Operation::Load);
    }
}

void ProcessMemoryPanel::PublishOperation(OperationOutcome outcome) {
    if (outcome.generation != generation_) return;
    const bool load = outcome.operation == Operation::Load ||
        outcome.operation == Operation::Reload;
    if (outcome.succeeded) {
        session_ = std::move(outcome.session);
        if (!load) cached_writes_armed_ = false;
        switch (outcome.operation) {
        case Operation::Load:
            status_ = UiText("Process memory view loaded.");
            break;
        case Operation::Reload:
            status_ = UiText("Process memory view reloaded from the target.");
            break;
        case Operation::Apply:
            status_ = UiText(
                "Process-memory changes were written and the full view matched on read-back.");
            break;
        case Operation::Rollback:
            status_ = UiText(
                "The previous process-memory baseline was restored and verified.");
            break;
        }
        if (outcome.cancel_observed && !load) {
            status_ += UiText(
                " Cancellation arrived after the safety-critical transaction began; verification and gate relock completed.");
        }
        return;
    }
    if (!load) {
        session_ = std::move(outcome.session);
        cached_writes_armed_ = false;
    }
    status_ = outcome.error.message;
}

void ProcessMemoryPanel::Draw() {
    PollOperation();
    const bool operation_busy = Busy();
    if (memory_ == nullptr || (!operation_busy && !memory_->IsOpen())) {
        ImGui::TextDisabled(UiText(
            "Attach to a process to browse and edit its memory."));
        return;
    }
    if (!operation_busy) cached_writes_armed_ = memory_->WritesArmed();

    ImGui::Text(
        UiText("Attached PID: %u | Process write gate: %s"),
        attached_pid_,
        operation_busy ? "TRANSACTION IN PROGRESS" :
            (cached_writes_armed_ ? "ARMED" : "LOCKED"));
    ImGui::SetNextItemWidth(220.0F);
    ImGui::InputText(
        UiLabel("Address", "Address").c_str(),
        address_.data(),
        address_.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0F);
    ImGui::InputInt(
        UiLabel("Length", "Length").c_str(), &length_);
    length_ = std::clamp(
        length_, 1,
        static_cast<int>(ProcessMemorySession::kMaximumViewSize));
    ImGui::SameLine();
    ImGui::BeginDisabled(operation_busy);
    if (ImGui::Button(UiText("Read View"))) {
        std::uint64_t address = 0;
        std::uint32_t length = 0;
        if (!ParseRange(&address, &length)) {
            status_ = UiText(
                "Enter a valid non-zero address and a length up to 1 MiB.");
        } else {
            StartLoad(address, length, Operation::Load);
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(operation_busy || !session_.HasBuffer());
    if (ImGui::Button(UiText("Reload Live"))) {
        StartLoad(
            session_.Address(),
            static_cast<std::uint32_t>(session_.Working().size()),
            Operation::Reload);
    }
    ImGui::EndDisabled();
    if (operation_busy) {
        ImGui::SameLine();
        if (ImGui::Button(UiText("Request Cancel"))) {
            cancel_requested_.store(true, std::memory_order_relaxed);
            status_ = UiText(
                "Cancellation requested. A started write transaction will finish verification and gate relock.");
        }
        const auto progress = operation_progress_.load(std::memory_order_relaxed);
        ImGui::ProgressBar(
            static_cast<float>(progress) / 2.0F,
            ImVec2(-1.0F, 0.0F),
            progress == 0 ? UiText("queued") :
                (progress == 1 ? UiText("working") : UiText("publishing")));
    }

    if (!session_.HasBuffer()) {
        ImGui::Separator();
        ImGui::TextDisabled(
            UiText(
                "Load a committed readable range from the Memory Map or enter an address."));
        if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());
        if (!operation_busy) DrawWriteGateModal();
        return;
    }

    ImGui::Separator();
    ImGui::Text(
        UiText(
            "State: %s | Range: 0x%016llX + 0x%llX | Dirty bytes: %llu"),
        StateText(session_.State()),
        static_cast<unsigned long long>(session_.Address()),
        static_cast<unsigned long long>(session_.Working().size()),
        static_cast<unsigned long long>(session_.DirtyCount()));

    editor_.UserData = &session_;
    auto* bytes = const_cast<std::uint8_t*>(session_.Working().data());
    ImGui::BeginDisabled(operation_busy);
    editor_.DrawContents(
        bytes,
        session_.Working().size(),
        static_cast<std::size_t>(session_.Address()));

    if (!session_.CanUndo()) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Undo Byte Edit"))) {
        SetStatus(
            session_.Undo(), UiText("Last process-memory byte edit undone."));
    }
    if (!session_.CanUndo()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!session_.CanRedo()) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Redo Byte Edit"))) {
        SetStatus(
            session_.Redo(), UiText("Last process-memory byte edit redone."));
    }
    if (!session_.CanRedo()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button(UiText("Revert Staged Edits"))) {
        session_.RevertAll();
        status_ = UiText("Staged process-memory edits reverted.");
    }
    ImGui::SameLine();
    if (!cached_writes_armed_) {
        if (ImGui::Button(UiText("Arm Process Writes"))) {
            write_confirmation_.fill('\0');
            const auto popup_label = UiLabel(
                "Arm Process Browser Writes",
                "Arm Process Browser Writes##KDBG");
            ImGui::OpenPopup(popup_label.c_str());
        }
    } else if (ImGui::Button(UiText("Lock Process Writes"))) {
        const auto result = memory_->SetWritesArmed(false);
        if (result) cached_writes_armed_ = false;
        SetStatus(result, UiText("Process writes locked."));
    }
    ImGui::SameLine();
    const bool can_apply = session_.IsDirty() && cached_writes_armed_;
    if (!can_apply) ImGui::BeginDisabled();
    if (ImGui::Button(UiText("Apply Changed Runs & Verify"))) {
        StartSessionOperation(Operation::Apply);
    }
    if (!can_apply) ImGui::EndDisabled();
    if (session_.CanRollback()) {
        ImGui::SameLine();
        if (!cached_writes_armed_) ImGui::BeginDisabled();
        if (ImGui::Button(UiText("Rollback Previous Apply"))) {
            StartSessionOperation(Operation::Rollback);
        }
        if (!cached_writes_armed_) ImGui::EndDisabled();
    }
    ImGui::EndDisabled();

    constexpr std::size_t kDiffPreviewCap = 16384;
    const auto diffs = session_.ByteDiffs(kDiffPreviewCap);
    const auto diff_header = UiLabel("Staged Byte Diff", "Staged Byte Diff");
    if (!diffs.empty() && ImGui::CollapsingHeader(
            diff_header.c_str(), ImGuiTreeNodeFlags_DefaultOpen)) {
        if (session_.DirtyCount() > diffs.size()) {
            ImGui::TextDisabled(
                UiText(
                    "Showing the first %llu of %llu changed bytes; the hex view retains every dirty highlight."),
                static_cast<unsigned long long>(diffs.size()),
                static_cast<unsigned long long>(session_.DirtyCount()));
        }
        if (ImGui::BeginTable(
                "process-memory-diffs", 4,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY,
                ImVec2(0.0F, 150.0F))) {
            ImGui::TableSetupColumn(UiLabel("Offset", "Offset").c_str());
            ImGui::TableSetupColumn(
                UiLabel("Virtual Address", "Virtual Address").c_str());
            ImGui::TableSetupColumn(UiLabel("Before", "Before").c_str());
            ImGui::TableSetupColumn(UiLabel("After", "After").c_str());
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
    if (!operation_busy) DrawWriteGateModal();
}

void ProcessMemoryPanel::DrawWriteGateModal() {
    if (memory_ == nullptr) return;
    const auto popup_label = UiLabel(
        "Arm Process Browser Writes", "Arm Process Browser Writes##KDBG");
    if (ImGui::BeginPopupModal(
            popup_label.c_str(), nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped(
            UiText(
                "Process writes affect the attached process on this Windows instance. "
                "Enter the attached PID (%u) to open the shared process write gate."),
            attached_pid_);
        ImGui::InputText(
            UiLabel("PID confirmation", "PID confirmation").c_str(),
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
            confirmed == attached_pid_ && !Busy();
        if (!valid) ImGui::BeginDisabled();
        if (ImGui::Button(UiText("Arm"))) {
            const auto result = memory_->SetWritesArmed(true);
            if (result) cached_writes_armed_ = true;
            SetStatus(result, UiText("Process writes armed."));
            if (result) ImGui::CloseCurrentPopup();
        }
        if (!valid) ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button(UiText("Cancel"))) ImGui::CloseCurrentPopup();
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

#include "core/memory/ProcessMemorySession.h"

#include <algorithm>
#include <limits>

namespace kdbg {
namespace {

class ProcessWriteArmGuard {
public:
    ProcessWriteArmGuard(IProcessMemory& memory, bool armed)
        : memory_(memory), armed_(armed) {}

    Result<void> Disarm() {
        if (!armed_) {
            return Result<void>::Success();
        }
        const auto result = memory_.SetWritesArmed(false);
        if (result) {
            armed_ = false;
        }
        return result;
    }

    ~ProcessWriteArmGuard() {
        if (armed_) {
            static_cast<void>(memory_.SetWritesArmed(false));
        }
    }

    ProcessWriteArmGuard(const ProcessWriteArmGuard&) = delete;
    ProcessWriteArmGuard& operator=(const ProcessWriteArmGuard&) = delete;

private:
    IProcessMemory& memory_;
    bool armed_{false};
};

}  // namespace

Result<void> ProcessMemorySession::Load(
    IProcessMemory& memory,
    std::uint64_t address,
    std::uint32_t length) {
    Reset();
    state_ = ProcessMemorySessionState::Error;
    if (!memory.IsOpen()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Target process is not attached",
            "ProcessMemorySession::Load"));
    }
    if (memory.ProcessId() == 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Target process has no valid PID",
            "ProcessMemorySession::Load"));
    }
    if (address == 0 || length == 0 || length > kMaximumViewSize ||
        address > std::numeric_limits<std::uint64_t>::max() - (length - 1U)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Process memory view address or length is invalid",
            "ProcessMemorySession::Load"));
    }
    auto bytes = memory.Read(address, length);
    if (!bytes) return Result<void>::Failure(bytes.GetError());
    if (bytes.Value().size() != length) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Process memory view returned fewer bytes than requested",
            "ProcessMemorySession::Load",
            0,
            length,
            bytes.Value().size()));
    }
    pid_ = memory.ProcessId();
    address_ = address;
    baseline_ = bytes.Value();
    working_ = bytes.TakeValue();
    dirty_.assign(working_.size(), false);
    rollback_.reset();
    rollback_expected_.reset();
    rollback_allows_partial_ = false;
    conflicts_.clear();
    mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    state_ = ProcessMemorySessionState::Clean;
    return Result<void>::Success();
}

void ProcessMemorySession::Reset() noexcept {
    pid_ = 0;
    address_ = 0;
    baseline_.clear();
    working_.clear();
    dirty_.clear();
    rollback_.reset();
    rollback_expected_.reset();
    rollback_allows_partial_ = false;
    conflicts_.clear();
    mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    state_ = ProcessMemorySessionState::Empty;
}

Result<void> ProcessMemorySession::ApplyLocalEdit(
    std::size_t offset,
    std::uint8_t value,
    bool record_history) {
    if (!HasBuffer() || offset >= working_.size()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Process memory edit offset is outside the loaded view",
            "ProcessMemorySession::ApplyLocalEdit"));
    }
    const auto previous = working_[offset];
    if (previous == value) {
        return Result<void>::Success();
    }
    if (record_history) {
        undo_stack_.push_back(ByteEdit{offset, previous, value});
        redo_stack_.clear();
    }
    working_[offset] = value;
    dirty_[offset] = working_[offset] != baseline_[offset];
    state_ = IsDirty()
        ? ProcessMemorySessionState::Dirty
        : ProcessMemorySessionState::Clean;
    return Result<void>::Success();
}

Result<void> ProcessMemorySession::EditByte(
    std::size_t offset,
    std::uint8_t value) {
    return ApplyLocalEdit(offset, value, true);
}

Result<void> ProcessMemorySession::RevertByte(std::size_t offset) {
    if (!HasBuffer() || offset >= working_.size()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Process memory revert offset is outside the loaded view",
            "ProcessMemorySession::RevertByte"));
    }
    return ApplyLocalEdit(offset, baseline_[offset], true);
}

Result<void> ProcessMemorySession::Undo() {
    if (undo_stack_.empty()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No process-memory edit is available to undo",
            "ProcessMemorySession::Undo"));
    }
    const auto edit = undo_stack_.back();
    undo_stack_.pop_back();
    const auto result = ApplyLocalEdit(edit.offset, edit.before, false);
    if (!result) {
        undo_stack_.push_back(edit);
        return result;
    }
    redo_stack_.push_back(edit);
    return Result<void>::Success();
}

Result<void> ProcessMemorySession::Redo() {
    if (redo_stack_.empty()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No process-memory edit is available to redo",
            "ProcessMemorySession::Redo"));
    }
    const auto edit = redo_stack_.back();
    redo_stack_.pop_back();
    const auto result = ApplyLocalEdit(edit.offset, edit.after, false);
    if (!result) {
        redo_stack_.push_back(edit);
        return result;
    }
    undo_stack_.push_back(edit);
    return Result<void>::Success();
}

void ProcessMemorySession::RevertAll() noexcept {
    if (!HasBuffer()) return;
    working_ = baseline_;
    std::fill(dirty_.begin(), dirty_.end(), false);
    conflicts_.clear();
    mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    state_ = ProcessMemorySessionState::Clean;
}

Result<std::vector<std::uint8_t>> ProcessMemorySession::ReadExact(
    IProcessMemory& memory) const {
    if (!HasBuffer() || working_.size() >
        std::numeric_limits<std::uint32_t>::max()) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::InternalInvariant,
            "Process memory session is not loaded",
            "ProcessMemorySession::ReadExact"));
    }
    auto bytes = memory.Read(
        address_,
        static_cast<std::uint32_t>(working_.size()));
    if (!bytes) return bytes;
    if (bytes.Value().size() != working_.size()) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Process memory read returned fewer bytes than requested",
            "ProcessMemorySession::ReadExact",
            0,
            working_.size(),
            bytes.Value().size()));
    }
    return bytes;
}

Result<void> ProcessMemorySession::ValidateTarget(
    const IProcessMemory& memory) const {
    if (!HasBuffer() || pid_ == 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InternalInvariant,
            "Process memory session is not bound to a target PID",
            "ProcessMemorySession::ValidateTarget"));
    }
    if (!memory.IsOpen()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Target process is no longer attached",
            "ProcessMemorySession::ValidateTarget"));
    }
    if (memory.ProcessId() != pid_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Process memory session was applied to a different PID",
            "ProcessMemorySession::ValidateTarget",
            0,
            pid_,
            memory.ProcessId()));
    }
    return Result<void>::Success();
}

Result<void> ProcessMemorySession::ApplyAndVerify(IProcessMemory& memory) {
    const bool writes_armed = memory.WritesArmed();
    ProcessWriteArmGuard arm_guard(memory, writes_armed);
    auto finish = [&](Result<void> outcome) -> Result<void> {
        const auto disarm = arm_guard.Disarm();
        if (!disarm) {
            state_ = ProcessMemorySessionState::Error;
            return Result<void>::Failure(disarm.GetError());
        }
        return outcome;
    };

    if (!HasBuffer() || !IsDirty()) {
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No process memory edits are pending",
            "ProcessMemorySession::ApplyAndVerify")));
    }
    if (!writes_armed) {
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Arm process writes before applying the memory view",
            "ProcessMemorySession::ApplyAndVerify")));
    }

    const auto target = ValidateTarget(memory);
    if (!target) {
        return finish(Result<void>::Failure(target.GetError()));
    }

    auto live = ReadExact(memory);
    if (!live) {
        state_ = ProcessMemorySessionState::Error;
        return finish(Result<void>::Failure(live.GetError()));
    }
    conflicts_.clear();
    mismatches_.clear();
    for (std::size_t index = 0; index < baseline_.size(); ++index) {
        if (live.Value()[index] != baseline_[index]) conflicts_.push_back(index);
    }
    if (!conflicts_.empty()) {
        state_ = ProcessMemorySessionState::Conflict;
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            "Process memory changed after the view was loaded",
            "ProcessMemorySession::ApplyAndVerify",
            0,
            baseline_.size(),
            conflicts_.size())));
    }

    rollback_ = baseline_;
    rollback_expected_ = working_;
    rollback_allows_partial_ = true;
    const auto runs = DiffRuns();
    for (const auto& run : runs) {
        const auto written = memory.Write(address_ + run.offset, run.after);
        if (!written) {
            state_ = ProcessMemorySessionState::Error;
            return finish(Result<void>::Failure(written.GetError()));
        }
        if (written.Value() != run.after.size()) {
            state_ = ProcessMemorySessionState::Error;
            return finish(Result<void>::Failure(MakeError(
                ErrorCode::ShortWrite,
                "Process memory write returned a short byte count",
                "ProcessMemorySession::ApplyAndVerify",
                0,
                run.after.size(),
                written.Value())));
        }
    }


    const auto disarm = arm_guard.Disarm();
    if (!disarm) {
        state_ = ProcessMemorySessionState::Error;
        return Result<void>::Failure(disarm.GetError());
    }

    auto readback = ReadExact(memory);
    if (!readback) {
        state_ = ProcessMemorySessionState::VerificationFailed;
        return Result<void>::Failure(readback.GetError());
    }
    mismatches_.clear();
    for (std::size_t index = 0; index < working_.size(); ++index) {
        if (readback.Value()[index] != working_[index]) {
            mismatches_.push_back(index);
        }
    }
    if (!mismatches_.empty()) {
        state_ = ProcessMemorySessionState::VerificationFailed;
        return Result<void>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            "Process memory read-back differs from the staged view",
            "ProcessMemorySession::ApplyAndVerify",
            0,
            working_.size(),
            working_.size() - mismatches_.size()));
    }

    baseline_ = working_;
    std::fill(dirty_.begin(), dirty_.end(), false);
    conflicts_.clear();
    mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    rollback_allows_partial_ = false;
    state_ = ProcessMemorySessionState::Clean;
    return Result<void>::Success();
}

Result<void> ProcessMemorySession::Rollback(IProcessMemory& memory) {
    const bool writes_armed = memory.WritesArmed();
    ProcessWriteArmGuard arm_guard(memory, writes_armed);
    auto finish = [&](Result<void> outcome) -> Result<void> {
        const auto disarm = arm_guard.Disarm();
        if (!disarm) {
            state_ = ProcessMemorySessionState::Error;
            return Result<void>::Failure(disarm.GetError());
        }
        return outcome;
    };

    if (!rollback_.has_value()) {
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No process memory rollback snapshot is available",
            "ProcessMemorySession::Rollback")));
    }
    if (!writes_armed) {
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Arm process writes before rollback",
            "ProcessMemorySession::Rollback")));
    }

    const auto target = ValidateTarget(memory);
    if (!target) {
        return finish(Result<void>::Failure(target.GetError()));
    }

    conflicts_.clear();
    mismatches_.clear();
    auto live = ReadExact(memory);
    if (!live) {
        state_ = ProcessMemorySessionState::Error;
        return finish(Result<void>::Failure(live.GetError()));
    }
    if (rollback_->size() != baseline_.size() ||
        (rollback_expected_ && rollback_expected_->size() != baseline_.size())) {
        state_ = ProcessMemorySessionState::Error;
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::InternalInvariant,
            "Process rollback evidence has an invalid size",
            "ProcessMemorySession::Rollback")));
    }
    for (std::size_t index = 0; index < baseline_.size(); ++index) {
        bool expected = live.Value()[index] == baseline_[index];
        if (rollback_allows_partial_ && rollback_expected_) {
            expected = live.Value()[index] == (*rollback_)[index] ||
                live.Value()[index] == (*rollback_expected_)[index];
        }
        if (!expected) {
            conflicts_.push_back(index);
        }
    }
    if (!conflicts_.empty()) {
        state_ = ProcessMemorySessionState::Conflict;
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            "Process memory changed before rollback",
            "ProcessMemorySession::Rollback",
            0,
            baseline_.size(),
            conflicts_.size())));
    }

    rollback_expected_ = live.Value();
    rollback_allows_partial_ = true;
    const auto written = memory.Write(address_, *rollback_);
    if (!written) {
        state_ = ProcessMemorySessionState::Error;
        return finish(Result<void>::Failure(written.GetError()));
    }
    if (written.Value() != rollback_->size()) {
        state_ = ProcessMemorySessionState::Error;
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::ShortWrite,
            "Process memory rollback returned a short byte count",
            "ProcessMemorySession::Rollback",
            0,
            rollback_->size(),
            written.Value())));
    }

    const auto disarm = arm_guard.Disarm();
    if (!disarm) {
        state_ = ProcessMemorySessionState::Error;
        return Result<void>::Failure(disarm.GetError());
    }
    auto readback = ReadExact(memory);
    if (!readback) {
        state_ = ProcessMemorySessionState::VerificationFailed;
        return Result<void>::Failure(readback.GetError());
    }
    for (std::size_t index = 0; index < rollback_->size(); ++index) {
        if (readback.Value()[index] != (*rollback_)[index]) {
            mismatches_.push_back(index);
        }
    }
    if (!mismatches_.empty()) {
        state_ = ProcessMemorySessionState::VerificationFailed;
        return Result<void>::Failure(MakeError(
            ErrorCode::RollbackFailed,
            "Process memory rollback read-back failed",
            "ProcessMemorySession::Rollback",
            0,
            rollback_->size(),
            rollback_->size() - mismatches_.size()));
    }
    baseline_ = *rollback_;
    working_ = baseline_;
    std::fill(dirty_.begin(), dirty_.end(), false);
    rollback_.reset();
    rollback_expected_.reset();
    rollback_allows_partial_ = false;
    conflicts_.clear();
    mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    state_ = ProcessMemorySessionState::Clean;
    return Result<void>::Success();
}

bool ProcessMemorySession::HasBuffer() const noexcept {
    return address_ != 0 && !working_.empty();
}

bool ProcessMemorySession::IsDirty() const noexcept {
    return std::any_of(dirty_.begin(), dirty_.end(), [](bool value) {
        return value;
    });
}

std::size_t ProcessMemorySession::DirtyCount() const noexcept {
    return static_cast<std::size_t>(std::count(dirty_.begin(), dirty_.end(), true));
}

bool ProcessMemorySession::CanRollback() const noexcept {
    return rollback_.has_value();
}

bool ProcessMemorySession::CanUndo() const noexcept {
    return !undo_stack_.empty();
}

bool ProcessMemorySession::CanRedo() const noexcept {
    return !redo_stack_.empty();
}

std::uint64_t ProcessMemorySession::Address() const noexcept { return address_; }
ProcessMemorySessionState ProcessMemorySession::State() const noexcept { return state_; }
const std::vector<std::uint8_t>& ProcessMemorySession::Baseline() const noexcept { return baseline_; }
const std::vector<std::uint8_t>& ProcessMemorySession::Working() const noexcept { return working_; }
const std::vector<bool>& ProcessMemorySession::DirtyBitmap() const noexcept { return dirty_; }
const std::vector<std::size_t>& ProcessMemorySession::ConflictOffsets() const noexcept { return conflicts_; }
const std::vector<std::size_t>& ProcessMemorySession::MismatchOffsets() const noexcept { return mismatches_; }

std::vector<ByteDiff> ProcessMemorySession::ByteDiffs() const {
    std::vector<ByteDiff> output;
    output.reserve(DirtyCount());
    for (std::size_t index = 0; index < dirty_.size(); ++index) {
        if (!dirty_[index]) continue;
        output.push_back(ByteDiff{index, baseline_[index], working_[index]});
    }
    return output;
}

std::vector<DiffRun> ProcessMemorySession::DiffRuns() const {
    std::vector<DiffRun> output;
    std::size_t index = 0;
    while (index < dirty_.size()) {
        if (!dirty_[index]) {
            ++index;
            continue;
        }
        const std::size_t start = index;
        while (index < dirty_.size() && dirty_[index]) ++index;
        DiffRun run{};
        run.offset = start;
        run.before.assign(
            baseline_.begin() + static_cast<std::ptrdiff_t>(start),
            baseline_.begin() + static_cast<std::ptrdiff_t>(index));
        run.after.assign(
            working_.begin() + static_cast<std::ptrdiff_t>(start),
            working_.begin() + static_cast<std::ptrdiff_t>(index));
        output.push_back(std::move(run));
    }
    return output;
}

void ProcessMemorySession::RecomputeDirty() noexcept {
    if (baseline_.size() != working_.size()) return;
    dirty_.resize(working_.size());
    for (std::size_t index = 0; index < working_.size(); ++index) {
        dirty_[index] = baseline_[index] != working_[index];
    }
}

}  // namespace kdbg

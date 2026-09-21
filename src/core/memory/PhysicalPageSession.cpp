#include "core/memory/PhysicalPageSession.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace kdbg {
namespace {

class WriteGateGuard {
public:
    explicit WriteGateGuard(IMemoryBackend& backend) : backend_(backend) {}

    Result<void> Enable() {
        const auto result = backend_.SetWriteEnabled(true);
        if (!result) {
            const auto fail_closed = backend_.SetWriteEnabled(false);
            if (!fail_closed) {
                auto error = fail_closed.GetError();
                error.message =
                    "Physical write-gate enable failed and fail-closed cleanup also failed: " +
                    error.message;
                return Result<void>::Failure(std::move(error));
            }
            return result;
        }
        enabled_ = true;
        return Result<void>::Success();
    }

    Result<void> Close() {
        if (!enabled_) {
            return Result<void>::Success();
        }
        const auto result = backend_.SetWriteEnabled(false);
        if (result) {
            enabled_ = false;
        }
        return result;
    }

    ~WriteGateGuard() {
        if (enabled_) {
            static_cast<void>(backend_.SetWriteEnabled(false));
        }
    }

    WriteGateGuard(const WriteGateGuard&) = delete;
    WriteGateGuard& operator=(const WriteGateGuard&) = delete;

private:
    IMemoryBackend& backend_;
    bool enabled_{false};
};

std::string FirstOffsetMessage(
    const char* prefix,
    const std::vector<std::size_t>& offsets) {
    std::ostringstream stream;
    stream << prefix;
    if (!offsets.empty()) {
        stream << " at offset 0x" << std::hex << offsets.front();
        if (offsets.size() > 1U) {
            stream << " (" << std::dec << offsets.size()
                   << " total mismatches)";
        }
    }
    return stream.str();
}

}  // namespace

Result<void> PhysicalPageSession::Load(
    IMemoryBackend& backend,
    const PfnAddress& address) {
    return Load(backend, PhysicalWriteTarget::RawPfn(address));
}

Result<void> PhysicalPageSession::Load(
    IMemoryBackend& backend,
    const PhysicalWriteTarget& target) {
    LockWrite();
    ClearPageData();
    state_ = PageSessionState::Loading;
    if (!target.address.IsConsistent()) {
        state_ = PageSessionState::Error;
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidPfn,
            "PFN and physical address do not identify the same complete page",
            "PhysicalPageSession::Load"));
    }
    if (!target.IsConsistent()) {
        state_ = PageSessionState::Error;
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Physical write target metadata is incomplete or inconsistent",
            "PhysicalPageSession::Load"));
    }
    target_ = target;

    const auto range_result = ValidatePageRange(backend);
    if (!range_result) {
        state_ = PageSessionState::Error;
        target_.reset();
        return range_result;
    }

    const auto read_result = ReadExactPage(backend);
    if (!read_result) {
        state_ = PageSessionState::Error;
        target_.reset();
        return Result<void>::Failure(read_result.GetError());
    }

    baseline_ = *read_result.Value();
    working_ = baseline_;
    evidence_.baseline = baseline_;
    ++revision_;
    state_ = PageSessionState::Clean;
    return Result<void>::Success();
}

Result<void> PhysicalPageSession::ReloadPreservingRollback(
    IMemoryBackend& backend) {
    if (!target_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical page is loaded",
            "PhysicalPageSession::ReloadPreservingRollback"));
    }
    if (dirty_.any() && !recovery_observation_required_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Revert or apply staged edits before an independent reload",
            "PhysicalPageSession::ReloadPreservingRollback"));
    }
    if (!rollback_snapshot_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Independent evidence reload requires a previous successful apply",
            "PhysicalPageSession::ReloadPreservingRollback"));
    }
    if (state_ == PageSessionState::Preflight ||
        state_ == PageSessionState::Writing ||
        state_ == PageSessionState::Verifying) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "The page cannot be reloaded while a physical operation is active",
            "PhysicalPageSession::ReloadPreservingRollback"));
    }

    evidence_.independent_reload.reset();
    LockWrite();
    last_conflicts_.clear();
    last_mismatches_.clear();
    const auto range_result = ValidatePageRange(backend);
    if (!range_result) {
        const auto error = range_result.GetError();
        if (error.code == ErrorCode::BackendDisconnected) {
            Invalidate();
            return Result<void>::Failure(error);
        }
        state_ = PageSessionState::Error;
        return range_result;
    }

    state_ = PageSessionState::Verifying;
    const auto reload_result = ReadExactPage(backend);
    if (!reload_result) {
        const auto error = reload_result.GetError();
        if (error.code == ErrorCode::BackendDisconnected) {
            Invalidate();
            return Result<void>::Failure(error);
        }
        state_ = PageSessionState::VerificationFailed;
        return Result<void>::Failure(error);
    }

    const auto& reloaded = *reload_result.Value();
    evidence_.independent_reload = reloaded;
    if (recovery_observation_required_) {
        rollback_expected_ = reloaded;
        recovery_observation_required_ = false;
        baseline_ = reloaded;
        working_ = reloaded;
        dirty_.reset();
        undo_stack_.clear();
        redo_stack_.clear();
        ++revision_;
        state_ = PageSessionState::Clean;

        if (rollback_snapshot_ && reloaded == *rollback_snapshot_) {
            rollback_snapshot_.reset();
            rollback_expected_.reset();
        }
        return Result<void>::Success();
    }
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        if (reloaded[offset] != baseline_[offset]) {
            last_mismatches_.push_back(offset);
        }
    }
    if (!last_mismatches_.empty()) {
        state_ = PageSessionState::VerificationFailed;
        return Result<void>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            FirstOffsetMessage(
                "Independent reload does not match the verified write",
                last_mismatches_),
            "PhysicalPageSession::ReloadPreservingRollback"));
    }

    baseline_ = reloaded;
    working_ = baseline_;
    dirty_.reset();
    undo_stack_.clear();
    redo_stack_.clear();
    ++revision_;
    state_ = PageSessionState::Clean;
    return Result<void>::Success();
}

void PhysicalPageSession::Invalidate() noexcept {
    LockWrite();
    ClearPageData();
    ++revision_;
    state_ = PageSessionState::Empty;
}

Result<void> PhysicalPageSession::ApplyLocalEdit(
    std::size_t offset,
    std::uint8_t value,
    bool record_history) {
    if (!target_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical page is loaded",
            "PhysicalPageSession::ApplyLocalEdit"));
    }
    if (offset >= kPhysicalPageSize) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Byte offset is outside the 4 KiB page",
            "PhysicalPageSession::ApplyLocalEdit"));
    }
    if (state_ == PageSessionState::Preflight ||
        state_ == PageSessionState::Writing ||
        state_ == PageSessionState::Verifying) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "The page cannot be edited while an apply operation is active",
            "PhysicalPageSession::ApplyLocalEdit"));
    }

    const auto previous = working_[offset];
    if (previous == value) {
        return Result<void>::Success();
    }
    if (record_history) {
        try {
            undo_stack_.push_back(ByteEdit{offset, previous, value});
        } catch (const std::bad_alloc&) {
            return Result<void>::Failure(MakeError(
                ErrorCode::LimitReached,
                "Physical-page edit history allocation failed",
                "PhysicalPageSession::ApplyLocalEdit"));
        } catch (const std::length_error&) {
            return Result<void>::Failure(MakeError(
                ErrorCode::LimitReached,
                "Physical-page edit history reached its container limit",
                "PhysicalPageSession::ApplyLocalEdit"));
        }
        if (undo_stack_.size() > kMaxEditHistory) {
            undo_stack_.pop_front();
        }
        redo_stack_.clear();
    }
    working_[offset] = value;
    dirty_.set(offset, baseline_[offset] != working_[offset]);
    ++revision_;
    LockWrite();
    state_ = dirty_.any() ? PageSessionState::Dirty
                          : PageSessionState::Clean;
    return Result<void>::Success();
}

Result<void> PhysicalPageSession::EditByte(
    std::size_t offset,
    std::uint8_t value) {
    return ApplyLocalEdit(offset, value, true);
}

Result<void> PhysicalPageSession::RevertByte(std::size_t offset) {
    if (!target_ || offset >= kPhysicalPageSize) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Cannot revert the requested byte",
            "PhysicalPageSession::RevertByte"));
    }
    return ApplyLocalEdit(offset, baseline_[offset], true);
}

Result<void> PhysicalPageSession::Undo() {
    if (undo_stack_.empty()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical-page edit is available to undo",
            "PhysicalPageSession::Undo"));
    }
    const auto edit = undo_stack_.back();
    try {
        redo_stack_.push_back(edit);
    } catch (const std::bad_alloc&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Physical-page redo history allocation failed",
            "PhysicalPageSession::Undo"));
    } catch (const std::length_error&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Physical-page redo history reached its container limit",
            "PhysicalPageSession::Undo"));
    }
    const auto result = ApplyLocalEdit(edit.offset, edit.before, false);
    if (!result) {
        redo_stack_.pop_back();
        return result;
    }
    undo_stack_.pop_back();
    return Result<void>::Success();
}

Result<void> PhysicalPageSession::Redo() {
    if (redo_stack_.empty()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical-page edit is available to redo",
            "PhysicalPageSession::Redo"));
    }
    const auto edit = redo_stack_.back();
    try {
        undo_stack_.push_back(edit);
    } catch (const std::bad_alloc&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Physical-page undo history allocation failed",
            "PhysicalPageSession::Redo"));
    } catch (const std::length_error&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Physical-page undo history reached its container limit",
            "PhysicalPageSession::Redo"));
    }
    const auto result = ApplyLocalEdit(edit.offset, edit.after, false);
    if (!result) {
        undo_stack_.pop_back();
        return result;
    }
    redo_stack_.pop_back();
    return Result<void>::Success();
}

void PhysicalPageSession::RevertAll() noexcept {
    if (!target_) {
        return;
    }
    working_ = baseline_;
    dirty_.reset();
    last_conflicts_.clear();
    last_mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    LockWrite();
    ++revision_;
    state_ = PageSessionState::Clean;
}

Result<void> PhysicalPageSession::UnlockForOneApply(
    std::uint64_t retyped_pfn) {
    if (!target_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical page is loaded",
            "PhysicalPageSession::UnlockForOneApply"));
    }
    if (!dirty_.any()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "There are no changes to apply",
            "PhysicalPageSession::UnlockForOneApply"));
    }
    if (retyped_pfn != target_->address.pfn) {
        return Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Retyped PFN does not match the current page",
            "PhysicalPageSession::UnlockForOneApply"));
    }

    write_unlocked_ = true;
    return Result<void>::Success();
}


Result<void> PhysicalPageSession::UnlockForRollback(
    std::uint64_t retyped_pfn) {
    if (!target_ || !rollback_snapshot_ || !rollback_expected_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No previous successful apply is available for rollback",
            "PhysicalPageSession::UnlockForRollback"));
    }
    if (retyped_pfn != target_->address.pfn) {
        return Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Retyped PFN does not match the current page",
            "PhysicalPageSession::UnlockForRollback"));
    }

    write_unlocked_ = true;
    return Result<void>::Success();
}

Result<void> PhysicalPageSession::ApplyAndVerify(
    IMemoryBackend& backend) {
    if (!target_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical page is loaded",
            "PhysicalPageSession::ApplyAndVerify"));
    }
    if (!dirty_.any()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "There are no dirty bytes",
            "PhysicalPageSession::ApplyAndVerify"));
    }
    if (!write_unlocked_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Write is locked for the current page",
            "PhysicalPageSession::ApplyAndVerify"));
    }

    LockWrite();
    last_apply_verified_ = false;
    recovery_observation_required_ = false;
    last_conflicts_.clear();
    last_mismatches_.clear();
    ClearEvidence();
    evidence_.baseline = baseline_;

    const auto range_result = ValidatePageRange(backend);
    if (!range_result) {
        const auto error = range_result.GetError();
        if (error.code == ErrorCode::BackendDisconnected) {
            Invalidate();
            return Result<void>::Failure(error);
        }
        state_ = PageSessionState::Error;
        return range_result;
    }

    rollback_snapshot_ = baseline_;
    rollback_expected_.reset();
    evidence_.expected_after = working_;

    WriteGateGuard gate(backend);
    const auto gate_result = gate.Enable();
    if (!gate_result) {
        rollback_snapshot_.reset();
        if (gate_result.GetError().code == ErrorCode::BackendDisconnected) {
            const auto error = gate_result.GetError();
            Invalidate();
            return Result<void>::Failure(error);
        }
        state_ = PageSessionState::Error;
        return gate_result;
    }

    state_ = PageSessionState::Writing;
    const auto transaction = backend.CompareWritePhysicalPage(
        target_->address.physical_address,
        std::span<const std::uint8_t>(baseline_.data(), baseline_.size()),
        std::span<const std::uint8_t>(working_.data(), working_.size()));
    if (!transaction) {
        rollback_expected_.reset();
        recovery_observation_required_ = true;
        state_ = PageSessionState::VerificationFailed;
        const auto close_result = gate.Close();
        if (!close_result) {
            return close_result;
        }
        return Result<void>::Failure(transaction.GetError());
    }

    const auto& result = transaction.Value();
    evidence_.readback = result.readback;
    if (result.outcome == PhysicalPageCompareWriteOutcome::Conflict) {
        evidence_.preflight = result.readback;
        rollback_snapshot_.reset();
        recovery_observation_required_ = false;
        for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
            if (result.readback[offset] != baseline_[offset]) {
                last_conflicts_.push_back(offset);
            }
        }
    } else {
        // The kernel transaction established that expected-before matched as
        // one complete page before attempting the write.
        evidence_.preflight = baseline_;
        rollback_expected_ = result.readback;
        recovery_observation_required_ = false;
    }

    const auto close_result = gate.Close();
    if (!close_result) {
        state_ = PageSessionState::Error;
        return close_result;
    }

    if (result.outcome == PhysicalPageCompareWriteOutcome::Conflict) {
        state_ = PageSessionState::Conflict;
        return Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            FirstOffsetMessage(
                "Live page changed after it was loaded",
                last_conflicts_),
            "PhysicalPageSession::ApplyAndVerify"));
    }

    state_ = PageSessionState::Verifying;
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        if (result.readback[offset] != working_[offset]) {
            last_mismatches_.push_back(offset);
        }
    }
    if (result.outcome != PhysicalPageCompareWriteOutcome::Applied ||
        result.transferred != kPhysicalPageSize ||
        !last_mismatches_.empty()) {
        state_ = PageSessionState::VerificationFailed;
        const auto error_code =
            result.transferred != 0U &&
                result.transferred != kPhysicalPageSize
            ? ErrorCode::ShortWrite
            : ErrorCode::VerificationMismatch;
        return Result<void>::Failure(MakeError(
            error_code,
            FirstOffsetMessage(
                "Verified physical transaction did not produce the requested page",
                last_mismatches_),
            "PhysicalPageSession::ApplyAndVerify",
            result.native_status,
            kPhysicalPageSize,
            result.transferred));
    }

    baseline_ = result.readback;
    working_ = result.readback;
    dirty_.reset();
    undo_stack_.clear();
    redo_stack_.clear();
    last_apply_verified_ = true;
    ++revision_;
    state_ = PageSessionState::Clean;
    return Result<void>::Success();
}

Result<void> PhysicalPageSession::RollbackBaseline(
    IMemoryBackend& backend) {
    if (!target_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical page is loaded",
            "PhysicalPageSession::RollbackBaseline"));
    }
    if (!rollback_snapshot_ || !rollback_expected_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No previous baseline snapshot is available for rollback",
            "PhysicalPageSession::RollbackBaseline"));
    }
    if (!write_unlocked_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Rollback requires a one-apply write unlock",
            "PhysicalPageSession::RollbackBaseline"));
    }

    LockWrite();
    last_conflicts_.clear();
    last_mismatches_.clear();
    evidence_.rollback.reset();
    const auto range_result = ValidatePageRange(backend);
    if (!range_result) {
        const auto error = range_result.GetError();
        if (error.code == ErrorCode::BackendDisconnected) {
            Invalidate();
            return Result<void>::Failure(error);
        }
        state_ = PageSessionState::Error;
        return range_result;
    }


    WriteGateGuard gate(backend);
    const auto gate_result = gate.Enable();
    if (!gate_result) {
        if (gate_result.GetError().code == ErrorCode::BackendDisconnected) {
            const auto error = gate_result.GetError();
            Invalidate();
            return Result<void>::Failure(error);
        }
        state_ = PageSessionState::Error;
        return gate_result;
    }

    state_ = PageSessionState::Writing;
    const auto transaction = backend.CompareWritePhysicalPage(
        target_->address.physical_address,
        std::span<const std::uint8_t>(
            rollback_expected_->data(), rollback_expected_->size()),
        std::span<const std::uint8_t>(
            rollback_snapshot_->data(), rollback_snapshot_->size()));
    if (!transaction) {
        rollback_expected_.reset();
        recovery_observation_required_ = true;
        state_ = PageSessionState::VerificationFailed;
        const auto close_result = gate.Close();
        if (!close_result) {
            return close_result;
        }
        return Result<void>::Failure(transaction.GetError());
    }

    const auto& result = transaction.Value();
    evidence_.rollback = result.readback;
    if (result.outcome != PhysicalPageCompareWriteOutcome::Conflict) {
        rollback_expected_ = result.readback;
    }
    const auto close_result = gate.Close();
    if (!close_result) {
        state_ = PageSessionState::Error;
        return close_result;
    }

    if (result.outcome == PhysicalPageCompareWriteOutcome::Conflict) {
        for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
            if (result.readback[offset] != (*rollback_expected_)[offset]) {
                last_conflicts_.push_back(offset);
            }
        }
        state_ = PageSessionState::Conflict;
        return Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            FirstOffsetMessage(
                "Live page changed before rollback",
                last_conflicts_),
            "PhysicalPageSession::RollbackBaseline"));
    }

    state_ = PageSessionState::Verifying;
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        if (result.readback[offset] != (*rollback_snapshot_)[offset]) {
            last_mismatches_.push_back(offset);
        }
    }
    if (result.outcome != PhysicalPageCompareWriteOutcome::Applied ||
        result.transferred != kPhysicalPageSize ||
        !last_mismatches_.empty()) {
        // A failed transaction still returns a complete observed page.  Bind
        // the next retry to that exact page; never accept a per-byte mixture.
        rollback_expected_ = result.readback;
        state_ = PageSessionState::VerificationFailed;
        return Result<void>::Failure(MakeError(
            ErrorCode::RollbackFailed,
            FirstOffsetMessage(
                "Rollback read-back does not match the baseline",
                last_mismatches_),
            "PhysicalPageSession::RollbackBaseline",
            result.native_status,
            kPhysicalPageSize,
            result.transferred));
    }

    baseline_ = *rollback_snapshot_;
    working_ = baseline_;
    rollback_snapshot_.reset();
    rollback_expected_.reset();
    recovery_observation_required_ = false;
    dirty_.reset();
    last_conflicts_.clear();
    last_mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    last_apply_verified_ = false;
    ++revision_;
    state_ = PageSessionState::Clean;
    return Result<void>::Success();
}

PageSessionState PhysicalPageSession::State() const noexcept {
    return state_;
}

bool PhysicalPageSession::HasPage() const noexcept {
    return target_.has_value();
}

bool PhysicalPageSession::IsDirty() const noexcept {
    return dirty_.any();
}

std::size_t PhysicalPageSession::DirtyCount() const noexcept {
    return dirty_.count();
}

bool PhysicalPageSession::WriteUnlocked() const noexcept {
    return write_unlocked_;
}

bool PhysicalPageSession::CanRollback() const noexcept {
    return rollback_snapshot_.has_value() && rollback_expected_.has_value();
}

bool PhysicalPageSession::RecoveryObservationRequired() const noexcept {
    return recovery_observation_required_;
}

bool PhysicalPageSession::LastApplyVerified() const noexcept {
    return last_apply_verified_;
}

bool PhysicalPageSession::CanUndo() const noexcept {
    return !undo_stack_.empty();
}

bool PhysicalPageSession::CanRedo() const noexcept {
    return !redo_stack_.empty();
}

std::size_t PhysicalPageSession::UndoDepth() const noexcept {
    return undo_stack_.size();
}

std::size_t PhysicalPageSession::RedoDepth() const noexcept {
    return redo_stack_.size();
}

std::uint64_t PhysicalPageSession::Revision() const noexcept {
    return revision_;
}

const PfnAddress& PhysicalPageSession::Address() const {
    if (!target_) {
        throw std::logic_error("No physical page is loaded");
    }
    return target_->address;
}

const PhysicalWriteTarget& PhysicalPageSession::Target() const {
    if (!target_) {
        throw std::logic_error("No physical write target is loaded");
    }
    return *target_;
}

const std::array<std::uint8_t, kPhysicalPageSize>&
PhysicalPageSession::Baseline() const noexcept {
    return baseline_;
}

const std::array<std::uint8_t, kPhysicalPageSize>&
PhysicalPageSession::Working() const noexcept {
    return working_;
}

const std::bitset<kPhysicalPageSize>&
PhysicalPageSession::DirtyBitmap() const noexcept {
    return dirty_;
}

const std::vector<std::size_t>&
PhysicalPageSession::LastConflictOffsets() const noexcept {
    return last_conflicts_;
}

const std::vector<std::size_t>&
PhysicalPageSession::LastMismatchOffsets() const noexcept {
    return last_mismatches_;
}

const PhysicalPageEvidence& PhysicalPageSession::Evidence() const noexcept {
    return evidence_;
}

std::vector<ByteDiff> PhysicalPageSession::ByteDiffs() const {
    std::vector<ByteDiff> output;
    output.reserve(dirty_.count());
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        if (dirty_.test(offset)) {
            output.push_back(ByteDiff{
                offset,
                baseline_[offset],
                working_[offset]
            });
        }
    }
    return output;
}

std::vector<DiffRun> PhysicalPageSession::DiffRuns() const {
    std::vector<DiffRun> output;
    std::size_t offset = 0;
    while (offset < kPhysicalPageSize) {
        if (!dirty_.test(offset)) {
            ++offset;
            continue;
        }

        const auto start = offset;
        while (offset < kPhysicalPageSize && dirty_.test(offset)) {
            ++offset;
        }

        DiffRun run{};
        run.offset = start;
        run.before.insert(
            run.before.end(),
            baseline_.begin() + static_cast<std::ptrdiff_t>(start),
            baseline_.begin() + static_cast<std::ptrdiff_t>(offset));
        run.after.insert(
            run.after.end(),
            working_.begin() + static_cast<std::ptrdiff_t>(start),
            working_.begin() + static_cast<std::ptrdiff_t>(offset));
        output.push_back(std::move(run));
    }
    return output;
}

Result<void> PhysicalPageSession::ValidatePageRange(
    IMemoryBackend& backend) const {
    if (!target_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical page is selected",
            "PhysicalPageSession::ValidatePageRange"));
    }

    const auto ranges_result = backend.GetPhysicalRanges();
    if (!ranges_result) {
        return Result<void>::Failure(ranges_result.GetError());
    }

    const auto found = std::any_of(
        ranges_result.Value().begin(),
        ranges_result.Value().end(),
        [this](const PhysicalRange& range) {
            return range.Contains(
                target_->address.physical_address,
                kPhysicalPageSize);
        });

    if (!found) {
        return Result<void>::Failure(MakeError(
            ErrorCode::OutsidePhysicalRam,
            "The complete 4 KiB page is not inside a physical RAM range",
            "PhysicalPageSession::ValidatePageRange"));
    }
    return Result<void>::Success();
}

Result<std::unique_ptr<std::array<std::uint8_t, kPhysicalPageSize>>>
PhysicalPageSession::ReadExactPage(IMemoryBackend& backend) const {
    using Page = std::array<std::uint8_t, kPhysicalPageSize>;
    if (!target_) {
        return Result<std::unique_ptr<Page>>::Failure(
            MakeError(
                ErrorCode::InvalidArgument,
                "No physical page is selected",
                "PhysicalPageSession::ReadExactPage"));
    }

    const auto read_result = backend.ReadPhysical(
        target_->address.physical_address,
        static_cast<std::uint32_t>(kPhysicalPageSize));
    if (!read_result) {
        return Result<std::unique_ptr<Page>>::Failure(
            read_result.GetError());
    }
    if (read_result.Value().size() != kPhysicalPageSize) {
        return Result<std::unique_ptr<Page>>::Failure(
            MakeError(
                ErrorCode::ShortRead,
                "Backend did not return a complete 4 KiB page",
                "PhysicalPageSession::ReadExactPage",
                0,
                kPhysicalPageSize,
                read_result.Value().size()));
    }

    auto page = std::make_unique<Page>();
    std::copy(read_result.Value().begin(), read_result.Value().end(),
              page->begin());
    return Result<std::unique_ptr<Page>>::Success(std::move(page));
}

void PhysicalPageSession::ClearEvidence() noexcept {
    evidence_.baseline.reset();
    evidence_.preflight.reset();
    evidence_.expected_after.reset();
    evidence_.readback.reset();
    evidence_.independent_reload.reset();
    evidence_.rollback.reset();
}

void PhysicalPageSession::ClearPageData() noexcept {
    target_.reset();
    baseline_.fill(0);
    working_.fill(0);
    rollback_snapshot_.reset();
    rollback_expected_.reset();
    last_apply_verified_ = false;
    recovery_observation_required_ = false;
    ClearEvidence();
    dirty_.reset();
    last_conflicts_.clear();
    last_mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
}

void PhysicalPageSession::RecomputeDirty() noexcept {
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        dirty_.set(offset, baseline_[offset] != working_[offset]);
    }
}

void PhysicalPageSession::LockWrite() noexcept {
    write_unlocked_ = false;
}

}  // namespace kdbg

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
    LockWrite();
    ClearPageData();
    state_ = PageSessionState::Loading;
    if (!address.IsConsistent()) {
        state_ = PageSessionState::Error;
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidPfn,
            "PFN and physical address do not identify the same complete page",
            "PhysicalPageSession::Load"));
    }
    address_ = address;

    const auto range_result = ValidatePageRange(backend);
    if (!range_result) {
        state_ = PageSessionState::Error;
        address_.reset();
        return range_result;
    }

    const auto read_result = ReadExactPage(backend);
    if (!read_result) {
        state_ = PageSessionState::Error;
        address_.reset();
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
    if (!address_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical page is loaded",
            "PhysicalPageSession::ReloadPreservingRollback"));
    }
    if (dirty_.any()) {
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
        state_ = PageSessionState::Error;
        return range_result;
    }

    state_ = PageSessionState::Verifying;
    const auto reload_result = ReadExactPage(backend);
    if (!reload_result) {
        state_ = PageSessionState::VerificationFailed;
        return Result<void>::Failure(reload_result.GetError());
    }

    const auto& reloaded = *reload_result.Value();
    evidence_.independent_reload = reloaded;
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

Result<void> PhysicalPageSession::ApplyLocalEdit(
    std::size_t offset,
    std::uint8_t value,
    bool record_history) {
    if (!address_) {
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
    if (!address_ || offset >= kPhysicalPageSize) {
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
    if (!address_) {
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
    if (!address_) {
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
    if (retyped_pfn != address_->pfn) {
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
    if (!address_ || !rollback_snapshot_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No previous successful apply is available for rollback",
            "PhysicalPageSession::UnlockForRollback"));
    }
    if (retyped_pfn != address_->pfn) {
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
    if (!address_) {
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
    last_conflicts_.clear();
    last_mismatches_.clear();
    ClearEvidence();
    evidence_.baseline = baseline_;

    const auto range_result = ValidatePageRange(backend);
    if (!range_result) {
        state_ = PageSessionState::Error;
        return range_result;
    }

    state_ = PageSessionState::Preflight;
    const auto preflight_result = ReadExactPage(backend);
    if (!preflight_result) {
        state_ = PageSessionState::Error;
        return Result<void>::Failure(preflight_result.GetError());
    }

    const auto& live = *preflight_result.Value();
    evidence_.preflight = live;
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        if (live[offset] != baseline_[offset]) {
            last_conflicts_.push_back(offset);
        }
    }
    if (!last_conflicts_.empty()) {
        state_ = PageSessionState::Conflict;
        return Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            FirstOffsetMessage(
                "Live page changed after it was loaded",
                last_conflicts_),
            "PhysicalPageSession::ApplyAndVerify"));
    }

    rollback_snapshot_ = baseline_;
    rollback_expected_ = working_;
    rollback_allows_partial_ = true;
    evidence_.expected_after = working_;

    state_ = PageSessionState::Writing;
    for (const auto& run : DiffRuns()) {
        WriteGateGuard gate(backend);
        const auto gate_result = gate.Enable();
        if (!gate_result) {
            state_ = PageSessionState::Error;
            return gate_result;
        }
        const auto physical_address =
            address_->physical_address +
            static_cast<std::uint64_t>(run.offset);
        const auto write_result = backend.WritePhysical(
            physical_address,
            std::span<const std::uint8_t>(run.after.data(), run.after.size()));
        if (!write_result) {
            state_ = PageSessionState::Error;
            const auto close_result = gate.Close();
            if (!close_result) {
                return close_result;
            }
            return Result<void>::Failure(write_result.GetError());
        }
        if (write_result.Value() != run.after.size()) {
            state_ = PageSessionState::Error;
            const auto close_result = gate.Close();
            if (!close_result) {
                return close_result;
            }
            return Result<void>::Failure(MakeError(
                ErrorCode::ShortWrite,
                "Backend completed fewer bytes than requested",
                "PhysicalPageSession::ApplyAndVerify",
                0,
                run.after.size(),
                write_result.Value()));
        }
        const auto close_result = gate.Close();
        if (!close_result) {
            state_ = PageSessionState::Error;
            return close_result;
        }
    }

    state_ = PageSessionState::Verifying;
    const auto readback_result = ReadExactPage(backend);
    if (!readback_result) {
        state_ = PageSessionState::VerificationFailed;
        return Result<void>::Failure(readback_result.GetError());
    }

    const auto& readback = *readback_result.Value();
    evidence_.readback = readback;
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        if (readback[offset] != working_[offset]) {
            last_mismatches_.push_back(offset);
        }
    }
    if (!last_mismatches_.empty()) {
        state_ = PageSessionState::VerificationFailed;
        return Result<void>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            FirstOffsetMessage(
                "Read-back does not match the requested bytes",
                last_mismatches_),
            "PhysicalPageSession::ApplyAndVerify"));
    }

    baseline_ = readback;
    working_ = readback;
    dirty_.reset();
    undo_stack_.clear();
    redo_stack_.clear();
    rollback_allows_partial_ = false;
    ++revision_;
    state_ = PageSessionState::Clean;
    return Result<void>::Success();
}

Result<void> PhysicalPageSession::RollbackBaseline(
    IMemoryBackend& backend) {
    if (!address_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No physical page is loaded",
            "PhysicalPageSession::RollbackBaseline"));
    }
    if (!rollback_snapshot_) {
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
        state_ = PageSessionState::Error;
        return range_result;
    }


    state_ = PageSessionState::Preflight;
    const auto preflight_result = ReadExactPage(backend);
    if (!preflight_result) {
        state_ = PageSessionState::Error;
        return Result<void>::Failure(preflight_result.GetError());
    }
    const auto& live = *preflight_result.Value();
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        bool expected = live[offset] == baseline_[offset];
        if (rollback_allows_partial_ && rollback_expected_) {
            expected = live[offset] == (*rollback_snapshot_)[offset] ||
                live[offset] == (*rollback_expected_)[offset];
        }
        if (!expected) {
            last_conflicts_.push_back(offset);
        }
    }
    if (!last_conflicts_.empty()) {
        state_ = PageSessionState::Conflict;
        return Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            FirstOffsetMessage(
                "Live page changed before rollback",
                last_conflicts_),
            "PhysicalPageSession::RollbackBaseline"));
    }

    WriteGateGuard gate(backend);
    const auto gate_result = gate.Enable();
    if (!gate_result) {
        state_ = PageSessionState::Error;
        return gate_result;
    }

    rollback_expected_ = live;
    rollback_allows_partial_ = true;
    state_ = PageSessionState::Writing;
    const auto write_result = backend.WritePhysical(
        address_->physical_address,
        std::span<const std::uint8_t>(
            rollback_snapshot_->data(),
            rollback_snapshot_->size()));
    if (!write_result) {
        state_ = PageSessionState::Error;
        const auto close_result = gate.Close();
        if (!close_result) {
            return close_result;
        }
        return Result<void>::Failure(write_result.GetError());
    }
    if (write_result.Value() != rollback_snapshot_->size()) {
        state_ = PageSessionState::Error;
        const auto close_result = gate.Close();
        if (!close_result) {
            return close_result;
        }
        return Result<void>::Failure(MakeError(
            ErrorCode::ShortWrite,
            "Rollback write was short",
            "PhysicalPageSession::RollbackBaseline",
            0,
            rollback_snapshot_->size(),
            write_result.Value()));
    }


    const auto close_result = gate.Close();
    if (!close_result) {
        state_ = PageSessionState::Error;
        return close_result;
    }

    state_ = PageSessionState::Verifying;
    const auto readback_result = ReadExactPage(backend);
    if (!readback_result) {
        state_ = PageSessionState::VerificationFailed;
        return Result<void>::Failure(readback_result.GetError());
    }
    for (std::size_t offset = 0; offset < kPhysicalPageSize; ++offset) {
        if ((*readback_result.Value())[offset] !=
            (*rollback_snapshot_)[offset]) {
            last_mismatches_.push_back(offset);
        }
    }
    evidence_.rollback = *readback_result.Value();
    if (!last_mismatches_.empty()) {
        state_ = PageSessionState::VerificationFailed;
        return Result<void>::Failure(MakeError(
            ErrorCode::RollbackFailed,
            FirstOffsetMessage(
                "Rollback read-back does not match the baseline",
                last_mismatches_),
            "PhysicalPageSession::RollbackBaseline"));
    }

    baseline_ = *rollback_snapshot_;
    working_ = baseline_;
    rollback_snapshot_.reset();
    rollback_expected_.reset();
    rollback_allows_partial_ = false;
    dirty_.reset();
    last_conflicts_.clear();
    last_mismatches_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    ++revision_;
    state_ = PageSessionState::Clean;
    return Result<void>::Success();
}

PageSessionState PhysicalPageSession::State() const noexcept {
    return state_;
}

bool PhysicalPageSession::HasPage() const noexcept {
    return address_.has_value();
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
    return rollback_snapshot_.has_value();
}

bool PhysicalPageSession::LastApplyVerified() const noexcept {
    return rollback_snapshot_.has_value() &&
        evidence_.expected_after.has_value() &&
        evidence_.readback.has_value() &&
        *evidence_.readback == *evidence_.expected_after;
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
    if (!address_) {
        throw std::logic_error("No physical page is loaded");
    }
    return *address_;
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
    if (!address_) {
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
                address_->physical_address,
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
    if (!address_) {
        return Result<std::unique_ptr<Page>>::Failure(
            MakeError(
                ErrorCode::InvalidArgument,
                "No physical page is selected",
                "PhysicalPageSession::ReadExactPage"));
    }

    const auto read_result = backend.ReadPhysical(
        address_->physical_address,
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
    address_.reset();
    baseline_.fill(0);
    working_.fill(0);
    rollback_snapshot_.reset();
    rollback_expected_.reset();
    rollback_allows_partial_ = false;
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

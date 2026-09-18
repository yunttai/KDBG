#pragma once

#include "core/common/Result.h"
#include "core/memory/IMemoryBackend.h"
#include "core/model/PhysicalPage.h"
#include "core/model/WriteDiff.h"
#include "core/pfn/PfnAddress.h"

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <vector>

namespace kdbg {

enum class PageSessionState {
    Empty,
    Loading,
    Clean,
    Dirty,
    Preflight,
    Writing,
    Verifying,
    Conflict,
    VerificationFailed,
    Error
};

struct PhysicalPageEvidence {
    std::optional<std::array<std::uint8_t, kPhysicalPageSize>> baseline;
    std::optional<std::array<std::uint8_t, kPhysicalPageSize>> preflight;
    std::optional<std::array<std::uint8_t, kPhysicalPageSize>> expected_after;
    std::optional<std::array<std::uint8_t, kPhysicalPageSize>> readback;
    std::optional<std::array<std::uint8_t, kPhysicalPageSize>> independent_reload;
    std::optional<std::array<std::uint8_t, kPhysicalPageSize>> rollback;

    [[nodiscard]] bool Complete() const noexcept {
        return baseline.has_value() && preflight.has_value() &&
            expected_after.has_value() && readback.has_value() &&
            independent_reload.has_value() && rollback.has_value() &&
            *preflight == *baseline && *readback == *expected_after &&
            *independent_reload == *expected_after && *rollback == *baseline;
    }
};

class PhysicalPageSession {
public:
    static constexpr std::size_t kMaxEditHistory = 4096U;

    Result<void> Load(IMemoryBackend& backend, const PfnAddress& address);
    Result<void> ReloadPreservingRollback(IMemoryBackend& backend);

    Result<void> EditByte(std::size_t offset, std::uint8_t value);
    Result<void> RevertByte(std::size_t offset);
    Result<void> Undo();
    Result<void> Redo();
    void RevertAll() noexcept;

    Result<void> UnlockForOneApply(std::uint64_t retyped_pfn);
    Result<void> UnlockForRollback(std::uint64_t retyped_pfn);
    Result<void> ApplyAndVerify(IMemoryBackend& backend);
    Result<void> RollbackBaseline(IMemoryBackend& backend);

    [[nodiscard]] PageSessionState State() const noexcept;
    [[nodiscard]] bool HasPage() const noexcept;
    [[nodiscard]] bool IsDirty() const noexcept;
    [[nodiscard]] std::size_t DirtyCount() const noexcept;
    [[nodiscard]] bool WriteUnlocked() const noexcept;
    [[nodiscard]] bool CanRollback() const noexcept;
    [[nodiscard]] bool LastApplyVerified() const noexcept;
    [[nodiscard]] bool CanUndo() const noexcept;
    [[nodiscard]] bool CanRedo() const noexcept;
    [[nodiscard]] std::size_t UndoDepth() const noexcept;
    [[nodiscard]] std::size_t RedoDepth() const noexcept;
    [[nodiscard]] std::uint64_t Revision() const noexcept;

    [[nodiscard]] const PfnAddress& Address() const;
    [[nodiscard]] const std::array<std::uint8_t, kPhysicalPageSize>&
    Baseline() const noexcept;
    [[nodiscard]] const std::array<std::uint8_t, kPhysicalPageSize>&
    Working() const noexcept;
    [[nodiscard]] const std::bitset<kPhysicalPageSize>&
    DirtyBitmap() const noexcept;
    [[nodiscard]] const std::vector<std::size_t>&
    LastConflictOffsets() const noexcept;
    [[nodiscard]] const std::vector<std::size_t>&
    LastMismatchOffsets() const noexcept;
    [[nodiscard]] const PhysicalPageEvidence& Evidence() const noexcept;

    [[nodiscard]] std::vector<ByteDiff> ByteDiffs() const;
    [[nodiscard]] std::vector<DiffRun> DiffRuns() const;

private:
    struct ByteEdit {
        std::size_t offset{0};
        std::uint8_t before{0};
        std::uint8_t after{0};
    };

    Result<void> ApplyLocalEdit(
        std::size_t offset,
        std::uint8_t value,
        bool record_history);
    Result<void> ValidatePageRange(IMemoryBackend& backend) const;
    Result<std::unique_ptr<
        std::array<std::uint8_t, kPhysicalPageSize>>> ReadExactPage(
            IMemoryBackend& backend) const;
    void ClearEvidence() noexcept;
    void ClearPageData() noexcept;
    void RecomputeDirty() noexcept;
    void LockWrite() noexcept;

    std::optional<PfnAddress> address_;
    std::array<std::uint8_t, kPhysicalPageSize> baseline_{};
    std::array<std::uint8_t, kPhysicalPageSize> working_{};
    std::optional<std::array<std::uint8_t, kPhysicalPageSize>> rollback_snapshot_;
    std::optional<std::array<std::uint8_t, kPhysicalPageSize>> rollback_expected_;
    PhysicalPageEvidence evidence_{};
    bool rollback_allows_partial_{false};
    std::bitset<kPhysicalPageSize> dirty_{};
    std::vector<std::size_t> last_conflicts_;
    std::vector<std::size_t> last_mismatches_;
    std::deque<ByteEdit> undo_stack_;
    std::deque<ByteEdit> redo_stack_;
    PageSessionState state_{PageSessionState::Empty};
    bool write_unlocked_{false};
    std::uint64_t revision_{0};
};

}  // namespace kdbg

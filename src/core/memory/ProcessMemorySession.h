#pragma once

#include "core/common/Result.h"
#include "core/model/WriteDiff.h"
#include "core/process/IProcessMemory.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <vector>

namespace kdbg {

enum class ProcessMemorySessionState {
    Empty,
    Clean,
    Dirty,
    Conflict,
    VerificationFailed,
    Error
};

class ProcessMemorySession {
public:
    static constexpr std::uint32_t kMaximumViewSize = 1024U * 1024U;
    static constexpr std::size_t kMaxEditHistory = 4096U;

    Result<void> Load(
        IProcessMemory& memory,
        std::uint64_t address,
        std::uint32_t length);
    void Reset() noexcept;

    Result<void> EditByte(std::size_t offset, std::uint8_t value);
    Result<void> RevertByte(std::size_t offset);
    Result<void> Undo();
    Result<void> Redo();
    void RevertAll() noexcept;

    Result<void> ApplyAndVerify(IProcessMemory& memory);
    Result<void> Rollback(IProcessMemory& memory);

    [[nodiscard]] bool HasBuffer() const noexcept;
    [[nodiscard]] bool IsDirty() const noexcept;
    [[nodiscard]] std::size_t DirtyCount() const noexcept;
    [[nodiscard]] bool CanRollback() const noexcept;
    [[nodiscard]] bool CanUndo() const noexcept;
    [[nodiscard]] bool CanRedo() const noexcept;
    [[nodiscard]] std::size_t UndoDepth() const noexcept;
    [[nodiscard]] std::size_t RedoDepth() const noexcept;
    [[nodiscard]] std::uint64_t Address() const noexcept;
    [[nodiscard]] ProcessMemorySessionState State() const noexcept;
    [[nodiscard]] const std::vector<std::uint8_t>& Baseline() const noexcept;
    [[nodiscard]] const std::vector<std::uint8_t>& Working() const noexcept;
    [[nodiscard]] const std::vector<bool>& DirtyBitmap() const noexcept;
    [[nodiscard]] const std::vector<std::size_t>& ConflictOffsets() const noexcept;
    [[nodiscard]] const std::vector<std::size_t>& MismatchOffsets() const noexcept;
    [[nodiscard]] std::vector<ByteDiff> ByteDiffs(
        std::size_t max_count = static_cast<std::size_t>(-1)) const;
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
    Result<std::vector<std::uint8_t>> ReadExact(
        IProcessMemory& memory) const;
    [[nodiscard]] Result<void> ValidateTarget(
        const IProcessMemory& memory) const;
    void RecomputeDirty() noexcept;

    std::uint32_t pid_{0};
    std::uint64_t address_{0};
    std::vector<std::uint8_t> baseline_;
    std::vector<std::uint8_t> working_;
    std::vector<bool> dirty_;
    std::size_t dirty_count_{0};
    std::optional<std::vector<std::uint8_t>> rollback_;
    std::optional<std::vector<std::uint8_t>> rollback_expected_;
    bool rollback_allows_partial_{false};
    std::vector<std::size_t> conflicts_;
    std::vector<std::size_t> mismatches_;
    std::deque<ByteEdit> undo_stack_;
    std::deque<ByteEdit> redo_stack_;
    ProcessMemorySessionState state_{ProcessMemorySessionState::Empty};
};

}  // namespace kdbg

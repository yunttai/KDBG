#include "TestHarness.h"

#include "core/common/Error.h"
#include "core/memory/ProcessMemorySession.h"
#include "core/process/MockProcessMemory.h"

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

class FaultProcessMemory final : public kdbg::IProcessMemory {
public:
    FaultProcessMemory(
        std::uint32_t pid,
        std::uint64_t base = 0x30000000U,
        std::size_t size = 0x2000U)
        : pid_(pid), base_(base), bytes_(size) {
        for (std::size_t index = 0; index < bytes_.size(); ++index) {
            bytes_[index] = static_cast<std::uint8_t>(index & 0xFFU);
        }
    }

    [[nodiscard]] std::uint32_t ProcessId() const noexcept override {
        return pid_;
    }
    [[nodiscard]] std::size_t PointerSize() const noexcept override { return 8U; }
    [[nodiscard]] bool IsOpen() const noexcept override { return open_; }
    [[nodiscard]] bool WritesArmed() const noexcept override { return armed_; }

    kdbg::Result<void> SetWritesArmed(bool armed) override {
        if (!armed) {
            ++disarm_calls_;
            if (fail_disarm_count_ != 0) {
                --fail_disarm_count_;
                return kdbg::Result<void>::Failure(kdbg::MakeError(
                    kdbg::ErrorCode::IoFailure,
                    "Injected process disarm failure",
                    "FaultProcessMemory::SetWritesArmed"));
            }
        }
        armed_ = armed;
        return kdbg::Result<void>::Success();
    }

    kdbg::Result<std::vector<std::uint8_t>> Read(
        std::uint64_t address,
        std::uint32_t length) override {
        if (!open_ || length == 0 || address < base_) {
            return kdbg::Result<std::vector<std::uint8_t>>::Failure(
                kdbg::MakeError(
                    kdbg::ErrorCode::ShortRead,
                    "Fault process read is invalid",
                    "FaultProcessMemory::Read"));
        }
        const auto offset = address - base_;
        if (offset > bytes_.size() || length > bytes_.size() - offset) {
            return kdbg::Result<std::vector<std::uint8_t>>::Failure(
                kdbg::MakeError(
                    kdbg::ErrorCode::ShortRead,
                    "Fault process read crosses the fixture",
                    "FaultProcessMemory::Read"));
        }
        std::size_t completed = length;
        if (short_read_ && completed > 1U) {
            completed /= 2U;
        }
        return kdbg::Result<std::vector<std::uint8_t>>::Success(
            std::vector<std::uint8_t>(
                bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
                bytes_.begin() + static_cast<std::ptrdiff_t>(offset + completed)));
    }

    kdbg::Result<std::uint32_t> Write(
        std::uint64_t address,
        std::span<const std::uint8_t> data) override {
        ++write_calls_;
        if (!armed_) {
            return kdbg::Result<std::uint32_t>::Failure(kdbg::MakeError(
                kdbg::ErrorCode::WriteLocked,
                "Fault process writes are locked",
                "FaultProcessMemory::Write"));
        }
        if (data.empty() || address < base_) {
            return kdbg::Result<std::uint32_t>::Failure(kdbg::MakeError(
                kdbg::ErrorCode::ShortWrite,
                "Fault process write is invalid",
                "FaultProcessMemory::Write"));
        }
        const auto offset = address - base_;
        if (offset > bytes_.size() || data.size() > bytes_.size() - offset) {
            return kdbg::Result<std::uint32_t>::Failure(kdbg::MakeError(
                kdbg::ErrorCode::ShortWrite,
                "Fault process write crosses the fixture",
                "FaultProcessMemory::Write"));
        }
        std::size_t completed = data.size();
        if (short_write_) {
            completed /= 2U;
        }
        if (!ignore_write_) {
            std::copy_n(
                data.begin(),
                static_cast<std::ptrdiff_t>(completed),
                bytes_.begin() + static_cast<std::ptrdiff_t>(offset));
        }
        if (mutate_after_write_) {
            bytes_.at(mutation_offset_) = mutation_value_;
            mutate_after_write_ = false;
        }
        return kdbg::Result<std::uint32_t>::Success(
            static_cast<std::uint32_t>(completed));
    }

    kdbg::Result<std::vector<kdbg::MemoryRegion>> Regions() override {
        return kdbg::Result<std::vector<kdbg::MemoryRegion>>::Success({});
    }
    kdbg::Result<std::vector<kdbg::ProcessModule>> Modules() override {
        return kdbg::Result<std::vector<kdbg::ProcessModule>>::Success({});
    }

    [[nodiscard]] std::uint64_t Base() const noexcept { return base_; }
    [[nodiscard]] std::vector<std::uint8_t>& Bytes() noexcept { return bytes_; }
    [[nodiscard]] std::size_t WriteCalls() const noexcept { return write_calls_; }
    [[nodiscard]] std::size_t DisarmCalls() const noexcept { return disarm_calls_; }

    bool open_{true};
    bool short_read_{false};
    bool short_write_{false};
    bool ignore_write_{false};
    bool mutate_after_write_{false};
    std::size_t mutation_offset_{0};
    std::uint8_t mutation_value_{0};
    std::size_t fail_disarm_count_{0};

private:
    std::uint32_t pid_{0};
    std::uint64_t base_{0};
    std::vector<std::uint8_t> bytes_;
    bool armed_{false};
    std::size_t write_calls_{0};
    std::size_t disarm_calls_{0};
};

}  // namespace

void RunProcessMemorySessionTests(kdbg::test::TestRunner& runner) {
    using namespace kdbg;

    MockProcessMemory memory(0x20000000U, 0x2000U, 8U);
    for (std::size_t index = 0; index < memory.Bytes().size(); ++index) {
        memory.Bytes()[index] = static_cast<std::uint8_t>(index & 0xFFU);
    }

    ProcessMemorySession session;
    constexpr std::uint64_t address = 0x20000100U;
    KDBG_CHECK(runner, session.Load(memory, address, 0x100U).Ok());
    KDBG_CHECK(runner, session.HasBuffer());
    KDBG_CHECK(runner, !session.IsDirty());
    KDBG_CHECK(runner, session.State() == ProcessMemorySessionState::Clean);

    KDBG_CHECK(runner, session.EditByte(3U, 0xA5U).Ok());
    KDBG_CHECK(runner, session.EditByte(4U, 0x5AU).Ok());
    KDBG_CHECK(runner, session.EditByte(9U, 0xCCU).Ok());
    KDBG_CHECK(runner, session.DirtyCount() == 3U);
    KDBG_CHECK(runner, session.DiffRuns().size() == 2U);
    KDBG_CHECK(runner, session.CanUndo());
    KDBG_CHECK(runner, !session.CanRedo());
    KDBG_CHECK(runner, session.Undo().Ok());
    KDBG_CHECK(runner, session.DirtyCount() == 2U);
    KDBG_CHECK(runner, session.CanRedo());
    KDBG_CHECK(runner, session.Redo().Ok());
    KDBG_CHECK(runner, session.DirtyCount() == 3U);

    const auto locked = session.ApplyAndVerify(memory);
    KDBG_CHECK(runner, !locked.Ok());
    if (!locked) {
        KDBG_CHECK(runner, locked.GetError().code == ErrorCode::WriteLocked);
    }

    KDBG_CHECK(runner, memory.SetWritesArmed(true).Ok());
    KDBG_CHECK(runner, session.ApplyAndVerify(memory).Ok());
    KDBG_CHECK(runner, !memory.WritesArmed());
    KDBG_CHECK(runner, !session.IsDirty());
    KDBG_CHECK(runner, session.CanRollback());
    KDBG_CHECK(runner, memory.Bytes()[0x103U] == 0xA5U);
    KDBG_CHECK(runner, memory.Bytes()[0x104U] == 0x5AU);
    KDBG_CHECK(runner, memory.Bytes()[0x109U] == 0xCCU);

    KDBG_CHECK(runner, memory.SetWritesArmed(true).Ok());
    KDBG_CHECK(runner, session.Rollback(memory).Ok());
    KDBG_CHECK(runner, !memory.WritesArmed());
    KDBG_CHECK(runner, !session.CanRollback());
    KDBG_CHECK(runner, memory.Bytes()[0x103U] == 0x03U);
    KDBG_CHECK(runner, memory.Bytes()[0x104U] == 0x04U);
    KDBG_CHECK(runner, memory.Bytes()[0x109U] == 0x09U);

    KDBG_CHECK(runner, session.EditByte(7U, 0x77U).Ok());
    memory.Bytes()[0x108U] ^= 0xFFU;
    KDBG_CHECK(runner, memory.SetWritesArmed(true).Ok());
    const auto conflict = session.ApplyAndVerify(memory);
    KDBG_CHECK(runner, !conflict.Ok());
    if (!conflict) {
        KDBG_CHECK(runner,
            conflict.GetError().code == ErrorCode::ConcurrentModification);
    }
    KDBG_CHECK(runner,
        session.State() == ProcessMemorySessionState::Conflict);
    KDBG_CHECK(runner, session.ConflictOffsets().size() == 1U);
    KDBG_CHECK(runner, !memory.WritesArmed());
    if (!session.ConflictOffsets().empty()) {
        KDBG_CHECK(runner, session.ConflictOffsets().front() == 8U);
    }

    session.RevertAll();
    KDBG_CHECK(runner, !session.IsDirty());
    KDBG_CHECK(runner, session.RevertByte(0x100U).Ok() == false);
    session.Reset();
    KDBG_CHECK(runner, !session.HasBuffer());

    {
        MockProcessMemory stale_memory(0x21000000U, 0x100U, 8U);
        ProcessMemorySession stale_session;
        KDBG_CHECK(runner, stale_session.Load(
            stale_memory, stale_memory.Base(), 0x80U).Ok());
        KDBG_CHECK(runner, stale_session.EditByte(0U, 0xA5U).Ok());
        const auto reload = stale_session.Load(
            stale_memory, stale_memory.Base() + 0xFFU, 4U);
        KDBG_CHECK(runner, !reload.Ok());
        KDBG_CHECK(runner, !stale_session.HasBuffer());
        KDBG_CHECK(runner, !stale_session.IsDirty());
        KDBG_CHECK(runner,
            stale_session.State() == ProcessMemorySessionState::Error);
    }

    {
        FaultProcessMemory first_process(1001U);
        FaultProcessMemory other_process(2002U);
        ProcessMemorySession bound_session;
        KDBG_CHECK(runner, bound_session.Load(
            first_process, first_process.Base() + 0x100U, 0x40U).Ok());
        KDBG_CHECK(runner, bound_session.EditByte(0U, 0xA5U).Ok());
        KDBG_CHECK(runner, other_process.SetWritesArmed(true).Ok());
        const auto wrong_target = bound_session.ApplyAndVerify(other_process);
        KDBG_CHECK(runner, !wrong_target.Ok());
        if (!wrong_target) {
            KDBG_CHECK(runner,
                wrong_target.GetError().code == ErrorCode::InvalidArgument);
        }
        KDBG_CHECK(runner, !other_process.WritesArmed());
        KDBG_CHECK(runner, other_process.WriteCalls() == 0U);
    }

    {
        FaultProcessMemory fault_memory(3003U);
        ProcessMemorySession fault_session;
        const auto session_address = fault_memory.Base() + 0x100U;
        const auto original = fault_memory.Bytes()[0x100U];
        KDBG_CHECK(runner, fault_session.Load(
            fault_memory, session_address, 0x40U).Ok());
        KDBG_CHECK(runner, fault_session.EditByte(
            0U, static_cast<std::uint8_t>(original ^ 1U)).Ok());
        fault_memory.fail_disarm_count_ = 1U;
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        const auto apply = fault_session.ApplyAndVerify(fault_memory);
        KDBG_CHECK(runner, !apply.Ok());
        if (!apply) {
            KDBG_CHECK(runner, apply.GetError().code == ErrorCode::IoFailure);
        }
        KDBG_CHECK(runner, fault_memory.DisarmCalls() == 2U);
        KDBG_CHECK(runner, !fault_memory.WritesArmed());
        KDBG_CHECK(runner, fault_session.CanRollback());

        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        KDBG_CHECK(runner, fault_session.Rollback(fault_memory).Ok());
        KDBG_CHECK(runner, fault_memory.Bytes()[0x100U] == original);
        KDBG_CHECK(runner, !fault_memory.WritesArmed());
    }

    {
        FaultProcessMemory fault_memory(4004U);
        ProcessMemorySession fault_session;
        const auto session_address = fault_memory.Base() + 0x200U;
        const auto first = fault_memory.Bytes()[0x200U];
        const auto second = fault_memory.Bytes()[0x201U];
        KDBG_CHECK(runner, fault_session.Load(
            fault_memory, session_address, 0x40U).Ok());
        KDBG_CHECK(runner, fault_session.EditByte(
            0U, static_cast<std::uint8_t>(first ^ 1U)).Ok());
        KDBG_CHECK(runner, fault_session.EditByte(
            1U, static_cast<std::uint8_t>(second ^ 1U)).Ok());
        fault_memory.short_write_ = true;
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        const auto apply = fault_session.ApplyAndVerify(fault_memory);
        KDBG_CHECK(runner, !apply.Ok());
        if (!apply) {
            KDBG_CHECK(runner, apply.GetError().code == ErrorCode::ShortWrite);
        }
        KDBG_CHECK(runner, !fault_memory.WritesArmed());
        KDBG_CHECK(runner, fault_session.CanRollback());

        fault_memory.short_write_ = false;
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        KDBG_CHECK(runner, fault_session.Rollback(fault_memory).Ok());
        KDBG_CHECK(runner, fault_memory.Bytes()[0x200U] == first);
        KDBG_CHECK(runner, fault_memory.Bytes()[0x201U] == second);
    }

    {
        FaultProcessMemory fault_memory(5005U);
        ProcessMemorySession fault_session;
        const auto session_address = fault_memory.Base() + 0x300U;
        KDBG_CHECK(runner, fault_session.Load(
            fault_memory, session_address, 0x40U).Ok());
        KDBG_CHECK(runner, fault_session.EditByte(3U, 0xEEU).Ok());
        fault_memory.ignore_write_ = true;
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        const auto apply = fault_session.ApplyAndVerify(fault_memory);
        KDBG_CHECK(runner, !apply.Ok());
        if (!apply) {
            KDBG_CHECK(runner,
                apply.GetError().code == ErrorCode::VerificationMismatch);
        }
        KDBG_CHECK(runner, fault_session.MismatchOffsets() ==
            std::vector<std::size_t>{3U});
        KDBG_CHECK(runner, !fault_memory.WritesArmed());

        fault_memory.ignore_write_ = false;
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        KDBG_CHECK(runner, fault_session.Rollback(fault_memory).Ok());
    }

    {
        FaultProcessMemory fault_memory(6006U);
        ProcessMemorySession fault_session;
        const auto session_address = fault_memory.Base() + 0x400U;
        KDBG_CHECK(runner, fault_session.Load(
            fault_memory, session_address, 0x40U).Ok());
        KDBG_CHECK(runner, fault_session.EditByte(1U, 0xABU).Ok());
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        KDBG_CHECK(runner, fault_session.ApplyAndVerify(fault_memory).Ok());
        fault_memory.Bytes()[0x410U] ^= 1U;
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        const auto rollback = fault_session.Rollback(fault_memory);
        KDBG_CHECK(runner, !rollback.Ok());
        if (!rollback) {
            KDBG_CHECK(runner,
                rollback.GetError().code == ErrorCode::ConcurrentModification);
        }
        KDBG_CHECK(runner, fault_session.ConflictOffsets() ==
            std::vector<std::size_t>{0x10U});
        KDBG_CHECK(runner, !fault_memory.WritesArmed());
    }

    {
        FaultProcessMemory fault_memory(7007U);
        ProcessMemorySession fault_session;
        const auto session_address = fault_memory.Base() + 0x500U;
        KDBG_CHECK(runner, fault_session.Load(
            fault_memory, session_address, 0x40U).Ok());
        KDBG_CHECK(runner, fault_session.EditByte(2U, 0xCDU).Ok());
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        KDBG_CHECK(runner, fault_session.ApplyAndVerify(fault_memory).Ok());
        fault_memory.ignore_write_ = true;
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        const auto rollback = fault_session.Rollback(fault_memory);
        KDBG_CHECK(runner, !rollback.Ok());
        if (!rollback) {
            KDBG_CHECK(runner,
                rollback.GetError().code == ErrorCode::RollbackFailed);
        }
        KDBG_CHECK(runner, fault_session.MismatchOffsets() ==
            std::vector<std::size_t>{2U});
        KDBG_CHECK(runner, !fault_memory.WritesArmed());
    }

    {
        FaultProcessMemory fault_memory(8008U);
        ProcessMemorySession clean_session;
        KDBG_CHECK(runner, clean_session.Load(
            fault_memory, fault_memory.Base() + 0x600U, 0x40U).Ok());
        KDBG_CHECK(runner, fault_memory.SetWritesArmed(true).Ok());
        const auto no_changes = clean_session.ApplyAndVerify(fault_memory);
        KDBG_CHECK(runner, !no_changes.Ok());
        KDBG_CHECK(runner, !fault_memory.WritesArmed());
    }
}

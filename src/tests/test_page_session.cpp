#include "TestHarness.h"

#include "core/memory/MockMemoryBackend.h"
#include "core/memory/PhysicalPageSession.h"
#include "core/pfn/PfnAddress.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

namespace {

kdbg::PfnAddress FixtureAddress() {
    return kdbg::PfnAddress{
        kdbg::MockMemoryBackend::kBaseAddress >> 12U,
        kdbg::MockMemoryBackend::kBaseAddress
    };
}

}  // namespace

void RunPageSessionTests(kdbg::test::TestRunner& runner) {
    using kdbg::ErrorCode;
    using kdbg::MockFaults;
    using kdbg::MockMemoryBackend;
    using kdbg::PageSessionState;
    using kdbg::PhysicalPageSession;

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());

        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, session.State() == PageSessionState::Clean);
        KDBG_CHECK(runner, !session.IsDirty());
        KDBG_CHECK(runner, session.Evidence().baseline.has_value());

        const auto original = session.Working()[0x10];
        KDBG_CHECK(
            runner,
            session.EditByte(
                0x10,
                static_cast<std::uint8_t>(original ^ 0xFFU)).Ok());
        KDBG_CHECK(runner, session.IsDirty());
        KDBG_CHECK(runner, session.DirtyCount() == 1U);
        KDBG_CHECK(runner, session.DiffRuns().size() == 1U);
        KDBG_CHECK(runner, session.CanUndo());
        KDBG_CHECK(runner, !session.CanRedo());
        KDBG_CHECK(runner, session.Undo().Ok());
        KDBG_CHECK(runner, !session.IsDirty());
        KDBG_CHECK(runner, session.CanRedo());
        KDBG_CHECK(runner, session.Redo().Ok());
        KDBG_CHECK(runner, session.IsDirty());

        const auto locked_apply = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !locked_apply.Ok());
        if (!locked_apply) {
            KDBG_CHECK(
                runner,
                locked_apply.GetError().code == ErrorCode::WriteLocked);
        }
        KDBG_CHECK(runner, backend.WriteCallCount() == 0U);

        KDBG_CHECK(runner, !session.UnlockForOneApply(0xDEADU).Ok());
        KDBG_CHECK(
            runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());
        KDBG_CHECK(runner, session.LastApplyVerified());
        KDBG_CHECK(runner, session.State() == PageSessionState::Clean);
        KDBG_CHECK(runner, !session.IsDirty());
        KDBG_CHECK(runner, backend.WriteCallCount() == 1U);
        KDBG_CHECK(runner, !backend.Info().write_enabled);
        KDBG_CHECK(runner, backend.WriteDisableCallCount() == 1U);
        KDBG_CHECK(runner, session.Evidence().preflight.has_value());
        KDBG_CHECK(runner, session.Evidence().expected_after.has_value());
        KDBG_CHECK(runner, session.Evidence().readback.has_value());

        // A full independent reload must preserve the rollback snapshot.
        KDBG_CHECK(runner, session.ReloadPreservingRollback(backend).Ok());
        KDBG_CHECK(runner, session.CanRollback());
        KDBG_CHECK(runner, session.Evidence().independent_reload.has_value());
        KDBG_CHECK(
            runner,
            session.Evidence().independent_reload ==
                session.Evidence().expected_after);

        // Roll back the previous successful apply.
        const auto changed_value = session.Working()[0x10];
        KDBG_CHECK(runner, changed_value != original);
        KDBG_CHECK(runner, session.CanRollback());
        KDBG_CHECK(
            runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.RollbackBaseline(backend).Ok());
        KDBG_CHECK(runner, session.Working()[0x10] == original);
        KDBG_CHECK(runner, !session.CanRollback());
        KDBG_CHECK(runner, !backend.Info().write_enabled);
        KDBG_CHECK(runner, session.Evidence().Complete());
        KDBG_CHECK(
            runner,
            session.Evidence().rollback == session.Evidence().baseline);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, !session.ReloadPreservingRollback(backend).Ok());

        KDBG_CHECK(runner, session.EditByte(
            0x90U,
            static_cast<std::uint8_t>(session.Working()[0x90U] ^ 1U)).Ok());
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());

        backend.Mutate(
            FixtureAddress().physical_address + 0x91U,
            static_cast<std::uint8_t>(session.Baseline()[0x91U] ^ 1U));
        const auto reload = session.ReloadPreservingRollback(backend);
        KDBG_CHECK(runner, !reload.Ok());
        if (!reload) {
            KDBG_CHECK(runner,
                reload.GetError().code == ErrorCode::VerificationMismatch);
        }
        KDBG_CHECK(runner, session.CanRollback());
        KDBG_CHECK(runner, session.LastMismatchOffsets() ==
            std::vector<std::size_t>{0x91U});
        KDBG_CHECK(
            runner,
            !session.Evidence().independent_reload.has_value() ||
                session.Evidence().independent_reload !=
                    session.Evidence().expected_after);
        KDBG_CHECK(runner, !session.Evidence().Complete());
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        const auto first_original = session.Working()[0xA0U];
        KDBG_CHECK(runner, session.EditByte(
            0xA0U, static_cast<std::uint8_t>(first_original ^ 1U)).Ok());
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());
        KDBG_CHECK(runner, session.ReloadPreservingRollback(backend).Ok());
        KDBG_CHECK(runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.RollbackBaseline(backend).Ok());
        KDBG_CHECK(runner, session.Evidence().Complete());

        const auto second_original = session.Working()[0xA1U];
        KDBG_CHECK(runner, session.EditByte(
            0xA1U, static_cast<std::uint8_t>(second_original ^ 1U)).Ok());
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());
        KDBG_CHECK(runner, !session.Evidence().Complete());
        KDBG_CHECK(
            runner,
            !session.Evidence().independent_reload.has_value());
        KDBG_CHECK(runner, !session.Evidence().rollback.has_value());

        KDBG_CHECK(runner, session.ReloadPreservingRollback(backend).Ok());
        KDBG_CHECK(
            runner,
            session.Evidence().independent_reload.has_value());
        backend.SetFaults(MockFaults{.short_read = true});
        const auto failed_reload = session.ReloadPreservingRollback(backend);
        KDBG_CHECK(runner, !failed_reload.Ok());
        if (!failed_reload) {
            KDBG_CHECK(runner,
                failed_reload.GetError().code == ErrorCode::ShortRead);
        }
        KDBG_CHECK(
            runner,
            !session.Evidence().independent_reload.has_value());
        KDBG_CHECK(runner, !session.Evidence().Complete());
        KDBG_CHECK(runner, session.CanRollback());

        backend.ClearFaults();
        KDBG_CHECK(runner, session.ReloadPreservingRollback(backend).Ok());
        KDBG_CHECK(runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.RollbackBaseline(backend).Ok());
        KDBG_CHECK(runner, session.Evidence().Complete());
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());

        const auto before = session.Working()[4];
        KDBG_CHECK(
            runner,
            session.EditByte(
                4,
                static_cast<std::uint8_t>(before + 1U)).Ok());
        backend.Mutate(
            FixtureAddress().physical_address + 8U,
            static_cast<std::uint8_t>(
                session.Baseline()[8] ^ 0x80U));

        KDBG_CHECK(
            runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        const auto result = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(
                runner,
                result.GetError().code ==
                    ErrorCode::ConcurrentModification);
        }
        KDBG_CHECK(runner, session.State() == PageSessionState::Conflict);
        KDBG_CHECK(runner, !session.LastConflictOffsets().empty());
    }

    {
        MockMemoryBackend backend;
        backend.SetFaults(MockFaults{.short_read = true});
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        const auto result = session.Load(backend, FixtureAddress());
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(
                runner,
                result.GetError().code == ErrorCode::ShortRead);
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());

        const auto original = session.Working()[0x20];
        KDBG_CHECK(
            runner,
            session.EditByte(
                0x20,
                static_cast<std::uint8_t>(original ^ 0xA5U)).Ok());
        backend.SetFaults(MockFaults{.ignore_write = true});
        KDBG_CHECK(
            runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());

        const auto result = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(
                runner,
                result.GetError().code ==
                    ErrorCode::VerificationMismatch);
        }
        KDBG_CHECK(
            runner,
            session.State() ==
                PageSessionState::VerificationFailed);
        KDBG_CHECK(runner, !session.LastMismatchOffsets().empty());
        KDBG_CHECK(runner, !backend.Info().write_enabled);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());

        KDBG_CHECK(
            runner,
            session.EditByte(
                0x30,
                static_cast<std::uint8_t>(
                    session.Working()[0x30] ^ 0x01U)).Ok());
        backend.SetFaults(MockFaults{.short_write = true});
        KDBG_CHECK(
            runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());

        const auto result = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(
                runner,
                result.GetError().code == ErrorCode::ShortWrite);
        }
        KDBG_CHECK(runner, !backend.Info().write_enabled);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, session.EditByte(
            4U,
            static_cast<std::uint8_t>(session.Working()[4U] ^ 0x40U)).Ok());

        MockFaults faults{};
        faults.mutate_address = FixtureAddress().physical_address + 8U;
        faults.mutate_value = static_cast<std::uint8_t>(
            session.Baseline()[8U] ^ 0x20U);
        faults.mutate_after_next_write = true;
        backend.SetFaults(faults);
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        const auto result = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(runner,
                result.GetError().code == ErrorCode::VerificationMismatch);
        }
        KDBG_CHECK(runner, std::find(
            session.LastMismatchOffsets().begin(),
            session.LastMismatchOffsets().end(),
            8U) != session.LastMismatchOffsets().end());
        KDBG_CHECK(runner, !backend.Info().write_enabled);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, session.EditByte(
            0x44U,
            static_cast<std::uint8_t>(session.Working()[0x44U] ^ 1U)).Ok());

        MockFaults faults{};
        faults.fail_write_disable_count = 1;
        backend.SetFaults(faults);
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        const auto result = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(runner, result.GetError().code == ErrorCode::IoFailure);
        }
        KDBG_CHECK(runner, backend.WriteDisableCallCount() == 2U);
        KDBG_CHECK(runner, !backend.Info().write_enabled);
        KDBG_CHECK(runner, session.CanRollback());
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, session.EditByte(
            0x55U,
            static_cast<std::uint8_t>(session.Working()[0x55U] ^ 1U)).Ok());

        MockFaults faults{};
        faults.fail_write_enable_count = 1;
        backend.SetFaults(faults);
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        const auto result = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !result.Ok());
        KDBG_CHECK(runner, backend.WriteCallCount() == 0U);
        KDBG_CHECK(runner, backend.WriteDisableCallCount() == 1U);
        KDBG_CHECK(runner, !backend.Info().write_enabled);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        const auto old_value = session.Working()[0x60U];
        KDBG_CHECK(runner, session.EditByte(
            0x60U,
            static_cast<std::uint8_t>(old_value ^ 0x80U)).Ok());
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());

        const auto conflict_offset = 0x70U;
        backend.Mutate(
            FixtureAddress().physical_address + conflict_offset,
            static_cast<std::uint8_t>(session.Baseline()[conflict_offset] ^ 1U));
        KDBG_CHECK(runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        const auto rollback = session.RollbackBaseline(backend);
        KDBG_CHECK(runner, !rollback.Ok());
        if (!rollback) {
            KDBG_CHECK(runner,
                rollback.GetError().code == ErrorCode::ConcurrentModification);
        }
        KDBG_CHECK(runner, session.LastConflictOffsets() ==
            std::vector<std::size_t>{conflict_offset});
        KDBG_CHECK(runner, backend.WriteCallCount() == 1U);
        KDBG_CHECK(runner, !backend.Info().write_enabled);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        const auto original = session.Working()[0x74U];
        KDBG_CHECK(runner, session.EditByte(
            0x74U,
            static_cast<std::uint8_t>(original ^ 1U)).Ok());
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());

        backend.SetFaults(MockFaults{.ignore_write = true});
        KDBG_CHECK(runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        const auto rollback = session.RollbackBaseline(backend);
        KDBG_CHECK(runner, !rollback.Ok());
        if (!rollback) {
            KDBG_CHECK(runner,
                rollback.GetError().code == ErrorCode::RollbackFailed);
        }
        KDBG_CHECK(runner, session.LastMismatchOffsets() ==
            std::vector<std::size_t>{0x74U});
        KDBG_CHECK(runner, session.CanRollback());
        KDBG_CHECK(runner, !backend.Info().write_enabled);

        backend.ClearFaults();
        KDBG_CHECK(runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.RollbackBaseline(backend).Ok());
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, session.EditByte(
            0x78U,
            static_cast<std::uint8_t>(session.Working()[0x78U] ^ 1U)).Ok());
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());

        MockFaults faults{};
        faults.fail_write_disable_count = 1U;
        backend.SetFaults(faults);
        KDBG_CHECK(runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        const auto rollback = session.RollbackBaseline(backend);
        KDBG_CHECK(runner, !rollback.Ok());
        if (!rollback) {
            KDBG_CHECK(runner, rollback.GetError().code == ErrorCode::IoFailure);
        }
        KDBG_CHECK(runner, !backend.Info().write_enabled);
        KDBG_CHECK(runner, session.CanRollback());

        backend.ClearFaults();
        KDBG_CHECK(runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.RollbackBaseline(backend).Ok());
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        const auto first = session.Working()[0x80U];
        const auto second = session.Working()[0x81U];
        KDBG_CHECK(runner, session.EditByte(
            0x80U,
            static_cast<std::uint8_t>(first ^ 1U)).Ok());
        KDBG_CHECK(runner, session.EditByte(
            0x81U,
            static_cast<std::uint8_t>(second ^ 1U)).Ok());
        backend.SetFaults(MockFaults{.short_write = true});
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        const auto apply = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !apply.Ok());
        KDBG_CHECK(runner, session.CanRollback());
        KDBG_CHECK(runner, !session.LastApplyVerified());
        KDBG_CHECK(runner, !backend.Info().write_enabled);

        backend.ClearFaults();
        KDBG_CHECK(runner,
            session.UnlockForRollback(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.RollbackBaseline(backend).Ok());
        const auto readback = backend.ReadPhysical(
            FixtureAddress().physical_address + 0x80U,
            2U);
        KDBG_CHECK(runner, readback.Ok());
        if (readback) {
            KDBG_CHECK(runner, (readback.Value() ==
                std::vector<std::uint8_t>{first, second}));
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, session.EditByte(
            1U,
            static_cast<std::uint8_t>(session.Working()[1U] ^ 1U)).Ok());
        backend.SetFaults(MockFaults{.short_read = true});
        const auto reload = session.Load(backend, FixtureAddress());
        KDBG_CHECK(runner, !reload.Ok());
        KDBG_CHECK(runner, !session.HasPage());
        KDBG_CHECK(runner, !session.IsDirty());
        KDBG_CHECK(runner, !session.CanUndo());
        KDBG_CHECK(runner, !session.CanRollback());
        KDBG_CHECK(runner, session.Baseline()[1U] == 0U);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        const auto inconsistent = FixtureAddress();
        const kdbg::PfnAddress bad{
            inconsistent.pfn,
            inconsistent.physical_address + kdbg::kPhysicalPageSize};
        const auto load = session.Load(backend, bad);
        KDBG_CHECK(runner, !load.Ok());
        if (!load) {
            KDBG_CHECK(runner, load.GetError().code == ErrorCode::InvalidPfn);
        }
        KDBG_CHECK(runner, !session.HasPage());
    }
}

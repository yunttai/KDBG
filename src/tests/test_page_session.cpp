#include "TestHarness.h"

#include "core/memory/MockMemoryBackend.h"
#include "core/memory/PhysicalPageSession.h"
#include "core/memory/ProbeEvidencePattern.h"
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

namespace {

void RunPageSessionTestsPart1(kdbg::test::TestRunner& runner) {
    using kdbg::ErrorCode;
    using kdbg::MockFaults;
    using kdbg::MockMemoryBackend;
    using kdbg::PageSessionState;
    using kdbg::PhysicalPageSession;

    {
        KDBG_CHECK(runner, kdbg::kProbeEvidenceEditOffset == 0x100U);
        KDBG_CHECK(runner, kdbg::kProbeEvidenceEditMask.size() == 8U);
        KDBG_CHECK(
            runner,
            kdbg::kProbeEvidenceEditOffset +
                kdbg::kProbeEvidenceEditMask.size() <=
                kdbg::kPhysicalPageSize);
        KDBG_CHECK(runner, std::all_of(
            kdbg::kProbeEvidenceEditMask.begin(),
            kdbg::kProbeEvidenceEditMask.end(),
            [](std::uint8_t value) { return value != 0U; }));

        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner,
            session.Target().kind == kdbg::PhysicalTargetKind::RawPfn);
        KDBG_CHECK(runner,
            session.Target().address.pfn == FixtureAddress().pfn);
        for (std::size_t index = 0;
             index < kdbg::kProbeEvidenceEditMask.size(); ++index) {
            const auto offset = kdbg::kProbeEvidenceEditOffset + index;
            KDBG_CHECK(runner, session.EditByte(
                offset,
                static_cast<std::uint8_t>(
                    session.Baseline()[offset] ^
                    kdbg::kProbeEvidenceEditMask[index])).Ok());
        }
        const auto runs = session.DiffRuns();
        KDBG_CHECK(runner, session.DirtyCount() == 8U);
        KDBG_CHECK(runner, runs.size() == 1U);
        if (runs.size() == 1U) {
            KDBG_CHECK(
                runner,
                runs.front().offset == kdbg::kProbeEvidenceEditOffset);
            KDBG_CHECK(runner, runs.front().after.size() == 8U);
        }
        backend.Close();
    }

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
}

void RunPageSessionTestsPart2(kdbg::test::TestRunner& runner) {
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
        KDBG_CHECK(runner, backend.WriteCallCount() == 0U);
        KDBG_CHECK(runner, backend.CompareWriteCallCount() == 1U);
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
        // A per-byte mixture of the original and applied images must not be
        // accepted as a rollback baseline.  The complete page is bound.
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        PhysicalPageSession session;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        const auto original_a = session.Working()[0x150U];
        const auto original_b = session.Working()[0x151U];
        KDBG_CHECK(runner, session.EditByte(
            0x150U, static_cast<std::uint8_t>(original_a ^ 1U)).Ok());
        KDBG_CHECK(runner, session.EditByte(
            0x151U, static_cast<std::uint8_t>(original_b ^ 1U)).Ok());
        KDBG_CHECK(runner, session.UnlockForOneApply(
            FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());

        backend.Mutate(
            FixtureAddress().physical_address + 0x150U,
            original_a);
        const auto writes_before = backend.WriteCallCount();
        KDBG_CHECK(runner, session.UnlockForRollback(
            FixtureAddress().pfn).Ok());
        const auto rollback = session.RollbackBaseline(backend);
        KDBG_CHECK(runner, !rollback.Ok());
        if (!rollback) {
            KDBG_CHECK(runner,
                rollback.GetError().code ==
                    ErrorCode::ConcurrentModification);
        }
        KDBG_CHECK(runner,
            session.LastConflictOffsets() ==
                std::vector<std::size_t>{0x150U});
        KDBG_CHECK(runner, backend.WriteCallCount() == writes_before);
    }
}

void RunPageSessionTestsPart3(kdbg::test::TestRunner& runner) {
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

    {
        // A UI restart before Apply must discard local edits and must not
        // leave the backend write gate open.
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const auto original = backend.ReadPhysical(
            FixtureAddress().physical_address + 0x180U,
            1U);
        KDBG_CHECK(runner, original.Ok());

        {
            auto abandoned_session_storage =
                std::make_unique<PhysicalPageSession>();
            auto& abandoned_session = *abandoned_session_storage;
            KDBG_CHECK(runner,
                abandoned_session.Load(backend, FixtureAddress()).Ok());
            KDBG_CHECK(runner, abandoned_session.EditByte(
                0x180U,
                static_cast<std::uint8_t>(
                    abandoned_session.Working()[0x180U] ^ 1U)).Ok());
            KDBG_CHECK(runner, abandoned_session.UnlockForOneApply(
                FixtureAddress().pfn).Ok());
            KDBG_CHECK(runner, abandoned_session.WriteUnlocked());
            KDBG_CHECK(runner, !backend.Info().write_enabled);
            KDBG_CHECK(runner, backend.WriteCallCount() == 0U);
        }

        auto restarted_session_storage =
            std::make_unique<PhysicalPageSession>();
        auto& restarted_session = *restarted_session_storage;
        KDBG_CHECK(runner,
            restarted_session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner,
            restarted_session.State() == PageSessionState::Clean);
        KDBG_CHECK(runner, !restarted_session.IsDirty());
        KDBG_CHECK(runner, !restarted_session.WriteUnlocked());
        KDBG_CHECK(runner, !restarted_session.CanRollback());
        const auto after_restart = backend.ReadPhysical(
            FixtureAddress().physical_address + 0x180U,
            1U);
        KDBG_CHECK(runner, after_restart.Ok());
        if (original && after_restart) {
            KDBG_CHECK(runner, after_restart.Value() == original.Value());
        }
    }
}

void RunPageSessionTestsPart4(kdbg::test::TestRunner& runner) {
    using kdbg::ErrorCode;
    using kdbg::MockMemoryBackend;
    using kdbg::PhysicalPageSession;

    {
        // Driver/service reconnect is modeled by Close/Open.  Every reconnect
        // must begin locked even if the previous session ended unlocked.
        MockMemoryBackend backend;
        for (std::size_t iteration = 0; iteration < 50U; ++iteration) {
            KDBG_CHECK(runner, backend.Open().Ok());
            KDBG_CHECK(runner, !backend.Info().write_enabled);
            KDBG_CHECK(runner, backend.SetWriteEnabled(true).Ok());
            KDBG_CHECK(runner, backend.Info().write_enabled);
            backend.Close();
            KDBG_CHECK(runner, !backend.Info().connected);
            KDBG_CHECK(runner, !backend.Info().write_enabled);
        }
        KDBG_CHECK(runner, backend.Open().Ok());
        const auto locked_write = backend.WritePhysical(
            FixtureAddress().physical_address,
            std::vector<std::uint8_t>{0xA5U});
        KDBG_CHECK(runner, !locked_write.Ok());
        if (!locked_write) {
            KDBG_CHECK(runner,
                locked_write.GetError().code == ErrorCode::WriteLocked);
        }
        backend.Close();
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        KDBG_CHECK(runner,
            backend.Info().supports_physical_page_compare_write);
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, session.EditByte(
            1U,
            static_cast<std::uint8_t>(session.Baseline()[1U] ^ 1U)).Ok());
        KDBG_CHECK(runner, session.EditByte(
            3U,
            static_cast<std::uint8_t>(session.Baseline()[3U] ^ 1U)).Ok());
        KDBG_CHECK(runner, session.DiffRuns().size() == 2U);
        const auto enables_before = backend.WriteEnableCallCount();
        const auto disables_before = backend.WriteDisableCallCount();
        const auto writes_before = backend.WriteCallCount();
        const auto transactions_before = backend.CompareWriteCallCount();
        KDBG_CHECK(runner,
            session.UnlockForOneApply(FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());
        KDBG_CHECK(runner,
            backend.WriteEnableCallCount() == enables_before + 1U);
        KDBG_CHECK(runner,
            backend.WriteDisableCallCount() == disables_before + 1U);
        KDBG_CHECK(runner, backend.WriteCallCount() == writes_before + 1U);
        KDBG_CHECK(runner,
            backend.CompareWriteCallCount() == transactions_before + 1U);
        KDBG_CHECK(runner, !backend.Info().write_enabled);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        PhysicalPageSession session;
        const auto process_target = kdbg::PhysicalWriteTarget::ProcessMapping(
            FixtureAddress(),
            MockMemoryBackend::kMockPid,
            MockMemoryBackend::kVirtualBase);
        KDBG_CHECK(runner, session.Load(backend, process_target).Ok());
        KDBG_CHECK(runner,
            session.Target().kind ==
                kdbg::PhysicalTargetKind::ProcessMapping);
        KDBG_CHECK(runner,
            session.Target().process_id == MockMemoryBackend::kMockPid);

        const auto original = session.Working()[0x120U];
        KDBG_CHECK(runner, session.EditByte(
            0x120U, static_cast<std::uint8_t>(original ^ 1U)).Ok());
        KDBG_CHECK(runner, session.UnlockForOneApply(
            FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());
        KDBG_CHECK(runner,
            session.Target().kind ==
                kdbg::PhysicalTargetKind::ProcessMapping);

        const auto probe_target =
            kdbg::PhysicalWriteTarget::ProbeFixture(FixtureAddress());
        KDBG_CHECK(runner, session.Load(backend, probe_target).Ok());
        KDBG_CHECK(runner,
            session.Target().kind ==
                kdbg::PhysicalTargetKind::ProbeFixture);
        KDBG_CHECK(runner, !session.CanRollback());
        KDBG_CHECK(runner, !session.WriteUnlocked());
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        PhysicalPageSession session;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        KDBG_CHECK(runner, session.EditByte(
            0x130U,
            static_cast<std::uint8_t>(session.Working()[0x130U] ^ 1U)).Ok());
        KDBG_CHECK(runner, session.UnlockForOneApply(
            FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());
        KDBG_CHECK(runner, session.CanRollback());

        backend.Close();
        const auto reload = session.ReloadPreservingRollback(backend);
        KDBG_CHECK(runner, !reload.Ok());
        if (!reload) {
            KDBG_CHECK(runner,
                reload.GetError().code == ErrorCode::BackendDisconnected);
        }
        KDBG_CHECK(runner, !session.HasPage());
        KDBG_CHECK(runner, !session.CanRollback());
        KDBG_CHECK(runner, !session.WriteUnlocked());
        KDBG_CHECK(runner, session.State() == kdbg::PageSessionState::Empty);
    }

    {
        // A lost transaction response is not proof that RAM was untouched.
        // No rollback is authorized until an independent exact-page read has
        // bound the observed page.
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        PhysicalPageSession session;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        const auto original = session.Working()[0x140U];
        KDBG_CHECK(runner, session.EditByte(
            0x140U, static_cast<std::uint8_t>(original ^ 1U)).Ok());
        const auto reads_before = backend.ReadCallCount();

        kdbg::MockFaults faults{};
        faults.fail_compare_write_transport_after_write = true;
        backend.SetFaults(faults);
        KDBG_CHECK(runner, session.UnlockForOneApply(
            FixtureAddress().pfn).Ok());
        const auto apply = session.ApplyAndVerify(backend);
        KDBG_CHECK(runner, !apply.Ok());
        if (!apply) {
            KDBG_CHECK(runner,
                apply.GetError().code == ErrorCode::IoFailure);
        }
        KDBG_CHECK(runner, session.RecoveryObservationRequired());
        KDBG_CHECK(runner, !session.CanRollback());
        KDBG_CHECK(runner, backend.ReadCallCount() == reads_before);
        KDBG_CHECK(runner,
            !session.UnlockForRollback(FixtureAddress().pfn).Ok());

        backend.ClearFaults();
        KDBG_CHECK(runner, session.ReloadPreservingRollback(backend).Ok());
        KDBG_CHECK(runner, !session.RecoveryObservationRequired());
        KDBG_CHECK(runner, session.CanRollback());
        KDBG_CHECK(runner, backend.ReadCallCount() == reads_before + 1U);
        KDBG_CHECK(runner, session.UnlockForRollback(
            FixtureAddress().pfn).Ok());
        KDBG_CHECK(runner, session.RollbackBaseline(backend).Ok());
        KDBG_CHECK(runner, session.Working()[0x140U] == original);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        auto session_storage = std::make_unique<PhysicalPageSession>();
        auto& session = *session_storage;
        KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
        bool edits_ok = true;
        for (std::size_t index = 0;
             index < PhysicalPageSession::kMaxEditHistory + 17U;
             ++index) {
            edits_ok = session.EditByte(
                0U,
                static_cast<std::uint8_t>(session.Working()[0U] ^ 1U)).Ok() &&
                edits_ok;
        }
        KDBG_CHECK(runner, edits_ok);
        KDBG_CHECK(runner, session.UndoDepth() ==
            PhysicalPageSession::kMaxEditHistory);
        KDBG_CHECK(runner, session.RedoDepth() == 0U);
    }
}

void RunPageSessionTestsPart5(kdbg::test::TestRunner& runner) {
    using kdbg::MockMemoryBackend;
    using kdbg::PhysicalPageSession;

    {
        // Exercise the documented repeated Apply/verify/rollback lifecycle.
        // Each transaction gets a fresh session, as it would after returning
        // to a clean page view.
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const auto original = backend.ReadPhysical(
            FixtureAddress().physical_address,
            static_cast<std::uint32_t>(kdbg::kPhysicalPageSize));
        KDBG_CHECK(runner, original.Ok());

        for (std::size_t iteration = 0; iteration < 10U; ++iteration) {
            auto session_storage = std::make_unique<PhysicalPageSession>();
            auto& session = *session_storage;
            KDBG_CHECK(runner, session.Load(backend, FixtureAddress()).Ok());
            const auto offset = 0x200U + iteration;
            KDBG_CHECK(runner, session.EditByte(
                offset,
                static_cast<std::uint8_t>(
                    session.Working()[offset] ^ 0x80U)).Ok());
            KDBG_CHECK(runner, session.UnlockForOneApply(
                FixtureAddress().pfn).Ok());
            KDBG_CHECK(runner, session.ApplyAndVerify(backend).Ok());
            KDBG_CHECK(runner, session.LastApplyVerified());
            KDBG_CHECK(runner, !backend.Info().write_enabled);
            KDBG_CHECK(runner,
                session.ReloadPreservingRollback(backend).Ok());
            KDBG_CHECK(runner, session.UnlockForRollback(
                FixtureAddress().pfn).Ok());
            KDBG_CHECK(runner, session.RollbackBaseline(backend).Ok());
            KDBG_CHECK(runner, session.Evidence().Complete());
            KDBG_CHECK(runner, !backend.Info().write_enabled);
        }

        const auto restored = backend.ReadPhysical(
            FixtureAddress().physical_address,
            static_cast<std::uint32_t>(kdbg::kPhysicalPageSize));
        KDBG_CHECK(runner, restored.Ok());
        if (original && restored) {
            KDBG_CHECK(runner, restored.Value() == original.Value());
        }
        KDBG_CHECK(runner, backend.WriteEnableCallCount() == 20U);
        KDBG_CHECK(runner, backend.WriteDisableCallCount() == 20U);
        KDBG_CHECK(runner, backend.WriteCallCount() == 20U);
    }
}

}  // namespace

void RunPageSessionTests(kdbg::test::TestRunner& runner) {
    RunPageSessionTestsPart1(runner);
    RunPageSessionTestsPart2(runner);
    RunPageSessionTestsPart3(runner);
    RunPageSessionTestsPart4(runner);
    RunPageSessionTestsPart5(runner);
}

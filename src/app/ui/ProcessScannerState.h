#pragma once

#include "core/process/IProcessMemory.h"
#include "core/scanner/MemoryScanner.h"
#include "core/scanner/ValueCodec.h"
#include "core/scanner/WatchList.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace kdbg {

// The PID confirmation is a UI-level authorization for a freeze session. The
// backend gate remains one-shot, so each entry must independently perform
// preflight -> arm -> write -> lock -> read-back. Keeping this helper outside
// the panel makes that ordering directly testable without an ImGui context.
[[nodiscard]] inline Result<void> RefreshAndMaybeFreezeEntryOneShot(
    IProcessMemory& memory,
    WatchEntry& entry,
    bool include_freeze) {
    const auto width = FixedValueWidth(entry.type);
    if (width == 0 || width > std::numeric_limits<std::uint32_t>::max()) {
        entry.last_error = "Watch entry has an invalid fixed width";
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            entry.last_error,
            "ProcessScannerPanel::RefreshWatchEntry"));
    }

    std::optional<Error> refresh_error;
    const auto read = memory.Read(
        entry.address, static_cast<std::uint32_t>(width));
    if (!read) {
        entry.last_error = read.GetError().message;
        refresh_error = read.GetError();
    } else if (read.Value().size() != width) {
        entry.last_error = "Watch refresh returned a short read";
        refresh_error = MakeError(
            ErrorCode::ShortRead,
            entry.last_error,
            "ProcessScannerPanel::RefreshWatchEntry",
            0,
            width,
            read.Value().size());
    } else {
        entry.value = read.Value();
        entry.last_error.clear();
    }

    if (!include_freeze || !entry.frozen) {
        return refresh_error.has_value()
            ? Result<void>::Failure(*refresh_error)
            : Result<void>::Success();
    }
    if (refresh_error.has_value()) {
        return Result<void>::Failure(*refresh_error);
    }
    if (entry.frozen_value.size() != width) {
        entry.last_error = "Frozen value has an invalid width";
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            entry.last_error,
            "ProcessScannerPanel::FreezeWatchEntry"));
    }

    const auto expected_before = memory.Read(
        entry.address, static_cast<std::uint32_t>(width));
    if (!expected_before) {
        entry.last_error = expected_before.GetError().message;
        return Result<void>::Failure(expected_before.GetError());
    }
    if (expected_before.Value().size() != width) {
        entry.last_error = "Freeze expected-before read was incomplete";
        return Result<void>::Failure(MakeError(
            ErrorCode::ShortRead,
            entry.last_error,
            "ProcessScannerPanel::FreezeWatchEntry",
            0,
            width,
            expected_before.Value().size()));
    }
    if (expected_before.Value() != entry.value) {
        entry.last_error =
            "Value changed during freeze preflight; no write was attempted";
        return Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            entry.last_error,
            "ProcessScannerPanel::FreezeWatchEntry"));
    }

    const auto armed = memory.SetWritesArmed(true);
    if (!armed) {
        entry.last_error = armed.GetError().message;
        return Result<void>::Failure(armed.GetError());
    }
    const auto written = memory.Write(entry.address, entry.frozen_value);
    const auto locked = memory.SetWritesArmed(false);
    if (!locked) {
        entry.last_error =
            "Freeze write returned, but the process write gate could not be confirmed locked: " +
            locked.GetError().message;
        return Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            entry.last_error,
            "ProcessScannerPanel::FreezeWatchEntry/lock",
            locked.GetError().native_code,
            entry.frozen_value.size(),
            written ? written.Value() : written.GetError().completed));
    }
    if (!written || written.Value() != entry.frozen_value.size()) {
        entry.last_error = written
            ? "Freeze write was incomplete"
            : written.GetError().message;
        return Result<void>::Failure(written
            ? MakeError(
                ErrorCode::ShortWrite,
                entry.last_error,
                "ProcessScannerPanel::FreezeWatchEntry",
                0,
                entry.frozen_value.size(),
                written.Value())
            : written.GetError());
    }

    const auto readback = memory.Read(
        entry.address,
        static_cast<std::uint32_t>(entry.frozen_value.size()));
    if (!readback || readback.Value() != entry.frozen_value) {
        entry.last_error = readback
            ? "Freeze read-back verification failed"
            : readback.GetError().message;
        return Result<void>::Failure(readback
            ? MakeError(
                ErrorCode::VerificationMismatch,
                entry.last_error,
                "ProcessScannerPanel::FreezeWatchEntry",
                0,
                entry.frozen_value.size(),
                readback.Value().size())
            : readback.GetError());
    }
    entry.value = readback.Value();
    entry.last_error.clear();
    return Result<void>::Success();
}

enum class ScanPublicationState {
    Complete,
    Partial,
    Failed,
};

[[nodiscard]] constexpr bool ScanReadReportIsIncomplete(
    const ScanReadReport& report) noexcept {
    return report.partial || report.cancelled || report.items_skipped != 0 ||
        report.failed_reads != 0 || report.short_reads != 0 ||
        report.items_completed < report.items_attempted ||
        report.completed_bytes < report.requested_bytes;
}

[[nodiscard]] constexpr ScanPublicationState ClassifyScanPublication(
    bool result_ok,
    const ScanReadReport& report) noexcept {
    if (!result_ok) return ScanPublicationState::Failed;
    return ScanReadReportIsIncomplete(report)
        ? ScanPublicationState::Partial
        : ScanPublicationState::Complete;
}

struct FreezeFailClosedState {
    std::size_t disarmed_entries{0};
    bool gate_locked{false};
    bool cleanup_retry_used{false};
    std::optional<Error> cleanup_error;
};

// Freeze is an automatic writer. Once its state becomes uncertain, remove every
// automatic retry source before asking the backend to close its write gate.
[[nodiscard]] inline FreezeFailClosedState FailCloseFreeze(
    IProcessMemory& memory,
    std::vector<WatchEntry>& entries) {
    FreezeFailClosedState state;
    for (auto& entry : entries) {
        if (entry.frozen) {
            ++state.disarmed_entries;
            if (entry.last_error.empty()) {
                entry.last_error =
                    "Freeze automatically disarmed after an unsafe batch outcome";
            }
        }
        entry.frozen = false;
        entry.frozen_value.clear();
    }

    const auto locked = memory.SetWritesArmed(false);
    if (locked) {
        state.gate_locked = true;
        return state;
    }

    state.cleanup_retry_used = true;
    const auto retry = memory.SetWritesArmed(false);
    if (retry) {
        state.gate_locked = true;
        return state;
    }

    Error error = locked.GetError();
    error.message += "; cleanup retry also failed: " +
        retry.GetError().message;
    state.cleanup_error = std::move(error);
    return state;
}

[[nodiscard]] inline bool HasFrozenEntries(
    const std::vector<WatchEntry>& entries) noexcept {
    return std::any_of(
        entries.begin(), entries.end(),
        [](const WatchEntry& entry) { return entry.frozen; });
}

}  // namespace kdbg

#include "core/memory/VerifiedWriter.h"

#include <algorithm>
#include <limits>

namespace kdbg {

VerifiedWriteArmToken::VerifiedWriteArmToken(
    VerifiedWriteArmToken&& other) noexcept
    : pid_(other.pid_), valid_(other.valid_) {
    other.pid_ = 0;
    other.valid_ = false;
}

VerifiedWriteArmToken& VerifiedWriteArmToken::operator=(
    VerifiedWriteArmToken&& other) noexcept {
    if (this == &other) return *this;
    pid_ = other.pid_;
    valid_ = other.valid_;
    other.pid_ = 0;
    other.valid_ = false;
    return *this;
}

bool VerifiedWriteArmToken::Consume(std::uint32_t pid) noexcept {
    const bool matches = valid_ && pid != 0 && pid_ == pid;
    pid_ = 0;
    valid_ = false;
    return matches;
}

Result<VerifiedWriteArmToken> VerifiedWriter::ArmProcessWrite(
    std::uint32_t confirmed_pid) const {
    if (confirmed_pid == 0) {
        return Result<VerifiedWriteArmToken>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Process-write confirmation requires a non-zero PID",
            "VerifiedWriter::ArmProcessWrite"));
    }
    return Result<VerifiedWriteArmToken>::Success(
        VerifiedWriteArmToken(confirmed_pid));
}

Result<VerifiedWriteResult> VerifiedWriter::Write(
    VerifiedWriteArmToken arm_token,
    const MemorySpace& space,
    std::uint64_t address,
    std::span<const std::uint8_t> data,
    std::optional<std::span<const std::uint8_t>> expected_before) {
    if (space.kind != MemorySpaceKind::ProcessVirtual) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::Unsupported,
            "Generic verified writes are process-virtual only; use "
            "PhysicalPageSession for typed-confirmed physical transactions",
            "VerifiedWriter::Write"));
    }
    if (space.pid == 0) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Process-virtual writes require a non-zero PID",
            "VerifiedWriter::Write"));
    }
    if (!arm_token.Consume(space.pid)) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Verified process write requires a fresh matching PID arm token",
            "VerifiedWriter::Write"));
    }
    if (data.empty() || data.size() > kMaxWriteLength ||
        data.size() > std::numeric_limits<std::uint32_t>::max()) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            data.size() > kMaxWriteLength
                ? ErrorCode::LimitReached
                : ErrorCode::InvalidArgument,
            "Verified write requires a non-empty bounded payload",
            "VerifiedWriter::Write",
            0,
            kMaxWriteLength,
            data.size()));
    }
    if (address > std::numeric_limits<std::uint64_t>::max() - data.size()) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Verified write address range overflowed",
            "VerifiedWriter::Write"));
    }
    if (expected_before.has_value() &&
        expected_before->size() != data.size()) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Expected-before data must match the write length",
            "VerifiedWriter::Write",
            0,
            data.size(),
            expected_before->size()));
    }

    const auto length = static_cast<std::uint32_t>(data.size());
    auto before = ReadMemory(backend_, space, address, length);
    if (!before) {
        return Result<VerifiedWriteResult>::Failure(before.GetError());
    }
    if (before.Value().size() != data.size()) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Pre-write read returned fewer bytes than requested",
            "VerifiedWriter::Write",
            0,
            data.size(),
            before.Value().size()));
    }
    if (expected_before.has_value()) {
        if (expected_before->size() != before.Value().size() ||
            !std::equal(
                expected_before->begin(),
                expected_before->end(),
                before.Value().begin(),
                before.Value().end())) {
            return Result<VerifiedWriteResult>::Failure(MakeError(
                ErrorCode::ConcurrentModification,
                "Memory changed after it was presented to the user",
                "VerifiedWriter::Write"));
        }
    }

    auto enabled = backend_.SetWriteEnabled(true);
    if (!enabled) {
        const auto fail_closed = backend_.SetWriteEnabled(false);
        if (!fail_closed) {
            auto error = fail_closed.GetError();
            error.message =
                "Write-gate enable failed and fail-closed cleanup also failed: " +
                error.message;
            return Result<VerifiedWriteResult>::Failure(std::move(error));
        }
        return Result<VerifiedWriteResult>::Failure(enabled.GetError());
    }

    auto written = WriteMemory(backend_, space, address, data);
    auto disabled = backend_.SetWriteEnabled(false);
    if (!disabled) {
        auto error = disabled.GetError();
        const auto retry = backend_.SetWriteEnabled(false);
        if (retry) {
            error.message +=
                "; a cleanup retry locked the gate, but the transaction is failed";
        } else {
            error.message += "; cleanup retry also failed: " +
                retry.GetError().message;
        }
        if (!written) {
            error.message += "; the write also failed: " +
                written.GetError().message;
        }
        return Result<VerifiedWriteResult>::Failure(std::move(error));
    }
    if (!written) {
        return Result<VerifiedWriteResult>::Failure(written.GetError());
    }
    if (written.Value() != data.size()) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::ShortWrite,
            "Backend wrote fewer bytes than requested",
            "VerifiedWriter::Write",
            0,
            data.size(),
            written.Value()));
    }

    auto readback = ReadMemory(backend_, space, address, length);
    if (!readback) {
        return Result<VerifiedWriteResult>::Failure(readback.GetError());
    }
    if (readback.Value().size() != data.size() ||
        !std::equal(data.begin(), data.end(), readback.Value().begin())) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            "Write read-back did not match the requested bytes",
            "VerifiedWriter::Write",
            0,
            data.size(),
            readback.Value().size()));
    }

    VerifiedWriteResult result{};
    result.space = space;
    result.address = address;
    result.before = before.TakeValue();
    result.requested.assign(data.begin(), data.end());
    result.readback = readback.TakeValue();
    result.verified = true;
    return Result<VerifiedWriteResult>::Success(std::move(result));
}

}  // namespace kdbg

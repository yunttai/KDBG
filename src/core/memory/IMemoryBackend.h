#pragma once

#include "core/common/Result.h"
#include "core/model/BackendInfo.h"
#include "core/model/MemorySpace.h"
#include "core/model/PhysicalPage.h"
#include "core/model/PhysicalRange.h"
#include "core/paging/X64PageTable.h"

#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace kdbg {

enum class PhysicalPageCompareWriteOutcome {
    Applied,
    Conflict,
    Failure,
};

struct PhysicalPageCompareWriteResult {
    PhysicalPageCompareWriteOutcome outcome{
        PhysicalPageCompareWriteOutcome::Conflict};
    std::uint32_t transferred{0};
    std::uint32_t first_mismatch_offset{
        std::numeric_limits<std::uint32_t>::max()};
    std::uint32_t native_status{0};
    std::array<std::uint8_t, kPhysicalPageSize> readback{};
};

class IMemoryBackend {
public:
    virtual ~IMemoryBackend() = default;

    virtual Result<void> Open() = 0;
    virtual void Close() noexcept = 0;
    [[nodiscard]] virtual BackendInfo Info() const = 0;

    virtual Result<BackendSessionStatus> QuerySessionStatus() {
        const auto info = Info();
        if (!info.connected) {
            return Result<BackendSessionStatus>::Failure(MakeError(
                ErrorCode::BackendDisconnected,
                "Memory backend is not connected",
                "IMemoryBackend::QuerySessionStatus"));
        }
        BackendSessionStatus status{};
        status.write_enabled = info.write_enabled;
        return Result<BackendSessionStatus>::Success(status);
    }

    virtual Result<std::vector<PhysicalRange>> GetPhysicalRanges() = 0;

    virtual Result<std::vector<std::uint8_t>> ReadPhysical(
        std::uint64_t physical_address,
        std::uint32_t length) = 0;

    virtual Result<void> SetWriteEnabled(bool enabled) = 0;

    virtual Result<std::uint32_t> WritePhysical(
        std::uint64_t physical_address,
        std::span<const std::uint8_t> data) = 0;

    virtual Result<PhysicalPageCompareWriteResult> CompareWritePhysicalPage(
        std::uint64_t physical_address,
        std::span<const std::uint8_t> expected_before,
        std::span<const std::uint8_t> desired) {
        (void)physical_address;
        (void)expected_before;
        (void)desired;
        return Result<PhysicalPageCompareWriteResult>::Failure(MakeError(
            ErrorCode::Unsupported,
            "This backend does not provide physical page compare/write",
            "IMemoryBackend::CompareWritePhysicalPage"));
    }

    virtual Result<ProcessContext> GetProcessContext(std::uint32_t pid) {
        (void)pid;
        return Result<ProcessContext>::Failure(MakeError(
            ErrorCode::Unsupported,
            "This backend does not provide process context",
            "IMemoryBackend::GetProcessContext"));
    }

    virtual Result<std::vector<std::uint8_t>> ReadProcessVirtual(
        std::uint32_t pid,
        std::uint64_t virtual_address,
        std::uint32_t length) {
        (void)pid;
        (void)virtual_address;
        (void)length;
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::Unsupported,
            "This backend does not provide process virtual reads",
            "IMemoryBackend::ReadProcessVirtual"));
    }

    virtual Result<std::uint32_t> WriteProcessVirtual(
        std::uint32_t pid,
        std::uint64_t virtual_address,
        std::span<const std::uint8_t> data) {
        (void)pid;
        (void)virtual_address;
        (void)data;
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::Unsupported,
            "This backend does not provide process virtual writes",
            "IMemoryBackend::WriteProcessVirtual"));
    }

    virtual Result<std::vector<std::uint8_t>> ReadKernelVirtual(
        std::uint64_t virtual_address,
        std::uint32_t length) {
        (void)virtual_address;
        (void)length;
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::Unsupported,
            "This backend does not provide kernel virtual reads",
            "IMemoryBackend::ReadKernelVirtual"));
    }

    virtual Result<TranslationWalk> TranslateVirtual(
        std::uint64_t directory_table_base,
        std::uint64_t virtual_address) = 0;
};

}  // namespace kdbg

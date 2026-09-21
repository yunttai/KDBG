#pragma once

#include "core/memory/MemoryAccess.h"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace kdbg {

struct VerifiedWriteResult {
    MemorySpace space;
    std::uint64_t address{0};
    std::vector<std::uint8_t> before;
    std::vector<std::uint8_t> requested;
    std::vector<std::uint8_t> readback;
    bool verified{false};
};

class VerifiedWriteArmToken {
public:
    VerifiedWriteArmToken(const VerifiedWriteArmToken&) = delete;
    VerifiedWriteArmToken& operator=(const VerifiedWriteArmToken&) = delete;
    VerifiedWriteArmToken(VerifiedWriteArmToken&& other) noexcept;
    VerifiedWriteArmToken& operator=(VerifiedWriteArmToken&& other) noexcept;

private:
    friend class VerifiedWriter;
    friend class AddressList;

    explicit VerifiedWriteArmToken(std::uint32_t pid) noexcept
        : pid_(pid), valid_(pid != 0) {}
    [[nodiscard]] bool Consume(std::uint32_t pid) noexcept;

    std::uint32_t pid_{0};
    bool valid_{false};
};

class VerifiedWriter {
public:
    static constexpr std::size_t kMaxWriteLength = 1024U * 1024U;

    explicit VerifiedWriter(IMemoryBackend& backend) : backend_(backend) {}

    [[nodiscard]] Result<VerifiedWriteArmToken> ArmProcessWrite(
        std::uint32_t confirmed_pid) const;

    Result<VerifiedWriteResult> Write(
        VerifiedWriteArmToken arm_token,
        const MemorySpace& space,
        std::uint64_t address,
        std::span<const std::uint8_t> data,
        std::optional<std::span<const std::uint8_t>> expected_before =
            std::nullopt);

private:
    IMemoryBackend& backend_;
};

}  // namespace kdbg

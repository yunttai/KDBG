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

class VerifiedWriter {
public:
    static constexpr std::size_t kMaxWriteLength = 1024U * 1024U;

    explicit VerifiedWriter(IMemoryBackend& backend) : backend_(backend) {}

    Result<VerifiedWriteResult> Write(
        const MemorySpace& space,
        std::uint64_t address,
        std::span<const std::uint8_t> data,
        std::optional<std::span<const std::uint8_t>> expected_before =
            std::nullopt);

private:
    IMemoryBackend& backend_;
};

}  // namespace kdbg

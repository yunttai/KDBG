#pragma once

#include "core/common/Result.h"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace kdbg {

inline constexpr std::size_t kMaxAobPatternBytes = 1024U * 1024U;

struct AobPattern {
    std::vector<std::uint8_t> bytes;
    std::vector<bool> exact;

    [[nodiscard]] bool Empty() const noexcept { return bytes.empty(); }
    [[nodiscard]] std::size_t Size() const noexcept { return bytes.size(); }
    [[nodiscard]] bool Matches(std::span<const std::uint8_t> input) const noexcept;
};

Result<AobPattern> ParseAobPattern(std::string_view text);

} // namespace kdbg

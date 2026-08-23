#pragma once

#include <cstdint>
#include <limits>

namespace kdbg {

struct PhysicalRange {
    std::uint64_t base{0};
    std::uint64_t length{0};

    [[nodiscard]] bool IsValid() const noexcept {
        return length != 0 &&
               base <= std::numeric_limits<std::uint64_t>::max() - length;
    }

    [[nodiscard]] bool Contains(
        std::uint64_t address,
        std::uint64_t size) const noexcept {
        if (!IsValid() || size == 0) {
            return false;
        }
        if (address > std::numeric_limits<std::uint64_t>::max() - size) {
            return false;
        }

        const auto range_end = base + length;
        const auto request_end = address + size;
        return address >= base && request_end <= range_end;
    }
};

}  // namespace kdbg

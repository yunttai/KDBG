#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace kdbg {

inline constexpr std::size_t kPhysicalPageSize = 0x1000;

struct PhysicalPage {
    std::uint64_t pfn{0};
    std::uint64_t physical_address{0};
    std::array<std::uint8_t, kPhysicalPageSize> bytes{};
    std::chrono::system_clock::time_point captured_at{};
};

}  // namespace kdbg

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace kdbg {

inline constexpr std::size_t kProbeEvidenceEditOffset = 0x100U;
inline constexpr std::array<std::uint8_t, 8> kProbeEvidenceEditMask{
    0x4BU, 0x44U, 0x42U, 0x47U, 0xA5U, 0x5AU, 0x3CU, 0xC3U};

}  // namespace kdbg

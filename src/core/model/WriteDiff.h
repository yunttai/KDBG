#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kdbg {

struct ByteDiff {
    std::size_t offset{0};
    std::uint8_t before{0};
    std::uint8_t after{0};
};

struct DiffRun {
    std::size_t offset{0};
    std::vector<std::uint8_t> before;
    std::vector<std::uint8_t> after;
};

}  // namespace kdbg

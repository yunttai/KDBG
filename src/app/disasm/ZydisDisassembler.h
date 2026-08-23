#pragma once

#include "core/common/Result.h"
#include "core/process/IProcessMemory.h"

#include <cstdint>
#include <string>
#include <vector>

namespace kdbg {

struct DisassembledInstruction {
    std::uint64_t address{0};
    std::vector<std::uint8_t> bytes;
    std::string text;
    bool branch{false};
    bool call{false};
    bool ret{false};
};

class ZydisDisassembler {
public:
    Result<std::vector<DisassembledInstruction>> Decode(
        IProcessMemory& memory,
        std::uint64_t address,
        std::uint32_t byte_count,
        std::size_t max_instructions = 512) const;
};

}  // namespace kdbg

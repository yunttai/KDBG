#pragma once

#include "core/common/Result.h"
#include "core/process/IProcessMemory.h"

#include <cstdint>
#include <functional>
#include <span>
#include <stop_token>
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

struct DisassemblyProgress {
    std::size_t bytes_consumed{0};
    std::size_t bytes_total{0};
    std::size_t instructions{0};
};

using DisassemblyProgressCallback =
    std::function<void(const DisassemblyProgress&)>;

struct DisassemblyReport {
    std::uint32_t requested_bytes{0};
    std::size_t read_bytes{0};
    std::size_t consumed_bytes{0};
    std::size_t fallback_bytes{0};
    bool truncated{false};
    std::vector<DisassembledInstruction> instructions;
};

class ZydisDisassembler {
public:
    Result<std::vector<DisassembledInstruction>> Decode(
        IProcessMemory& memory,
        std::uint64_t address,
        std::uint32_t byte_count,
        std::size_t max_instructions = 512) const;

    Result<std::vector<DisassembledInstruction>> DecodeBytes(
        std::span<const std::uint8_t> bytes,
        std::uint64_t address,
        bool x64,
        std::size_t max_instructions = 512) const;

    Result<DisassemblyReport> DecodeDetailed(
        IProcessMemory& memory,
        std::uint64_t address,
        std::uint32_t byte_count,
        std::size_t max_instructions,
        std::stop_token stop_token,
        const DisassemblyProgressCallback& progress = {}) const;

    Result<DisassemblyReport> DecodeBytesDetailed(
        std::span<const std::uint8_t> bytes,
        std::uint64_t address,
        bool x64,
        std::size_t max_instructions,
        std::stop_token stop_token = {},
        const DisassemblyProgressCallback& progress = {}) const;
};

}  // namespace kdbg

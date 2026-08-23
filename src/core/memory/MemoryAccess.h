#pragma once

#include "core/memory/IMemoryBackend.h"

#include <cstdint>
#include <span>
#include <vector>

namespace kdbg {

Result<std::vector<std::uint8_t>> ReadMemory(
    IMemoryBackend& backend,
    const MemorySpace& space,
    std::uint64_t address,
    std::uint32_t length);

Result<std::uint32_t> WriteMemory(
    IMemoryBackend& backend,
    const MemorySpace& space,
    std::uint64_t address,
    std::span<const std::uint8_t> data);

}  // namespace kdbg

#pragma once

#include "core/process/IProcessMemory.h"

#include <cstdint>
#include <vector>

namespace kdbg {

class MockProcessMemory final : public IProcessMemory {
public:
    explicit MockProcessMemory(
        std::uint64_t base = 0x10000000,
        std::size_t size = 0x10000,
        std::size_t pointer_size = 8);

    [[nodiscard]] std::uint32_t ProcessId() const noexcept override;
    [[nodiscard]] std::size_t PointerSize() const noexcept override;
    [[nodiscard]] bool IsOpen() const noexcept override;
    [[nodiscard]] bool WritesArmed() const noexcept override;
    Result<void> SetWritesArmed(bool armed) override;
    Result<std::vector<std::uint8_t>> Read(
        std::uint64_t address,
        std::uint32_t length) override;
    Result<std::uint32_t> Write(
        std::uint64_t address,
        std::span<const std::uint8_t> data) override;
    Result<std::vector<MemoryRegion>> Regions() override;
    Result<std::vector<ProcessModule>> Modules() override;

    std::vector<std::uint8_t>& Bytes() noexcept;
    const std::vector<std::uint8_t>& Bytes() const noexcept;
    [[nodiscard]] std::uint64_t Base() const noexcept;
    void AddRegion(MemoryRegion region);
    void SetModules(std::vector<ProcessModule> modules);

private:
    std::uint64_t base_{0};
    std::size_t pointer_size_{8};
    std::vector<std::uint8_t> bytes_;
    std::vector<MemoryRegion> regions_;
    std::vector<ProcessModule> modules_;
    bool writes_armed_{false};
};

}  // namespace kdbg

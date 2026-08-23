#pragma once

#include "core/memory/KDbgBackend.h"
#include "core/process/IProcessMemory.h"

#include <memory>

namespace kdbg {

class Win32ProcessMemory final : public IProcessMemory {
public:
    static Result<std::unique_ptr<Win32ProcessMemory>> Attach(
        std::uint32_t pid,
        KDbgBackend* driver_backend = nullptr);

    ~Win32ProcessMemory() override;
    Win32ProcessMemory(const Win32ProcessMemory&) = delete;
    Win32ProcessMemory& operator=(const Win32ProcessMemory&) = delete;

    [[nodiscard]] std::uint32_t ProcessId() const noexcept override;
    [[nodiscard]] std::uint64_t ProcessIdentityToken() const noexcept override;
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

private:
    Win32ProcessMemory();
    Result<void> Open(std::uint32_t pid, KDbgBackend* backend);
    Result<void> ReopenForWrite();

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace kdbg

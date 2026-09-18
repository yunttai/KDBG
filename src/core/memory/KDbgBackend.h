#pragma once

#include "core/memory/IMemoryBackend.h"

#include <memory>
#include <string>

namespace kdbg {

class KDbgBackend final : public IMemoryBackend {
public:
    explicit KDbgBackend(std::wstring device_name = L"\\\\.\\KDBG");
    ~KDbgBackend() override;

    KDbgBackend(const KDbgBackend&) = delete;
    KDbgBackend& operator=(const KDbgBackend&) = delete;

    Result<void> Open() override;
    void Close() noexcept override;
    [[nodiscard]] BackendInfo Info() const override;

    Result<BackendSessionStatus> QuerySessionStatus() override;
    Result<std::vector<PhysicalRange>> GetPhysicalRanges() override;
    Result<std::vector<std::uint8_t>> ReadPhysical(
        std::uint64_t physical_address,
        std::uint32_t length) override;
    Result<void> SetWriteEnabled(bool enabled) override;
    Result<std::uint32_t> WritePhysical(
        std::uint64_t physical_address,
        std::span<const std::uint8_t> data) override;

    Result<ProcessContext> GetProcessContext(std::uint32_t pid) override;
    Result<std::vector<std::uint8_t>> ReadProcessVirtual(
        std::uint32_t pid,
        std::uint64_t virtual_address,
        std::uint32_t length) override;
    Result<std::uint32_t> WriteProcessVirtual(
        std::uint32_t pid,
        std::uint64_t virtual_address,
        std::span<const std::uint8_t> data) override;
    Result<std::vector<std::uint8_t>> ReadKernelVirtual(
        std::uint64_t virtual_address,
        std::uint32_t length) override;

    Result<TranslationWalk> TranslateVirtual(
        std::uint64_t directory_table_base,
        std::uint64_t virtual_address) override;

private:
    Result<void> ForceWriteGateClosed(const char* operation);

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace kdbg

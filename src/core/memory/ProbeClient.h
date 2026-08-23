#pragma once

#include "core/common/Result.h"

#include <cstdint>
#include <memory>
#include <string>

namespace kdbg {

struct ProbeInfo {
    std::uint32_t generation{0};
    std::uint32_t byte_count{0};
    std::uint64_t virtual_address{0};
    std::uint64_t physical_address{0};
    std::uint64_t pfn{0};
    std::uint32_t crc32{0};
};

class ProbeClient {
public:
    explicit ProbeClient(std::wstring device_name = L"\\\\.\\KDBGProbe");
    ~ProbeClient();

    ProbeClient(const ProbeClient&) = delete;
    ProbeClient& operator=(const ProbeClient&) = delete;

    Result<void> Open();
    void Close() noexcept;
    [[nodiscard]] bool IsOpen() const noexcept;

    Result<ProbeInfo> Query();
    Result<void> Reset();
    Result<void> Fill(std::uint8_t value);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace kdbg

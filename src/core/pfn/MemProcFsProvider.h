#pragma once

#include "core/pfn/IPfnUsageProvider.h"

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kdbg {

struct MemProcFsConfiguration {
    // UTF-8 is the product boundary for MemProcFS' narrow VMMDLL argv.  The
    // provider converts it explicitly to UTF-16 for CreateProcessW and the
    // bridge converts the resulting wide argv back to UTF-8 without using the
    // active Windows code page.
    std::optional<std::string> device;
    std::optional<std::filesystem::path> vmm_path;
    std::vector<std::string> vmm_arguments;
};

class MemProcFsProvider final : public IPfnUsageProvider {
public:
    static constexpr std::size_t kMaxProtocolMappings = 4096;
    static constexpr std::size_t kMaxVmmArguments = 64;
    static constexpr std::size_t kMaxBridgeConfigurationArguments =
        (kMaxVmmArguments * 2U) + 4U;
    static constexpr std::size_t kMaxBridgeArguments =
        kMaxBridgeConfigurationArguments + 2U;
    static constexpr std::size_t kMaxBridgeArgumentBytes = 32U * 1024U;

    explicit MemProcFsProvider(
        std::filesystem::path bridge_path,
        MemProcFsConfiguration configuration = {},
        std::chrono::milliseconds timeout =
            std::chrono::milliseconds{15000});

    [[nodiscard]] static std::filesystem::path PackagedBridgePath();

    [[nodiscard]] const char* Name() const noexcept override;

    Result<PfnUsageResult> Query(
        std::uint64_t pfn,
        std::stop_token stop_token) override;

    static Result<PfnUsageResult> ParseOutput(
        std::uint64_t expected_pfn,
        std::string_view output,
        std::size_t max_mappings = kMaxProtocolMappings);

private:
    Result<std::string> Execute(
        std::uint32_t pfn,
        std::stop_token stop_token) const;
    std::filesystem::path bridge_path_;
    MemProcFsConfiguration configuration_;
    std::chrono::milliseconds timeout_;
};

}  // namespace kdbg

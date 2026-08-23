#pragma once

#include "core/pfn/IPfnUsageProvider.h"

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace kdbg {

class MemProcFsProvider final : public IPfnUsageProvider {
public:
    static constexpr std::size_t kMaxProtocolMappings = 4096;

    explicit MemProcFsProvider(
        std::filesystem::path bridge_path,
        std::vector<std::string> bridge_arguments = {},
        std::chrono::milliseconds timeout =
            std::chrono::milliseconds{15000});

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
        const std::vector<std::string>& arguments,
        std::stop_token stop_token) const;
    std::filesystem::path bridge_path_;
    std::vector<std::string> bridge_arguments_;
    std::chrono::milliseconds timeout_;
};

}  // namespace kdbg

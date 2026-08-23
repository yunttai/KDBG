#pragma once

#include "core/memory/IMemoryBackend.h"
#include "core/pfn/IPfnUsageProvider.h"

#include <cstdint>
#include <string>
#include <vector>

namespace kdbg {

struct ProcessScanTarget {
    std::uint32_t pid{0};
    std::string process_name;
    std::uint64_t directory_table_base{0};
    bool la57{false};
};

struct ReverseMapLimits {
    std::size_t max_table_pages{262144};
    std::size_t max_results{4096};
    bool include_page_table_pages{true};
    bool continue_on_read_error{true};
};

class PageTableReverseMapper final : public IPfnUsageProvider {
public:
    explicit PageTableReverseMapper(IMemoryBackend& backend);

    void SetTargets(std::vector<ProcessScanTarget> targets);
    void SetLimits(ReverseMapLimits limits) noexcept;

    [[nodiscard]] const char* Name() const noexcept override;

    Result<PfnUsageResult> Query(
        std::uint64_t pfn,
        std::stop_token stop_token) override;

private:
    IMemoryBackend& backend_;
    std::vector<ProcessScanTarget> targets_;
    ReverseMapLimits limits_{};
};

}  // namespace kdbg

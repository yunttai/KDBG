#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace kdbg {

enum class MappingConfidence {
    Unknown,
    Low,
    Medium,
    High
};

struct ProcessUsage {
    std::uint32_t pid{0};
    std::string process_name;
    std::uint64_t virtual_address{0};
    std::uint64_t pte_address{0};
    std::uint64_t page_size{0x1000};
    std::string mapping_type;
    std::string source;
    MappingConfidence confidence{MappingConfidence::Unknown};
    bool shared{false};
    bool writable{false};
    bool user_accessible{false};
    bool no_execute{false};
};

struct PfnUsageResult {
    std::uint64_t pfn{0};
    std::vector<ProcessUsage> mappings;
    std::string provider;
};

}  // namespace kdbg

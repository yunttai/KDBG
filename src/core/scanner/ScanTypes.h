#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace kdbg {

enum class ScanValueType {
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    Utf8,
    Utf16,
    ByteArray
};

enum class ScanCompare {
    Exact,
    NotEqual,
    GreaterThan,
    LessThan,
    Between,
    UnknownInitial,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy,
    DecreasedBy
};

struct ScanQuery {
    ScanValueType type{ScanValueType::Int32};
    ScanCompare comparison{ScanCompare::Exact};
    std::string value;
    std::string second_value;
    bool hexadecimal{false};
    bool case_sensitive{true};
    bool scan_private{true};
    bool scan_image{true};
    bool scan_mapped{true};
    bool require_writable{false};
    bool include_executable{true};
    std::size_t alignment{0};
    std::size_t max_results{1'000'000};
    std::size_t chunk_size{1024 * 1024};
};

struct ScanCandidate {
    std::uint64_t address{0};
    std::vector<std::uint8_t> previous;
    std::vector<std::uint8_t> current;
};

struct ScanProgress {
    std::string phase;
    std::uint64_t bytes_total{0};
    std::uint64_t bytes_scanned{0};
    std::size_t regions_total{0};
    std::size_t regions_scanned{0};
    std::size_t candidates{0};
};

using ScanProgressCallback = std::function<void(const ScanProgress&)>;

struct ScanSummary {
    std::size_t result_count{0};
    std::uint64_t bytes_scanned{0};
    bool truncated{false};
};

}  // namespace kdbg

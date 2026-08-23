#pragma once

#include "core/common/Result.h"
#include "core/process/IProcessMemory.h"
#include "core/scanner/ScanTypes.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <stop_token>
#include <string>
#include <vector>

namespace kdbg {

struct PointerScanOptions {
    std::uint32_t max_depth{3};
    std::uint64_t max_offset{0x1000};
    std::size_t max_results{100000};
    std::size_t chunk_size{1024 * 1024};
    bool aligned_only{true};
    bool writable_only{false};
    bool static_roots_only{false};
};

struct PointerPath {
    std::uint64_t root_address{0};
    std::string module_name;
    std::uint64_t module_offset{0};
    std::vector<std::uint64_t> offsets;
    std::uint64_t resolved_address{0};
};

class PointerScanner {
public:
    static constexpr std::uint32_t kMaxDepth = 8;
    static constexpr std::uint64_t kMaxOffset = 16ULL * 1024ULL * 1024ULL;
    static constexpr std::size_t kMaxResults = 1'000'000;
    static constexpr std::size_t kMaxChunkSize = 16ULL * 1024ULL * 1024ULL;

    explicit PointerScanner(IProcessMemory& memory);

    Result<std::vector<PointerPath>> Scan(
        std::uint64_t target,
        const PointerScanOptions& options,
        ScanProgressCallback progress = {},
        std::stop_token stop_token = {});

private:
    struct FrontierNode {
        std::uint64_t address{0};
        std::vector<std::uint64_t> offsets;
    };

    Result<std::vector<FrontierNode>> FindParents(
        const std::vector<FrontierNode>& frontier,
        const PointerScanOptions& options,
        ScanProgress& state,
        const ScanProgressCallback& progress,
        std::stop_token stop_token,
        bool& truncated);

    IProcessMemory& memory_;
};

}  // namespace kdbg

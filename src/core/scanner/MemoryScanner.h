#pragma once

#include "core/common/Result.h"
#include "core/process/IProcessMemory.h"
#include "core/scanner/ScanTypes.h"
#include "core/scanner/ValueCodec.h"

#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <vector>

namespace kdbg {

// Read failures are deliberately reported separately from matches. A partial
// scan may still produce useful candidates, but callers must be able to tell
// that one or more source ranges were not evaluated.
struct ScanReadReport {
    std::uint64_t items_attempted{0};
    std::uint64_t items_completed{0};
    std::uint64_t items_skipped{0};
    std::uint64_t requested_bytes{0};
    std::uint64_t completed_bytes{0};
    std::uint64_t failed_reads{0};
    std::uint64_t short_reads{0};
    bool partial{false};
    bool cancelled{false};
    Error first_error{};
};

class MemoryScanner {
public:
    static constexpr std::size_t kMaxResults = 2'000'000;
    static constexpr std::size_t kMaxChunkBytes = 16U * 1024U * 1024U;
    static constexpr std::size_t kMaxQueryTextBytes = 4U * 1024U * 1024U;
    static constexpr std::size_t kMaxValueWidth = 1024U * 1024U;
    static constexpr std::size_t kMaxCandidateBytes = 512U * 1024U * 1024U;

    explicit MemoryScanner(IProcessMemory& memory);

    Result<ScanSummary> FirstScan(
        const ScanQuery& query,
        ScanProgressCallback progress = {},
        std::stop_token stop_token = {});

    Result<ScanSummary> NextScan(
        const ScanQuery& query,
        ScanProgressCallback progress = {},
        std::stop_token stop_token = {});

    void Reset() noexcept;

    [[nodiscard]] bool HasScan() const noexcept;
    [[nodiscard]] const std::vector<ScanCandidate>& Candidates() const noexcept;
    [[nodiscard]] const CompiledScanQuery* ActiveQuery() const noexcept;
    [[nodiscard]] std::uint64_t Generation() const noexcept;
    [[nodiscard]] ScanReadReport LastReadReport() const;

private:
    [[nodiscard]] static bool RegionAllowed(
        const MemoryRegion& region,
        const ScanQuery& query) noexcept;

    Result<void> ScanRegion(
        const MemoryRegion& region,
        const CompiledScanQuery& query,
        std::vector<ScanCandidate>& output,
        ScanProgress& progress_state,
        ScanReadReport& read_report,
        const ScanProgressCallback& callback,
        std::stop_token stop_token,
        bool& truncated);

    IProcessMemory& memory_;
    std::vector<ScanCandidate> candidates_;
    CompiledScanQuery active_query_{};
    bool has_scan_{false};
    std::uint64_t generation_{0};
    ScanReadReport last_read_report_{};
};

}  // namespace kdbg

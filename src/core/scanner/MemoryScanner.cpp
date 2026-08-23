#include "core/scanner/MemoryScanner.h"

#include <algorithm>
#include <limits>
#include <span>
#include <utility>

namespace kdbg {
namespace {

constexpr std::uint64_t kProgressUpdateBytes = 4ULL * 1024ULL * 1024ULL;

void AddProgressBytes(std::uint64_t& total, std::size_t amount) noexcept {
    const auto amount64 = static_cast<std::uint64_t>(amount);
    if (amount64 > std::numeric_limits<std::uint64_t>::max() - total) {
        total = std::numeric_limits<std::uint64_t>::max();
    } else {
        total += amount64;
    }
}

std::uint64_t NextProgressBoundary(std::uint64_t current) noexcept {
    if (current >
        std::numeric_limits<std::uint64_t>::max() - kProgressUpdateBytes) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return current + kProgressUpdateBytes;
}

void ReportProgress(
    const ScanProgressCallback& callback,
    const ScanProgress& progress) {
    if (callback) {
        callback(progress);
    }
}

Result<void> ValidateQueryLimits(const ScanQuery& query) {
    if (query.max_results == 0 ||
        query.max_results > MemoryScanner::kMaxResults) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Scan result limit is zero or exceeds the core cap",
            "MemoryScanner::ValidateQueryLimits",
            0,
            MemoryScanner::kMaxResults,
            query.max_results));
    }
    if (query.chunk_size == 0 ||
        query.chunk_size > MemoryScanner::kMaxChunkBytes) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Scan chunk size is zero or exceeds the core cap",
            "MemoryScanner::ValidateQueryLimits",
            0,
            MemoryScanner::kMaxChunkBytes,
            query.chunk_size));
    }
    if (query.value.size() > MemoryScanner::kMaxQueryTextBytes ||
        query.second_value.size() > MemoryScanner::kMaxQueryTextBytes) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Scan query text exceeds the core cap",
            "MemoryScanner::ValidateQueryLimits"));
    }
    return Result<void>::Success();
}

Result<void> ValidateCompiledLimits(const CompiledScanQuery& query) {
    if (query.width == 0 || query.width > MemoryScanner::kMaxValueWidth) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Scan value width is zero or exceeds the core cap",
            "MemoryScanner::ValidateCompiledLimits",
            0,
            MemoryScanner::kMaxValueWidth,
            query.width));
    }
    const auto bytes_per_candidate = query.width * 2U;
    if (query.query.max_results >
        MemoryScanner::kMaxCandidateBytes / bytes_per_candidate) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Scan candidate payload budget exceeds the core cap",
            "MemoryScanner::ValidateCompiledLimits"));
    }
    return Result<void>::Success();
}

}  // namespace

MemoryScanner::MemoryScanner(IProcessMemory& memory) : memory_(memory) {}

Result<ScanSummary> MemoryScanner::FirstScan(
    const ScanQuery& query,
    ScanProgressCallback progress,
    std::stop_token stop_token) {
    if (!memory_.IsOpen()) {
        return Result<ScanSummary>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "No process is attached",
            "MemoryScanner::FirstScan"));
    }

    const auto valid_limits = ValidateQueryLimits(query);
    if (!valid_limits) {
        return Result<ScanSummary>::Failure(valid_limits.GetError());
    }

    const auto compiled_result = CompileScanQuery(query);
    if (!compiled_result) {
        return Result<ScanSummary>::Failure(compiled_result.GetError());
    }
    auto compiled = compiled_result.Value();
    const auto valid_compiled = ValidateCompiledLimits(compiled);
    if (!valid_compiled) {
        return Result<ScanSummary>::Failure(valid_compiled.GetError());
    }

    const auto regions_result = memory_.Regions();
    if (!regions_result) {
        return Result<ScanSummary>::Failure(regions_result.GetError());
    }

    std::vector<MemoryRegion> regions;
    regions.reserve(regions_result.Value().size());
    ScanProgress state{};
    state.phase = "first-scan";
    for (const auto& region : regions_result.Value()) {
        if (!RegionAllowed(region, compiled.query)) {
            continue;
        }
        regions.push_back(region);
        if (state.bytes_total <=
            std::numeric_limits<std::uint64_t>::max() - region.size) {
            state.bytes_total += region.size;
        } else {
            state.bytes_total = std::numeric_limits<std::uint64_t>::max();
        }
    }
    state.regions_total = regions.size();
    ReportProgress(progress, state);

    std::vector<ScanCandidate> next_candidates;
    next_candidates.reserve(std::min<std::size_t>(
        compiled.query.max_results,
        262144));

    bool truncated = false;
    for (const auto& region : regions) {
        if (stop_token.stop_requested()) {
            return Result<ScanSummary>::Failure(MakeError(
                ErrorCode::Cancelled,
                "Memory scan was cancelled",
                "MemoryScanner::FirstScan"));
        }
        const auto result = ScanRegion(
            region,
            compiled,
            next_candidates,
            state,
            progress,
            stop_token,
            truncated);
        if (!result) {
            return Result<ScanSummary>::Failure(result.GetError());
        }
        ++state.regions_scanned;
        state.candidates = next_candidates.size();
        ReportProgress(progress, state);
        if (truncated) {
            break;
        }
    }

    candidates_ = std::move(next_candidates);
    active_query_ = std::move(compiled);
    has_scan_ = true;
    ++generation_;

    ScanSummary summary{};
    summary.result_count = candidates_.size();
    summary.bytes_scanned = state.bytes_scanned;
    summary.truncated = truncated;
    return Result<ScanSummary>::Success(summary);
}

Result<ScanSummary> MemoryScanner::NextScan(
    const ScanQuery& query,
    ScanProgressCallback progress,
    std::stop_token stop_token) {
    if (!has_scan_) {
        return Result<ScanSummary>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Run a first scan before a next scan",
            "MemoryScanner::NextScan"));
    }
    if (!memory_.IsOpen()) {
        return Result<ScanSummary>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "The attached process is no longer available",
            "MemoryScanner::NextScan"));
    }

    const auto valid_limits = ValidateQueryLimits(query);
    if (!valid_limits) {
        return Result<ScanSummary>::Failure(valid_limits.GetError());
    }

    const auto compiled_result = CompileScanQuery(query);
    if (!compiled_result) {
        return Result<ScanSummary>::Failure(compiled_result.GetError());
    }
    auto compiled = compiled_result.Value();
    const auto valid_compiled = ValidateCompiledLimits(compiled);
    if (!valid_compiled) {
        return Result<ScanSummary>::Failure(valid_compiled.GetError());
    }
    if (compiled.width != active_query_.width ||
        compiled.query.type != active_query_.query.type) {
        return Result<ScanSummary>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Next scan must use the same value type and width as the first scan",
            "MemoryScanner::NextScan"));
    }

    ScanProgress state{};
    state.phase = "next-scan";
    state.regions_total = 1;
    state.bytes_total = static_cast<std::uint64_t>(candidates_.size()) *
        static_cast<std::uint64_t>(compiled.width);
    ReportProgress(progress, state);

    std::vector<ScanCandidate> survivors;
    survivors.reserve(std::min(candidates_.size(), compiled.query.max_results));
    bool truncated = false;
    std::uint64_t next_report = kProgressUpdateBytes;

    for (const auto& candidate : candidates_) {
        if (stop_token.stop_requested()) {
            return Result<ScanSummary>::Failure(MakeError(
                ErrorCode::Cancelled,
                "Memory scan was cancelled",
                "MemoryScanner::NextScan"));
        }

        const auto current_result = memory_.Read(
            candidate.address,
            static_cast<std::uint32_t>(compiled.width));
        if (!current_result) {
            return Result<ScanSummary>::Failure(current_result.GetError());
        }
        AddProgressBytes(state.bytes_scanned, current_result.Value().size());
        if (current_result.Value().size() != compiled.width) {
            return Result<ScanSummary>::Failure(MakeError(
                ErrorCode::ShortRead,
                "Next scan returned a short read",
                "MemoryScanner::NextScan",
                0,
                compiled.width,
                current_result.Value().size()));
        }

        const auto& current = current_result.Value();
        if (MatchNextValue(compiled, candidate.current, current)) {
            ScanCandidate survivor{};
            survivor.address = candidate.address;
            survivor.previous = candidate.current;
            survivor.current = current;
            survivors.push_back(std::move(survivor));
            if (survivors.size() >= compiled.query.max_results) {
                truncated = true;
                break;
            }
        }

        if (state.bytes_scanned >= next_report) {
            state.candidates = survivors.size();
            ReportProgress(progress, state);
            next_report = NextProgressBoundary(state.bytes_scanned);
        }
    }

    state.regions_scanned = 1;
    state.candidates = survivors.size();
    ReportProgress(progress, state);

    candidates_ = std::move(survivors);
    active_query_ = std::move(compiled);
    ++generation_;

    ScanSummary summary{};
    summary.result_count = candidates_.size();
    summary.bytes_scanned = state.bytes_scanned;
    summary.truncated = truncated;
    return Result<ScanSummary>::Success(summary);
}

void MemoryScanner::Reset() noexcept {
    candidates_.clear();
    active_query_ = {};
    has_scan_ = false;
    ++generation_;
}

bool MemoryScanner::HasScan() const noexcept { return has_scan_; }

const std::vector<ScanCandidate>& MemoryScanner::Candidates() const noexcept {
    return candidates_;
}

const CompiledScanQuery* MemoryScanner::ActiveQuery() const noexcept {
    return has_scan_ ? &active_query_ : nullptr;
}

std::uint64_t MemoryScanner::Generation() const noexcept { return generation_; }

bool MemoryScanner::RegionAllowed(
    const MemoryRegion& region,
    const ScanQuery& query) noexcept {
    if (!region.committed || !region.readable || region.guard || region.size == 0) {
        return false;
    }
    if (query.require_writable && !region.writable) {
        return false;
    }
    if (!query.include_executable && region.executable) {
        return false;
    }

    // Windows memory type values: MEM_PRIVATE=0x20000,
    // MEM_MAPPED=0x40000, MEM_IMAGE=0x1000000. Unknown/mock types are kept.
    constexpr std::uint32_t kMemPrivate = 0x00020000;
    constexpr std::uint32_t kMemMapped = 0x00040000;
    constexpr std::uint32_t kMemImage = 0x01000000;
    if (region.type == kMemPrivate && !query.scan_private) return false;
    if (region.type == kMemMapped && !query.scan_mapped) return false;
    if (region.type == kMemImage && !query.scan_image) return false;
    return true;
}

Result<void> MemoryScanner::ScanRegion(
    const MemoryRegion& region,
    const CompiledScanQuery& query,
    std::vector<ScanCandidate>& output,
    ScanProgress& state,
    const ScanProgressCallback& callback,
    std::stop_token stop_token,
    bool& truncated) {
    if (query.width == 0 || query.width > std::numeric_limits<std::uint32_t>::max()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid scan width",
            "MemoryScanner::ScanRegion"));
    }

    if (region.size > std::numeric_limits<std::uint64_t>::max() - region.base) {
        return Result<void>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Scan region address range overflows",
            "MemoryScanner::ScanRegion"));
    }
    const auto region_end = region.base + region.size;
    const auto chunk_size = std::max<std::size_t>(query.query.chunk_size, query.width);
    const auto overlap = query.width > 1 ? query.width - 1 : 0;
    std::uint64_t cursor = region.base;
    std::vector<std::uint8_t> carry;
    carry.reserve(overlap);
    std::uint64_t next_report = NextProgressBoundary(state.bytes_scanned);

    while (cursor < region_end) {
        if (stop_token.stop_requested()) {
            return Result<void>::Failure(MakeError(
                ErrorCode::Cancelled,
                "Memory scan was cancelled",
                "MemoryScanner::ScanRegion"));
        }
        const auto remaining = region_end - cursor;
        const auto request64 = std::min<std::uint64_t>(
            remaining,
            std::min<std::uint64_t>(
                chunk_size,
                std::numeric_limits<std::uint32_t>::max()));
        const auto request = static_cast<std::uint32_t>(request64);
        const auto read_result = memory_.Read(cursor, request);

        if (!read_result) {
            carry.clear();
            cursor += request;
            if (state.bytes_scanned >= next_report) {
                state.candidates = output.size();
                ReportProgress(callback, state);
                next_report = NextProgressBoundary(state.bytes_scanned);
            }
            continue;
        }
        AddProgressBytes(state.bytes_scanned, read_result.Value().size());
        if (read_result.Value().size() != request) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ShortRead,
                "Memory scan returned a short read",
                "MemoryScanner::ScanRegion",
                0,
                request,
                read_result.Value().size()));
        }

        std::vector<std::uint8_t> window;
        window.reserve(carry.size() + read_result.Value().size());
        window.insert(window.end(), carry.begin(), carry.end());
        window.insert(
            window.end(),
            read_result.Value().begin(),
            read_result.Value().end());
        const auto window_base = cursor - static_cast<std::uint64_t>(carry.size());

        if (window.size() >= query.width) {
            const auto last = window.size() - query.width;
            for (std::size_t offset = 0; offset <= last; ++offset) {
                const auto address = window_base + offset;
                if (address < region.base || address >= region_end ||
                    query.width > region_end - address) {
                    continue;
                }
                if (query.query.alignment > 1 &&
                    (address % query.query.alignment) != 0) {
                    continue;
                }
                // Bytes wholly contained in the carry were already considered.
                if (!carry.empty() && offset + query.width <= carry.size()) {
                    continue;
                }
                const std::span<const std::uint8_t> value(
                    window.data() + offset,
                    query.width);
                if (!MatchInitialValue(query, value)) {
                    continue;
                }

                ScanCandidate candidate{};
                candidate.address = address;
                candidate.previous.assign(value.begin(), value.end());
                candidate.current = candidate.previous;
                output.push_back(std::move(candidate));
                if (output.size() >= query.query.max_results) {
                    truncated = true;
                    return Result<void>::Success();
                }
            }
        }

        const auto carry_count = std::min(overlap, window.size());
        carry.assign(window.end() - static_cast<std::ptrdiff_t>(carry_count), window.end());
        cursor += request;
        if (state.bytes_scanned >= next_report) {
            state.candidates = output.size();
            ReportProgress(callback, state);
            next_report = NextProgressBoundary(state.bytes_scanned);
        }
    }

    return Result<void>::Success();
}

}  // namespace kdbg

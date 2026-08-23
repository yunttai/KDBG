#include "core/scanner/PointerScanner.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

namespace kdbg {
namespace {

std::uint64_t ReadPointer(
    std::span<const std::uint8_t> bytes,
    std::size_t pointer_size) noexcept {
    std::uint64_t value = 0;
    if (pointer_size == 4 && bytes.size() >= 4) {
        std::uint32_t narrow = 0;
        std::memcpy(&narrow, bytes.data(), sizeof(narrow));
        value = narrow;
    } else if (pointer_size == 8 && bytes.size() >= 8) {
        std::memcpy(&value, bytes.data(), sizeof(value));
    }
    return value;
}

bool IsCanonicalUserPointer(std::uint64_t value, std::size_t pointer_size) noexcept {
    if (pointer_size == 4) {
        return value >= 0x10000ULL && value <= 0xFFFFFFFFULL;
    }
    return value >= 0x10000ULL && value <= 0x00007FFFFFFFFFFFULL;
}

}  // namespace

PointerScanner::PointerScanner(IProcessMemory& memory) : memory_(memory) {}

Result<std::vector<PointerPath>> PointerScanner::Scan(
    std::uint64_t target,
    const PointerScanOptions& options,
    ScanProgressCallback progress,
    std::stop_token stop_token) {
    if (!memory_.IsOpen()) {
        return Result<std::vector<PointerPath>>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "No process is attached",
            "PointerScanner::Scan"));
    }
    const auto pointer_size = memory_.PointerSize();
    if (target == 0 || options.max_depth == 0 || options.max_results == 0 ||
        options.chunk_size == 0 ||
        options.max_depth > kMaxDepth ||
        options.max_offset > kMaxOffset ||
        options.max_results > kMaxResults ||
        options.chunk_size > kMaxChunkSize ||
        (pointer_size != 4 && pointer_size != 8) ||
        !IsCanonicalUserPointer(target, pointer_size)) {
        return Result<std::vector<PointerPath>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid pointer scan options",
            "PointerScanner::Scan"));
    }

    const auto modules_result = memory_.Modules();
    if (!modules_result) {
        return Result<std::vector<PointerPath>>::Failure(modules_result.GetError());
    }
    const auto modules = modules_result.Value();

    std::vector<FrontierNode> frontier{{target, {}}};
    std::vector<PointerPath> results;
    results.reserve(std::min<std::size_t>(options.max_results, 16384));
    bool globally_truncated = false;

    for (std::uint32_t depth = 1; depth <= options.max_depth; ++depth) {
        if (stop_token.stop_requested()) {
            return Result<std::vector<PointerPath>>::Failure(MakeError(
                ErrorCode::Cancelled,
                "Pointer scan was cancelled",
                "PointerScanner::Scan"));
        }
        ScanProgress state{};
        state.phase = "pointer-depth-" + std::to_string(depth);
        bool level_truncated = false;
        const auto parents_result = FindParents(
            frontier,
            options,
            state,
            progress,
            stop_token,
            level_truncated);
        if (!parents_result) {
            return Result<std::vector<PointerPath>>::Failure(parents_result.GetError());
        }
        frontier = parents_result.Value();
        globally_truncated = globally_truncated || level_truncated;
        if (frontier.empty()) {
            break;
        }

        for (const auto& node : frontier) {
            const auto module = std::find_if(
                modules.begin(),
                modules.end(),
                [&](const ProcessModule& item) { return item.Contains(node.address); });
            if (options.static_roots_only && module == modules.end()) {
                continue;
            }
            PointerPath path{};
            path.root_address = node.address;
            path.offsets = node.offsets;
            path.resolved_address = target;
            if (module != modules.end()) {
                path.module_name = module->name;
                path.module_offset = node.address - module->base;
            }
            results.push_back(std::move(path));
            if (results.size() >= options.max_results) {
                globally_truncated = true;
                break;
            }
        }
        if (results.size() >= options.max_results || globally_truncated) {
            break;
        }
    }

    std::sort(
        results.begin(),
        results.end(),
        [](const PointerPath& left, const PointerPath& right) {
            if (left.offsets.size() != right.offsets.size()) {
                return left.offsets.size() < right.offsets.size();
            }
            if (left.module_name.empty() != right.module_name.empty()) {
                return !left.module_name.empty();
            }
            return left.root_address < right.root_address;
        });
    results.erase(
        std::unique(
            results.begin(),
            results.end(),
            [](const PointerPath& left, const PointerPath& right) {
                return left.root_address == right.root_address &&
                    left.offsets == right.offsets;
            }),
        results.end());
    if (results.size() > options.max_results) {
        results.resize(options.max_results);
    }
    return Result<std::vector<PointerPath>>::Success(std::move(results));
}

Result<std::vector<PointerScanner::FrontierNode>> PointerScanner::FindParents(
    const std::vector<FrontierNode>& frontier,
    const PointerScanOptions& options,
    ScanProgress& state,
    const ScanProgressCallback& progress,
    std::stop_token stop_token,
    bool& truncated) {
    const auto regions_result = memory_.Regions();
    if (!regions_result) {
        return Result<std::vector<FrontierNode>>::Failure(regions_result.GetError());
    }

    std::vector<FrontierNode> sorted_frontier = frontier;
    std::sort(
        sorted_frontier.begin(),
        sorted_frontier.end(),
        [](const FrontierNode& left, const FrontierNode& right) {
            if (left.address != right.address) {
                return left.address < right.address;
            }
            return left.offsets < right.offsets;
        });
    sorted_frontier.erase(
        std::unique(
            sorted_frontier.begin(),
            sorted_frontier.end(),
            [](const FrontierNode& left, const FrontierNode& right) {
                return left.address == right.address &&
                    left.offsets == right.offsets;
            }),
        sorted_frontier.end());

    std::vector<MemoryRegion> regions;
    for (const auto& region : regions_result.Value()) {
        if (!region.committed || !region.readable || region.guard || region.size == 0) {
            continue;
        }
        if (options.writable_only && !region.writable) {
            continue;
        }
        regions.push_back(region);
        if (state.bytes_total <= std::numeric_limits<std::uint64_t>::max() - region.size) {
            state.bytes_total += region.size;
        }
    }
    state.regions_total = regions.size();
    if (progress) progress(state);

    const auto pointer_size = memory_.PointerSize();
    const auto alignment = options.aligned_only ? pointer_size : 1U;
    const auto chunk_size = std::max<std::size_t>(options.chunk_size, pointer_size);
    std::vector<FrontierNode> parents;
    parents.reserve(std::min<std::size_t>(options.max_results, 32768));
    using ParentKey = std::pair<std::uint64_t, std::vector<std::uint64_t>>;
    std::set<ParentKey> seen;

    for (const auto& region : regions) {
        std::uint64_t cursor = region.base;
        std::vector<std::uint8_t> carry;
        carry.reserve(pointer_size - 1U);
        const auto end = region.size > std::numeric_limits<std::uint64_t>::max() - region.base
            ? std::numeric_limits<std::uint64_t>::max()
            : region.base + region.size;
        while (cursor < end) {
            if (stop_token.stop_requested()) {
                return Result<std::vector<FrontierNode>>::Failure(MakeError(
                    ErrorCode::Cancelled,
                    "Pointer scan was cancelled",
                    "PointerScanner::FindParents"));
            }
            const auto request = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                end - cursor,
                std::min<std::uint64_t>(chunk_size, std::numeric_limits<std::uint32_t>::max())));
            const auto data_result = memory_.Read(cursor, request);
            if (data_result) {
                const auto& bytes = data_result.Value();
                if (bytes.size() > request) {
                    return Result<std::vector<FrontierNode>>::Failure(MakeError(
                        ErrorCode::InternalInvariant,
                        "Process backend returned more bytes than requested",
                        "PointerScanner::FindParents",
                        0,
                        request,
                        bytes.size()));
                }
                if (state.bytes_scanned <=
                    std::numeric_limits<std::uint64_t>::max() - bytes.size()) {
                    state.bytes_scanned += bytes.size();
                } else {
                    state.bytes_scanned = std::numeric_limits<std::uint64_t>::max();
                }

                std::vector<std::uint8_t> window;
                window.reserve(carry.size() + bytes.size());
                window.insert(window.end(), carry.begin(), carry.end());
                window.insert(window.end(), bytes.begin(), bytes.end());
                const auto window_base = cursor - carry.size();
                if (window.size() >= pointer_size) {
                    const auto last = window.size() - pointer_size;
                    const auto remainder = static_cast<std::size_t>(
                        window_base % alignment);
                    const auto first = remainder == 0 ? 0U : alignment - remainder;
                    for (std::size_t offset = first; offset <= last; offset += alignment) {
                        const auto storage = window_base + offset;
                        const std::span<const std::uint8_t> view(
                            window.data() + offset,
                            pointer_size);
                        const auto pointer = ReadPointer(view, pointer_size);
                        if (!IsCanonicalUserPointer(pointer, pointer_size)) {
                            continue;
                        }
                        const auto lower = pointer;
                        const auto upper = options.max_offset > std::numeric_limits<std::uint64_t>::max() - pointer
                            ? std::numeric_limits<std::uint64_t>::max()
                            : pointer + options.max_offset;
                        auto it = std::lower_bound(
                            sorted_frontier.begin(),
                            sorted_frontier.end(),
                            lower,
                            [](const FrontierNode& node, std::uint64_t value) {
                                return node.address < value;
                            });
                        for (; it != sorted_frontier.end() && it->address <= upper; ++it) {
                            FrontierNode parent{};
                            parent.address = storage;
                            parent.offsets.reserve(it->offsets.size() + 1);
                            parent.offsets.push_back(it->address - pointer);
                            parent.offsets.insert(
                                parent.offsets.end(),
                                it->offsets.begin(),
                                it->offsets.end());
                            if (!seen.emplace(storage, parent.offsets).second) {
                                continue;
                            }
                            parents.push_back(std::move(parent));
                            if (parents.size() >= options.max_results) {
                                truncated = true;
                                state.candidates = parents.size();
                                if (progress) progress(state);
                                return Result<std::vector<FrontierNode>>::Success(std::move(parents));
                            }
                        }
                    }
                }

                carry.clear();
                if (bytes.size() == request && !bytes.empty()) {
                    const auto carry_size = std::min<std::size_t>(
                        pointer_size - 1U,
                        window.size());
                    carry.insert(
                        carry.end(),
                        window.end() - static_cast<std::ptrdiff_t>(carry_size),
                        window.end());
                }
            } else {
                // A failed or inaccessible chunk creates a real address gap.  Never
                // combine its neighboring bytes into a synthetic pointer value.
                carry.clear();
            }
            cursor += request;
            state.candidates = parents.size();
            if (progress) progress(state);
        }
        ++state.regions_scanned;
    }

    return Result<std::vector<FrontierNode>>::Success(std::move(parents));
}

}  // namespace kdbg

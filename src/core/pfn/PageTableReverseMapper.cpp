#include "core/pfn/PageTableReverseMapper.h"

#include "core/paging/X64PageTable.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <set>
#include <tuple>
#include <unordered_set>

namespace kdbg {
namespace {

constexpr std::uint64_t kPageSize = 0x1000ULL;
constexpr std::uint64_t kEntryAddressMask = 0x000FFFFFFFFFF000ULL;

std::uint64_t ShiftForLevel(int level) {
    switch (level) {
    case 5: return 48;
    case 4: return 39;
    case 3: return 30;
    case 2: return 21;
    case 1: return 12;
    default: return 0;
    }
}

const char* NextTableName(int level) {
    switch (level) {
    case 5: return "page-table: PML4";
    case 4: return "page-table: PDPT";
    case 3: return "page-table: PD";
    case 2: return "page-table: PT";
    default: return "page-table";
    }
}

}  // namespace

PageTableReverseMapper::PageTableReverseMapper(IMemoryBackend& backend)
    : backend_(backend) {}

void PageTableReverseMapper::SetTargets(
    std::vector<ProcessScanTarget> targets) {
    targets_ = std::move(targets);
}

void PageTableReverseMapper::SetLimits(ReverseMapLimits limits) noexcept {
    limits_ = limits;
}

const char* PageTableReverseMapper::Name() const noexcept {
    return "selected-process-page-table-scan";
}

Result<PfnUsageResult> PageTableReverseMapper::Query(
    std::uint64_t target_pfn,
    std::stop_token stop_token) {
    if (target_pfn > (std::numeric_limits<std::uint64_t>::max() >> 12U)) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::InvalidPfn,
            "PFN cannot be converted to a physical address",
            "PageTableReverseMapper::Query"));
    }
    if (!backend_.Info().connected) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Memory backend is not connected",
            "PageTableReverseMapper::Query"));
    }
    if (targets_.empty()) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No process scan target is configured",
            "PageTableReverseMapper::Query"));
    }
    if (limits_.max_table_pages == 0 || limits_.max_results == 0) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Reverse-map limits must be non-zero",
            "PageTableReverseMapper::Query"));
    }

    PfnUsageResult output{};
    output.pfn = target_pfn;
    output.provider = Name();
    std::size_t table_pages_read = 0;
    using MappingKey = std::tuple<
        std::uint32_t,
        std::uint64_t,
        std::uint64_t,
        std::uint64_t,
        std::string>;
    std::set<MappingKey> seen_mappings;
    auto append_mapping = [&](ProcessUsage usage) -> Result<void> {
        MappingKey key{
            usage.pid,
            usage.virtual_address,
            usage.pte_address,
            usage.page_size,
            usage.mapping_type};
        if (seen_mappings.contains(key)) {
            return Result<void>::Success();
        }
        if (output.mappings.size() >= limits_.max_results) {
            return Result<void>::Failure(MakeError(
                ErrorCode::LimitReached,
                "PFN reverse mapping reached the result limit",
                "PageTableReverseMapper::Query",
                0,
                limits_.max_results,
                output.mappings.size() + 1U));
        }
        seen_mappings.insert(std::move(key));
        output.mappings.push_back(std::move(usage));
        return Result<void>::Success();
    };

    for (auto target : targets_) {
        if (stop_token.stop_requested()) {
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::Cancelled,
                "PFN reverse mapping was cancelled",
                "PageTableReverseMapper::Query"));
        }
        if (target.pid == 0) {
            continue;
        }
        if (target.directory_table_base == 0) {
            auto context = backend_.GetProcessContext(target.pid);
            if (!context) {
                if (limits_.continue_on_read_error) continue;
                return Result<PfnUsageResult>::Failure(context.GetError());
            }
            target.directory_table_base = context.Value().directory_table_base;
        }

        const std::uint64_t root_pfn =
            (target.directory_table_base & ~0xFFFULL) >> 12U;
        if (limits_.include_page_table_pages && root_pfn == target_pfn) {
            ProcessUsage usage{};
            usage.pid = target.pid;
            usage.process_name = target.process_name;
            usage.mapping_type = target.la57
                ? "page-table: PML5 root"
                : "page-table: PML4 root";
            usage.source = Name();
            usage.confidence = MappingConfidence::High;
            auto appended = append_mapping(std::move(usage));
            if (!appended) {
                return Result<PfnUsageResult>::Failure(appended.GetError());
            }
        }

        std::unordered_set<std::uint64_t> active_path;
        std::function<Result<void>(
            std::uint64_t,
            int,
            std::uint64_t,
            bool,
            bool,
            bool)> walk;

        walk = [&](std::uint64_t table_pfn,
                   int level,
                   std::uint64_t virtual_prefix,
                   bool effective_writable,
                   bool effective_user,
                   bool effective_nx) -> Result<void> {
            if (stop_token.stop_requested()) {
                return Result<void>::Failure(MakeError(
                    ErrorCode::Cancelled,
                    "PFN reverse mapping was cancelled",
                    "PageTableReverseMapper::Query"));
            }
            if (!active_path.insert(table_pfn).second) {
                return Result<void>::Success();
            }
            if (table_pages_read >= limits_.max_table_pages) {
                active_path.erase(table_pfn);
                return Result<void>::Failure(MakeError(
                    ErrorCode::LimitReached,
                    "PFN reverse mapping reached the table-page limit",
                    "PageTableReverseMapper::Query",
                    0,
                    limits_.max_table_pages,
                    table_pages_read));
            }

            if (table_pfn > (std::numeric_limits<std::uint64_t>::max() >> 12U)) {
                active_path.erase(table_pfn);
                return Result<void>::Success();
            }
            auto page = backend_.ReadPhysical(table_pfn << 12U, 0x1000);
            ++table_pages_read;
            if (!page || page.Value().size() != 0x1000) {
                active_path.erase(table_pfn);
                if (limits_.continue_on_read_error) {
                    return Result<void>::Success();
                }
                return page
                    ? Result<void>::Failure(MakeError(
                        ErrorCode::ShortRead,
                        "Page-table read returned fewer than 4096 bytes",
                        "PageTableReverseMapper::Query"))
                    : Result<void>::Failure(page.GetError());
            }

            for (std::uint64_t index = 0; index < 512; ++index) {
                std::uint64_t entry = 0;
                std::memcpy(
                    &entry,
                    page.Value().data() + index * sizeof(entry),
                    sizeof(entry));
                const auto flags = DecodePageEntry(entry);
                if (!flags.present) continue;

                const std::uint64_t next_prefix =
                    virtual_prefix | (index << ShiftForLevel(level));
                const bool writable = effective_writable && flags.writable;
                const bool user = effective_user && flags.user;
                const bool nx = effective_nx || flags.no_execute;
                const std::uint64_t entry_pa =
                    (table_pfn << 12U) + index * sizeof(entry);

                if (level == 3 && flags.page_size) {
                    const auto base_address = LeafPhysicalAddress(
                        PagingLevel::Pdpt, entry, 0);
                    if (!base_address) continue;
                    const std::uint64_t base_pfn = base_address.Value() >> 12U;
                    constexpr std::uint64_t pages = 0x40000000ULL / kPageSize;
                    if (target_pfn >= base_pfn &&
                        target_pfn - base_pfn < pages) {
                        ProcessUsage usage{};
                        usage.pid = target.pid;
                        usage.process_name = target.process_name;
                        usage.virtual_address = CanonicalizeVirtualAddress(
                            next_prefix + ((target_pfn - base_pfn) << 12U),
                            target.la57);
                        usage.pte_address = entry_pa;
                        usage.page_size = 0x40000000ULL;
                        usage.mapping_type = "1 GiB large page";
                        usage.source = Name();
                        usage.confidence = MappingConfidence::High;
                        usage.writable = writable;
                        usage.user_accessible = user;
                        usage.no_execute = nx;
                        auto appended = append_mapping(std::move(usage));
                        if (!appended) return appended;
                    }
                    continue;
                }

                if (level == 2 && flags.page_size) {
                    const auto base_address = LeafPhysicalAddress(
                        PagingLevel::Pd, entry, 0);
                    if (!base_address) continue;
                    const std::uint64_t base_pfn = base_address.Value() >> 12U;
                    constexpr std::uint64_t pages = 0x200000ULL / kPageSize;
                    if (target_pfn >= base_pfn &&
                        target_pfn - base_pfn < pages) {
                        ProcessUsage usage{};
                        usage.pid = target.pid;
                        usage.process_name = target.process_name;
                        usage.virtual_address = CanonicalizeVirtualAddress(
                            next_prefix + ((target_pfn - base_pfn) << 12U),
                            target.la57);
                        usage.pte_address = entry_pa;
                        usage.page_size = 0x200000ULL;
                        usage.mapping_type = "2 MiB large page";
                        usage.source = Name();
                        usage.confidence = MappingConfidence::High;
                        usage.writable = writable;
                        usage.user_accessible = user;
                        usage.no_execute = nx;
                        auto appended = append_mapping(std::move(usage));
                        if (!appended) return appended;
                    }
                    continue;
                }

                const std::uint64_t next_pfn =
                    (entry & kEntryAddressMask) >> 12U;
                if (level == 1) {
                    if (next_pfn == target_pfn) {
                        ProcessUsage usage{};
                        usage.pid = target.pid;
                        usage.process_name = target.process_name;
                        usage.virtual_address = CanonicalizeVirtualAddress(
                            next_prefix, target.la57);
                        usage.pte_address = entry_pa;
                        usage.page_size = kPageSize;
                        usage.mapping_type = "4 KiB page";
                        usage.source = Name();
                        usage.confidence = MappingConfidence::High;
                        usage.writable = writable;
                        usage.user_accessible = user;
                        usage.no_execute = nx;
                        auto appended = append_mapping(std::move(usage));
                        if (!appended) return appended;
                    }
                    continue;
                }

                if (limits_.include_page_table_pages && next_pfn == target_pfn) {
                    ProcessUsage usage{};
                    usage.pid = target.pid;
                    usage.process_name = target.process_name;
                    usage.virtual_address = CanonicalizeVirtualAddress(
                        next_prefix, target.la57);
                    usage.pte_address = entry_pa;
                    usage.page_size = kPageSize;
                    usage.mapping_type = NextTableName(level);
                    usage.source = Name();
                    usage.confidence = MappingConfidence::Medium;
                    usage.writable = writable;
                    usage.user_accessible = user;
                    usage.no_execute = nx;
                    auto appended = append_mapping(std::move(usage));
                    if (!appended) return appended;
                }

                auto nested = walk(
                    next_pfn,
                    level - 1,
                    next_prefix,
                    writable,
                    user,
                    nx);
                if (!nested) {
                    active_path.erase(table_pfn);
                    return nested;
                }
            }

            active_path.erase(table_pfn);
            return Result<void>::Success();
        };

        auto result = walk(
            root_pfn,
            target.la57 ? 5 : 4,
            0,
            true,
            true,
            false);
        if (!result) {
            if (result.GetError().code == ErrorCode::LimitReached ||
                result.GetError().code == ErrorCode::Cancelled ||
                !limits_.continue_on_read_error) {
                return Result<PfnUsageResult>::Failure(result.GetError());
            }
        }
    }

    std::sort(
        output.mappings.begin(),
        output.mappings.end(),
        [](const ProcessUsage& left, const ProcessUsage& right) {
            return std::tie(
                       left.pid,
                       left.virtual_address,
                       left.pte_address,
                       left.page_size,
                       left.mapping_type) <
                   std::tie(
                       right.pid,
                       right.virtual_address,
                       right.pte_address,
                       right.page_size,
                       right.mapping_type);
        });

    return Result<PfnUsageResult>::Success(std::move(output));
}

}  // namespace kdbg

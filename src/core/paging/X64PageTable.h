#pragma once

#include "core/common/Result.h"

#include <cstdint>
#include <vector>

namespace kdbg {

enum class PagingLevel {
    Pml5,
    Pml4,
    Pdpt,
    Pd,
    Pt
};

struct VirtualAddressIndices {
    std::uint16_t pml5{0};
    std::uint16_t pml4{0};
    std::uint16_t pdpt{0};
    std::uint16_t pd{0};
    std::uint16_t pt{0};
    std::uint16_t offset{0};
    bool la57{false};

    static Result<VirtualAddressIndices> Decode(
        std::uint64_t virtual_address,
        bool la57);
};

struct PageEntryFlags {
    bool present{false};
    bool writable{false};
    bool user{false};
    bool write_through{false};
    bool cache_disable{false};
    bool accessed{false};
    bool dirty{false};
    bool page_size{false};
    bool global{false};
    bool no_execute{false};
    std::uint8_t protection_key{0};
    std::uint64_t pfn{0};
};

struct TranslationStep {
    PagingLevel level{PagingLevel::Pml4};
    std::uint16_t index{0};
    std::uint64_t entry_physical_address{0};
    std::uint64_t entry_value{0};
    std::uint64_t next_pfn{0};
    PageEntryFlags flags{};
};

struct TranslationWalk {
    std::uint64_t directory_table_base{0};
    std::uint64_t virtual_address{0};
    std::uint64_t physical_address{0};
    std::uint64_t page_size{0};
    std::uint64_t page_offset{0};
    bool la57{false};
    bool translated{false};
    std::vector<TranslationStep> steps;
};

[[nodiscard]] PageEntryFlags DecodePageEntry(std::uint64_t entry) noexcept;

[[nodiscard]] std::uint64_t CanonicalizeVirtualAddress(
    std::uint64_t raw_address,
    bool la57) noexcept;

[[nodiscard]] Result<std::uint64_t> LeafPhysicalAddress(
    PagingLevel level,
    std::uint64_t entry,
    std::uint64_t virtual_address);

}  // namespace kdbg

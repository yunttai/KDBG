#include "core/paging/X64PageTable.h"

namespace kdbg {
namespace {

[[nodiscard]] bool IsCanonical48(std::uint64_t address) noexcept {
    const auto bit47 = (address >> 47U) & 1U;
    const auto upper = address >> 48U;
    return bit47 == 0U ? upper == 0U : upper == 0xFFFFU;
}

[[nodiscard]] bool IsCanonical57(std::uint64_t address) noexcept {
    const auto bit56 = (address >> 56U) & 1U;
    const auto upper = address >> 57U;
    return bit56 == 0U ? upper == 0U : upper == 0x7FU;
}

}  // namespace

Result<VirtualAddressIndices> VirtualAddressIndices::Decode(
    std::uint64_t virtual_address,
    bool la57_enabled) {
    const bool canonical =
        la57_enabled ? IsCanonical57(virtual_address)
                     : IsCanonical48(virtual_address);
    if (!canonical) {
        return Result<VirtualAddressIndices>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Virtual address is not canonical for the selected paging mode",
            "VirtualAddressIndices::Decode"));
    }

    VirtualAddressIndices value{};
    value.offset = static_cast<std::uint16_t>(virtual_address & 0xFFFU);
    value.pt = static_cast<std::uint16_t>((virtual_address >> 12U) & 0x1FFU);
    value.pd = static_cast<std::uint16_t>((virtual_address >> 21U) & 0x1FFU);
    value.pdpt = static_cast<std::uint16_t>((virtual_address >> 30U) & 0x1FFU);
    value.pml4 = static_cast<std::uint16_t>((virtual_address >> 39U) & 0x1FFU);
    value.pml5 = static_cast<std::uint16_t>((virtual_address >> 48U) & 0x1FFU);
    value.la57 = la57_enabled;
    return Result<VirtualAddressIndices>::Success(value);
}

PageEntryFlags DecodePageEntry(std::uint64_t entry) noexcept {
    PageEntryFlags flags{};
    flags.present = (entry & (1ULL << 0U)) != 0;
    flags.writable = (entry & (1ULL << 1U)) != 0;
    flags.user = (entry & (1ULL << 2U)) != 0;
    flags.write_through = (entry & (1ULL << 3U)) != 0;
    flags.cache_disable = (entry & (1ULL << 4U)) != 0;
    flags.accessed = (entry & (1ULL << 5U)) != 0;
    flags.dirty = (entry & (1ULL << 6U)) != 0;
    flags.page_size = (entry & (1ULL << 7U)) != 0;
    flags.global = (entry & (1ULL << 8U)) != 0;
    flags.protection_key =
        static_cast<std::uint8_t>((entry >> 59U) & 0xFU);
    flags.no_execute = (entry & (1ULL << 63U)) != 0;
    flags.pfn = (entry & kX64PageEntryAddressMask) >> 12U;
    return flags;
}

std::uint64_t CanonicalizeVirtualAddress(
    std::uint64_t raw_address,
    bool la57) noexcept {
    if (la57) {
        constexpr std::uint64_t kAddressBits = (1ULL << 57U) - 1ULL;
        raw_address &= kAddressBits;
        if ((raw_address & (1ULL << 56U)) != 0) {
            raw_address |= ~kAddressBits;
        }
        return raw_address;
    }

    constexpr std::uint64_t kAddressBits = (1ULL << 48U) - 1ULL;
    raw_address &= kAddressBits;
    if ((raw_address & (1ULL << 47U)) != 0) {
        raw_address |= ~kAddressBits;
    }
    return raw_address;
}

Result<std::uint64_t> LeafPhysicalAddress(
    PagingLevel level,
    std::uint64_t entry,
    std::uint64_t virtual_address) {
    const auto flags = DecodePageEntry(entry);
    if (!flags.present) {
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Page-table entry is not present",
            "LeafPhysicalAddress"));
    }

    switch (level) {
    case PagingLevel::Pt: {
        return Result<std::uint64_t>::Success(
            (entry & kX64PageEntryAddressMask) |
            (virtual_address & 0xFFFULL));
    }
    case PagingLevel::Pd: {
        if (!flags.page_size) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "PD entry is not a 2 MiB leaf",
                "LeafPhysicalAddress"));
        }
        // Bit 12 is PAT for a 2 MiB leaf; address bits 20:13 are reserved.
        constexpr std::uint64_t kReservedAddressBits = 0x00000000001FE000ULL;
        if ((entry & kReservedAddressBits) != 0) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "2 MiB leaf has reserved address bits set",
                "LeafPhysicalAddress"));
        }
        constexpr std::uint64_t kAddressMask = 0x000FFFFFFFE00000ULL;
        return Result<std::uint64_t>::Success(
            (entry & kAddressMask) | (virtual_address & 0x1FFFFFULL));
    }
    case PagingLevel::Pdpt: {
        if (!flags.page_size) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "PDPT entry is not a 1 GiB leaf",
                "LeafPhysicalAddress"));
        }
        // Bit 12 is PAT for a 1 GiB leaf; address bits 29:13 are reserved.
        constexpr std::uint64_t kReservedAddressBits = 0x000000003FFFE000ULL;
        if ((entry & kReservedAddressBits) != 0) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "1 GiB leaf has reserved address bits set",
                "LeafPhysicalAddress"));
        }
        constexpr std::uint64_t kAddressMask = 0x000FFFFFC0000000ULL;
        return Result<std::uint64_t>::Success(
            (entry & kAddressMask) | (virtual_address & 0x3FFFFFFFULL));
    }
    case PagingLevel::Pml4:
    case PagingLevel::Pml5:
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "PML entry cannot be treated as a leaf",
            "LeafPhysicalAddress"));
    }

    return Result<std::uint64_t>::Failure(MakeError(
        ErrorCode::InternalInvariant,
        "Unknown paging level",
        "LeafPhysicalAddress"));
}

}  // namespace kdbg

#include "core/pfn/PfnAddress.h"

#include "core/model/PhysicalPage.h"

#include <charconv>
#include <limits>
#include <string>

namespace kdbg {

Result<PfnAddress> PfnAddress::FromPfn(std::uint64_t pfn) {
    constexpr auto kMaxPfn =
        std::numeric_limits<std::uint64_t>::max() >> 12U;

    if (pfn > kMaxPfn) {
        return Result<PfnAddress>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "PFN shifted by 12 would overflow a 64-bit physical address",
            "PfnAddress::FromPfn"));
    }

    const auto physical_address = pfn << 12U;
    if (physical_address >
        std::numeric_limits<std::uint64_t>::max() - kPhysicalPageSize) {
        return Result<PfnAddress>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Physical page end would overflow a 64-bit address",
            "PfnAddress::FromPfn"));
    }

    return Result<PfnAddress>::Success(PfnAddress{pfn, physical_address});
}

Result<PfnAddress> PfnAddress::Parse(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    if (text.empty()) {
        return Result<PfnAddress>::Failure(MakeError(
            ErrorCode::InvalidPfn,
            "PFN input is empty",
            "PfnAddress::Parse"));
    }
    if (text.front() == '-' || text.front() == '+') {
        return Result<PfnAddress>::Failure(MakeError(
            ErrorCode::InvalidPfn,
            "Signed PFN input is not accepted",
            "PfnAddress::Parse"));
    }

    int base = 10;
    if (text.size() > 2 && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }
    if (text.empty()) {
        return Result<PfnAddress>::Failure(MakeError(
            ErrorCode::InvalidPfn,
            "PFN value is missing after prefix",
            "PfnAddress::Parse"));
    }

    std::uint64_t value = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto parse = std::from_chars(begin, end, value, base);
    if (parse.ec != std::errc{} || parse.ptr != end) {
        return Result<PfnAddress>::Failure(MakeError(
            ErrorCode::InvalidPfn,
            "PFN must be an unsigned decimal or 0x-prefixed hexadecimal integer",
            "PfnAddress::Parse"));
    }

    return FromPfn(value);
}

bool PfnAddress::IsConsistent() const noexcept {
    constexpr auto kMaxPfn =
        std::numeric_limits<std::uint64_t>::max() >> 12U;
    if (pfn > kMaxPfn) {
        return false;
    }
    const auto expected_address = pfn << 12U;
    return expected_address == physical_address &&
        expected_address <=
            std::numeric_limits<std::uint64_t>::max() - kPhysicalPageSize;
}

}  // namespace kdbg

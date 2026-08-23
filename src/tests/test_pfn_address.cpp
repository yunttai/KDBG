#include "TestHarness.h"

#include "core/model/PhysicalRange.h"
#include "core/pfn/PfnAddress.h"

#include <cstdint>
#include <limits>

void RunPfnAddressTests(kdbg::test::TestRunner& runner) {
    using kdbg::ErrorCode;
    using kdbg::PfnAddress;
    using kdbg::PhysicalRange;

    const auto hexadecimal = PfnAddress::Parse("0x12345");
    KDBG_CHECK(runner, hexadecimal.Ok());
    if (hexadecimal) {
        KDBG_CHECK(runner, hexadecimal.Value().pfn == 0x12345ULL);
        KDBG_CHECK(
            runner,
            hexadecimal.Value().physical_address == 0x12345000ULL);
        KDBG_CHECK(runner, hexadecimal.Value().IsConsistent());
    }

    const auto decimal = PfnAddress::Parse("256");
    KDBG_CHECK(runner, decimal.Ok());
    if (decimal) {
        KDBG_CHECK(runner, decimal.Value().physical_address == 0x100000ULL);
    }

    KDBG_CHECK(runner, !PfnAddress::Parse("-1").Ok());
    KDBG_CHECK(runner, !PfnAddress::Parse("+1").Ok());
    KDBG_CHECK(runner, !PfnAddress::Parse("1.5").Ok());
    KDBG_CHECK(runner, !PfnAddress::Parse("0x").Ok());
    KDBG_CHECK(runner, !PfnAddress::Parse("xyz").Ok());

    const auto too_large =
        (std::numeric_limits<std::uint64_t>::max() >> 12U);
    const auto overflow = PfnAddress::FromPfn(too_large);
    KDBG_CHECK(runner, !overflow.Ok());
    if (!overflow) {
        KDBG_CHECK(
            runner,
            overflow.GetError().code == ErrorCode::AddressOverflow);
    }

    const auto near_max = PfnAddress::FromPfn(too_large - 1U);
    KDBG_CHECK(runner, near_max.Ok());
    if (near_max) {
        KDBG_CHECK(runner, near_max.Value().IsConsistent());
    }

    const PfnAddress inconsistent{
        0x100U,
        0x101000U};
    KDBG_CHECK(runner, !inconsistent.IsConsistent());
    const PfnAddress overflowing{
        std::numeric_limits<std::uint64_t>::max(),
        0};
    KDBG_CHECK(runner, !overflowing.IsConsistent());

    const PhysicalRange range{0x100000ULL, 0x200000ULL};
    KDBG_CHECK(runner, range.IsValid());
    KDBG_CHECK(runner, range.Contains(0x100000ULL, 0x1000ULL));
    KDBG_CHECK(runner, range.Contains(0x2FF000ULL, 0x1000ULL));
    KDBG_CHECK(runner, !range.Contains(0x2FF001ULL, 0x1000ULL));
    KDBG_CHECK(runner, !range.Contains(0x0FFFFFULL, 0x1000ULL));
    KDBG_CHECK(runner, !range.Contains(0x100000ULL, 0));
}

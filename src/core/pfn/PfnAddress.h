#pragma once

#include "core/common/Result.h"

#include <cstdint>
#include <string_view>

namespace kdbg {

struct PfnAddress {
    std::uint64_t pfn{0};
    std::uint64_t physical_address{0};

    static Result<PfnAddress> FromPfn(std::uint64_t pfn);
    static Result<PfnAddress> Parse(std::string_view text);
    [[nodiscard]] bool IsConsistent() const noexcept;
};

}  // namespace kdbg

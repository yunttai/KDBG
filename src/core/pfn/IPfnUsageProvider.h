#pragma once

#include "core/common/Result.h"
#include "core/model/ProcessUsage.h"

#include <cstdint>
#include <stop_token>

namespace kdbg {

class IPfnUsageProvider {
public:
    virtual ~IPfnUsageProvider() = default;

    [[nodiscard]] virtual const char* Name() const noexcept = 0;

    virtual Result<PfnUsageResult> Query(
        std::uint64_t pfn,
        std::stop_token stop_token) = 0;
};

}  // namespace kdbg

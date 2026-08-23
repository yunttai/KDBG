#pragma once

#include "core/common/Result.h"
#include "core/scanner/AobPattern.h"
#include "core/scanner/ScanTypes.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace kdbg {

struct CompiledScanQuery {
    ScanQuery query;
    std::size_t width{0};
    std::vector<std::uint8_t> first;
    std::vector<std::uint8_t> second;
    AobPattern aob;
};

[[nodiscard]] std::size_t FixedValueWidth(ScanValueType type) noexcept;
Result<CompiledScanQuery> CompileScanQuery(const ScanQuery& query);
[[nodiscard]] bool MatchInitialValue(
    const CompiledScanQuery& query,
    std::span<const std::uint8_t> current) noexcept;
[[nodiscard]] bool MatchNextValue(
    const CompiledScanQuery& query,
    std::span<const std::uint8_t> previous,
    std::span<const std::uint8_t> current) noexcept;
Result<std::vector<std::uint8_t>> EncodeValue(
    ScanValueType type,
    std::string_view text,
    bool hexadecimal = false);
std::string FormatValue(
    ScanValueType type,
    std::span<const std::uint8_t> bytes,
    bool hexadecimal = false);

}  // namespace kdbg

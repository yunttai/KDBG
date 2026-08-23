#include "core/scanner/AobPattern.h"

#include <charconv>
#include <cctype>
#include <string>

namespace kdbg {

bool AobPattern::Matches(std::span<const std::uint8_t> input) const noexcept {
    if (exact.size() != bytes.size() || input.size() < bytes.size()) return false;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (exact[i] && input[i] != bytes[i]) return false;
    }
    return true;
}

Result<AobPattern> ParseAobPattern(std::string_view text) {
    AobPattern pattern;
    std::size_t pos = 0;
    while (pos < text.size()) {
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        if (pos >= text.size()) break;
        const auto start = pos;
        while (pos < text.size() && !std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        const auto token = text.substr(start, pos - start);
        if (pattern.bytes.size() >= kMaxAobPatternBytes) {
            return Result<AobPattern>::Failure(MakeError(
                ErrorCode::LimitReached,
                "AOB pattern exceeds the product byte cap",
                "ParseAobPattern",
                0,
                kMaxAobPatternBytes,
                pattern.bytes.size() + 1U));
        }
        if (token == "?" || token == "??" || token == "**") {
            pattern.bytes.push_back(0);
            pattern.exact.push_back(false);
            continue;
        }
        if (token.size() != 2) {
            return Result<AobPattern>::Failure(MakeError(ErrorCode::ParseError, "AOB tokens must be two hex digits or ??", "ParseAobPattern"));
        }
        unsigned value = 0;
        const auto result = std::from_chars(token.data(), token.data() + token.size(), value, 16);
        if (result.ec != std::errc{} || result.ptr != token.data() + token.size() || value > 0xFF) {
            return Result<AobPattern>::Failure(MakeError(ErrorCode::ParseError, "Invalid AOB hex token", "ParseAobPattern"));
        }
        pattern.bytes.push_back(static_cast<std::uint8_t>(value));
        pattern.exact.push_back(true);
    }
    if (pattern.Empty()) {
        return Result<AobPattern>::Failure(MakeError(ErrorCode::ParseError, "AOB pattern is empty", "ParseAobPattern"));
    }
    return Result<AobPattern>::Success(std::move(pattern));
}

} // namespace kdbg

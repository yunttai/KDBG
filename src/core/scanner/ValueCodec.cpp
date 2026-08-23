#include "core/scanner/ValueCodec.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <type_traits>

namespace kdbg {
namespace {

template <typename T>
Result<std::vector<std::uint8_t>> EncodeInteger(
    std::string_view text,
    bool hexadecimal) {
    T value{};
    int base = hexadecimal ? 16 : 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ParseError,
            "Numeric scan value is empty",
            "EncodeInteger"));
    }
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), value, base);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ParseError,
            "Numeric scan value is invalid or out of range",
            "EncodeInteger"));
    }
    std::vector<std::uint8_t> output(sizeof(T));
    std::memcpy(output.data(), &value, sizeof(value));
    return Result<std::vector<std::uint8_t>>::Success(std::move(output));
}

template <typename T>
Result<std::vector<std::uint8_t>> EncodeFloating(std::string_view text) {
    if (text.empty() || text.size() > 128U ||
        std::isspace(static_cast<unsigned char>(text.front())) != 0 ||
        std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ParseError,
            "Floating-point scan value is empty, padded, or too long",
            "EncodeFloating"));
    }
    std::string owned(text);
    char* end = nullptr;
    errno = 0;
    long double parsed = std::strtold(owned.c_str(), &end);
    if (end == owned.c_str() || *end != '\0' || errno == ERANGE ||
        !std::isfinite(parsed) ||
        parsed < static_cast<long double>(std::numeric_limits<T>::lowest()) ||
        parsed > static_cast<long double>(std::numeric_limits<T>::max())) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ParseError,
            "Floating-point scan value is invalid",
            "EncodeFloating"));
    }
    const T value = static_cast<T>(parsed);
    if (!std::isfinite(value)) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ParseError,
            "Floating-point scan value is out of range",
            "EncodeFloating"));
    }
    std::vector<std::uint8_t> output(sizeof(T));
    std::memcpy(output.data(), &value, sizeof(value));
    return Result<std::vector<std::uint8_t>>::Success(std::move(output));
}

Result<std::u16string> Utf8ToUtf16(std::string_view input) {
    std::u16string output;
    for (std::size_t i = 0; i < input.size();) {
        const auto first = static_cast<unsigned char>(input[i]);
        std::uint32_t cp = 0;
        std::size_t count = 0;
        if ((first & 0x80U) == 0) {
            cp = first; count = 1;
        } else if ((first & 0xE0U) == 0xC0U) {
            cp = first & 0x1FU; count = 2;
        } else if ((first & 0xF0U) == 0xE0U) {
            cp = first & 0x0FU; count = 3;
        } else if ((first & 0xF8U) == 0xF0U) {
            cp = first & 0x07U; count = 4;
        } else {
            return Result<std::u16string>::Failure(MakeError(
                ErrorCode::ParseError,
                "Invalid UTF-8 lead byte",
                "Utf8ToUtf16"));
        }
        if (i + count > input.size()) {
            return Result<std::u16string>::Failure(MakeError(
                ErrorCode::ParseError,
                "Truncated UTF-8 sequence",
                "Utf8ToUtf16"));
        }
        for (std::size_t j = 1; j < count; ++j) {
            const auto next = static_cast<unsigned char>(input[i + j]);
            if ((next & 0xC0U) != 0x80U) {
                return Result<std::u16string>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "Invalid UTF-8 continuation byte",
                    "Utf8ToUtf16"));
            }
            cp = (cp << 6U) | (next & 0x3FU);
        }
        if ((count == 2 && cp < 0x80U) ||
            (count == 3 && cp < 0x800U) ||
            (count == 4 && cp < 0x10000U) ||
            cp > 0x10FFFFU ||
            (cp >= 0xD800U && cp <= 0xDFFFU)) {
            return Result<std::u16string>::Failure(MakeError(
                ErrorCode::ParseError,
                "Invalid UTF-8 code point",
                "Utf8ToUtf16"));
        }
        if (cp <= 0xFFFFU) {
            output.push_back(static_cast<char16_t>(cp));
        } else {
            cp -= 0x10000U;
            output.push_back(static_cast<char16_t>(0xD800U + (cp >> 10U)));
            output.push_back(static_cast<char16_t>(0xDC00U + (cp & 0x3FFU)));
        }
        i += count;
    }
    return Result<std::u16string>::Success(std::move(output));
}

bool ByteEqual(
    std::span<const std::uint8_t> left,
    std::span<const std::uint8_t> right) noexcept {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

template <typename T>
T Load(std::span<const std::uint8_t> bytes) noexcept {
    T value{};
    if (bytes.size() >= sizeof(T)) {
        std::memcpy(&value, bytes.data(), sizeof(T));
    }
    return value;
}

template <typename T>
bool CheckedAdd(T left, T right, T& output) noexcept {
    if constexpr (std::is_integral_v<T>) {
        if constexpr (std::is_unsigned_v<T>) {
            if (left > std::numeric_limits<T>::max() - right) {
                return false;
            }
        } else {
            if ((right > 0 && left > std::numeric_limits<T>::max() - right) ||
                (right < 0 && left < std::numeric_limits<T>::lowest() - right)) {
                return false;
            }
        }
    }
    output = static_cast<T>(left + right);
    return true;
}

template <typename T>
bool CheckedSubtract(T left, T right, T& output) noexcept {
    if constexpr (std::is_integral_v<T>) {
        if constexpr (std::is_unsigned_v<T>) {
            if (left < right) {
                return false;
            }
        } else {
            if ((right > 0 && left < std::numeric_limits<T>::lowest() + right) ||
                (right < 0 && left > std::numeric_limits<T>::max() + right)) {
                return false;
            }
        }
    }
    output = static_cast<T>(left - right);
    return true;
}

template <typename T>
bool MatchInitialTyped(
    ScanCompare comparison,
    std::span<const std::uint8_t> current,
    std::span<const std::uint8_t> first,
    std::span<const std::uint8_t> second) noexcept {
    const T value = Load<T>(current);
    const T a = Load<T>(first);
    const T b = Load<T>(second);
    switch (comparison) {
    case ScanCompare::Exact: return value == a;
    case ScanCompare::NotEqual: return value != a;
    case ScanCompare::GreaterThan: return value > a;
    case ScanCompare::LessThan: return value < a;
    case ScanCompare::Between: return value >= std::min(a, b) && value <= std::max(a, b);
    case ScanCompare::UnknownInitial: return true;
    default: return false;
    }
}

template <typename T>
bool MatchNextTyped(
    ScanCompare comparison,
    std::span<const std::uint8_t> previous,
    std::span<const std::uint8_t> current,
    std::span<const std::uint8_t> first,
    std::span<const std::uint8_t> second) noexcept {
    const T old_value = Load<T>(previous);
    const T new_value = Load<T>(current);
    const T a = Load<T>(first);
    const T b = Load<T>(second);
    switch (comparison) {
    case ScanCompare::Exact: return new_value == a;
    case ScanCompare::NotEqual: return new_value != a;
    case ScanCompare::GreaterThan: return new_value > a;
    case ScanCompare::LessThan: return new_value < a;
    case ScanCompare::Between: return new_value >= std::min(a, b) && new_value <= std::max(a, b);
    case ScanCompare::Changed: return new_value != old_value;
    case ScanCompare::Unchanged: return new_value == old_value;
    case ScanCompare::Increased: return new_value > old_value;
    case ScanCompare::Decreased: return new_value < old_value;
    case ScanCompare::IncreasedBy: {
        T expected{};
        return CheckedAdd(old_value, a, expected) && new_value == expected;
    }
    case ScanCompare::DecreasedBy: {
        T expected{};
        return CheckedSubtract(old_value, a, expected) && new_value == expected;
    }
    case ScanCompare::UnknownInitial: return true;
    }
    return false;
}

template <typename T>
std::string FormatTyped(std::span<const std::uint8_t> bytes, bool hex) {
    const T value = Load<T>(bytes);
    std::ostringstream stream;
    if constexpr (std::is_floating_point_v<T>) {
        stream << std::setprecision(std::numeric_limits<T>::max_digits10) << value;
    } else if (hex) {
        using U = std::make_unsigned_t<T>;
        stream << "0x" << std::uppercase << std::hex
               << static_cast<unsigned long long>(static_cast<U>(value));
    } else if constexpr (std::is_signed_v<T>) {
        stream << static_cast<long long>(value);
    } else {
        stream << static_cast<unsigned long long>(value);
    }
    return stream.str();
}

bool MatchByTypeInitial(
    const CompiledScanQuery& q,
    std::span<const std::uint8_t> current) noexcept {
#define KDBG_MATCH_INITIAL(T) return MatchInitialTyped<T>(q.query.comparison, current, q.first, q.second)
    switch (q.query.type) {
    case ScanValueType::Int8: KDBG_MATCH_INITIAL(std::int8_t);
    case ScanValueType::UInt8: KDBG_MATCH_INITIAL(std::uint8_t);
    case ScanValueType::Int16: KDBG_MATCH_INITIAL(std::int16_t);
    case ScanValueType::UInt16: KDBG_MATCH_INITIAL(std::uint16_t);
    case ScanValueType::Int32: KDBG_MATCH_INITIAL(std::int32_t);
    case ScanValueType::UInt32: KDBG_MATCH_INITIAL(std::uint32_t);
    case ScanValueType::Int64: KDBG_MATCH_INITIAL(std::int64_t);
    case ScanValueType::UInt64: KDBG_MATCH_INITIAL(std::uint64_t);
    case ScanValueType::Float: KDBG_MATCH_INITIAL(float);
    case ScanValueType::Double: KDBG_MATCH_INITIAL(double);
    default: break;
    }
#undef KDBG_MATCH_INITIAL
    return false;
}

bool MatchByTypeNext(
    const CompiledScanQuery& q,
    std::span<const std::uint8_t> previous,
    std::span<const std::uint8_t> current) noexcept {
#define KDBG_MATCH_NEXT(T) return MatchNextTyped<T>(q.query.comparison, previous, current, q.first, q.second)
    switch (q.query.type) {
    case ScanValueType::Int8: KDBG_MATCH_NEXT(std::int8_t);
    case ScanValueType::UInt8: KDBG_MATCH_NEXT(std::uint8_t);
    case ScanValueType::Int16: KDBG_MATCH_NEXT(std::int16_t);
    case ScanValueType::UInt16: KDBG_MATCH_NEXT(std::uint16_t);
    case ScanValueType::Int32: KDBG_MATCH_NEXT(std::int32_t);
    case ScanValueType::UInt32: KDBG_MATCH_NEXT(std::uint32_t);
    case ScanValueType::Int64: KDBG_MATCH_NEXT(std::int64_t);
    case ScanValueType::UInt64: KDBG_MATCH_NEXT(std::uint64_t);
    case ScanValueType::Float: KDBG_MATCH_NEXT(float);
    case ScanValueType::Double: KDBG_MATCH_NEXT(double);
    default: break;
    }
#undef KDBG_MATCH_NEXT
    return false;
}

}  // namespace

std::size_t FixedValueWidth(ScanValueType type) noexcept {
    switch (type) {
    case ScanValueType::Int8:
    case ScanValueType::UInt8: return 1;
    case ScanValueType::Int16:
    case ScanValueType::UInt16: return 2;
    case ScanValueType::Int32:
    case ScanValueType::UInt32:
    case ScanValueType::Float: return 4;
    case ScanValueType::Int64:
    case ScanValueType::UInt64:
    case ScanValueType::Double: return 8;
    case ScanValueType::Utf8:
    case ScanValueType::Utf16:
    case ScanValueType::ByteArray: return 0;
    }
    return 0;
}

Result<std::vector<std::uint8_t>> EncodeValue(
    ScanValueType type,
    std::string_view text,
    bool hexadecimal) {
    constexpr std::size_t kMaxTextValueBytes = 1024U * 1024U;
    if ((type == ScanValueType::Utf8 || type == ScanValueType::Utf16) &&
        text.size() > kMaxTextValueBytes) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Text scan value exceeds the product byte cap",
            "EncodeValue",
            0,
            kMaxTextValueBytes,
            text.size()));
    }
    switch (type) {
    case ScanValueType::Int8: return EncodeInteger<std::int8_t>(text, hexadecimal);
    case ScanValueType::UInt8: return EncodeInteger<std::uint8_t>(text, hexadecimal);
    case ScanValueType::Int16: return EncodeInteger<std::int16_t>(text, hexadecimal);
    case ScanValueType::UInt16: return EncodeInteger<std::uint16_t>(text, hexadecimal);
    case ScanValueType::Int32: return EncodeInteger<std::int32_t>(text, hexadecimal);
    case ScanValueType::UInt32: return EncodeInteger<std::uint32_t>(text, hexadecimal);
    case ScanValueType::Int64: return EncodeInteger<std::int64_t>(text, hexadecimal);
    case ScanValueType::UInt64: return EncodeInteger<std::uint64_t>(text, hexadecimal);
    case ScanValueType::Float: return EncodeFloating<float>(text);
    case ScanValueType::Double: return EncodeFloating<double>(text);
    case ScanValueType::Utf8:
        return Result<std::vector<std::uint8_t>>::Success(
            std::vector<std::uint8_t>(text.begin(), text.end()));
    case ScanValueType::Utf16: {
        const auto converted = Utf8ToUtf16(text);
        if (!converted) return Result<std::vector<std::uint8_t>>::Failure(converted.GetError());
        if (converted.Value().size() >
            kMaxTextValueBytes / sizeof(char16_t)) {
            return Result<std::vector<std::uint8_t>>::Failure(MakeError(
                ErrorCode::LimitReached,
                "UTF-16 scan value exceeds the product byte cap",
                "EncodeValue"));
        }
        std::vector<std::uint8_t> output(converted.Value().size() * sizeof(char16_t));
        if (!output.empty()) std::memcpy(output.data(), converted.Value().data(), output.size());
        return Result<std::vector<std::uint8_t>>::Success(std::move(output));
    }
    case ScanValueType::ByteArray: {
        const auto parsed = ParseAobPattern(text);
        if (!parsed) return Result<std::vector<std::uint8_t>>::Failure(parsed.GetError());
        if (std::find(parsed.Value().exact.begin(), parsed.Value().exact.end(), false) != parsed.Value().exact.end()) {
            return Result<std::vector<std::uint8_t>>::Failure(MakeError(ErrorCode::ParseError, "Wildcard AOB cannot be encoded as a concrete value", "EncodeValue"));
        }
        return Result<std::vector<std::uint8_t>>::Success(parsed.Value().bytes);
    }
    }
    return Result<std::vector<std::uint8_t>>::Failure(MakeError(ErrorCode::Unsupported, "Unsupported value type", "EncodeValue"));
}

Result<CompiledScanQuery> CompileScanQuery(const ScanQuery& query) {
    CompiledScanQuery compiled{};
    compiled.query = query;

    const bool change_only =
        query.comparison == ScanCompare::Changed ||
        query.comparison == ScanCompare::Unchanged ||
        query.comparison == ScanCompare::Increased ||
        query.comparison == ScanCompare::Decreased;

    if (query.type == ScanValueType::ByteArray) {
        if (query.comparison != ScanCompare::Exact &&
            query.comparison != ScanCompare::NotEqual &&
            query.comparison != ScanCompare::Changed &&
            query.comparison != ScanCompare::Unchanged) {
            return Result<CompiledScanQuery>::Failure(MakeError(ErrorCode::InvalidArgument, "AOB scans support exact/not-equal/changed/unchanged comparisons", "CompileScanQuery"));
        }
        if (query.value.empty()) {
            return Result<CompiledScanQuery>::Failure(MakeError(ErrorCode::InvalidArgument, "AOB next scans require the original pattern to preserve width", "CompileScanQuery"));
        }
        const auto aob = ParseAobPattern(query.value);
        if (!aob) return Result<CompiledScanQuery>::Failure(aob.GetError());
        compiled.aob = aob.Value();
        compiled.width = compiled.aob.Size();
        compiled.first = compiled.aob.bytes;
    } else if (query.comparison == ScanCompare::UnknownInitial || change_only) {
        compiled.width = FixedValueWidth(query.type);
        if (compiled.width == 0) {
            if (query.value.empty()) {
                return Result<CompiledScanQuery>::Failure(MakeError(ErrorCode::InvalidArgument, "Variable-width changed scans require the original value to preserve width", "CompileScanQuery"));
            }
            const auto original = EncodeValue(query.type, query.value, query.hexadecimal);
            if (!original) return Result<CompiledScanQuery>::Failure(original.GetError());
            compiled.first = original.Value();
            compiled.width = compiled.first.size();
        }
    } else {
        const auto first = EncodeValue(query.type, query.value, query.hexadecimal);
        if (!first) return Result<CompiledScanQuery>::Failure(first.GetError());
        compiled.first = first.Value();
        compiled.width = compiled.first.size();
        if (compiled.width == 0) {
            return Result<CompiledScanQuery>::Failure(MakeError(ErrorCode::InvalidArgument, "Scan value must not be empty", "CompileScanQuery"));
        }
        if (query.comparison == ScanCompare::Between) {
            const auto second = EncodeValue(query.type, query.second_value, query.hexadecimal);
            if (!second) return Result<CompiledScanQuery>::Failure(second.GetError());
            if (second.Value().size() != compiled.width) {
                return Result<CompiledScanQuery>::Failure(MakeError(ErrorCode::InvalidArgument, "Between-scan values have different widths", "CompileScanQuery"));
            }
            compiled.second = second.Value();
        }
    }

    if (compiled.query.alignment == 0) {
        compiled.query.alignment = query.type == ScanValueType::ByteArray ||
            query.type == ScanValueType::Utf8 || query.type == ScanValueType::Utf16
            ? 1
            : compiled.width;
    }
    if (compiled.query.chunk_size < compiled.width) {
        compiled.query.chunk_size = std::max<std::size_t>(compiled.width, 4096);
    }
    if (compiled.query.max_results == 0) {
        return Result<CompiledScanQuery>::Failure(MakeError(ErrorCode::InvalidArgument, "max_results must be greater than zero", "CompileScanQuery"));
    }
    return Result<CompiledScanQuery>::Success(std::move(compiled));
}

bool MatchInitialValue(
    const CompiledScanQuery& query,
    std::span<const std::uint8_t> current) noexcept {
    if (current.size() < query.width) return false;
    if (query.query.type == ScanValueType::ByteArray) {
        const bool match = query.aob.Matches(current.first(query.width));
        return query.query.comparison == ScanCompare::NotEqual ? !match : match;
    }
    if (query.query.type == ScanValueType::Utf8 ||
        query.query.type == ScanValueType::Utf16) {
        bool match = ByteEqual(current.first(query.width), query.first);
        return query.query.comparison == ScanCompare::NotEqual ? !match : match;
    }
    return MatchByTypeInitial(query, current.first(query.width));
}

bool MatchNextValue(
    const CompiledScanQuery& query,
    std::span<const std::uint8_t> previous,
    std::span<const std::uint8_t> current) noexcept {
    if (previous.size() < query.width || current.size() < query.width) return false;
    if (query.query.type == ScanValueType::ByteArray ||
        query.query.type == ScanValueType::Utf8 ||
        query.query.type == ScanValueType::Utf16) {
        const bool changed = !ByteEqual(previous.first(query.width), current.first(query.width));
        switch (query.query.comparison) {
        case ScanCompare::Changed: return changed;
        case ScanCompare::Unchanged: return !changed;
        case ScanCompare::Exact:
            if (query.query.type == ScanValueType::ByteArray) return query.aob.Matches(current.first(query.width));
            return ByteEqual(current.first(query.width), query.first);
        case ScanCompare::NotEqual:
            if (query.query.type == ScanValueType::ByteArray) return !query.aob.Matches(current.first(query.width));
            return !ByteEqual(current.first(query.width), query.first);
        default: return false;
        }
    }
    return MatchByTypeNext(query, previous.first(query.width), current.first(query.width));
}

std::string FormatValue(
    ScanValueType type,
    std::span<const std::uint8_t> bytes,
    bool hexadecimal) {
    if (bytes.size() < FixedValueWidth(type) && FixedValueWidth(type) != 0) return "<short>";
    switch (type) {
    case ScanValueType::Int8: return FormatTyped<std::int8_t>(bytes, hexadecimal);
    case ScanValueType::UInt8: return FormatTyped<std::uint8_t>(bytes, hexadecimal);
    case ScanValueType::Int16: return FormatTyped<std::int16_t>(bytes, hexadecimal);
    case ScanValueType::UInt16: return FormatTyped<std::uint16_t>(bytes, hexadecimal);
    case ScanValueType::Int32: return FormatTyped<std::int32_t>(bytes, hexadecimal);
    case ScanValueType::UInt32: return FormatTyped<std::uint32_t>(bytes, hexadecimal);
    case ScanValueType::Int64: return FormatTyped<std::int64_t>(bytes, hexadecimal);
    case ScanValueType::UInt64: return FormatTyped<std::uint64_t>(bytes, hexadecimal);
    case ScanValueType::Float: return FormatTyped<float>(bytes, false);
    case ScanValueType::Double: return FormatTyped<double>(bytes, false);
    case ScanValueType::Utf8: return std::string(bytes.begin(), bytes.end());
    case ScanValueType::Utf16: {
        std::ostringstream stream;
        for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
            const auto ch = static_cast<char16_t>(bytes[i] | (static_cast<unsigned>(bytes[i + 1]) << 8U));
            if (ch >= 0x20 && ch < 0x7F) stream << static_cast<char>(ch); else stream << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(ch);
        }
        return stream.str();
    }
    case ScanValueType::ByteArray: {
        std::ostringstream stream;
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            if (i) stream << ' ';
            stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(bytes[i]);
        }
        return stream.str();
    }
    }
    return {};
}

}  // namespace kdbg

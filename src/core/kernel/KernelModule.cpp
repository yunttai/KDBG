#include "core/kernel/KernelModule.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <limits>
#include <system_error>
#include <type_traits>

namespace kdbg {
namespace {

template <typename T>
bool ReadLittleEndian(
    std::span<const std::uint8_t> bytes,
    std::size_t offset,
    T& value) noexcept {
    static_assert(std::is_unsigned_v<T>);
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) return false;
    std::uint64_t assembled = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        assembled |= static_cast<std::uint64_t>(bytes[offset + index]) <<
            (index * 8U);
    }
    value = static_cast<T>(assembled);
    return true;
}

std::string_view Trim(std::string_view value) noexcept {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

bool HasRemoteSymbolSyntax(std::string_view value) {
    std::string lowered(value);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return lowered.find("srv*") != std::string::npos ||
        lowered.find("http://") != std::string::npos ||
        lowered.find("https://") != std::string::npos;
}

std::filesystem::path PathFromUtf8(std::string_view value) {
    std::u8string encoded;
    encoded.reserve(value.size());
    for (const char byte : value) {
        encoded.push_back(static_cast<char8_t>(
            static_cast<unsigned char>(byte)));
    }
    return std::filesystem::path(encoded);
}

}  // namespace

bool KernelModule::Contains(std::uint64_t address) const noexcept {
    return image_size != 0 && address >= base &&
        address - base < static_cast<std::uint64_t>(image_size);
}

bool IsCanonicalX64Address(
    std::uint64_t address,
    bool la57) noexcept {
    const auto sign_bit = la57 ? 56U : 47U;
    const auto address_bits = la57 ? 57U : 48U;
    const auto upper = address >> address_bits;
    const bool sign = ((address >> sign_bit) & 1U) != 0;
    const auto expected_upper = sign
        ? ((1ULL << (64U - address_bits)) - 1ULL)
        : 0ULL;
    return upper == expected_upper;
}

bool IsCanonicalX64KernelAddress(
    std::uint64_t address,
    bool la57) noexcept {
    const auto sign_bit = la57 ? 56U : 47U;
    return IsCanonicalX64Address(address, la57) &&
        ((address >> sign_bit) & 1U) != 0;
}

Result<PeImageMetadata> ParsePe64ImageMetadata(
    std::span<const std::uint8_t> bytes) {
    constexpr std::uint16_t kDosMagic = 0x5A4D;
    constexpr std::uint32_t kPeSignature = 0x00004550;
    constexpr std::uint16_t kAmd64Machine = 0x8664;
    constexpr std::uint16_t kPe32PlusMagic = 0x020B;
    constexpr std::size_t kDosPeOffset = 0x3C;
    constexpr std::size_t kCoffHeaderBytes = 20;
    constexpr std::size_t kOptionalImageSizeOffset = 56;
    constexpr std::size_t kOptionalChecksumOffset = 64;
    constexpr std::uint16_t kMaximumSections = 96;

    std::uint16_t dos_magic = 0;
    std::uint32_t pe_offset = 0;
    if (!ReadLittleEndian(bytes, 0, dos_magic) || dos_magic != kDosMagic ||
        !ReadLittleEndian(bytes, kDosPeOffset, pe_offset)) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::ParseError,
            "File does not contain a complete DOS header",
            "ParsePe64ImageMetadata"));
    }
    const std::size_t pe = pe_offset;
    if (pe > bytes.size() || bytes.size() - pe < 4U + kCoffHeaderBytes) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::ParseError,
            "PE header offset is outside the bounded input",
            "ParsePe64ImageMetadata"));
    }

    std::uint32_t signature = 0;
    std::uint16_t machine = 0;
    std::uint16_t section_count = 0;
    std::uint32_t timestamp = 0;
    std::uint16_t optional_size = 0;
    const std::size_t coff = pe + 4U;
    if (!ReadLittleEndian(bytes, pe, signature) || signature != kPeSignature ||
        !ReadLittleEndian(bytes, coff, machine) ||
        !ReadLittleEndian(bytes, coff + 2U, section_count) ||
        !ReadLittleEndian(bytes, coff + 4U, timestamp) ||
        !ReadLittleEndian(bytes, coff + 16U, optional_size)) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::ParseError,
            "File does not contain a complete PE/COFF header",
            "ParsePe64ImageMetadata"));
    }
    if (machine != kAmd64Machine) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::Unsupported,
            "Kernel image is not AMD64",
            "ParsePe64ImageMetadata",
            machine));
    }
    if (section_count == 0 || section_count > kMaximumSections) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::LimitReached,
            "PE section count is zero or exceeds the parser limit",
            "ParsePe64ImageMetadata",
            0,
            kMaximumSections,
            section_count));
    }

    const std::size_t optional = coff + kCoffHeaderBytes;
    const std::size_t required_optional = kOptionalChecksumOffset + 4U;
    if (optional_size < required_optional || optional > bytes.size() ||
        bytes.size() - optional < optional_size) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::ParseError,
            "PE32+ optional header is incomplete",
            "ParsePe64ImageMetadata"));
    }
    std::uint16_t optional_magic = 0;
    std::uint32_t image_size = 0;
    std::uint32_t checksum = 0;
    if (!ReadLittleEndian(bytes, optional, optional_magic) ||
        optional_magic != kPe32PlusMagic ||
        !ReadLittleEndian(bytes, optional + kOptionalImageSizeOffset, image_size) ||
        !ReadLittleEndian(bytes, optional + kOptionalChecksumOffset, checksum)) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::ParseError,
            "Image does not contain a valid PE32+ optional header",
            "ParsePe64ImageMetadata"));
    }
    if (image_size == 0) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::ParseError,
            "PE image size is zero",
            "ParsePe64ImageMetadata"));
    }
    return Result<PeImageMetadata>::Success(PeImageMetadata{
        machine, section_count, timestamp, image_size, checksum});
}

Result<std::vector<std::filesystem::path>> ParseLocalSymbolPath(
    std::string_view text) {
    constexpr std::size_t kMaximumInputBytes = 8192;
    constexpr std::size_t kMaximumEntries = 32;
    if (text.empty() || text.size() > kMaximumInputBytes) {
        return Result<std::vector<std::filesystem::path>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Local symbol path is empty or exceeds 8192 bytes",
            "ParseLocalSymbolPath",
            0,
            kMaximumInputBytes,
            text.size()));
    }
    if (HasRemoteSymbolSyntax(text)) {
        return Result<std::vector<std::filesystem::path>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Only explicit local symbol directories or PDB files are accepted",
            "ParseLocalSymbolPath"));
    }

    std::vector<std::filesystem::path> paths;
    std::size_t begin = 0;
    while (begin <= text.size()) {
        const auto separator = text.find(';', begin);
        const auto end = separator == std::string_view::npos ? text.size() : separator;
        const auto entry = Trim(text.substr(begin, end - begin));
        if (entry.empty()) {
            return Result<std::vector<std::filesystem::path>>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Local symbol path contains an empty entry",
                "ParseLocalSymbolPath"));
        }
        if (paths.size() == kMaximumEntries) {
            return Result<std::vector<std::filesystem::path>>::Failure(MakeError(
                ErrorCode::LimitReached,
                "Local symbol path exceeds 32 entries",
                "ParseLocalSymbolPath"));
        }
        paths.push_back(PathFromUtf8(entry));
        if (separator == std::string_view::npos) break;
        begin = separator + 1U;
    }
    return Result<std::vector<std::filesystem::path>>::Success(std::move(paths));
}

}  // namespace kdbg

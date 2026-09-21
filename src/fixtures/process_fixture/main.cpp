#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kPageSize = 4096;
constexpr std::size_t kMaxCommandBytes = 4096;
constexpr std::size_t kMaxMutationBytes = 64;
constexpr std::uint32_t kProtocolVersion = 1;

constexpr std::size_t kMagicOffset = 0x00;
constexpr std::size_t kVersionOffset = 0x08;
constexpr std::size_t kGenerationOffset = 0x0C;
constexpr std::size_t kSigned32Offset = 0x20;
constexpr std::size_t kUnsigned64Offset = 0x28;
constexpr std::size_t kFloatOffset = 0x38;
constexpr std::size_t kDoubleOffset = 0x40;
constexpr std::size_t kUtf8Offset = 0x60;
constexpr std::size_t kUtf16Offset = 0xA0;
constexpr std::size_t kAobOffset = 0x100;
constexpr std::size_t kFreezeOffset = 0x180;
constexpr std::size_t kCodeOffset = 0x200;
constexpr std::size_t kPointer1Offset = 0x300;
constexpr std::size_t kPointer2Offset = 0x400;
constexpr std::size_t kPointerTargetOffset = 0x500;

constexpr std::array<std::uint8_t, 8> kMagic{
    'K', 'D', 'B', 'G', 'F', 'X', '0', '1'};
constexpr std::array<std::uint8_t, 8> kAob{
    0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0x42, 0x99};
constexpr std::array<std::uint8_t, 7> kCode{
    0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3};
constexpr std::string_view kUtf8 = "KDBG_PROCESS_FIXTURE_UTF8";
constexpr std::u16string_view kUtf16 = u"KDBG_PROCESS_FIXTURE_UTF16";

std::uint32_t Crc32(std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t crc = 0xFFFFFFFFU;
    for (const auto byte : bytes) {
        crc ^= byte;
        for (unsigned int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask =
                0U - static_cast<std::uint32_t>(crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}

template <typename T>
void Store(std::span<std::uint8_t> page, std::size_t offset, T value) {
    static_assert(std::is_trivially_copyable_v<T>);
    std::memcpy(page.data() + offset, &value, sizeof(value));
}

std::string Hex(std::uint64_t value, unsigned int width = 0) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::nouppercase << std::setfill('0');
    if (width != 0) stream << std::setw(static_cast<int>(width));
    stream << value;
    return stream.str();
}

std::string BytesToHex(std::span<const std::uint8_t> bytes) {
    std::ostringstream stream;
    stream << std::hex << std::nouppercase << std::setfill('0');
    for (const auto value : bytes) {
        stream << std::setw(2) << static_cast<unsigned int>(value);
    }
    return stream.str();
}

std::string JsonEscape(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const char raw_character : value) {
        const auto character = static_cast<unsigned char>(raw_character);
        switch (character) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (character < 0x20U) {
                    std::ostringstream stream;
                    stream << "\\u" << std::hex << std::setfill('0')
                           << std::setw(4)
                           << static_cast<unsigned int>(character);
                    escaped += stream.str();
                } else {
                    escaped.push_back(static_cast<char>(character));
                }
                break;
        }
    }
    return escaped;
}

std::string Trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::optional<std::uint64_t> ParseUnsigned(std::string_view text) {
    if (text.empty() || text.front() == '+' || text.front() == '-') {
        return std::nullopt;
    }
    int base = 10;
    if (text.size() > 2 && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }
    if (text.empty()) return std::nullopt;
    std::uint64_t value = 0;
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (error != std::errc{} || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::vector<std::uint8_t>> ParseHexBytes(
    std::string_view text) {
    if (text.empty() || (text.size() & 1U) != 0 ||
        text.size() / 2 > kMaxMutationBytes) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(text.size() / 2);
    for (std::size_t offset = 0; offset < text.size(); offset += 2) {
        unsigned int value = 0;
        const auto* first = text.data() + offset;
        const auto* last = first + 2;
        const auto [end, error] = std::from_chars(first, last, value, 16);
        if (error != std::errc{} || end != last || value > 0xFFU) {
            return std::nullopt;
        }
        bytes.push_back(static_cast<std::uint8_t>(value));
    }
    return bytes;
}

std::uint64_t CurrentProcessStartId() noexcept {
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    if (::GetProcessTimes(
            ::GetCurrentProcess(), &creation, &exit, &kernel, &user) == FALSE) {
        return 0;
    }
    ULARGE_INTEGER combined{};
    combined.LowPart = creation.dwLowDateTime;
    combined.HighPart = creation.dwHighDateTime;
    return combined.QuadPart;
}

class FixturePage {
public:
    FixturePage() {
        page_ = static_cast<std::uint8_t*>(::VirtualAlloc(
            nullptr,
            kPageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE));
        if (page_ == nullptr) return;
        if ((reinterpret_cast<std::uintptr_t>(page_) & (kPageSize - 1U)) != 0) {
            ::VirtualFree(page_, 0, MEM_RELEASE);
            page_ = nullptr;
            return;
        }
        if (::VirtualLock(page_, kPageSize) == FALSE) {
            ::VirtualFree(page_, 0, MEM_RELEASE);
            page_ = nullptr;
            return;
        }
        locked_ = true;
        Fill(false);
    }

    ~FixturePage() {
        if (page_ != nullptr) {
            if (locked_) static_cast<void>(::VirtualUnlock(page_, kPageSize));
            ::VirtualFree(page_, 0, MEM_RELEASE);
        }
    }

    FixturePage(const FixturePage&) = delete;
    FixturePage& operator=(const FixturePage&) = delete;

    [[nodiscard]] bool Ready() const noexcept {
        return page_ != nullptr && locked_;
    }

    [[nodiscard]] std::uint8_t* Data() noexcept { return page_; }
    [[nodiscard]] const std::uint8_t* Data() const noexcept { return page_; }
    [[nodiscard]] std::uint32_t Generation() const noexcept {
        return generation_;
    }
    [[nodiscard]] std::uint32_t BaselineCrc32() const noexcept {
        return baseline_crc32_;
    }
    [[nodiscard]] std::uint32_t CurrentCrc32() const noexcept {
        ::MemoryBarrier();
        return Crc32(std::span<const std::uint8_t>(page_, kPageSize));
    }

    void Reset() noexcept { Fill(true); }

    bool Mutate(
        std::size_t offset,
        std::span<const std::uint8_t> bytes) noexcept {
        if (page_ == nullptr || bytes.empty() ||
            offset >= kPageSize || bytes.size() > kPageSize - offset) {
            return false;
        }
        std::memcpy(page_ + offset, bytes.data(), bytes.size());
        ::MemoryBarrier();
        return true;
    }

private:
    void Fill(bool increment_generation) noexcept {
        if (increment_generation && generation_ !=
                std::numeric_limits<std::uint32_t>::max()) {
            ++generation_;
        }
        std::span<std::uint8_t> page(page_, kPageSize);
        for (std::size_t index = 0; index < page.size(); ++index) {
            page[index] = static_cast<std::uint8_t>(
                ((index * 131U) + 17U) & 0xFFU);
        }
        std::memcpy(page.data() + kMagicOffset, kMagic.data(), kMagic.size());
        Store(page, kVersionOffset, kProtocolVersion);
        Store(page, kGenerationOffset, generation_);
        Store(page, kSigned32Offset, static_cast<std::int32_t>(0x13579BDF));
        Store(page, kUnsigned64Offset, UINT64_C(0x1122334455667788));
        Store(page, kFloatOffset, 1234.5F);
        Store(page, kDoubleOffset, -9876.25);
        std::memcpy(page.data() + kUtf8Offset, kUtf8.data(), kUtf8.size());
        page[kUtf8Offset + kUtf8.size()] = 0;
        std::memcpy(
            page.data() + kUtf16Offset,
            kUtf16.data(),
            kUtf16.size() * sizeof(char16_t));
        Store<std::uint16_t>(
            page, kUtf16Offset + kUtf16.size() * sizeof(char16_t), 0);
        std::memcpy(page.data() + kAobOffset, kAob.data(), kAob.size());
        Store(page, kFreezeOffset, static_cast<std::int32_t>(0x2468ACE0));
        std::memcpy(page.data() + kCodeOffset, kCode.data(), kCode.size());
        const auto base = reinterpret_cast<std::uintptr_t>(page_);
        Store(page, kPointer1Offset,
              static_cast<std::uint64_t>(base + kPointer2Offset));
        Store(page, kPointer2Offset,
              static_cast<std::uint64_t>(base + kPointerTargetOffset));
        Store(page, kPointerTargetOffset, UINT64_C(0xCAFEBABE0BADF00D));
        ::MemoryBarrier();
        baseline_crc32_ = Crc32(page);
    }

    std::uint8_t* page_{nullptr};
    bool locked_{false};
    std::uint32_t generation_{1};
    std::uint32_t baseline_crc32_{0};
};

struct FixtureIdentity {
    DWORD pid{::GetCurrentProcessId()};
    std::uint64_t process_start_id{CurrentProcessStartId()};
    std::array<std::uint8_t, 16> nonce{};
    std::string pipe_name;
};

std::optional<FixtureIdentity> MakeIdentity() {
    FixtureIdentity identity;
    if (::BCryptGenRandom(
            nullptr,
            identity.nonce.data(),
            static_cast<ULONG>(identity.nonce.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return std::nullopt;
    }
    identity.pipe_name = "\\\\.\\pipe\\KDBG.ProcessFixture." +
        std::to_string(identity.pid);
    return identity;
}

std::string MetadataJson(
    const FixturePage& fixture,
    const FixtureIdentity& identity,
    bool ok = true,
    std::string_view command = "INFO") {
    std::ostringstream stream;
    stream << "{\"schema\":\"kdbg.process-fixture.v1\""
           << ",\"ok\":" << (ok ? "true" : "false")
           << ",\"command\":\"" << JsonEscape(command) << "\""
           << ",\"protocol_version\":" << kProtocolVersion
           << ",\"pid\":" << identity.pid
           << ",\"process_start_id\":\""
           << Hex(identity.process_start_id, 16) << "\""
           << ",\"fixture_nonce\":\""
           << BytesToHex(identity.nonce) << "\""
           << ",\"image_basename\":\"kdbg_process_fixture.exe\""
           << ",\"virtual_address\":\""
           << Hex(reinterpret_cast<std::uintptr_t>(fixture.Data()), 16)
           << "\""
           << ",\"byte_count\":" << kPageSize
           << ",\"generation\":" << fixture.Generation()
           << ",\"baseline_crc32\":\""
           << Hex(fixture.BaselineCrc32(), 8) << "\""
           << ",\"current_crc32\":\""
           << Hex(fixture.CurrentCrc32(), 8) << "\""
           << ",\"virtual_locked\":true"
           << ",\"pipe_name\":\"" << JsonEscape(identity.pipe_name)
           << "\""
           << ",\"corpus\":{"
           << "\"signed32\":" << kSigned32Offset
           << ",\"unsigned64\":" << kUnsigned64Offset
           << ",\"float32\":" << kFloatOffset
           << ",\"float64\":" << kDoubleOffset
           << ",\"utf8\":" << kUtf8Offset
           << ",\"utf16\":" << kUtf16Offset
           << ",\"aob\":" << kAobOffset
           << ",\"freeze_value\":" << kFreezeOffset
           << ",\"x64_code\":" << kCodeOffset
           << ",\"pointer_root\":" << kPointer1Offset
           << ",\"pointer_second\":" << kPointer2Offset
           << ",\"pointer_target\":" << kPointerTargetOffset
           << "}}";
    return stream.str();
}

std::string ErrorJson(std::string_view error) {
    return "{\"schema\":\"kdbg.process-fixture.v1\",\"ok\":false,"
           "\"error\":\"" + JsonEscape(error) + "\"}";
}

struct CommandResult {
    std::string response;
    bool exit_requested{false};
};

CommandResult ExecuteCommand(
    std::string command_line,
    FixturePage& fixture,
    const FixtureIdentity& identity) {
    command_line = Trim(std::move(command_line));
    std::istringstream parser(command_line);
    std::string command;
    parser >> command;
    std::string first;
    std::string second;
    std::string extra;
    parser >> first >> second >> extra;

    if (command == "INFO" && first.empty()) {
        return {MetadataJson(fixture, identity), false};
    }
    if (command == "RESET" && first.empty()) {
        fixture.Reset();
        return {MetadataJson(fixture, identity, true, "RESET"), false};
    }
    if (command == "MUTATE" && !first.empty() && !second.empty() &&
        extra.empty()) {
        const auto offset = ParseUnsigned(first);
        const auto bytes = ParseHexBytes(second);
        if (!offset.has_value() || !bytes.has_value() ||
            *offset > std::numeric_limits<std::size_t>::max() ||
            !fixture.Mutate(
                static_cast<std::size_t>(*offset),
                std::span<const std::uint8_t>(*bytes))) {
            return {ErrorJson("invalid_or_out_of_bounds_mutation"), false};
        }
        return {MetadataJson(fixture, identity, true, "MUTATE"), false};
    }
    if (command == "VERIFY" && !first.empty() && !second.empty() &&
        extra.empty()) {
        const auto generation = ParseUnsigned(first);
        const auto crc = ParseUnsigned(second);
        if (!generation.has_value() || !crc.has_value() ||
            *generation > std::numeric_limits<std::uint32_t>::max() ||
            *crc > std::numeric_limits<std::uint32_t>::max()) {
            return {ErrorJson("invalid_verification_arguments"), false};
        }
        const bool matches =
            fixture.Generation() == static_cast<std::uint32_t>(*generation) &&
            fixture.CurrentCrc32() == static_cast<std::uint32_t>(*crc);
        if (!matches) {
            return {ErrorJson("verification_mismatch"), false};
        }
        return {MetadataJson(fixture, identity, true, "VERIFY"), false};
    }
    if (command == "EXIT" && first.empty()) {
        return {MetadataJson(fixture, identity, true, "EXIT"), true};
    }
    return {ErrorJson("unknown_or_malformed_command"), false};
}

class PipeSecurity {
public:
    PipeSecurity() {
        static constexpr wchar_t kSddl[] =
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
        valid_ = ::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kSddl,
            SDDL_REVISION_1,
            &descriptor_,
            nullptr) != FALSE;
        attributes_.nLength = sizeof(attributes_);
        attributes_.lpSecurityDescriptor = descriptor_;
        attributes_.bInheritHandle = FALSE;
    }

    ~PipeSecurity() {
        if (descriptor_ != nullptr) ::LocalFree(descriptor_);
    }

    [[nodiscard]] bool Valid() const noexcept { return valid_; }
    [[nodiscard]] SECURITY_ATTRIBUTES* Attributes() noexcept {
        return &attributes_;
    }

private:
    PSECURITY_DESCRIPTOR descriptor_{nullptr};
    SECURITY_ATTRIBUTES attributes_{};
    bool valid_{false};
};

bool WriteResponse(HANDLE pipe, const std::string& response) {
    const std::string line = response + "\n";
    DWORD written = 0;
    return ::WriteFile(
               pipe,
               line.data(),
               static_cast<DWORD>(line.size()),
               &written,
               nullptr) != FALSE &&
        written == line.size();
}

int RunPipeServer(FixturePage& fixture, const FixtureIdentity& identity) {
    PipeSecurity security;
    if (!security.Valid()) {
        std::cerr << "Unable to create the local named-pipe security descriptor: "
                  << ::GetLastError() << '\n';
        return 3;
    }

    std::cout << MetadataJson(fixture, identity) << std::endl;
    bool exit_requested = false;
    while (!exit_requested) {
        const std::wstring pipe_name(
            identity.pipe_name.begin(), identity.pipe_name.end());
        const HANDLE pipe = ::CreateNamedPipeW(
            pipe_name.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
                PIPE_REJECT_REMOTE_CLIENTS,
            1,
            static_cast<DWORD>(kMaxCommandBytes),
            static_cast<DWORD>(kMaxCommandBytes),
            0,
            security.Attributes());
        if (pipe == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateNamedPipeW failed: " << ::GetLastError() << '\n';
            return 4;
        }

        const bool connected = ::ConnectNamedPipe(pipe, nullptr) != FALSE ||
            ::GetLastError() == ERROR_PIPE_CONNECTED;
        if (!connected) {
            ::CloseHandle(pipe);
            continue;
        }

        std::array<char, kMaxCommandBytes + 1> input{};
        DWORD received = 0;
        const bool read = ::ReadFile(
            pipe,
            input.data(),
            static_cast<DWORD>(kMaxCommandBytes),
            &received,
            nullptr) != FALSE;
        CommandResult result;
        if (!read && ::GetLastError() == ERROR_MORE_DATA) {
            result.response = ErrorJson("request_exceeds_4096_bytes");
        } else if (!read) {
            result.response = ErrorJson("request_read_failed");
        } else {
            input[received] = '\0';
            result = ExecuteCommand(
                std::string(input.data(), received), fixture, identity);
        }
        static_cast<void>(WriteResponse(pipe, result.response));
        static_cast<void>(::FlushFileBuffers(pipe));
        static_cast<void>(::DisconnectNamedPipe(pipe));
        ::CloseHandle(pipe);
        exit_requested = result.exit_requested;
    }
    return 0;
}

int RunSelfTest() {
    FixturePage fixture;
    const auto identity = MakeIdentity();
    std::size_t checks = 0;
    const auto check = [&](bool condition) {
        ++checks;
        return condition;
    };
    if (!check(fixture.Ready()) || !identity.has_value()) return 10;
    if (!check((reinterpret_cast<std::uintptr_t>(fixture.Data()) & 0xFFFU) == 0)) {
        return 11;
    }
    if (!check(std::memcmp(
            fixture.Data() + kMagicOffset, kMagic.data(), kMagic.size()) == 0)) {
        return 12;
    }
    if (!check(std::memcmp(
            fixture.Data() + kAobOffset, kAob.data(), kAob.size()) == 0)) {
        return 13;
    }
    if (!check(fixture.BaselineCrc32() == fixture.CurrentCrc32())) return 14;
    const auto generation = fixture.Generation();
    const std::array<std::uint8_t, 1> mutation{0xA5};
    if (!check(fixture.Mutate(kFreezeOffset, mutation))) return 15;
    if (!check(fixture.BaselineCrc32() != fixture.CurrentCrc32())) return 16;
    fixture.Reset();
    if (!check(fixture.Generation() == generation + 1U)) return 17;
    if (!check(fixture.BaselineCrc32() == fixture.CurrentCrc32())) return 18;
    const auto malformed = ExecuteCommand(
        "MUTATE 4095 0011", fixture, *identity);
    if (!check(malformed.response.find("\"ok\":false") != std::string::npos)) {
        return 19;
    }
    const auto verified = ExecuteCommand(
        "VERIFY " + std::to_string(fixture.Generation()) + " " +
            Hex(fixture.CurrentCrc32(), 8),
        fixture,
        *identity);
    if (!check(verified.response.find("\"ok\":true") != std::string::npos)) {
        return 20;
    }
    std::cout << "{\"schema\":\"kdbg.process-fixture.self-test.v1\","
              << "\"success\":true,\"checks\":" << checks << "}\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--self-test") {
        return RunSelfTest();
    }
    if (argc != 1) {
        std::cerr << "Usage: kdbg_process_fixture.exe [--self-test]\n";
        return 2;
    }
    FixturePage fixture;
    if (!fixture.Ready()) {
        std::cerr << "Unable to allocate and lock the 4096-byte fixture page: "
                  << ::GetLastError() << '\n';
        return 3;
    }
    const auto identity = MakeIdentity();
    if (!identity.has_value()) {
        std::cerr << "Unable to generate the fixture nonce.\n";
        return 3;
    }
    return RunPipeServer(fixture, *identity);
}

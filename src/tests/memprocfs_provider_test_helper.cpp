#ifdef _WIN32
#include <Windows.h>
#endif

#include <array>
#include <bit>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

std::string Environment(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0) return {};
    std::string result = value == nullptr ? "" : value;
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value == nullptr ? "" : value;
#endif
}

bool ParseUnsigned(std::wstring_view text, std::uint64_t* value) {
    if (value == nullptr || text.empty()) return false;
    std::uint64_t parsed = 0;
    for (const wchar_t character : text) {
        if (character < L'0' || character > L'9') return false;
        const auto digit = static_cast<std::uint64_t>(character - L'0');
        if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) /
                10U) {
            return false;
        }
        parsed = parsed * 10U + digit;
    }
    *value = parsed;
    return true;
}

bool ParseUnsigned(std::string_view text, std::uint64_t* value) {
    if (value == nullptr || text.empty()) return false;
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), *value, 10);
    return parsed.ec == std::errc{} &&
        parsed.ptr == text.data() + text.size();
}

struct ParsedArguments {
    std::optional<std::uint64_t> pfn;
    std::optional<std::wstring> device;
    std::optional<std::wstring> vmm_path;
    std::vector<std::wstring> vmm_arguments;
};

std::optional<ParsedArguments> ParseArguments(
    const std::vector<std::wstring>& arguments) {
    ParsedArguments parsed{};
    for (std::size_t index = 1; index < arguments.size(); ++index) {
        const std::wstring_view option = arguments[index];
        if (option == L"--child-hold") {
            std::this_thread::sleep_for(std::chrono::seconds{10});
            std::exit(0);
        }
        if (index + 1U >= arguments.size()) return std::nullopt;
        const std::wstring value = arguments[++index];
        if (option == L"--pfn") {
            std::uint64_t pfn = 0;
            if (!ParseUnsigned(value, &pfn)) return std::nullopt;
            parsed.pfn = pfn;
        } else if (option == L"--vmm-arg") {
            parsed.vmm_arguments.push_back(value);
        } else if (option == L"--device") {
            parsed.device = value;
        } else if (option == L"--vmm") {
            parsed.vmm_path = value;
        } else {
            return std::nullopt;
        }
    }
    if (!parsed.pfn.has_value()) return std::nullopt;
    return parsed;
}

#ifdef _WIN32
std::optional<std::vector<std::wstring>> WideCommandLineArguments() {
    using CommandLineToArgvWFn = wchar_t**(WINAPI*)(const wchar_t*, int*);
    const HMODULE shell = LoadLibraryExW(
        L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (shell == nullptr) return std::nullopt;
    const auto address = GetProcAddress(shell, "CommandLineToArgvW");
    if (address == nullptr) {
        FreeLibrary(shell);
        return std::nullopt;
    }
    static_assert(sizeof(CommandLineToArgvWFn) == sizeof(FARPROC));
    const auto parse = std::bit_cast<CommandLineToArgvWFn>(address);
    int count = 0;
    wchar_t** raw = parse(GetCommandLineW(), &count);
    std::vector<std::wstring> result;
    if (raw != nullptr && count > 0) {
        result.reserve(static_cast<std::size_t>(count));
        for (int index = 0; index < count; ++index) {
            result.emplace_back(raw[index]);
        }
    }
    if (raw != nullptr) LocalFree(raw);
    FreeLibrary(shell);
    if (result.empty()) return std::nullopt;
    return result;
}

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int bytes = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (bytes <= 0) return {};
    std::string result(static_cast<std::size_t>(bytes), '\0');
    return WideCharToMultiByte(
               CP_UTF8,
               WC_ERR_INVALID_CHARS,
               value.data(),
               static_cast<int>(value.size()),
               result.data(),
               bytes,
               nullptr,
               nullptr) == bytes
        ? result
        : std::string{};
}
#endif

bool WriteMarker() {
    const auto marker = Environment("KDBG_MEMPROCFS_TEST_MARKER");
    if (marker.empty()) return true;
    std::ofstream file(std::filesystem::path(marker), std::ios::binary);
    file << "started\n";
    return static_cast<bool>(file);
}

void WriteSuccess(std::uint64_t pfn) {
    std::cout << "KDBG_PFN_RESULT\t1\t" << pfn << "\nEND\n";
    std::cout.flush();
}

#ifdef _WIN32
bool SpawnPipeHolder() {
    std::vector<wchar_t> executable(32768U, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (length == 0 ||
        static_cast<std::size_t>(length) >= executable.size()) {
        return false;
    }

    std::wstring command = L"\"";
    command.append(executable.data(), length);
    command += L"\" --child-hold";
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        executable.data(),
        mutable_command.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup,
        &process);
    if (!created) return false;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}
#endif

}  // namespace

int main() {
#ifdef _WIN32
    const auto arguments = WideCommandLineArguments();
    auto parsed = arguments.has_value()
        ? ParseArguments(*arguments)
        : std::optional<ParsedArguments>{};
#else
    std::optional<ParsedArguments> parsed;
#endif
    if (!parsed) {
        std::cerr << "helper argument parsing failed\n";
        return 9;
    }

    const auto mode = Environment("KDBG_MEMPROCFS_TEST_MODE");
    if (mode == "exit") {
        std::cerr << "deterministic helper exit\n";
        return 7;
    }
    if (mode == "sleep") {
        if (!WriteMarker()) return 10;
        std::this_thread::sleep_for(std::chrono::seconds{10});
        return 0;
    }
    if (mode == "flood") {
        constexpr std::size_t kOutputBytes =
            (8U * 1024U * 1024U) + 4096U;
        constexpr std::array<char, 4096> chunk{};
        for (std::size_t completed = 0; completed < kOutputBytes;
             completed += chunk.size()) {
            std::cout.write(chunk.data(), chunk.size());
        }
        std::cout.flush();
        return std::cout ? 0 : 11;
    }

    const auto expected_count_text =
        Environment("KDBG_MEMPROCFS_TEST_EXPECTED_COUNT");
    if (!expected_count_text.empty()) {
        std::uint64_t expected_count = 0;
        if (!ParseUnsigned(expected_count_text, &expected_count) ||
            parsed->vmm_arguments.size() != expected_count) {
            std::cerr << "unexpected --vmm-arg count\n";
            return 12;
        }
    }
    const auto expected_argument =
        Environment("KDBG_MEMPROCFS_TEST_EXPECTED_ARGUMENT");
    if (!expected_argument.empty()) {
        bool found = false;
        for (const auto& argument : parsed->vmm_arguments) {
#ifdef _WIN32
            if (WideToUtf8(argument) == expected_argument) {
                found = true;
                break;
            }
#endif
        }
        if (!found) {
            std::cerr << "quoted argument was not preserved\n";
            return 13;
        }
    }

    if (mode == "unicode") {
        constexpr std::wstring_view expected_device =
            L"dump-\u914D\u7F6E-\uACBD\uB85C-\U0001F642.raw";
        constexpr std::wstring_view expected_vmm =
            L"C:\\runtime-\u914D\u7F6E-\uACBD\uB85C-\U0001F642\\vmm.dll";
        constexpr std::wstring_view expected_unicode_argument =
            L"value-\u914D\u7F6E-\uACBD\uB85C-\U0001F642";
        if (!parsed->device.has_value() ||
            !parsed->vmm_path.has_value() ||
            *parsed->device != expected_device ||
            *parsed->vmm_path != expected_vmm ||
            parsed->vmm_arguments.size() != 1U ||
            parsed->vmm_arguments.front() != expected_unicode_argument) {
            std::cerr << "Unicode bridge arguments were not preserved\n";
            return 15;
        }
    }

    WriteSuccess(*parsed->pfn);
    if (mode == "descendant") {
#ifdef _WIN32
        if (!SpawnPipeHolder()) return 14;
#else
        return 14;
#endif
    }
    return 0;
}

// KDBG MemProcFS bridge.
//
// This executable is intentionally a separate process so the AGPL-licensed
// MemProcFS runtime is not linked into the main KDBG GUI process. It loads the
// official vmm.dll API at runtime and emits a small line-based protocol.

#ifdef _WIN32
#include <Windows.h>
#endif

#include <array>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

#ifdef _WIN32
using VMM_HANDLE = void*;

constexpr std::uint32_t kPfnMapVersion = 1;
constexpr std::uint32_t kPfnFlagExtended = 1;
constexpr std::uint32_t kProcessStringUserImage = 2;
constexpr std::size_t kMaxCommandArgumentBytes = 32U * 1024U;
constexpr std::size_t kMaxVmmArguments = 64U;
constexpr std::size_t kMaxProtocolNameBytes = 1024U;

enum class PfnExtendedType : std::uint32_t {
    Unknown = 0,
    Unused = 1,
    ProcessPrivate = 2,
    PageTable = 3,
    LargePage = 4,
    DriverLocked = 5,
    Shareable = 6,
    File = 7
};

#pragma pack(push, 8)
struct PfnAddressInfo {
    union {
        std::uint32_t pid;
        std::uint32_t pfn_pte[5];
    } owner{};
    std::uint64_t virtual_address;
};

struct PfnEntry {
    std::uint32_t pfn;
    std::uint32_t extended_type;
    PfnAddressInfo address_info;
    std::uint64_t pte_address;
    std::uint64_t original_pte;
    std::uint32_t u3;
    std::uint32_t alignment;
    std::uint64_t u4;
    std::uint32_t future[6];
};

struct PfnMap {
    std::uint32_t version;
    std::uint32_t reserved[5];
    std::uint32_t count;
    std::uint32_t alignment;
    PfnEntry entries[1];
};
#pragma pack(pop)

static_assert(offsetof(PfnMap, entries) == 32);
static_assert(sizeof(PfnEntry) == 96);

using InitializeFn = VMM_HANDLE(WINAPI*)(DWORD, const char*[]);
using CloseFn = void(WINAPI*)(VMM_HANDLE);
using MemFreeFn = void(WINAPI*)(void*);
using GetPfnExFn = BOOL(WINAPI*)(
    VMM_HANDLE,
    std::uint32_t[],
    std::uint32_t,
    PfnMap**,
    std::uint32_t);
using ProcessStringFn = char*(WINAPI*)(
    VMM_HANDLE,
    std::uint32_t,
    std::uint32_t);

struct Api {
    HMODULE module{nullptr};
    InitializeFn initialize{nullptr};
    CloseFn close{nullptr};
    MemFreeFn mem_free{nullptr};
    GetPfnExFn get_pfn_ex{nullptr};
    ProcessStringFn process_string{nullptr};

    ~Api() {
        if (module != nullptr) FreeLibrary(module);
    }
};

struct VmmHandleGuard {
    Api* api{nullptr};
    VMM_HANDLE handle{nullptr};

    ~VmmHandleGuard() {
        if (api != nullptr && api->close != nullptr && handle != nullptr) {
            api->close(handle);
        }
    }
};

struct VmmAllocationGuard {
    Api* api{nullptr};
    void* pointer{nullptr};

    ~VmmAllocationGuard() {
        if (api != nullptr && api->mem_free != nullptr && pointer != nullptr) {
            api->mem_free(pointer);
        }
    }
};

std::wstring ExecutableDirectory() {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(
        nullptr,
        buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return {};
    return std::filesystem::path(
        std::wstring(buffer.data(), length)).parent_path().wstring();
}

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (size <= 0) return {};
    std::string output(static_cast<std::size_t>(size), '\0');
    const int converted = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        output.data(),
        size,
        nullptr,
        nullptr);
    return converted == size ? output : std::string{};
}

std::optional<std::vector<std::wstring>> ParseWindowsCommandLine() {
    using CommandLineToArgvWFn = wchar_t**(WINAPI*)(const wchar_t*, int*);
    const HMODULE shell = LoadLibraryExW(
        L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (shell == nullptr) return std::nullopt;
    const FARPROC address = GetProcAddress(shell, "CommandLineToArgvW");
    if (address == nullptr) {
        FreeLibrary(shell);
        return std::nullopt;
    }
    static_assert(sizeof(CommandLineToArgvWFn) == sizeof(FARPROC));
    const auto parse = std::bit_cast<CommandLineToArgvWFn>(address);
    int count = 0;
    wchar_t** raw = parse(GetCommandLineW(), &count);
    std::vector<std::wstring> arguments;
    if (raw != nullptr && count > 0) {
        arguments.reserve(static_cast<std::size_t>(count));
        for (int index = 0; index < count; ++index) {
            arguments.emplace_back(raw[index]);
        }
    }
    if (raw != nullptr) LocalFree(raw);
    FreeLibrary(shell);
    if (arguments.empty()) return std::nullopt;
    return arguments;
}

std::string BaseName(std::string path) {
    const auto slash = path.find_last_of("/\\");
    if (slash != std::string::npos) path.erase(0, slash + 1);
    return path;
}

std::string ProtocolText(std::string value) {
    if (value.size() > kMaxProtocolNameBytes) {
        value.resize(kMaxProtocolNameBytes);
    }
    for (auto& character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 0x20U || byte == 0x7FU) {
            character = '?';
        }
    }
    return value;
}

const char* ExtendedTypeName(std::uint32_t type) {
    switch (static_cast<PfnExtendedType>(type)) {
    case PfnExtendedType::Unused: return "unused";
    case PfnExtendedType::ProcessPrivate: return "process-private";
    case PfnExtendedType::PageTable: return "page-table";
    case PfnExtendedType::LargePage: return "large-page";
    case PfnExtendedType::DriverLocked: return "driver-locked";
    case PfnExtendedType::Shareable: return "shareable";
    case PfnExtendedType::File: return "file-backed";
    case PfnExtendedType::Unknown: return "unknown";
    }
    return "unknown";
}

bool LoadApi(
    const std::filesystem::path& explicit_path,
    Api* api,
    std::string* error) {
    if (api == nullptr || error == nullptr) return false;
    std::filesystem::path path = explicit_path;
    if (path.empty()) {
        const auto directory = ExecutableDirectory();
        if (directory.empty()) {
            *error = "Unable to resolve the bridge directory for vmm.dll";
            return false;
        }
        path = std::filesystem::path(directory) / L"vmm.dll";
    }

    std::error_code path_error;
    path = std::filesystem::absolute(path, path_error);
    if (path_error) {
        *error = "Unable to resolve the configured vmm.dll path (error " +
            std::to_string(path_error.value()) + ")";
        return false;
    }
    const auto status = std::filesystem::status(path, path_error);
    if (path_error || !std::filesystem::is_regular_file(status)) {
        *error = "Configured vmm.dll is unavailable or is not a regular file";
        return false;
    }

    // Resolve the explicitly selected DLL itself and its side-by-side
    // dependencies from that DLL's directory, with only System32 as the
    // additional fallback. Do not search the current directory or PATH.
    api->module = LoadLibraryExW(
        path.c_str(),
        nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (api->module == nullptr) {
        *error = "Unable to safely load configured vmm.dll or a side-by-side/System32 dependency "
            "(Win32 error " +
            std::to_string(GetLastError()) + ")";
        return false;
    }

    auto load_export = [api, error]<typename Function>(
                           const char* name,
                           Function* target) {
        static_assert(sizeof(Function) == sizeof(FARPROC));
        const FARPROC address = GetProcAddress(api->module, name);
        if (address == nullptr) {
            *error = std::string("vmm.dll is missing required API export: ") +
                name;
            return false;
        }
        *target = std::bit_cast<Function>(address);
        return true;
    };
    return load_export("VMMDLL_Initialize", &api->initialize) &&
           load_export("VMMDLL_Close", &api->close) &&
           load_export("VMMDLL_MemFree", &api->mem_free) &&
           load_export("VMMDLL_Map_GetPfnEx", &api->get_pfn_ex) &&
           load_export(
               "VMMDLL_ProcessGetInformationString",
               &api->process_string);
}
#endif

#ifdef _WIN32
struct Options {
    std::optional<std::uint32_t> pfn;
    std::wstring device;
    std::filesystem::path vmm_path;
    std::vector<std::wstring> vmm_arguments;
};

bool ParseUnsigned(std::wstring_view text, std::uint64_t* value) {
    if (value == nullptr || text.empty()) return false;
    std::uint32_t base = 10;
    if (text.size() > 2U && text[0] == L'0' &&
        (text[1] == L'x' || text[1] == L'X')) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return false;

    std::uint64_t parsed = 0;
    for (const wchar_t character : text) {
        std::uint32_t digit = 0;
        if (character >= L'0' && character <= L'9') {
            digit = static_cast<std::uint32_t>(character - L'0');
        } else if (base == 16U && character >= L'a' && character <= L'f') {
            digit = static_cast<std::uint32_t>(character - L'a') + 10U;
        } else if (base == 16U && character >= L'A' && character <= L'F') {
            digit = static_cast<std::uint32_t>(character - L'A') + 10U;
        } else {
            return false;
        }
        if (digit >= base ||
            parsed > (std::numeric_limits<std::uint64_t>::max() - digit) /
                base) {
            return false;
        }
        parsed = parsed * base + digit;
    }
    *value = parsed;
    return true;
}

[[nodiscard]] bool AsciiEqualInsensitive(
    std::wstring_view left,
    std::wstring_view right) noexcept {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        wchar_t lhs = left[index];
        wchar_t rhs = right[index];
        if (lhs >= L'A' && lhs <= L'Z') lhs += L'a' - L'A';
        if (rhs >= L'A' && rhs <= L'Z') rhs += L'a' - L'A';
        if (lhs != rhs) return false;
    }
    return true;
}

[[nodiscard]] bool IsProviderControlledVmmArgument(
    std::wstring_view argument) noexcept {
    return AsciiEqualInsensitive(argument, L"-device") ||
        AsciiEqualInsensitive(argument, L"--device") ||
        AsciiEqualInsensitive(argument, L"-waitinitialize") ||
        AsciiEqualInsensitive(argument, L"--waitinitialize") ||
        AsciiEqualInsensitive(argument, L"-disable-python") ||
        AsciiEqualInsensitive(argument, L"--disable-python");
}

std::wstring ConfiguredDevice() {
    wchar_t* configured = nullptr;
    std::size_t length = 0;
    if (_wdupenv_s(&configured, &length, L"KDBG_MEMPROCFS_DEVICE") != 0) {
        return {};
    }
    std::wstring value = configured == nullptr ? L"" : configured;
    std::free(configured);
    return value;
}

std::optional<Options> ParseOptions(
    const std::vector<std::wstring>& arguments,
    std::string* error) {
    Options options{};
    options.device = ConfiguredDevice();
    if (options.device.empty()) options.device = L"pmem";
    bool saw_device = false;
    bool saw_vmm = false;

    for (std::size_t index = 1; index < arguments.size(); ++index) {
        const std::wstring_view argument = arguments[index];
        const auto encoded_argument = WideToUtf8(argument);
        if ((!argument.empty() && encoded_argument.empty()) ||
            encoded_argument.size() > kMaxCommandArgumentBytes) {
            *error = "Command-line argument exceeds the product cap";
            return std::nullopt;
        }
        auto need_value = [&](const char* name) -> const std::wstring* {
            if (index + 1U >= arguments.size()) {
                *error = std::string(name) + " requires a value";
                return nullptr;
            }
            return &arguments[++index];
        };
        if (argument == L"--pfn") {
            if (options.pfn.has_value()) {
                *error = "--pfn may be specified only once";
                return std::nullopt;
            }
            const std::wstring* value = need_value("--pfn");
            if (value == nullptr) return std::nullopt;
            if (value->size() > 32U) {
                *error = "--pfn is too long";
                return std::nullopt;
            }
            std::uint64_t parsed = 0;
            if (!ParseUnsigned(*value, &parsed) ||
                parsed > std::numeric_limits<std::uint32_t>::max()) {
                *error = "--pfn is invalid or exceeds 32 bits";
                return std::nullopt;
            }
            options.pfn = static_cast<std::uint32_t>(parsed);
        } else if (argument == L"--device") {
            if (saw_device) {
                *error = "--device may be specified only once";
                return std::nullopt;
            }
            const std::wstring* value = need_value("--device");
            if (value == nullptr) return std::nullopt;
            const std::wstring_view device = *value;
            const auto encoded = WideToUtf8(device);
            if (device.empty() || device.front() == L'-' ||
                encoded.empty() || encoded.size() > kMaxCommandArgumentBytes) {
                *error = "--device is empty, option-like, or too long";
                return std::nullopt;
            }
            options.device = device;
            saw_device = true;
        } else if (argument == L"--vmm") {
            if (saw_vmm) {
                *error = "--vmm may be specified only once";
                return std::nullopt;
            }
            const std::wstring* value = need_value("--vmm");
            if (value == nullptr) return std::nullopt;
            const std::wstring_view path = *value;
            const auto encoded = WideToUtf8(path);
            if (path.empty() || encoded.empty() ||
                encoded.size() > kMaxCommandArgumentBytes) {
                *error = "--vmm is empty or too long";
                return std::nullopt;
            }
            options.vmm_path = std::filesystem::path(path);
            saw_vmm = true;
        } else if (argument == L"--vmm-arg") {
            const std::wstring* value = need_value("--vmm-arg");
            if (value == nullptr) return std::nullopt;
            const std::wstring_view vmm_argument = *value;
            const auto encoded = WideToUtf8(vmm_argument);
            if (options.vmm_arguments.size() >= kMaxVmmArguments ||
                (!vmm_argument.empty() && encoded.empty()) ||
                encoded.size() > kMaxCommandArgumentBytes) {
                *error = "Too many or oversized --vmm-arg values";
                return std::nullopt;
            }
            if (IsProviderControlledVmmArgument(vmm_argument)) {
                *error = "--vmm-arg must not override provider-controlled options";
                return std::nullopt;
            }
            options.vmm_arguments.emplace_back(vmm_argument);
        } else if (argument == L"--help" || argument == L"-h") {
            std::wcout
                << L"Usage: memprocfs_bridge --pfn <number> "
                   L"[--device pmem|dump.raw] [--vmm path] "
                   L"[--vmm-arg value]\n";
            std::exit(0);
        } else {
            *error = "Unknown argument: " + ProtocolText(encoded_argument);
            return std::nullopt;
        }
    }
    if (!options.pfn.has_value()) {
        *error = "--pfn is required";
        return std::nullopt;
    }
    const auto encoded_device = WideToUtf8(options.device);
    if (options.device.empty() || options.device.front() == L'-' ||
        encoded_device.empty() ||
        encoded_device.size() > kMaxCommandArgumentBytes) {
        *error = "Configured MemProcFS device is empty or too long";
        return std::nullopt;
    }
    return options;
}
#endif

int Fail(std::string message) {
    std::cerr << message << '\n';
    return 2;
}

}  // namespace

#ifdef _WIN32
int main() {
    std::string error;
    const auto arguments = ParseWindowsCommandLine();
    if (!arguments.has_value()) {
        return Fail("Windows command line could not be decoded as UTF-16 argv");
    }
    auto options = ParseOptions(*arguments, &error);
    if (!options) return Fail(error);

    Api api{};
    if (!LoadApi(options->vmm_path, &api, &error)) {
        return Fail(error);
    }
    if (api.initialize == nullptr || api.get_pfn_ex == nullptr) {
        return Fail("vmm.dll API initialization was incomplete");
    }
    const InitializeFn initialize = api.initialize;
    const GetPfnExFn get_pfn_ex = api.get_pfn_ex;

    const auto encoded_device = WideToUtf8(options->device);
    if (encoded_device.empty()) {
        return Fail("Configured MemProcFS device is not valid Unicode");
    }
    std::vector<std::string> argument_storage{
        "kdbg-memprocfs-bridge",
        "-device",
        encoded_device,
        "-waitinitialize",
        "-disable-python"};
    argument_storage.reserve(
        argument_storage.size() + options->vmm_arguments.size());
    for (const auto& argument : options->vmm_arguments) {
        const auto encoded = WideToUtf8(argument);
        if (!argument.empty() && encoded.empty()) {
            return Fail("MemProcFS additional argument is not valid Unicode");
        }
        argument_storage.push_back(encoded);
    }
    std::vector<const char*> argument_pointers;
    argument_pointers.reserve(argument_storage.size());
    for (const auto& argument : argument_storage) {
        argument_pointers.push_back(argument.c_str());
    }

    SetLastError(ERROR_SUCCESS);
    VMM_HANDLE handle = initialize(
        static_cast<DWORD>(argument_pointers.size()),
        argument_pointers.data());
    const DWORD initialize_error = GetLastError();
    if (handle == nullptr) {
        std::string diagnostic =
            "stage=VMMDLL_Initialize device=\"" +
            ProtocolText(encoded_device) + "\" failed";
        if (initialize_error != ERROR_SUCCESS) {
            diagnostic += " (Win32 error " +
                std::to_string(initialize_error) + ")";
        }
        if (options->device == L"pmem") {
            diagnostic +=
                "; pmem acquisition is not ready: verify elevated execution, "
                "the compatible LeechCore runtime, and its acquisition driver";
        } else {
            diagnostic +=
                "; verify that the acquisition device is readable and matches "
                "the installed MemProcFS runtime";
        }
        return Fail(std::move(diagnostic));
    }
    VmmHandleGuard handle_guard{&api, handle};

    std::uint32_t requested = *options->pfn;
    PfnMap* map = nullptr;
    SetLastError(ERROR_SUCCESS);
    const BOOL queried = get_pfn_ex(
        handle,
        &requested,
        1,
        &map,
        kPfnFlagExtended);
    const DWORD query_error = GetLastError();
    VmmAllocationGuard map_guard{&api, map};
    if (!queried || map == nullptr) {
        std::string diagnostic = "stage=VMMDLL_Map_GetPfnEx failed";
        if (query_error != ERROR_SUCCESS) {
            diagnostic += " (Win32 error " +
                std::to_string(query_error) + ")";
        }
        return Fail(std::move(diagnostic));
    }
    if (map->version != kPfnMapVersion || map->count != 1U) {
        return Fail(
            "MemProcFS returned an incompatible PFN map (version=" +
            std::to_string(map->version) + ", count=" +
            std::to_string(map->count) + ")");
    }

    std::cout << "KDBG_PFN_RESULT\t1\t" << requested << '\n';
    bool found_requested = false;
    for (std::uint32_t index = 0; index < map->count; ++index) {
        const auto& entry = map->entries[index];
        if (entry.pfn != requested) continue;
        found_requested = true;
        const bool address_has_pid =
            entry.extended_type != static_cast<std::uint32_t>(PfnExtendedType::PageTable) &&
            entry.extended_type != static_cast<std::uint32_t>(PfnExtendedType::Unused);
        const std::uint32_t pid = address_has_pid
            ? entry.address_info.owner.pid
            : 0U;
        const std::uint64_t va = address_has_pid
            ? entry.address_info.virtual_address
            : 0ULL;
        std::string process_name;
        if (pid != 0) {
            char* name = api.process_string(
                handle,
                pid,
                kProcessStringUserImage);
            if (name != nullptr) {
                VmmAllocationGuard name_guard{&api, name};
                process_name = ProtocolText(BaseName(name));
            }
        }
        const bool shared =
            entry.extended_type == static_cast<std::uint32_t>(PfnExtendedType::Shareable) ||
            entry.extended_type == static_cast<std::uint32_t>(PfnExtendedType::File);
        const bool writable = (entry.original_pte & (1ULL << 1U)) != 0;
        const bool user_accessible = (entry.original_pte & (1ULL << 2U)) != 0;
        const bool no_execute = (entry.original_pte & (1ULL << 63U)) != 0;
        const int confidence = pid != 0 && va != 0 ? 3 : pid != 0 ? 2 : 1;
        std::cout
            << "MAP\t" << pid
            << '\t' << va
            << '\t' << entry.pte_address
            << '\t' << 0x1000
            << '\t' << confidence
            << '\t' << (shared ? 1 : 0)
            << '\t' << (writable ? 1 : 0)
            << '\t' << (user_accessible ? 1 : 0)
            << '\t' << (no_execute ? 1 : 0)
            << '\t'
            << std::quoted(ExtendedTypeName(entry.extended_type))
            << '\t' << std::quoted(process_name)
            << '\n';
    }
    if (!found_requested) {
        return Fail("MemProcFS PFN map did not contain the requested PFN");
    }
    std::cout << "END\n";
    if (!std::cout) {
        return Fail("Failed while writing the bridge protocol response");
    }
    return 0;
}
#else
int main() {
    return Fail("MemProcFS bridge is currently supported only on Windows");
}
#endif

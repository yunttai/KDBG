// KDBG MemProcFS bridge.
//
// This executable is intentionally a separate process so the AGPL-licensed
// MemProcFS runtime is not linked into the main KDBG GUI process. It loads the
// official vmm.dll API at runtime and emits a small line-based protocol.

#ifdef _WIN32
#include <Windows.h>
#endif

#include <array>
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

std::wstring Utf8ToWide(std::string_view value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    if (size <= 0) return {};
    std::wstring output(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        output.data(),
        size);
    return output;
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

bool LoadApi(const std::wstring& explicit_path, Api* api, std::string* error) {
    if (api == nullptr || error == nullptr) return false;
    std::wstring path = explicit_path;
    if (path.empty()) {
        const auto directory = ExecutableDirectory();
        if (!directory.empty()) {
            path = (std::filesystem::path(directory) / L"vmm.dll").wstring();
        }
    }
    api->module = LoadLibraryW(path.empty() ? L"vmm.dll" : path.c_str());
    if (api->module == nullptr) {
        *error = "Unable to load vmm.dll (Win32 error " +
            std::to_string(GetLastError()) + ")";
        return false;
    }
    api->initialize = reinterpret_cast<InitializeFn>(
        GetProcAddress(api->module, "VMMDLL_Initialize"));
    api->close = reinterpret_cast<CloseFn>(
        GetProcAddress(api->module, "VMMDLL_Close"));
    api->mem_free = reinterpret_cast<MemFreeFn>(
        GetProcAddress(api->module, "VMMDLL_MemFree"));
    api->get_pfn_ex = reinterpret_cast<GetPfnExFn>(
        GetProcAddress(api->module, "VMMDLL_Map_GetPfnEx"));
    api->process_string = reinterpret_cast<ProcessStringFn>(
        GetProcAddress(api->module, "VMMDLL_ProcessGetInformationString"));
    if (api->initialize == nullptr || api->close == nullptr ||
        api->mem_free == nullptr || api->get_pfn_ex == nullptr ||
        api->process_string == nullptr) {
        *error = "vmm.dll is missing one or more required API exports";
        return false;
    }
    return true;
}
#endif

struct Options {
    std::optional<std::uint32_t> pfn;
    std::string device;
    std::wstring vmm_path;
    std::vector<std::string> vmm_arguments;
};

bool ParseUnsigned(std::string_view text, std::uint64_t* value) {
    if (value == nullptr || text.empty()) return false;
    try {
        std::size_t consumed = 0;
        const auto parsed = std::stoull(std::string(text), &consumed, 0);
        if (consumed != text.size()) return false;
        *value = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

std::string ConfiguredDevice() {
#ifdef _WIN32
    char* configured = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&configured, &length, "KDBG_MEMPROCFS_DEVICE") != 0) {
        return {};
    }
    std::string value = configured == nullptr ? "" : configured;
    std::free(configured);
    return value;
#else
    const char* configured = std::getenv("KDBG_MEMPROCFS_DEVICE");
    return configured == nullptr ? "" : configured;
#endif
}

std::optional<Options> ParseOptions(int argc, char** argv, std::string* error) {
    Options options{};
    options.device = ConfiguredDevice();
    if (options.device.empty()) options.device = "pmem";

    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument.size() > kMaxCommandArgumentBytes) {
            *error = "Command-line argument exceeds the product cap";
            return std::nullopt;
        }
        auto need_value = [&](const char* name) -> const char* {
            if (index + 1 >= argc) {
                *error = std::string(name) + " requires a value";
                return nullptr;
            }
            return argv[++index];
        };
        if (argument == "--pfn") {
            const char* value = need_value("--pfn");
            if (value == nullptr) return std::nullopt;
            if (std::string_view(value).size() > 32U) {
                *error = "--pfn is too long";
                return std::nullopt;
            }
            std::uint64_t parsed = 0;
            if (!ParseUnsigned(value, &parsed) ||
                parsed > std::numeric_limits<std::uint32_t>::max()) {
                *error = "--pfn is invalid or exceeds 32 bits";
                return std::nullopt;
            }
            options.pfn = static_cast<std::uint32_t>(parsed);
        } else if (argument == "--device") {
            const char* value = need_value("--device");
            if (value == nullptr) return std::nullopt;
            if (*value == '\0' ||
                std::string_view(value).size() > kMaxCommandArgumentBytes) {
                *error = "--device is empty or too long";
                return std::nullopt;
            }
            options.device = value;
        } else if (argument == "--vmm") {
            const char* value = need_value("--vmm");
            if (value == nullptr) return std::nullopt;
#ifdef _WIN32
            if (*value == '\0' ||
                std::string_view(value).size() > kMaxCommandArgumentBytes) {
                *error = "--vmm is empty or too long";
                return std::nullopt;
            }
            options.vmm_path = Utf8ToWide(value);
            if (options.vmm_path.empty()) {
                *error = "--vmm is not valid UTF-8";
                return std::nullopt;
            }
#else
            (void)value;
#endif
        } else if (argument == "--vmm-arg") {
            const char* value = need_value("--vmm-arg");
            if (value == nullptr) return std::nullopt;
            if (options.vmm_arguments.size() >= kMaxVmmArguments ||
                std::string_view(value).size() > kMaxCommandArgumentBytes) {
                *error = "Too many or oversized --vmm-arg values";
                return std::nullopt;
            }
            options.vmm_arguments.emplace_back(value);
        } else if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: memprocfs_bridge --pfn <number> "
                   "[--device pmem|dump.raw] [--vmm path] "
                   "[--vmm-arg value]\n";
            std::exit(0);
        } else {
            *error = "Unknown argument: " + argument;
            return std::nullopt;
        }
    }
    if (!options.pfn.has_value()) {
        *error = "--pfn is required";
        return std::nullopt;
    }
    if (options.device.empty() ||
        options.device.size() > kMaxCommandArgumentBytes) {
        *error = "Configured MemProcFS device is empty or too long";
        return std::nullopt;
    }
    return options;
}

int Fail(std::string message) {
    std::cerr << message << '\n';
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string error;
    auto options = ParseOptions(argc, argv, &error);
    if (!options) return Fail(error);

#ifndef _WIN32
    return Fail("MemProcFS bridge is currently supported only on Windows");
#else
    Api api{};
    if (!LoadApi(options->vmm_path, &api, &error)) {
        return Fail(error);
    }
    if (api.initialize == nullptr || api.get_pfn_ex == nullptr) {
        return Fail("vmm.dll API initialization was incomplete");
    }
    const InitializeFn initialize = api.initialize;
    const GetPfnExFn get_pfn_ex = api.get_pfn_ex;

    std::vector<std::string> argument_storage{
        "kdbg-memprocfs-bridge",
        "-device",
        options->device,
        "-waitinitialize",
        "-disable-python"
    };
    argument_storage.insert(
        argument_storage.end(),
        options->vmm_arguments.begin(),
        options->vmm_arguments.end());
    std::vector<const char*> argument_pointers;
    argument_pointers.reserve(argument_storage.size());
    for (const auto& argument : argument_storage) {
        argument_pointers.push_back(argument.c_str());
    }

    VMM_HANDLE handle = initialize(
        static_cast<DWORD>(argument_pointers.size()),
        argument_pointers.data());
    if (handle == nullptr) {
        return Fail("VMMDLL_Initialize failed for device: " + options->device);
    }
    VmmHandleGuard handle_guard{&api, handle};

    std::uint32_t requested = *options->pfn;
    PfnMap* map = nullptr;
    const BOOL queried = get_pfn_ex(
        handle,
        &requested,
        1,
        &map,
        kPfnFlagExtended);
    VmmAllocationGuard map_guard{&api, map};
    if (!queried || map == nullptr) {
        return Fail("VMMDLL_Map_GetPfnEx failed");
    }
    if (map->version != kPfnMapVersion || map->count != 1U) {
        return Fail("MemProcFS returned an incompatible PFN map");
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
#endif
}

#include "core/kernel/KernelModule.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <sstream>
#include <type_traits>

#ifdef _WIN32
#include <Windows.h>
#include <Psapi.h>
#endif

namespace kdbg {
namespace {

#ifdef _WIN32
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

class ScopedDebugPrivilege {
public:
    ScopedDebugPrivilege() noexcept {
        if (OpenProcessToken(
                GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &token_) == FALSE) {
            native_error_ = GetLastError();
            return;
        }
        LUID luid{};
        if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid) == FALSE) {
            native_error_ = GetLastError();
            return;
        }
        TOKEN_PRIVILEGES requested{};
        requested.PrivilegeCount = 1;
        requested.Privileges[0].Luid = luid;
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD previous_bytes = sizeof(previous_);
        SetLastError(ERROR_SUCCESS);
        if (AdjustTokenPrivileges(
                token_, FALSE, &requested, sizeof(previous_), &previous_,
                &previous_bytes) == FALSE) {
            native_error_ = GetLastError();
            return;
        }
        native_error_ = GetLastError();
        if (native_error_ == ERROR_SUCCESS) {
            adjusted_ = true;
            enabled_ = true;
        }
    }

    ~ScopedDebugPrivilege() {
        if (adjusted_ && token_ != nullptr) {
            static_cast<void>(AdjustTokenPrivileges(
                token_, FALSE, &previous_, 0, nullptr, nullptr));
        }
        if (token_ != nullptr) CloseHandle(token_);
    }

    ScopedDebugPrivilege(const ScopedDebugPrivilege&) = delete;
    ScopedDebugPrivilege& operator=(const ScopedDebugPrivilege&) = delete;

    [[nodiscard]] bool Enabled() const noexcept { return enabled_; }
    [[nodiscard]] DWORD NativeError() const noexcept { return native_error_; }

private:
    HANDLE token_{nullptr};
    TOKEN_PRIVILEGES previous_{};
    DWORD native_error_{ERROR_SUCCESS};
    bool adjusted_{false};
    bool enabled_{false};
};

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string output(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), output.data(), required,
            nullptr, nullptr) != required) {
        return {};
    }
    return output;
}

std::filesystem::path ResolveKernelImagePath(std::wstring_view raw) {
    constexpr std::wstring_view system_root = L"\\SystemRoot\\";
    constexpr std::wstring_view object_prefix = L"\\??\\";
    if (raw.starts_with(system_root)) {
        std::array<wchar_t, MAX_PATH> windows{};
        const UINT length = GetWindowsDirectoryW(
            windows.data(), static_cast<UINT>(windows.size()));
        if (length != 0 && length < windows.size()) {
            return std::filesystem::path(
                std::wstring_view(windows.data(), length)) /
                std::filesystem::path(raw.substr(system_root.size()));
        }
    }
    if (raw.starts_with(object_prefix)) {
        return std::filesystem::path(raw.substr(object_prefix.size()));
    }
    if (raw.size() >= 3U && raw[1] == L':' &&
        (raw[2] == L'\\' || raw[2] == L'/')) {
        return std::filesystem::path(raw);
    }

    constexpr std::wstring_view device_prefix = L"\\Device\\";
    if (raw.starts_with(device_prefix)) {
        std::array<wchar_t, 1024> mapping{};
        for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
            const std::array<wchar_t, 3> name{drive, L':', L'\0'};
            const DWORD length = QueryDosDeviceW(
                name.data(), mapping.data(),
                static_cast<DWORD>(mapping.size()));
            if (length == 0) continue;
            const std::wstring_view mapped(mapping.data());
            if (raw.starts_with(mapped) &&
                (raw.size() == mapped.size() || raw[mapped.size()] == L'\\')) {
                std::wstring resolved{name.data()};
                resolved.append(raw.substr(mapped.size()));
                return std::filesystem::path(std::move(resolved));
            }
        }
    }
    return std::filesystem::path(raw);
}

Result<PeImageMetadata> ReadImageMetadata(
    const std::filesystem::path& path) {
    constexpr std::size_t kInitialHeaderBytes = 4096U;
    constexpr std::size_t kMaximumHeaderBytes = 1024U * 1024U;
    constexpr std::size_t kDosPeOffset = 0x3CU;
    constexpr std::size_t kMaximumBoundedPeHeaders = 4096U;
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Local kernel image could not be opened",
            "EnumerateKernelModules.ReadImageMetadata"));
    }
    std::vector<std::uint8_t> bytes(kInitialHeaderBytes);
    stream.read(
        reinterpret_cast<char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    const auto completed = stream.gcount();
    if (completed <= 0) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Local kernel image header could not be read",
            "EnumerateKernelModules.ReadImageMetadata"));
    }
    bytes.resize(static_cast<std::size_t>(completed));
    auto parsed = ParsePe64ImageMetadata(bytes);
    if (parsed) return parsed;

    std::uint16_t dos_magic = 0;
    std::uint32_t pe_offset = 0;
    if (!ReadLittleEndian(bytes, 0, dos_magic) || dos_magic != 0x5A4DU ||
        !ReadLittleEndian(bytes, kDosPeOffset, pe_offset)) {
        return parsed;
    }
    constexpr std::size_t kPeAndCoffBytes = 4U + 20U;
    if (pe_offset > kMaximumHeaderBytes - kPeAndCoffBytes ||
        static_cast<std::size_t>(pe_offset) + kPeAndCoffBytes >
            kMaximumHeaderBytes - kMaximumBoundedPeHeaders) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Local PE header offset exceeds the bounded metadata read",
            "EnumerateKernelModules.ReadImageMetadata",
            0,
            kMaximumHeaderBytes,
            pe_offset));
    }
    const std::size_t required = static_cast<std::size_t>(pe_offset) +
        kPeAndCoffBytes + kMaximumBoundedPeHeaders;
    if (required <= bytes.size()) return parsed;

    bytes.resize(required);
    stream.clear();
    stream.seekg(0, std::ios::beg);
    stream.read(
        reinterpret_cast<char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    const auto second_completed = stream.gcount();
    if (second_completed <= 0) {
        return Result<PeImageMetadata>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Local kernel image header could not be read",
            "EnumerateKernelModules.ReadImageMetadata"));
    }
    bytes.resize(static_cast<std::size_t>(second_completed));
    return ParsePe64ImageMetadata(bytes);
}
#endif

}  // namespace

Result<KernelModuleSnapshot> EnumerateKernelModules(
    const KernelModuleEnumerationControl& control) {
#ifdef _WIN32
    if (control.completed != nullptr) control.completed->store(0);
    if (control.total != nullptr) control.total->store(0);

    // Windows 11 24H2 can return a correctly-sized list whose bases are all
    // NULL unless SeDebugPrivilege is enabled. Enable it only for this scoped
    // enumeration and restore the caller's previous token state afterwards.
    ScopedDebugPrivilege debug_privilege;

    DWORD required_bytes = 0;
    if (EnumDeviceDrivers(nullptr, 0, &required_bytes) == FALSE) {
        return Result<KernelModuleSnapshot>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Windows could not size the loaded-kernel-module list",
            "EnumerateKernelModules.EnumDeviceDrivers",
            GetLastError()));
    }
    if (required_bytes == 0 || required_bytes % sizeof(LPVOID) != 0) {
        return Result<KernelModuleSnapshot>::Failure(MakeError(
            ErrorCode::InternalInvariant,
            "Windows returned an invalid loaded-kernel-module list size",
            "EnumerateKernelModules.EnumDeviceDrivers",
            0,
            sizeof(LPVOID),
            required_bytes));
    }
    const auto requested_count =
        static_cast<std::size_t>(required_bytes) / sizeof(LPVOID);
    if (requested_count > kMaximumKernelModules) {
        return Result<KernelModuleSnapshot>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Loaded-kernel-module count exceeds the bounded catalog limit",
            "EnumerateKernelModules",
            0,
            kMaximumKernelModules,
            requested_count));
    }

    std::vector<LPVOID> addresses(requested_count);
    DWORD returned_bytes = 0;
    if (EnumDeviceDrivers(
            addresses.data(), required_bytes, &returned_bytes) == FALSE) {
        return Result<KernelModuleSnapshot>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Windows could not enumerate loaded kernel modules",
            "EnumerateKernelModules.EnumDeviceDrivers",
            GetLastError()));
    }
    if (returned_bytes > required_bytes || returned_bytes % sizeof(LPVOID) != 0) {
        return Result<KernelModuleSnapshot>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Loaded-kernel-module list changed during enumeration; refresh again",
            "EnumerateKernelModules.EnumDeviceDrivers",
            0,
            required_bytes,
            returned_bytes));
    }
    addresses.resize(static_cast<std::size_t>(returned_bytes) / sizeof(LPVOID));
    const bool all_bases_hidden = !addresses.empty() && std::all_of(
        addresses.begin(), addresses.end(),
        [](const LPVOID address) { return address == nullptr; });
    if (all_bases_hidden) {
        const std::string reason = debug_privilege.Enabled()
            ? "Windows returned only NULL kernel module bases even after temporarily enabling SeDebugPrivilege"
            : "Windows returned only NULL kernel module bases and SeDebugPrivilege could not be enabled";
        return Result<KernelModuleSnapshot>::Failure(MakeError(
            ErrorCode::AccessDenied,
            reason,
            "EnumerateKernelModules.EnumDeviceDrivers.Privilege",
            debug_privilege.NativeError(),
            addresses.size(),
            0));
    }
    if (control.total != nullptr) control.total->store(addresses.size());

    KernelModuleSnapshot snapshot;
    snapshot.modules.reserve(addresses.size());
    for (std::size_t index = 0; index < addresses.size(); ++index) {
        if (control.cancel_requested != nullptr &&
            control.cancel_requested->load(std::memory_order_relaxed)) {
            return Result<KernelModuleSnapshot>::Failure(MakeError(
                ErrorCode::Cancelled,
                "Kernel module enumeration was cancelled",
                "EnumerateKernelModules"));
        }
        const auto address = reinterpret_cast<std::uintptr_t>(addresses[index]);
        if (address == 0 ||
            !IsCanonicalX64KernelAddress(address, control.la57)) {
            snapshot.diagnostics.push_back(
                "Windows returned a zero or non-canonical kernel module base");
            if (control.completed != nullptr) control.completed->store(index + 1U);
            continue;
        }

        std::vector<wchar_t> path_buffer(32768, L'\0');
        const DWORD path_length = GetDeviceDriverFileNameW(
            addresses[index], path_buffer.data(),
            static_cast<DWORD>(path_buffer.size()));
        std::array<wchar_t, 512> name_buffer{};
        const DWORD name_length = GetDeviceDriverBaseNameW(
            addresses[index], name_buffer.data(),
            static_cast<DWORD>(name_buffer.size()));

        KernelModule module;
        module.base = static_cast<std::uint64_t>(address);
        if (name_length != 0 && name_length < name_buffer.size()) {
            module.name = WideToUtf8(
                std::wstring_view(name_buffer.data(), name_length));
        }
        if (path_length != 0 && path_length < path_buffer.size()) {
            module.image_path = ResolveKernelImagePath(
                std::wstring_view(path_buffer.data(), path_length));
        }
        if (module.name.empty() && !module.image_path.empty()) {
            module.name = WideToUtf8(module.image_path.filename().native());
        }
        if (module.name.empty()) module.name = "<unnamed>";

        if (module.image_path.empty()) {
            module.metadata_status =
                "Windows did not expose an image path; size/PE metadata unavailable";
        } else {
            const auto metadata = ReadImageMetadata(module.image_path);
            if (metadata) {
                module.image_size = metadata.Value().image_size;
                module.timestamp = metadata.Value().timestamp;
                module.checksum = metadata.Value().checksum;
                module.metadata_status = "local PE32+ metadata verified";
            } else {
                module.metadata_status = metadata.GetError().message;
            }
        }
        snapshot.modules.push_back(std::move(module));
        if (control.completed != nullptr) control.completed->store(index + 1U);
    }
    std::sort(snapshot.modules.begin(), snapshot.modules.end(),
        [](const KernelModule& left, const KernelModule& right) {
            return left.base < right.base;
        });
    if (snapshot.modules.empty()) {
        return Result<KernelModuleSnapshot>::Failure(MakeError(
            ErrorCode::AccessDenied,
            "No canonical kernel module bases were exposed; Administrator/SeDebugPrivilege may be required",
            "EnumerateKernelModules"));
    }
    return Result<KernelModuleSnapshot>::Success(std::move(snapshot));
#else
    (void)control;
    return Result<KernelModuleSnapshot>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Kernel module enumeration is available only on Windows",
        "EnumerateKernelModules"));
#endif
}

}  // namespace kdbg

#include "LiveVerify.h"

#include "core/memory/KDbgBackend.h"
#include "core/memory/ProbeClient.h"
#include "shared/KDbgIoctl.h"
#include "shared/KDbgProbeIoctl.h"

#include <Windows.h>
#include <bcrypt.h>
#include <winsvc.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdio>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

std::atomic_bool g_cancelled{false};

class UniqueHandle {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueHandle() { Reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            Reset();
            handle_ = std::exchange(other.handle_, INVALID_HANDLE_VALUE);
        }
        return *this;
    }

    [[nodiscard]] HANDLE Get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

private:
    void Reset() noexcept {
        if (*this) CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }

    HANDLE handle_{INVALID_HANDLE_VALUE};
};

class UniqueServiceHandle {
public:
    UniqueServiceHandle() noexcept = default;
    explicit UniqueServiceHandle(SC_HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueServiceHandle() {
        if (handle_ != nullptr) CloseServiceHandle(handle_);
    }

    UniqueServiceHandle(const UniqueServiceHandle&) = delete;
    UniqueServiceHandle& operator=(const UniqueServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE Get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr;
    }

private:
    SC_HANDLE handle_{nullptr};
};

class UniqueAlgorithmHandle {
public:
    explicit UniqueAlgorithmHandle(BCRYPT_ALG_HANDLE handle) noexcept
        : handle_(handle) {}
    ~UniqueAlgorithmHandle() {
        if (handle_ != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(handle_, 0));
        }
    }

    UniqueAlgorithmHandle(const UniqueAlgorithmHandle&) = delete;
    UniqueAlgorithmHandle& operator=(const UniqueAlgorithmHandle&) = delete;

    [[nodiscard]] BCRYPT_ALG_HANDLE Get() const noexcept { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_{nullptr};
};

class UniqueHashHandle {
public:
    explicit UniqueHashHandle(BCRYPT_HASH_HANDLE handle) noexcept
        : handle_(handle) {}
    ~UniqueHashHandle() {
        if (handle_ != nullptr) {
            static_cast<void>(BCryptDestroyHash(handle_));
        }
    }

    UniqueHashHandle(const UniqueHashHandle&) = delete;
    UniqueHashHandle& operator=(const UniqueHashHandle&) = delete;

    [[nodiscard]] BCRYPT_HASH_HANDLE Get() const noexcept { return handle_; }

private:
    BCRYPT_HASH_HANDLE handle_{nullptr};
};

kdbg::Error Win32Error(
    std::string message,
    std::string operation,
    DWORD code = GetLastError()) {
    return kdbg::MakeError(
        kdbg::ErrorCode::IoFailure,
        std::move(message),
        std::move(operation),
        code);
}

kdbg::Error CngError(
    std::string message,
    std::string operation,
    NTSTATUS status) {
    return kdbg::MakeError(
        kdbg::ErrorCode::IoFailure,
        std::move(message),
        std::move(operation),
        static_cast<std::uint32_t>(status));
}

kdbg::Result<std::string> WideToUtf8(
    std::wstring_view value,
    std::string_view operation) {
    if (value.empty()) {
        return kdbg::Result<std::string>::Failure(kdbg::MakeError(
            kdbg::ErrorCode::InvalidArgument,
            "A required Windows path is empty",
            std::string(operation)));
    }
    if (value.size() > static_cast<std::size_t>(
            std::numeric_limits<int>::max())) {
        return kdbg::Result<std::string>::Failure(kdbg::MakeError(
            kdbg::ErrorCode::LimitReached,
            "A Windows path exceeds the UTF-8 conversion limit",
            std::string(operation)));
    }
    const int input_size = static_cast<int>(value.size());
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), input_size,
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return kdbg::Result<std::string>::Failure(Win32Error(
            "Unable to size a UTF-8 path conversion",
            std::string(operation)));
    }
    std::string converted(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), input_size,
        converted.data(), required, nullptr, nullptr);
    if (written != required) {
        return kdbg::Result<std::string>::Failure(Win32Error(
            "Unable to convert a Windows path to UTF-8",
            std::string(operation)));
    }
    return kdbg::Result<std::string>::Success(std::move(converted));
}

std::filesystem::path Utf8Path(std::string_view value) {
    std::u8string converted;
    converted.reserve(value.size());
    for (const char byte : value) {
        converted.push_back(static_cast<char8_t>(
            static_cast<unsigned char>(byte)));
    }
    return std::filesystem::path(converted);
}

kdbg::Result<std::string> DefaultEvidencePath() {
    std::wstring local_app_data(32768U, L'\0');
    const DWORD length = GetEnvironmentVariableW(
        L"LOCALAPPDATA", local_app_data.data(),
        static_cast<DWORD>(local_app_data.size()));
    if (length == 0 || length >= local_app_data.size()) {
        return kdbg::Result<std::string>::Failure(kdbg::MakeError(
            kdbg::ErrorCode::NotFound,
            "Unable to resolve LOCALAPPDATA for the default evidence path",
            "live_verify::default_evidence_path",
            GetLastError()));
    }
    local_app_data.resize(length);
    const std::wstring filename = L"kdbg-live-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64()) + L".json";
    const auto target = std::filesystem::path(local_app_data) /
        L"KDBG" / L"evidence" / filename;
    return WideToUtf8(
        target.native(), "live_verify::default_evidence_path");
}

kdbg::Result<std::wstring> CanonicalPathForHandle(
    HANDLE handle,
    std::string_view operation) {
    constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    const DWORD required = GetFinalPathNameByHandleW(
        handle, nullptr, 0, flags);
    if (required == 0 || required > 32767U) {
        return kdbg::Result<std::wstring>::Failure(Win32Error(
            "Unable to size the canonical file path",
            std::string(operation)));
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(required) + 1U);
    const DWORD written = GetFinalPathNameByHandleW(
        handle, buffer.data(), static_cast<DWORD>(buffer.size()), flags);
    if (written == 0 || written >= buffer.size()) {
        return kdbg::Result<std::wstring>::Failure(Win32Error(
            "Unable to capture the canonical file path",
            std::string(operation)));
    }
    return kdbg::Result<std::wstring>::Success(
        std::wstring(buffer.data(), written));
}

kdbg::Result<std::string> Sha256ForHandle(
    HANDLE file,
    std::string_view operation) {
    BCRYPT_ALG_HANDLE raw_algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &raw_algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        return kdbg::Result<std::string>::Failure(CngError(
            "Unable to open the Windows SHA-256 provider",
            std::string(operation), status));
    }
    UniqueAlgorithmHandle algorithm(raw_algorithm);

    DWORD object_length = 0;
    DWORD result_length = 0;
    status = BCryptGetProperty(
        algorithm.Get(), BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length),
        &result_length, 0);
    if (status < 0 || result_length != sizeof(object_length) ||
        object_length == 0) {
        return kdbg::Result<std::string>::Failure(CngError(
            "Unable to query the Windows SHA-256 object length",
            std::string(operation), status));
    }

    DWORD hash_length = 0;
    result_length = 0;
    status = BCryptGetProperty(
        algorithm.Get(), BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length),
        &result_length, 0);
    if (status < 0 || result_length != sizeof(hash_length) ||
        hash_length != 32U) {
        return kdbg::Result<std::string>::Failure(CngError(
            "Windows did not provide a 32-byte SHA-256 digest",
            std::string(operation), status));
    }

    std::vector<UCHAR> hash_object(object_length);
    BCRYPT_HASH_HANDLE raw_hash = nullptr;
    status = BCryptCreateHash(
        algorithm.Get(), &raw_hash, hash_object.data(), object_length,
        nullptr, 0, 0);
    if (status < 0) {
        return kdbg::Result<std::string>::Failure(CngError(
            "Unable to create a Windows SHA-256 hash",
            std::string(operation), status));
    }
    UniqueHashHandle hash(raw_hash);

    LARGE_INTEGER beginning{};
    if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN)) {
        return kdbg::Result<std::string>::Failure(Win32Error(
            "Unable to seek to the beginning of an identity file",
            std::string(operation)));
    }
    std::vector<UCHAR> buffer(64U * 1024U);
    while (true) {
        DWORD read = 0;
        if (!ReadFile(
                file, buffer.data(), static_cast<DWORD>(buffer.size()),
                &read, nullptr)) {
            return kdbg::Result<std::string>::Failure(Win32Error(
                "Unable to read an identity file for SHA-256",
                std::string(operation)));
        }
        if (read == 0) break;
        status = BCryptHashData(hash.Get(), buffer.data(), read, 0);
        if (status < 0) {
            return kdbg::Result<std::string>::Failure(CngError(
                "Unable to update a Windows SHA-256 hash",
                std::string(operation), status));
        }
    }

    std::array<UCHAR, 32> digest{};
    status = BCryptFinishHash(
        hash.Get(), digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (status < 0) {
        return kdbg::Result<std::string>::Failure(CngError(
            "Unable to finish a Windows SHA-256 hash",
            std::string(operation), status));
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string hexadecimal(digest.size() * 2U, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        hexadecimal[index * 2U] = digits[digest[index] >> 4U];
        hexadecimal[index * 2U + 1U] = digits[digest[index] & 0x0FU];
    }
    return kdbg::Result<std::string>::Success(std::move(hexadecimal));
}

kdbg::Result<std::string> Sha256ForBytes(
    std::span<const std::uint8_t> bytes,
    std::string_view operation) {
    BCRYPT_ALG_HANDLE raw_algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &raw_algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        return kdbg::Result<std::string>::Failure(CngError(
            "Unable to open the Windows SHA-256 provider",
            std::string(operation), status));
    }
    UniqueAlgorithmHandle algorithm(raw_algorithm);
    std::array<UCHAR, 32> digest{};
    status = BCryptHash(
        algorithm.Get(), nullptr, 0,
        const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    if (status < 0) {
        return kdbg::Result<std::string>::Failure(CngError(
            "Unable to hash the machine binding material",
            std::string(operation), status));
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string hexadecimal(digest.size() * 2U, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        hexadecimal[index * 2U] = digits[digest[index] >> 4U];
        hexadecimal[index * 2U + 1U] = digits[digest[index] & 0x0FU];
    }
    return kdbg::Result<std::string>::Success(std::move(hexadecimal));
}

struct CapturedFileIdentity {
    std::wstring canonical_path;
    std::string sha256;
};

kdbg::Result<CapturedFileIdentity> CaptureFileIdentity(
    std::wstring_view path,
    std::string_view operation) {
    const std::wstring owned_path(path);
    UniqueHandle file(CreateFileW(
        owned_path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file) {
        return kdbg::Result<CapturedFileIdentity>::Failure(
            Win32Error(
                "Unable to open a runtime identity file",
                std::string(operation)));
    }
    const auto canonical = CanonicalPathForHandle(file.Get(), operation);
    if (!canonical) {
        return kdbg::Result<CapturedFileIdentity>::Failure(
            canonical.GetError());
    }
    const auto sha256 = Sha256ForHandle(file.Get(), operation);
    if (!sha256) {
        return kdbg::Result<CapturedFileIdentity>::Failure(
            sha256.GetError());
    }
    return kdbg::Result<CapturedFileIdentity>::Success({
        canonical.Value(), sha256.Value()});
}

bool PathsEqual(std::wstring_view left, std::wstring_view right) {
    if (left.size() > static_cast<std::size_t>(
            std::numeric_limits<int>::max()) ||
        right.size() > static_cast<std::size_t>(
            std::numeric_limits<int>::max())) {
        return false;
    }
    return CompareStringOrdinal(
        left.data(), static_cast<int>(left.size()),
        right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

std::wstring ComparableAbsolutePath(const std::filesystem::path& path) {
    std::error_code error;
    auto absolute = std::filesystem::absolute(path, error).lexically_normal();
    if (error) return {};
    std::wstring value = absolute.native();
    constexpr std::wstring_view extended_unc = L"\\\\?\\UNC\\";
    constexpr std::wstring_view extended = L"\\\\?\\";
    if (std::wstring_view(value).starts_with(extended_unc)) {
        value = L"\\\\" + value.substr(extended_unc.size());
    } else if (std::wstring_view(value).starts_with(extended)) {
        value.erase(0, extended.size());
    }
    while (value.size() > 3U &&
           (value.back() == L'\\' || value.back() == L'/')) {
        value.pop_back();
    }
    return value;
}

bool IsPathWithin(
    const std::filesystem::path& root,
    const std::filesystem::path& candidate) {
    const std::wstring root_value = ComparableAbsolutePath(root);
    const std::wstring candidate_value = ComparableAbsolutePath(candidate);
    if (root_value.empty() || candidate_value.size() <= root_value.size() ||
        !PathsEqual(
            std::wstring_view(candidate_value).substr(0, root_value.size()),
            root_value)) {
        return false;
    }
    const wchar_t boundary = candidate_value[root_value.size()];
    return boundary == L'\\' || boundary == L'/';
}

kdbg::Result<std::wstring> CurrentExecutablePath() {
    std::vector<wchar_t> path(32768U);
    DWORD length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(
            GetCurrentProcess(), 0, path.data(), &length) || length == 0) {
        return kdbg::Result<std::wstring>::Failure(Win32Error(
            "Unable to query the running verifier path",
            "live_verify::attest_verifier"));
    }
    return kdbg::Result<std::wstring>::Success(
        std::wstring(path.data(), length));
}

std::wstring_view Trim(std::wstring_view value) {
    const auto is_space = [](wchar_t character) {
        return character == L' ' || character == L'\t' ||
            character == L'\r' || character == L'\n';
    };
    while (!value.empty() && is_space(value.front())) value.remove_prefix(1);
    while (!value.empty() && is_space(value.back())) value.remove_suffix(1);
    return value;
}

kdbg::Result<std::wstring> ResolveServiceBinaryPath(
    std::wstring_view configured,
    std::string_view operation) {
    configured = Trim(configured);
    if (configured.empty()) {
        return kdbg::Result<std::wstring>::Failure(kdbg::MakeError(
            kdbg::ErrorCode::NotFound,
            "The service has no configured binary path",
            std::string(operation)));
    }
    std::wstring parsed;
    if (configured.front() == L'\"') {
        const std::size_t closing = configured.find(L'\"', 1U);
        if (closing == std::wstring_view::npos ||
            !Trim(configured.substr(closing + 1U)).empty()) {
            return kdbg::Result<std::wstring>::Failure(kdbg::MakeError(
                kdbg::ErrorCode::ParseError,
                "The driver service binary path has invalid quoting or arguments",
                std::string(operation)));
        }
        parsed.assign(configured.substr(1U, closing - 1U));
    } else {
        parsed.assign(configured);
    }
    if (parsed.empty()) {
        return kdbg::Result<std::wstring>::Failure(kdbg::MakeError(
            kdbg::ErrorCode::ParseError,
            "The driver service binary path is empty",
            std::string(operation)));
    }

    const DWORD expanded_size = ExpandEnvironmentStringsW(
        parsed.c_str(), nullptr, 0);
    if (expanded_size == 0 || expanded_size > 32768U) {
        return kdbg::Result<std::wstring>::Failure(Win32Error(
            "Unable to size the expanded driver service path",
            std::string(operation)));
    }
    std::vector<wchar_t> expanded(expanded_size);
    const DWORD expanded_written = ExpandEnvironmentStringsW(
        parsed.c_str(), expanded.data(), expanded_size);
    if (expanded_written == 0 || expanded_written > expanded_size) {
        return kdbg::Result<std::wstring>::Failure(Win32Error(
            "Unable to expand the driver service path",
            std::string(operation)));
    }
    parsed.assign(expanded.data());

    if (parsed.starts_with(L"\\??\\")) {
        parsed.erase(0, 4U);
    }
    constexpr std::wstring_view system_root_prefix = L"\\SystemRoot\\";
    constexpr std::wstring_view relative_system_root_prefix = L"SystemRoot\\";
    std::wstring_view suffix;
    if (std::wstring_view(parsed).starts_with(system_root_prefix)) {
        suffix = std::wstring_view(parsed).substr(system_root_prefix.size());
    } else if (std::wstring_view(parsed).starts_with(
                   relative_system_root_prefix)) {
        suffix = std::wstring_view(parsed).substr(
            relative_system_root_prefix.size());
    }
    if (!suffix.empty()) {
        std::array<wchar_t, MAX_PATH + 1U> windows_directory{};
        const UINT windows_length = GetWindowsDirectoryW(
            windows_directory.data(), static_cast<UINT>(windows_directory.size()));
        if (windows_length == 0 || windows_length >= windows_directory.size()) {
            return kdbg::Result<std::wstring>::Failure(Win32Error(
                "Unable to query the Windows directory",
                std::string(operation)));
        }
        parsed.assign(windows_directory.data(), windows_length);
        parsed.push_back(L'\\');
        parsed.append(suffix);
    }
    return kdbg::Result<std::wstring>::Success(std::move(parsed));
}

std::optional<kdbg::Error> CaptureServiceIdentity(
    SC_HANDLE manager,
    const wchar_t* service_name,
    const std::filesystem::path& expected_path,
    std::string package_relative_path,
    kdbg::live_verify::ServiceIdentityRecord& record) {
    const auto name = WideToUtf8(
        service_name, "live_verify::attest_service_name");
    record.name = name ? name.Value() : std::string{};
    UniqueServiceHandle service(OpenServiceW(
        manager, service_name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
    if (!service) {
        return Win32Error(
            "Unable to open a required driver service for attestation",
            "live_verify::attest_service_open");
    }

    DWORD config_size = 0;
    SetLastError(ERROR_SUCCESS);
    const BOOL sized_config = QueryServiceConfigW(
        service.Get(), nullptr, 0, &config_size);
    const DWORD config_size_error = GetLastError();
    if (sized_config != FALSE ||
        config_size_error != ERROR_INSUFFICIENT_BUFFER || config_size == 0 ||
        config_size > 1024U * 1024U) {
        return Win32Error(
            "Unable to size the driver service configuration",
            "live_verify::attest_service_config");
    }
    std::vector<std::byte> config_buffer(config_size);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(
        config_buffer.data());
    if (!QueryServiceConfigW(
            service.Get(), config, config_size, &config_size) ||
        config->lpBinaryPathName == nullptr) {
        return Win32Error(
            "Unable to query the driver service configuration",
            "live_verify::attest_service_config");
    }
    record.service_type = config->dwServiceType;
    SERVICE_STATUS_PROCESS status{};
    DWORD status_size = 0;
    if (!QueryServiceStatusEx(
            service.Get(), SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &status_size) ||
        status_size != sizeof(status)) {
        return Win32Error(
            "Unable to query the driver service state",
            "live_verify::attest_service_status");
    }
    record.current_state = status.dwCurrentState;

    const auto resolved = ResolveServiceBinaryPath(
        config->lpBinaryPathName, "live_verify::attest_service_binary");
    if (!resolved) return resolved.GetError();
    const auto binary = CaptureFileIdentity(
        resolved.Value(), "live_verify::attest_service_binary");
    if (!binary) return binary.GetError();
    const auto expected = CaptureFileIdentity(
        expected_path.native(), "live_verify::attest_package_binary");
    if (!expected) return expected.GetError();
    if (!PathsEqual(
            binary.Value().canonical_path,
            expected.Value().canonical_path) ||
        binary.Value().sha256 != expected.Value().sha256) {
        return kdbg::MakeError(
            kdbg::ErrorCode::AccessDenied,
            "A driver service does not match its required package path and hash",
            "live_verify::attest_service_binary");
    }
    record.binary.package_relative_path = std::move(package_relative_path);
    record.binary.sha256 = binary.Value().sha256;
    record.running_kernel_driver =
        record.service_type == SERVICE_KERNEL_DRIVER &&
        record.current_state == SERVICE_RUNNING;
    if (!record.running_kernel_driver) {
        return kdbg::MakeError(
            kdbg::ErrorCode::AccessDenied,
            "A required service is not a running kernel driver",
            "live_verify::attest_service_status");
    }
    return std::nullopt;
}

struct RuntimeIdentityCapture {
    kdbg::live_verify::RuntimeIdentityRecord record;
    std::optional<std::filesystem::path> package_root;
    std::optional<kdbg::Error> error;
};

RuntimeIdentityCapture CaptureRuntimeIdentity() {
    RuntimeIdentityCapture capture{};
    capture.record.kdbg_service.name = "KDBG";
    capture.record.probe_service.name = "KDBGProbe";
    const auto remember_error = [&](const kdbg::Error& error) {
        if (!capture.error) capture.error = error;
    };

    const auto executable = CurrentExecutablePath();
    std::optional<std::filesystem::path> package_root;
    if (!executable) {
        remember_error(executable.GetError());
    } else {
        const auto verifier = CaptureFileIdentity(
            executable.Value(), "live_verify::attest_verifier");
        if (verifier) {
            const std::filesystem::path verifier_path(
                verifier.Value().canonical_path);
            const auto tools_directory = verifier_path.parent_path();
            if (!PathsEqual(verifier_path.filename().native(),
                            L"kdbg_live_verify.exe") ||
                !PathsEqual(tools_directory.filename().native(), L"tools") ||
                tools_directory.parent_path().empty()) {
                remember_error(kdbg::MakeError(
                    kdbg::ErrorCode::AccessDenied,
                    "The verifier is not running from tools/kdbg_live_verify.exe",
                    "live_verify::attest_verifier"));
            } else {
                package_root = tools_directory.parent_path();
                capture.package_root = package_root;
                capture.record.verifier.package_relative_path =
                    "tools/kdbg_live_verify.exe";
                capture.record.verifier.sha256 = verifier.Value().sha256;
            }
        } else {
            remember_error(verifier.GetError());
        }
    }

    UniqueServiceHandle manager(OpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager) {
        remember_error(Win32Error(
            "Unable to open the Service Control Manager for attestation",
            "live_verify::attest_scm"));
    } else if (package_root) {
        const auto kdbg_error = CaptureServiceIdentity(
            manager.Get(), KDBG_SERVICE_NAME,
            *package_root / L"drivers" / L"KDbgDriver.sys",
            "drivers/KDbgDriver.sys", capture.record.kdbg_service);
        if (kdbg_error) remember_error(*kdbg_error);
        const auto probe_error = CaptureServiceIdentity(
            manager.Get(), KDBG_PROBE_SERVICE_NAME,
            *package_root / L"drivers" / L"KDbgProbe.sys",
            "drivers/KDbgProbe.sys",
            capture.record.probe_service);
        if (probe_error) remember_error(*probe_error);
    }
    capture.record.verified = !capture.error &&
        capture.record.kdbg_service.running_kernel_driver &&
        capture.record.probe_service.running_kernel_driver;
    return capture;
}

BOOL WINAPI ConsoleHandler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT ||
        event == CTRL_CLOSE_EVENT || event == CTRL_LOGOFF_EVENT ||
        event == CTRL_SHUTDOWN_EVENT) {
        g_cancelled.store(true);
        return TRUE;
    }
    return FALSE;
}

std::string UtcNow() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    char buffer[64]{};
    const int written = std::snprintf(
        buffer, sizeof(buffer),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
        time.wSecond, time.wMilliseconds);
    return written > 0 ? std::string(buffer) : std::string{};
}

kdbg::live_verify::SystemRecord QuerySystem(std::string build_id) {
    kdbg::live_verify::SystemRecord record{};
    record.generated_utc = UtcNow();
    record.os_name = "Windows";
    record.architecture = "unknown";
    record.build_id = std::move(build_id);

    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll != nullptr) {
        const FARPROC procedure = GetProcAddress(ntdll, "RtlGetVersion");
        static_assert(sizeof(RtlGetVersionFn) == sizeof(procedure));
        const auto rtl_get_version = procedure == nullptr
            ? nullptr
            : std::bit_cast<RtlGetVersionFn>(procedure);
        if (rtl_get_version != nullptr) {
            RTL_OSVERSIONINFOW version{};
            version.dwOSVersionInfoSize = sizeof(version);
            if (rtl_get_version(&version) == 0) {
                record.os_major = version.dwMajorVersion;
                record.os_minor = version.dwMinorVersion;
                record.os_build = version.dwBuildNumber;
            }
        }
    }
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    if (system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        record.architecture = "x64";
    } else if (system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        record.architecture = "arm64";
    } else if (system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        record.architecture = "x86";
    }
    return record;
}

bool WriteEvidence(
    const std::string& path,
    const kdbg::live_verify::VerificationReport& report) {
    const std::filesystem::path target = Utf8Path(path);
    if (target.empty() || target.filename().empty()) return false;
    std::error_code ec;
    if (!target.parent_path().empty()) {
        std::filesystem::create_directories(target.parent_path(), ec);
        if (ec) return false;
    }
    auto temporary = target;
    temporary += L".tmp-" + std::to_wstring(GetCurrentProcessId());
    std::filesystem::remove(temporary, ec);
    ec.clear();
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    const std::string json = kdbg::live_verify::ToJson(report);
    output.write(json.data(), static_cast<std::streamsize>(json.size()));
    output.put('\n');
    output.flush();
    output.close();
    if (!output || !MoveFileExW(
            temporary.c_str(),
            target.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(temporary, ec);
        return false;
    }
    return true;
}

std::optional<kdbg::Error> WriteBaremetalArtifacts(
    const std::string& directory,
    kdbg::live_verify::VerificationReport& report) {
    const std::filesystem::path root = Utf8Path(directory);
    if (root.empty()) {
        return kdbg::MakeError(
            kdbg::ErrorCode::InvalidArgument,
            "Bare-metal artifact directory is empty",
            "live_verify::write_raw_pages");
    }
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    if (ec) {
        return kdbg::MakeError(
            kdbg::ErrorCode::IoFailure,
            "Unable to create the bare-metal artifact directory",
            "live_verify::write_raw_pages",
            static_cast<std::uint32_t>(ec.value()));
    }
    const DWORD root_attributes = GetFileAttributesW(root.c_str());
    if (root_attributes == INVALID_FILE_ATTRIBUTES ||
        (root_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (root_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return kdbg::MakeError(
            kdbg::ErrorCode::AccessDenied,
            "Bare-metal artifact directory must be a non-reparse directory",
            "live_verify::write_raw_pages");
    }

    for (auto& artifact : report.raw_page_artifacts) {
        const auto digest = Sha256ForBytes(
            std::span<const std::uint8_t>(
                artifact.bytes.data(), artifact.bytes.size()),
            "live_verify::write_raw_pages");
        if (!digest) return digest.GetError();
        const auto target = root / Utf8Path(artifact.file_name);
        const DWORD existing = GetFileAttributesW(target.c_str());
        if (existing != INVALID_FILE_ATTRIBUTES &&
            ((existing & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
             (existing & FILE_ATTRIBUTE_REPARSE_POINT) != 0)) {
            return kdbg::MakeError(
                kdbg::ErrorCode::AccessDenied,
                "A raw-page artifact target is not a regular file",
                "live_verify::write_raw_pages");
        }
        auto temporary = target;
        temporary += L".tmp-" + std::to_wstring(GetCurrentProcessId());
        std::filesystem::remove(temporary, ec);
        ec.clear();
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) {
            return kdbg::MakeError(
                kdbg::ErrorCode::IoFailure,
                "Unable to create a raw-page artifact",
                "live_verify::write_raw_pages");
        }
        output.write(
            reinterpret_cast<const char*>(artifact.bytes.data()),
            static_cast<std::streamsize>(artifact.bytes.size()));
        output.flush();
        output.close();
        if (!output || !MoveFileExW(
                temporary.c_str(), target.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            std::filesystem::remove(temporary, ec);
            return Win32Error(
                "Unable to publish a raw-page artifact",
                "live_verify::write_raw_pages");
        }
        const auto published = CaptureFileIdentity(
            target.native(), "live_verify::verify_raw_page");
        const auto published_size = std::filesystem::file_size(target, ec);
        if (!published || ec || published_size != artifact.bytes.size() ||
            published.Value().sha256 != digest.Value()) {
            return published
                ? kdbg::MakeError(
                    kdbg::ErrorCode::VerificationMismatch,
                    "Published raw-page artifact did not match its 4 KiB source",
                    "live_verify::verify_raw_page",
                    0, artifact.bytes.size(),
                    ec ? 0U : published_size)
                : published.GetError();
        }
        artifact.sha256 = published.Value().sha256;
        artifact.written = true;
    }
    if (report.raw_page_artifacts.size() != 6U ||
        std::any_of(
            report.raw_page_artifacts.begin(),
            report.raw_page_artifacts.end(),
            [](const kdbg::live_verify::RawPageArtifactRecord& artifact) {
                return !artifact.written || artifact.sha256.size() != 64U;
            })) {
        return kdbg::MakeError(
            kdbg::ErrorCode::VerificationMismatch,
            "Bare-metal evidence did not produce all six raw 4 KiB pages",
            "live_verify::write_raw_pages",
            0, 6, report.raw_page_artifacts.size());
    }
    return std::nullopt;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string_view> arguments;
    arguments.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0U);
    for (int index = 1; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }
    const auto parsed = kdbg::live_verify::ParseOptions(arguments);
    if (!parsed) {
        std::cerr << parsed.GetError().message << '\n'
                  << kdbg::live_verify::Usage();
        return 2;
    }
    auto options = parsed.Value();
    if (options.help) {
        std::cout << kdbg::live_verify::Usage();
        return 0;
    }
    if (options.output_path.empty()) {
        const auto default_output = DefaultEvidencePath();
        if (!default_output) {
            std::cerr << default_output.GetError().message << '\n';
            return 2;
        }
        options.output_path = default_output.Value();
    }

    auto system = QuerySystem(options.build_id);
    SetConsoleCtrlHandler(&ConsoleHandler, TRUE);

    RuntimeIdentityCapture identity_capture{};
    try {
        identity_capture = CaptureRuntimeIdentity();
    } catch (const std::exception& exception) {
        identity_capture.error = kdbg::MakeError(
            kdbg::ErrorCode::InternalInvariant,
            std::string("Runtime identity attestation failed: ") +
                exception.what(),
            "live_verify::attest_runtime");
    } catch (...) {
        identity_capture.error = kdbg::MakeError(
            kdbg::ErrorCode::InternalInvariant,
            "Runtime identity attestation failed with a non-standard exception",
            "live_verify::attest_runtime");
    }
    const bool needs_local_artifacts =
        options.baremetal_evidence || options.raw_pfn_evidence;
    if (identity_capture.package_root.has_value() &&
        (IsPathWithin(
             *identity_capture.package_root,
             Utf8Path(options.output_path)) ||
         (needs_local_artifacts && IsPathWithin(
             *identity_capture.package_root,
             Utf8Path(options.artifact_directory))))) {
        std::cerr <<
            "Evidence output and raw pages must be outside the validated package directory\n";
        SetConsoleCtrlHandler(&ConsoleHandler, FALSE);
        return 2;
    }
    if (!kdbg::live_verify::IsSupportedSystem(system)) {
        const auto report = kdbg::live_verify::FailureReport(
            options, std::move(system), std::move(identity_capture.record),
            kdbg::MakeError(
                kdbg::ErrorCode::Unsupported,
                "KDBG live verification requires Windows x64 build 19041 or newer",
                "live_verify::system_contract"));
        SetConsoleCtrlHandler(&ConsoleHandler, FALSE);
        if (!WriteEvidence(options.output_path, report)) return 3;
        return 1;
    }
    if (identity_capture.error) {
        const auto report = kdbg::live_verify::FailureReport(
            options, std::move(system), std::move(identity_capture.record),
            *identity_capture.error);
        SetConsoleCtrlHandler(&ConsoleHandler, FALSE);
        if (!WriteEvidence(options.output_path, report)) return 3;
        return 1;
    }
    const auto runtime_identity = std::move(identity_capture.record);

    kdbg::KDbgBackend backend;
    const auto opened = backend.Open();
    if (!opened) {
        auto report = kdbg::live_verify::FailureReport(
            options, std::move(system), runtime_identity, opened.GetError());
        report.backend = backend.Info();
        if (!WriteEvidence(options.output_path, report)) return 3;
        return 1;
    }

    kdbg::ProbeClient probe;
    const auto probe_opened = probe.Open();
    if (!probe_opened) {
        auto report = kdbg::live_verify::FailureReport(
            options, std::move(system), runtime_identity,
            probe_opened.GetError());
        report.backend = backend.Info();
        backend.Close();
        if (!WriteEvidence(options.output_path, report)) return 3;
        return 1;
    }

    kdbg::live_verify::VerificationReport report{};
    try {
        report = kdbg::live_verify::Run(
            backend,
            [&probe]() { return probe.Query(); },
            options,
            std::move(system),
            runtime_identity,
            []() { return g_cancelled.load(); });
    } catch (const std::exception& exception) {
        report = kdbg::live_verify::FailureReport(
            options,
            QuerySystem(options.build_id),
            runtime_identity,
            kdbg::MakeError(
                kdbg::ErrorCode::InternalInvariant,
                std::string("Unhandled verification exception: ") +
                    exception.what(),
                "kdbg_live_verify::main"));
    } catch (...) {
        report = kdbg::live_verify::FailureReport(
            options,
            QuerySystem(options.build_id),
            runtime_identity,
            kdbg::MakeError(
                kdbg::ErrorCode::InternalInvariant,
                "Unhandled non-standard verification exception",
                "kdbg_live_verify::main"));
    }
    probe.Close();
    backend.Close();
    SetConsoleCtrlHandler(&ConsoleHandler, FALSE);

    if (needs_local_artifacts) {
        const auto artifact_error = WriteBaremetalArtifacts(
            options.artifact_directory, report);
        if (artifact_error) {
            report.success = false;
            report.errors.push_back(kdbg::live_verify::ErrorRecord{
                "io_failure",
                artifact_error->operation,
                artifact_error->message,
                artifact_error->native_code,
                artifact_error->requested,
                artifact_error->completed});
        }
    }

    if (!WriteEvidence(options.output_path, report)) {
        std::cerr << "Unable to write JSON evidence: "
                  << options.output_path << '\n';
        return 3;
    }
    std::cout << "KDBG live verification "
              << (report.success ? "PASS" : "FAILED")
              << "; evidence: " << options.output_path << '\n';
    return report.success ? 0 : 1;
}

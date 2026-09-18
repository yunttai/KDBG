#include "core/windows/DriverService.h"

#ifdef _WIN32
#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <thread>
#include <utility>
#include <vector>

namespace kdbg {
namespace {

struct ScHandle {
    SC_HANDLE value{nullptr};
    ~ScHandle() { if (value != nullptr) CloseServiceHandle(value); }
};

Error ServiceError(const char* message, const char* operation) {
    return MakeError(
        ErrorCode::IoFailure,
        message,
        operation,
        GetLastError());
}

constexpr auto kServiceTimeout = std::chrono::seconds(30);

bool IsValidServiceText(const std::wstring& value) noexcept {
    return !value.empty() && value.size() <= 256 &&
        value.find(L'\0') == std::wstring::npos;
}

Result<SERVICE_STATUS_PROCESS> QueryStatus(
    SC_HANDLE service,
    const char* operation) {
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    if (!QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytes)) {
        return Result<SERVICE_STATUS_PROCESS>::Failure(
            ServiceError("QueryServiceStatusEx failed", operation));
    }
    if (bytes != sizeof(status)) {
        return Result<SERVICE_STATUS_PROCESS>::Failure(MakeError(
            ErrorCode::IoFailure,
            "QueryServiceStatusEx returned an unexpected size",
            operation,
            ERROR_INVALID_DATA,
            sizeof(status),
            bytes));
    }
    return Result<SERVICE_STATUS_PROCESS>::Success(status);
}

Result<void> WaitForState(
    SC_HANDLE service,
    DWORD desired,
    std::chrono::steady_clock::duration timeout,
    const char* operation) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto queried = QueryStatus(service, operation);
        if (!queried) {
            return Result<void>::Failure(queried.GetError());
        }
        const auto& status = queried.Value();
        if (status.dwCurrentState == desired) {
            return Result<void>::Success();
        }
        if (status.dwCurrentState == SERVICE_STOPPED &&
            desired != SERVICE_STOPPED) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Driver service stopped before reaching the requested state",
                operation,
                status.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR
                    ? status.dwServiceSpecificExitCode
                    : status.dwWin32ExitCode));
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        const DWORD wait_hint = std::clamp<DWORD>(
            status.dwWaitHint / 10,
            50,
            1000);
        std::this_thread::sleep_for(std::chrono::milliseconds(wait_hint));
    }
    return Result<void>::Failure(MakeError(
        ErrorCode::IoFailure,
        "Timed out waiting for driver service state",
        operation,
        WAIT_TIMEOUT));
}

Result<void> WaitForDeletion(
    SC_HANDLE manager,
    const std::wstring& service_name,
    const char* operation) {
    const auto deadline = std::chrono::steady_clock::now() + kServiceTimeout;
    while (std::chrono::steady_clock::now() < deadline) {
        ScHandle service{OpenServiceW(
            manager,
            service_name.c_str(),
            SERVICE_QUERY_STATUS)};
        if (service.value == nullptr) {
            const DWORD error = GetLastError();
            if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
                return Result<void>::Success();
            }
            if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
                return Result<void>::Failure(MakeError(
                    ErrorCode::IoFailure,
                    "OpenServiceW failed while waiting for deletion",
                    operation,
                    error));
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return Result<void>::Failure(MakeError(
        ErrorCode::IoFailure,
        "Timed out waiting for driver service deletion; close all service handles or reboot the lab VM",
        operation,
        WAIT_TIMEOUT));
}

Result<DriverServiceConfiguration> QueryConfigurationWithManager(
    SC_HANDLE manager,
    const std::wstring& service_name,
    const char* operation) {
    ScHandle service{OpenServiceW(
        manager,
        service_name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)};
    if (service.value == nullptr) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST ||
            error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            return Result<DriverServiceConfiguration>::Success({});
        }
        return Result<DriverServiceConfiguration>::Failure(MakeError(
            ErrorCode::IoFailure,
            "OpenServiceW failed while querying driver configuration",
            operation,
            error));
    }

    DWORD required = 0;
    static_cast<void>(QueryServiceConfigW(
        service.value,
        nullptr,
        0,
        &required));
    const DWORD sizing_error = GetLastError();
    constexpr DWORD kMaximumConfigBytes = 64U * 1024U;
    if (sizing_error != ERROR_INSUFFICIENT_BUFFER || required == 0 ||
        required > kMaximumConfigBytes) {
        return Result<DriverServiceConfiguration>::Failure(MakeError(
            ErrorCode::IoFailure,
            "QueryServiceConfigW returned an invalid configuration size",
            operation,
            sizing_error,
            kMaximumConfigBytes,
            required));
    }
    std::vector<std::uint8_t> storage(required);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
    DWORD completed = 0;
    if (!QueryServiceConfigW(
            service.value,
            config,
            required,
            &completed)) {
        return Result<DriverServiceConfiguration>::Failure(
            ServiceError("QueryServiceConfigW failed", operation));
    }
    auto status = QueryStatus(service.value, operation);
    if (!status) {
        return Result<DriverServiceConfiguration>::Failure(status.GetError());
    }
    const auto state = status.Value().dwCurrentState;
    if (state != SERVICE_STOPPED && state != SERVICE_RUNNING) {
        return Result<DriverServiceConfiguration>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Driver service is in a pending state; wait for it to settle before repair",
            operation,
            ERROR_SERVICE_CANNOT_ACCEPT_CTRL));
    }
    if (config->lpBinaryPathName == nullptr ||
        config->lpDisplayName == nullptr) {
        return Result<DriverServiceConfiguration>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Driver service configuration contains null text fields",
            operation,
            ERROR_INVALID_DATA));
    }

    DriverServiceConfiguration result{};
    result.exists = true;
    result.running = state == SERVICE_RUNNING;
    result.service_type = config->dwServiceType;
    result.start_type = config->dwStartType;
    result.error_control = config->dwErrorControl;
    result.binary_path = config->lpBinaryPathName;
    result.display_name = config->lpDisplayName;
    return Result<DriverServiceConfiguration>::Success(std::move(result));
}

}  // namespace

Result<void> DriverService::InstallOrUpdate(
    const std::wstring& service_name,
    const std::wstring& display_name,
    const std::filesystem::path& driver_path) {
    if (!IsValidServiceText(service_name) ||
        !IsValidServiceText(display_name)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid driver service name or display name",
            "DriverService::InstallOrUpdate"));
    }
    std::error_code ec;
    const auto absolute = std::filesystem::canonical(driver_path, ec);
    const auto extension = absolute.extension().native();
    if (ec || !std::filesystem::is_regular_file(absolute, ec) || ec ||
        CompareStringOrdinal(
            extension.c_str(),
            -1,
            L".sys",
            -1,
            TRUE) != CSTR_EQUAL) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Driver .sys path does not exist",
            "DriverService::InstallOrUpdate"));
    }
    const auto native_path = absolute.native();
    if (native_path.size() > 32765) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Driver path is too long for the service configuration",
            "DriverService::InstallOrUpdate"));
    }

    ScHandle manager{OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)};
    if (manager.value == nullptr) {
        return Result<void>::Failure(
            ServiceError("OpenSCManagerW failed", "InstallOrUpdate"));
    }

    ScHandle service{OpenServiceW(
        manager.value,
        service_name.c_str(),
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG |
            SERVICE_QUERY_STATUS)};
    const std::wstring quoted_path = L"\"" + native_path + L"\"";
    if (service.value == nullptr) {
        const DWORD open_error = GetLastError();
        if (open_error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            auto deleted = WaitForDeletion(
                manager.value,
                service_name,
                "DriverService::InstallOrUpdate");
            if (!deleted) {
                return deleted;
            }
        } else if (open_error != ERROR_SERVICE_DOES_NOT_EXIST) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "OpenServiceW failed",
                "DriverService::InstallOrUpdate",
                open_error));
        }
        service.value = CreateServiceW(
            manager.value,
            service_name.c_str(),
            display_name.c_str(),
            SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG |
                SERVICE_QUERY_STATUS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            quoted_path.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);
        if (service.value == nullptr) {
            return Result<void>::Failure(
                ServiceError("CreateServiceW failed", "InstallOrUpdate"));
        }
    } else if (!ChangeServiceConfigW(
                   service.value,
                   SERVICE_KERNEL_DRIVER,
                   SERVICE_DEMAND_START,
                   SERVICE_ERROR_NORMAL,
                   quoted_path.c_str(),
                   nullptr,
                   nullptr,
                   nullptr,
                   nullptr,
                   nullptr,
                   display_name.c_str())) {
        return Result<void>::Failure(
            ServiceError("ChangeServiceConfigW failed", "InstallOrUpdate"));
    }

    return Result<void>::Success();
}

Result<void> DriverService::Start(const std::wstring& service_name) {
    if (!IsValidServiceText(service_name)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid driver service name",
            "DriverService::Start"));
    }
    ScHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (manager.value == nullptr) {
        return Result<void>::Failure(
            ServiceError("OpenSCManagerW failed", "DriverService::Start"));
    }
    ScHandle service{OpenServiceW(
        manager.value,
        service_name.c_str(),
        SERVICE_START | SERVICE_QUERY_STATUS)};
    if (service.value == nullptr) {
        return Result<void>::Failure(
            ServiceError("OpenServiceW failed", "DriverService::Start"));
    }
    auto queried = QueryStatus(service.value, "DriverService::Start");
    if (!queried) {
        return Result<void>::Failure(queried.GetError());
    }
    if (queried.Value().dwCurrentState == SERVICE_RUNNING) {
        return Result<void>::Success();
    }
    if (queried.Value().dwCurrentState == SERVICE_START_PENDING) {
        return WaitForState(
            service.value,
            SERVICE_RUNNING,
            kServiceTimeout,
            "DriverService::Start");
    }
    if (queried.Value().dwCurrentState == SERVICE_STOP_PENDING) {
        auto stopped = WaitForState(
            service.value,
            SERVICE_STOPPED,
            kServiceTimeout,
            "DriverService::Start");
        if (!stopped) {
            return stopped;
        }
    } else if (queried.Value().dwCurrentState != SERVICE_STOPPED) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Driver service is not in a startable state",
            "DriverService::Start",
            ERROR_SERVICE_CANNOT_ACCEPT_CTRL));
    }
    if (!StartServiceW(service.value, 0, nullptr)) {
        const auto error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "StartServiceW failed",
                "DriverService::Start",
                error));
        }
    }
    return WaitForState(
        service.value,
        SERVICE_RUNNING,
        kServiceTimeout,
        "DriverService::Start");
}

Result<void> DriverService::Stop(const std::wstring& service_name) {
    if (!IsValidServiceText(service_name)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid driver service name",
            "DriverService::Stop"));
    }
    ScHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (manager.value == nullptr) {
        return Result<void>::Failure(
            ServiceError("OpenSCManagerW failed", "DriverService::Stop"));
    }
    ScHandle service{OpenServiceW(
        manager.value,
        service_name.c_str(),
        SERVICE_STOP | SERVICE_QUERY_STATUS)};
    if (service.value == nullptr) {
        const auto error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            return Result<void>::Success();
        }
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            return WaitForDeletion(
                manager.value,
                service_name,
                "DriverService::Stop");
        }
        return Result<void>::Failure(
            ServiceError("OpenServiceW failed", "DriverService::Stop"));
    }
    auto queried = QueryStatus(service.value, "DriverService::Stop");
    if (!queried) {
        return Result<void>::Failure(queried.GetError());
    }
    if (queried.Value().dwCurrentState == SERVICE_STOPPED) {
        return Result<void>::Success();
    }
    if (queried.Value().dwCurrentState == SERVICE_STOP_PENDING) {
        return WaitForState(
            service.value,
            SERVICE_STOPPED,
            kServiceTimeout,
            "DriverService::Stop");
    }
    if (queried.Value().dwCurrentState == SERVICE_START_PENDING) {
        auto started = WaitForState(
            service.value,
            SERVICE_RUNNING,
            kServiceTimeout,
            "DriverService::Stop");
        if (!started) {
            auto final_status = QueryStatus(
                service.value,
                "DriverService::Stop");
            if (final_status &&
                final_status.Value().dwCurrentState == SERVICE_STOPPED) {
                return Result<void>::Success();
            }
            return started;
        }
    }
    SERVICE_STATUS status{};
    if (!ControlService(service.value, SERVICE_CONTROL_STOP, &status)) {
        const auto error = GetLastError();
        if (error == ERROR_SERVICE_NOT_ACTIVE) {
            return Result<void>::Success();
        }
        if (error == ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
            auto current = QueryStatus(
                service.value,
                "DriverService::Stop");
            if (current) {
                if (current.Value().dwCurrentState == SERVICE_STOPPED) {
                    return Result<void>::Success();
                }
                if (current.Value().dwCurrentState == SERVICE_STOP_PENDING) {
                    return WaitForState(
                        service.value,
                        SERVICE_STOPPED,
                        kServiceTimeout,
                        "DriverService::Stop");
                }
            }
        }
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "ControlService(SERVICE_CONTROL_STOP) failed",
            "DriverService::Stop",
            error));
    }
    return WaitForState(
        service.value,
        SERVICE_STOPPED,
        kServiceTimeout,
        "DriverService::Stop");
}

Result<void> DriverService::Remove(const std::wstring& service_name) {
    if (!IsValidServiceText(service_name)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid driver service name",
            "DriverService::Remove"));
    }
    auto stopped = Stop(service_name);
    if (!stopped) {
        return stopped;
    }
    ScHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (manager.value == nullptr) {
        return Result<void>::Failure(
            ServiceError("OpenSCManagerW failed", "DriverService::Remove"));
    }
    ScHandle service{OpenServiceW(
        manager.value,
        service_name.c_str(),
        DELETE)};
    if (service.value == nullptr) {
        const auto error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            return Result<void>::Success();
        }
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            return WaitForDeletion(
                manager.value,
                service_name,
                "DriverService::Remove");
        }
        return Result<void>::Failure(
            ServiceError("OpenServiceW failed", "DriverService::Remove"));
    }
    if (!DeleteService(service.value)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "DeleteService failed",
                "DriverService::Remove",
                error));
        }
    }
    CloseServiceHandle(service.value);
    service.value = nullptr;
    return WaitForDeletion(
        manager.value,
        service_name,
        "DriverService::Remove");
}

Result<bool> DriverService::IsRunning(const std::wstring& service_name) {
    if (!IsValidServiceText(service_name)) {
        return Result<bool>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid driver service name",
            "DriverService::IsRunning"));
    }
    ScHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (manager.value == nullptr) {
        return Result<bool>::Failure(
            ServiceError("OpenSCManagerW failed", "DriverService::IsRunning"));
    }
    ScHandle service{OpenServiceW(
        manager.value,
        service_name.c_str(),
        SERVICE_QUERY_STATUS)};
    if (service.value == nullptr) {
        const auto error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST ||
            error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            return Result<bool>::Success(false);
        }
        return Result<bool>::Failure(
            ServiceError("OpenServiceW failed", "DriverService::IsRunning"));
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    if (!QueryServiceStatusEx(
            service.value,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytes)) {
        return Result<bool>::Failure(
            ServiceError("QueryServiceStatusEx failed", "DriverService::IsRunning"));
    }
    return Result<bool>::Success(status.dwCurrentState == SERVICE_RUNNING);
}

Result<DriverServiceConfiguration> DriverService::QueryConfiguration(
    const std::wstring& service_name) {
    if (!IsValidServiceText(service_name)) {
        return Result<DriverServiceConfiguration>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid driver service name",
            "DriverService::QueryConfiguration"));
    }
    ScHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (manager.value == nullptr) {
        return Result<DriverServiceConfiguration>::Failure(
            ServiceError(
                "OpenSCManagerW failed",
                "DriverService::QueryConfiguration"));
    }
    return QueryConfigurationWithManager(
        manager.value,
        service_name,
        "DriverService::QueryConfiguration");
}

Result<void> DriverService::RestoreConfiguration(
    const std::wstring& service_name,
    const DriverServiceConfiguration& configuration) {
    if (!IsValidServiceText(service_name)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid driver service name",
            "DriverService::RestoreConfiguration"));
    }
    if (!configuration.exists) {
        return Remove(service_name);
    }
    if (configuration.service_type != SERVICE_KERNEL_DRIVER ||
        configuration.binary_path.empty() ||
        configuration.display_name.empty()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Refusing to restore an invalid or non-kernel service configuration",
            "DriverService::RestoreConfiguration"));
    }

    auto stopped = Stop(service_name);
    if (!stopped) return stopped;

    ScHandle manager{OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)};
    if (manager.value == nullptr) {
        return Result<void>::Failure(
            ServiceError(
                "OpenSCManagerW failed",
                "DriverService::RestoreConfiguration"));
    }
    ScHandle service{OpenServiceW(
        manager.value,
        service_name.c_str(),
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG |
            SERVICE_QUERY_STATUS)};
    if (service.value == nullptr) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_DOES_NOT_EXIST) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "OpenServiceW failed while restoring driver configuration",
                "DriverService::RestoreConfiguration",
                error));
        }
        service.value = CreateServiceW(
            manager.value,
            service_name.c_str(),
            configuration.display_name.c_str(),
            SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG |
                SERVICE_QUERY_STATUS,
            configuration.service_type,
            configuration.start_type,
            configuration.error_control,
            configuration.binary_path.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);
        if (service.value == nullptr) {
            return Result<void>::Failure(ServiceError(
                "CreateServiceW failed while restoring driver configuration",
                "DriverService::RestoreConfiguration"));
        }
    } else if (!ChangeServiceConfigW(
                   service.value,
                   configuration.service_type,
                   configuration.start_type,
                   configuration.error_control,
                   configuration.binary_path.c_str(),
                   nullptr,
                   nullptr,
                   nullptr,
                   nullptr,
                   nullptr,
                   configuration.display_name.c_str())) {
        return Result<void>::Failure(ServiceError(
            "ChangeServiceConfigW failed while restoring driver configuration",
            "DriverService::RestoreConfiguration"));
    }

    if (configuration.running) {
        return Start(service_name);
    }
    return Result<void>::Success();
}

}  // namespace kdbg

#else
namespace kdbg {
Result<void> DriverService::InstallOrUpdate(const std::wstring&, const std::wstring&, const std::filesystem::path&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<void> DriverService::Start(const std::wstring&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<void> DriverService::Stop(const std::wstring&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<void> DriverService::Remove(const std::wstring&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<bool> DriverService::IsRunning(const std::wstring&) { return Result<bool>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<DriverServiceConfiguration> DriverService::QueryConfiguration(const std::wstring&) { return Result<DriverServiceConfiguration>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<void> DriverService::RestoreConfiguration(const std::wstring&, const DriverServiceConfiguration&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
} // namespace kdbg
#endif

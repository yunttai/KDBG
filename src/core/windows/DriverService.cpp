#include "core/windows/DriverService.h"

#ifdef _WIN32
#include <Windows.h>

#include <chrono>
#include <thread>

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

Result<void> WaitForState(
    SC_HANDLE service,
    DWORD desired,
    std::chrono::seconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status),
                sizeof(status),
                &bytes)) {
            return Result<void>::Failure(
                ServiceError("QueryServiceStatusEx failed", "WaitForState"));
        }
        if (status.dwCurrentState == desired) {
            return Result<void>::Success();
        }
        if (status.dwCurrentState == SERVICE_STOPPED &&
            desired != SERVICE_STOPPED) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Driver service stopped before reaching the requested state",
                "WaitForState",
                status.dwWin32ExitCode));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return Result<void>::Failure(MakeError(
        ErrorCode::IoFailure,
        "Timed out waiting for driver service state",
        "WaitForState",
        WAIT_TIMEOUT));
}

}  // namespace

Result<void> DriverService::InstallOrUpdate(
    const std::wstring& service_name,
    const std::wstring& display_name,
    const std::filesystem::path& driver_path) {
    std::error_code ec;
    const auto absolute = std::filesystem::absolute(driver_path, ec);
    const auto extension = absolute.extension().native();
    if (ec || !std::filesystem::is_regular_file(absolute) ||
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

    ScHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
    if (manager.value == nullptr) {
        return Result<void>::Failure(
            ServiceError("OpenSCManagerW failed", "InstallOrUpdate"));
    }

    ScHandle service{OpenServiceW(
        manager.value,
        service_name.c_str(),
        SERVICE_ALL_ACCESS)};
    const auto native_path = absolute.native();
    const std::wstring quoted_path = L"\"" + native_path + L"\"";
    if (service.value == nullptr) {
        if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
            return Result<void>::Failure(
                ServiceError("OpenServiceW failed", "InstallOrUpdate"));
        }
        service.value = CreateServiceW(
            manager.value,
            service_name.c_str(),
            display_name.c_str(),
            SERVICE_ALL_ACCESS,
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
    return WaitForState(service.value, SERVICE_RUNNING, std::chrono::seconds(10));
}

Result<void> DriverService::Stop(const std::wstring& service_name) {
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
        return Result<void>::Failure(
            ServiceError("OpenServiceW failed", "DriverService::Stop"));
    }
    SERVICE_STATUS status{};
    if (!ControlService(service.value, SERVICE_CONTROL_STOP, &status)) {
        const auto error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "ControlService(SERVICE_CONTROL_STOP) failed",
                "DriverService::Stop",
                error));
        }
        return Result<void>::Success();
    }
    return WaitForState(service.value, SERVICE_STOPPED, std::chrono::seconds(10));
}

Result<void> DriverService::Remove(const std::wstring& service_name) {
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
        return Result<void>::Failure(
            ServiceError("OpenServiceW failed", "DriverService::Remove"));
    }
    if (!DeleteService(service.value)) {
        return Result<void>::Failure(
            ServiceError("DeleteService failed", "DriverService::Remove"));
    }
    return Result<void>::Success();
}

Result<bool> DriverService::IsRunning(const std::wstring& service_name) {
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
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
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

}  // namespace kdbg

#else
namespace kdbg {
Result<void> DriverService::InstallOrUpdate(const std::wstring&, const std::wstring&, const std::filesystem::path&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<void> DriverService::Start(const std::wstring&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<void> DriverService::Stop(const std::wstring&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<void> DriverService::Remove(const std::wstring&) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
Result<bool> DriverService::IsRunning(const std::wstring&) { return Result<bool>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "DriverService")); }
} // namespace kdbg
#endif

#include "app/LocalDiagnostics.h"

#ifdef _WIN32

#include <Windows.h>
#include <DbgHelp.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>

namespace kdbg {
namespace {

constexpr LONGLONG kMaximumLogBytes = 1024LL * 1024LL;
constexpr std::size_t kMaximumDirectoryCharacters = 32768;

std::mutex g_log_mutex;
HANDLE g_log_file = INVALID_HANDLE_VALUE;
std::wstring g_log_path;
std::array<wchar_t, kMaximumDirectoryCharacters> g_diagnostics_directory{};
std::array<wchar_t, kMaximumDirectoryCharacters> g_crash_dump_path{};
std::array<wchar_t, kMaximumDirectoryCharacters> g_crash_text_path{};
LPTOP_LEVEL_EXCEPTION_FILTER g_previous_exception_filter = nullptr;
bool g_exception_filter_installed = false;

const char* EventName(DiagnosticEvent event) noexcept {
    switch (event) {
    case DiagnosticEvent::ApplicationStarting: return "application.starting";
    case DiagnosticEvent::ApplicationStarted: return "application.started";
    case DiagnosticEvent::ApplicationStopping: return "application.stopping";
    case DiagnosticEvent::ApplicationStopped: return "application.stopped";
    case DiagnosticEvent::WindowClassRegistrationFailed: return "window.class_registration_failed";
    case DiagnosticEvent::WindowCreationFailed: return "window.creation_failed";
    case DiagnosticEvent::GraphicsInitializationFailed: return "graphics.initialization_failed";
    case DiagnosticEvent::FatalStandardException: return "fatal.standard_exception";
    case DiagnosticEvent::FatalUnknownException: return "fatal.unknown_exception";
    case DiagnosticEvent::DriverConnectSucceeded: return "driver.connect_succeeded";
    case DiagnosticEvent::DriverConnectFailed: return "driver.connect_failed";
    case DiagnosticEvent::DriverServiceInstallSucceeded: return "driver.service_install_succeeded";
    case DiagnosticEvent::DriverServiceInstallFailed: return "driver.service_install_failed";
    case DiagnosticEvent::DriverServiceStartSucceeded: return "driver.service_start_succeeded";
    case DiagnosticEvent::DriverServiceStartFailed: return "driver.service_start_failed";
    case DiagnosticEvent::DriverServiceStopSucceeded: return "driver.service_stop_succeeded";
    case DiagnosticEvent::DriverServiceStopFailed: return "driver.service_stop_failed";
    case DiagnosticEvent::DriverServiceRemoveSucceeded: return "driver.service_remove_succeeded";
    case DiagnosticEvent::DriverServiceRemoveFailed: return "driver.service_remove_failed";
    case DiagnosticEvent::ProbeServiceInstallSucceeded: return "probe.service_install_succeeded";
    case DiagnosticEvent::ProbeServiceInstallFailed: return "probe.service_install_failed";
    case DiagnosticEvent::ProbeServiceStartSucceeded: return "probe.service_start_succeeded";
    case DiagnosticEvent::ProbeServiceStartFailed: return "probe.service_start_failed";
    case DiagnosticEvent::ProbeServiceStopSucceeded: return "probe.service_stop_succeeded";
    case DiagnosticEvent::ProbeServiceStopFailed: return "probe.service_stop_failed";
    case DiagnosticEvent::ProbeServiceRemoveSucceeded: return "probe.service_remove_succeeded";
    case DiagnosticEvent::ProbeServiceRemoveFailed: return "probe.service_remove_failed";
    case DiagnosticEvent::ProbeDeviceOpenSucceeded: return "probe.device_open_succeeded";
    case DiagnosticEvent::ProbeDeviceOpenFailed: return "probe.device_open_failed";
    case DiagnosticEvent::ProbeQuerySucceeded: return "probe.query_succeeded";
    case DiagnosticEvent::ProbeQueryFailed: return "probe.query_failed";
    case DiagnosticEvent::ProbeResetSucceeded: return "probe.reset_succeeded";
    case DiagnosticEvent::ProbeResetFailed: return "probe.reset_failed";
    case DiagnosticEvent::PhysicalGateLockSucceeded: return "physical_gate.lock_succeeded";
    case DiagnosticEvent::PhysicalGateLockFailed: return "physical_gate.lock_failed";
    case DiagnosticEvent::PhysicalApplySucceeded: return "physical.apply_succeeded";
    case DiagnosticEvent::PhysicalApplyFailed: return "physical.apply_failed";
    case DiagnosticEvent::PhysicalRollbackSucceeded: return "physical.rollback_succeeded";
    case DiagnosticEvent::PhysicalRollbackFailed: return "physical.rollback_failed";
    }
    return "diagnostic.unknown";
}

void CloseLogFile() noexcept {
    if (g_log_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log_file);
        g_log_file = INVALID_HANDLE_VALUE;
    }
}

void RotateLogFiles() noexcept {
    CloseLogFile();
    const std::wstring first_backup = g_log_path + L".1";
    const std::wstring second_backup = g_log_path + L".2";
    static_cast<void>(DeleteFileW(second_backup.c_str()));
    static_cast<void>(MoveFileExW(
        first_backup.c_str(), second_backup.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
    static_cast<void>(MoveFileExW(
        g_log_path.c_str(), first_backup.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
}

void OpenLogFile() noexcept {
    g_log_file = CreateFileW(
        g_log_path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
}

void EnsureLogCapacity(std::size_t incoming_bytes) noexcept {
    if (g_log_file == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size{};
    if (GetFileSizeEx(g_log_file, &size) == FALSE) return;
    if (size.QuadPart + static_cast<LONGLONG>(incoming_bytes) <=
        kMaximumLogBytes) {
        return;
    }
    RotateLogFiles();
    OpenLogFile();
}

bool BuildDiagnosticsDirectory() noexcept {
    try {
        std::wstring local_app_data(kMaximumDirectoryCharacters, L'\0');
        const DWORD length = GetEnvironmentVariableW(
            L"LOCALAPPDATA", local_app_data.data(),
            static_cast<DWORD>(local_app_data.size()));
        if (length == 0 || length >= local_app_data.size()) return false;
        local_app_data.resize(length);
        const std::filesystem::path directory =
            std::filesystem::path(local_app_data) / L"KDBG" / L"logs";
        std::error_code error;
        std::filesystem::create_directories(directory, error);
        if (error) return false;
        const auto native = directory.native();
        if (native.size() + 1 > g_diagnostics_directory.size()) return false;
        std::copy(
            native.begin(), native.end(), g_diagnostics_directory.begin());
        g_diagnostics_directory[native.size()] = L'\0';
        g_log_path = (directory / L"kdbg.log").native();
        return true;
    } catch (...) {
        return false;
    }
}

void WriteCrashText(
    const wchar_t* filename,
    const SYSTEMTIME& time,
    DWORD process_id,
    DWORD thread_id,
    DWORD exception_code,
    const void* exception_address,
    bool dump_written) noexcept {
    HANDLE file = CreateFileW(
        filename, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    std::array<char, 1024> text{};
    const int length = std::snprintf(
        text.data(), text.size(),
        "KDBG local crash diagnostic\r\n"
        "UTC: %04u-%02u-%02uT%02u:%02u:%02u.%03uZ\r\n"
        "Process ID: %lu\r\nThread ID: %lu\r\n"
        "Exception code: 0x%08lX\r\nException address: %p\r\n"
        "MiniDumpNormal: %s\r\nExternal transmission: none\r\n",
        time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
        static_cast<unsigned long>(process_id),
        static_cast<unsigned long>(thread_id),
        static_cast<unsigned long>(exception_code),
        exception_address,
        dump_written ? "written" : "failed");
    if (length > 0) {
        DWORD written = 0;
        static_cast<void>(WriteFile(
            file, text.data(),
            static_cast<DWORD>(std::min<std::size_t>(
                static_cast<std::size_t>(length), text.size() - 1)),
            &written, nullptr));
    }
    static_cast<void>(FlushFileBuffers(file));
    CloseHandle(file);
}

LONG WINAPI UnhandledExceptionDiagnostic(
    EXCEPTION_POINTERS* exception_pointers) noexcept {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    const DWORD process_id = GetCurrentProcessId();
    const DWORD thread_id = GetCurrentThreadId();
    const DWORD exception_code = exception_pointers != nullptr &&
            exception_pointers->ExceptionRecord != nullptr
        ? exception_pointers->ExceptionRecord->ExceptionCode
        : 0;
    const void* exception_address = exception_pointers != nullptr &&
            exception_pointers->ExceptionRecord != nullptr
        ? exception_pointers->ExceptionRecord->ExceptionAddress
        : nullptr;

    const wchar_t* directory = g_diagnostics_directory.data();
    const int dump_length = swprintf_s(
        g_crash_dump_path.data(), g_crash_dump_path.size(),
        L"%s\\kdbg-crash-%04u%02u%02u-%02u%02u%02u-%lu-%lu.dmp",
        directory, time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond,
        static_cast<unsigned long>(process_id),
        static_cast<unsigned long>(thread_id));
    const int text_length = swprintf_s(
        g_crash_text_path.data(), g_crash_text_path.size(),
        L"%s\\kdbg-crash-%04u%02u%02u-%02u%02u%02u-%lu-%lu.txt",
        directory, time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond,
        static_cast<unsigned long>(process_id),
        static_cast<unsigned long>(thread_id));

    bool dump_written = false;
    if (dump_length > 0 && directory[0] != L'\0') {
        HANDLE dump = CreateFileW(
            g_crash_dump_path.data(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (dump != INVALID_HANDLE_VALUE) {
            MINIDUMP_EXCEPTION_INFORMATION exception_information{};
            exception_information.ThreadId = thread_id;
            exception_information.ExceptionPointers = exception_pointers;
            exception_information.ClientPointers = FALSE;
            dump_written = MiniDumpWriteDump(
                GetCurrentProcess(), process_id, dump, MiniDumpNormal,
                exception_pointers != nullptr ? &exception_information : nullptr,
                nullptr, nullptr) != FALSE;
            static_cast<void>(FlushFileBuffers(dump));
            CloseHandle(dump);
        }
    }
    if (text_length > 0 && directory[0] != L'\0') {
        WriteCrashText(
            g_crash_text_path.data(), time, process_id, thread_id,
            exception_code, exception_address, dump_written);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

}  // namespace

void InitializeLocalDiagnostics() noexcept {
    std::scoped_lock lock(g_log_mutex);
    if (g_log_file != INVALID_HANDLE_VALUE) return;
    if (BuildDiagnosticsDirectory()) {
        OpenLogFile();
        if (g_log_file != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size{};
            if (GetFileSizeEx(g_log_file, &size) != FALSE &&
                size.QuadPart >= kMaximumLogBytes) {
                RotateLogFiles();
                OpenLogFile();
            }
        }
    }
    g_previous_exception_filter =
        SetUnhandledExceptionFilter(&UnhandledExceptionDiagnostic);
    g_exception_filter_installed = true;
}

void ShutdownLocalDiagnostics() noexcept {
    std::scoped_lock lock(g_log_mutex);
    if (g_exception_filter_installed) {
        static_cast<void>(SetUnhandledExceptionFilter(
            g_previous_exception_filter));
        g_previous_exception_filter = nullptr;
        g_exception_filter_installed = false;
    }
    CloseLogFile();
}

void LogDiagnostic(
    DiagnosticEvent event,
    std::uint64_t status_code,
    std::uint64_t native_code) noexcept {
    std::scoped_lock lock(g_log_mutex);
    if (g_log_file == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME time{};
    GetSystemTime(&time);
    std::array<char, 384> line{};
    const int length = std::snprintf(
        line.data(), line.size(),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ "
        "pid=%lu tid=%lu event=%s status=%llu native=%llu\r\n",
        time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        EventName(event),
        static_cast<unsigned long long>(status_code),
        static_cast<unsigned long long>(native_code));
    if (length <= 0) return;
    const auto byte_count = std::min<std::size_t>(
        static_cast<std::size_t>(length), line.size() - 1);
    EnsureLogCapacity(byte_count);
    if (g_log_file == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    static_cast<void>(WriteFile(
        g_log_file, line.data(), static_cast<DWORD>(byte_count),
        &written, nullptr));
    static_cast<void>(FlushFileBuffers(g_log_file));
}

}  // namespace kdbg

#else

namespace kdbg {

void InitializeLocalDiagnostics() noexcept {}
void ShutdownLocalDiagnostics() noexcept {}
void LogDiagnostic(
    DiagnosticEvent,
    std::uint64_t,
    std::uint64_t) noexcept {}

}  // namespace kdbg

#endif

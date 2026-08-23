#include "core/process/ProcessCatalog.h"

#ifdef _WIN32

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <string>

namespace kdbg {
namespace {

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string output(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        output.data(), size, nullptr, nullptr);
    return output;
}

std::string QueryPath(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return {};
    std::wstring path(32768, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process, 0, path.data(), &length)) {
        CloseHandle(process);
        return {};
    }
    CloseHandle(process);
    path.resize(length);
    return WideToUtf8(path);
}

bool Is64Bit(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return sizeof(void*) == 8;
    bool result = sizeof(void*) == 8;
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto function = kernel32 != nullptr
        ? reinterpret_cast<IsWow64Process2Fn>(
              GetProcAddress(kernel32, "IsWow64Process2"))
        : nullptr;
    if (function != nullptr) {
        USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (function(process, &process_machine, &native_machine)) {
            result = process_machine == IMAGE_FILE_MACHINE_UNKNOWN &&
                (native_machine == IMAGE_FILE_MACHINE_AMD64 ||
                 native_machine == IMAGE_FILE_MACHINE_ARM64);
        }
    } else {
        BOOL wow64 = FALSE;
        if (IsWow64Process(process, &wow64)) {
#if defined(_WIN64)
            result = wow64 == FALSE;
#else
            result = false;
#endif
        }
    }
    CloseHandle(process);
    return result;
}

}  // namespace

Result<std::vector<ProcessInfo>> ProcessCatalog::Enumerate() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return Result<std::vector<ProcessInfo>>::Failure(MakeError(
            ErrorCode::IoFailure,
            "CreateToolhelp32Snapshot failed",
            "ProcessCatalog::Enumerate",
            GetLastError()));
    }

    std::vector<ProcessInfo> output;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            ProcessInfo info{};
            info.pid = entry.th32ProcessID;
            info.parent_pid = entry.th32ParentProcessID;
            info.name = WideToUtf8(entry.szExeFile);
            info.path = QueryPath(entry.th32ProcessID);
            info.is_64_bit = Is64Bit(entry.th32ProcessID);
            output.push_back(std::move(info));
        } while (Process32NextW(snapshot, &entry));
    }
    const auto last_error = GetLastError();
    CloseHandle(snapshot);
    if (output.empty() && last_error != ERROR_NO_MORE_FILES) {
        return Result<std::vector<ProcessInfo>>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Process enumeration failed",
            "ProcessCatalog::Enumerate",
            last_error));
    }

    std::sort(
        output.begin(), output.end(),
        [](const ProcessInfo& left, const ProcessInfo& right) {
            if (left.name != right.name) return left.name < right.name;
            return left.pid < right.pid;
        });
    return Result<std::vector<ProcessInfo>>::Success(std::move(output));
}

}  // namespace kdbg

#else

namespace kdbg {
Result<std::vector<ProcessInfo>> ProcessCatalog::Enumerate() {
    return Result<std::vector<ProcessInfo>>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Process enumeration is Windows-only",
        "ProcessCatalog::Enumerate"));
}
}  // namespace kdbg

#endif

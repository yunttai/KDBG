#include "core/process/Win32ProcessMemory.h"

#ifdef _WIN32

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <algorithm>
#include <limits>
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

bool ProtectionReadable(DWORD protection) noexcept {
    const DWORD base = protection & 0xFFU;
    return base == PAGE_READONLY || base == PAGE_READWRITE ||
        base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READ ||
        base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool ProtectionWritable(DWORD protection) noexcept {
    const DWORD base = protection & 0xFFU;
    return base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
        base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool ProtectionExecutable(DWORD protection) noexcept {
    const DWORD base = protection & 0xFFU;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
        base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool QueryCreationTime(HANDLE process, ULONGLONG* creation_time) noexcept {
    if (process == nullptr || creation_time == nullptr) return false;
    FILETIME created{};
    FILETIME exited{};
    FILETIME kernel{};
    FILETIME user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        return false;
    }
    ULARGE_INTEGER value{};
    value.LowPart = created.dwLowDateTime;
    value.HighPart = created.dwHighDateTime;
    *creation_time = value.QuadPart;
    return true;
}

Result<void> ValidateDriverIdentity(
    KDbgBackend* backend,
    std::uint32_t pid,
    std::uint64_t expected_eprocess,
    std::uint64_t expected_dtb,
    const char* operation) {
    if (backend == nullptr || !backend->Info().connected ||
        expected_eprocess == 0 || expected_dtb == 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "KDBG process identity is unavailable",
            operation));
    }
    auto context = backend->GetProcessContext(pid);
    if (!context) return Result<void>::Failure(context.GetError());
    if (context.Value().eprocess != expected_eprocess ||
        context.Value().directory_table_base != expected_dtb) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            "PID now refers to a different process instance",
            operation));
    }
    return Result<void>::Success();
}

}  // namespace

struct Win32ProcessMemory::Impl {
    HANDLE process{nullptr};
    std::uint32_t pid{0};
    std::size_t pointer_size{8};
    bool writes_armed{false};
    bool direct_write_access{false};
    KDbgBackend* backend{nullptr};
    ULONGLONG creation_time{0};
    std::uint64_t driver_eprocess{0};
    std::uint64_t driver_dtb{0};
};

Win32ProcessMemory::Win32ProcessMemory() : impl_(std::make_unique<Impl>()) {}

Win32ProcessMemory::~Win32ProcessMemory() {
    if (impl_->backend != nullptr && impl_->writes_armed) {
        static_cast<void>(impl_->backend->SetWriteEnabled(false));
    }
    if (impl_->process != nullptr) {
        CloseHandle(impl_->process);
    }
}

Result<std::unique_ptr<Win32ProcessMemory>> Win32ProcessMemory::Attach(
    std::uint32_t pid,
    KDbgBackend* driver_backend) {
    auto instance = std::unique_ptr<Win32ProcessMemory>(new Win32ProcessMemory());
    const auto opened = instance->Open(pid, driver_backend);
    if (!opened) {
        return Result<std::unique_ptr<Win32ProcessMemory>>::Failure(opened.GetError());
    }
    return Result<std::unique_ptr<Win32ProcessMemory>>::Success(std::move(instance));
}

Result<void> Win32ProcessMemory::Open(
    std::uint32_t pid,
    KDbgBackend* backend) {
    if (pid == 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "PID 0 cannot be attached",
            "Win32ProcessMemory::Open"));
    }
    impl_->process = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid);
    if (impl_->process == nullptr) {
        impl_->process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (impl_->process == nullptr && backend == nullptr) {
        return Result<void>::Failure(MakeError(
            GetLastError() == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::IoFailure,
            "OpenProcess failed and no KDBG driver fallback is available",
            "Win32ProcessMemory::Open",
            GetLastError()));
    }

    impl_->pid = pid;
    impl_->backend = backend;
    impl_->pointer_size = 8;
    if (impl_->process != nullptr) {
        if (!QueryCreationTime(impl_->process, &impl_->creation_time) ||
            GetProcessId(impl_->process) != pid) {
            CloseHandle(impl_->process);
            impl_->process = nullptr;
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Unable to establish stable process identity",
                "Win32ProcessMemory::Open",
                GetLastError()));
        }
        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        const auto function = kernel32 != nullptr
            ? reinterpret_cast<IsWow64Process2Fn>(
                  GetProcAddress(kernel32, "IsWow64Process2"))
            : nullptr;
        if (function != nullptr) {
            USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (function(impl_->process, &process_machine, &native_machine) &&
                process_machine != IMAGE_FILE_MACHINE_UNKNOWN) {
                impl_->pointer_size = 4;
            }
        } else {
            BOOL wow64 = FALSE;
            if (IsWow64Process(impl_->process, &wow64) && wow64) {
                impl_->pointer_size = 4;
            }
        }
    }
    if (backend != nullptr && backend->Info().connected) {
        auto context = backend->GetProcessContext(pid);
        if (!context && impl_->process == nullptr) {
            return Result<void>::Failure(context.GetError());
        }
        if (context) {
            impl_->driver_eprocess = context.Value().eprocess;
            impl_->driver_dtb = context.Value().directory_table_base;
        }
    }
    return Result<void>::Success();
}

std::uint32_t Win32ProcessMemory::ProcessId() const noexcept { return impl_->pid; }
std::uint64_t Win32ProcessMemory::ProcessIdentityToken() const noexcept {
    return impl_->creation_time;
}
std::size_t Win32ProcessMemory::PointerSize() const noexcept { return impl_->pointer_size; }
bool Win32ProcessMemory::IsOpen() const noexcept {
    if (impl_->pid == 0) return false;
    if (impl_->process != nullptr) {
        DWORD code = 0;
        ULONGLONG creation_time = 0;
        return GetProcessId(impl_->process) == impl_->pid &&
            QueryCreationTime(impl_->process, &creation_time) &&
            creation_time == impl_->creation_time &&
            GetExitCodeProcess(impl_->process, &code) && code == STILL_ACTIVE;
    }
    return impl_->backend != nullptr && impl_->backend->Info().connected;
}
bool Win32ProcessMemory::WritesArmed() const noexcept { return impl_->writes_armed; }

Result<void> Win32ProcessMemory::ReopenForWrite() {
    HANDLE write_process = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        impl_->pid);
    if (write_process == nullptr) {
        return Result<void>::Failure(MakeError(
            GetLastError() == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::IoFailure,
            "Unable to open the process for direct writes",
            "Win32ProcessMemory::ReopenForWrite",
            GetLastError()));
    }
    ULONGLONG creation_time = 0;
    if (GetProcessId(write_process) != impl_->pid ||
        !QueryCreationTime(write_process, &creation_time) ||
        (impl_->creation_time != 0 && creation_time != impl_->creation_time)) {
        CloseHandle(write_process);
        return Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            "PID now refers to a different process instance",
            "Win32ProcessMemory::ReopenForWrite"));
    }
    if (impl_->process != nullptr) CloseHandle(impl_->process);
    impl_->process = write_process;
    impl_->creation_time = creation_time;
    impl_->direct_write_access = true;
    return Result<void>::Success();
}

Result<void> Win32ProcessMemory::SetWritesArmed(bool armed) {
    if (!armed) {
        if (impl_->backend != nullptr && impl_->backend->Info().connected) {
            const auto disabled = impl_->backend->SetWriteEnabled(false);
            if (!disabled) return disabled;
        }
        impl_->writes_armed = false;
        return Result<void>::Success();
    }

    if (impl_->process != nullptr && !impl_->direct_write_access) {
        const auto direct = ReopenForWrite();
        if (!direct && (impl_->backend == nullptr || !impl_->backend->Info().connected)) {
            return direct;
        }
    }
    if (impl_->backend != nullptr && impl_->backend->Info().connected) {
        const auto enabled = impl_->backend->SetWriteEnabled(true);
        if (!enabled && !impl_->direct_write_access) return enabled;
    }
    impl_->writes_armed = true;
    return Result<void>::Success();
}

Result<std::vector<std::uint8_t>> Win32ProcessMemory::Read(
    std::uint64_t address,
    std::uint32_t length) {
    if (address == 0 || length == 0) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid process read request",
            "Win32ProcessMemory::Read"));
    }
    if (impl_->process != nullptr) {
        std::vector<std::uint8_t> output(length);
        SIZE_T completed = 0;
        if (ReadProcessMemory(
                impl_->process,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
                output.data(),
                output.size(),
                &completed) && completed == output.size()) {
            return Result<std::vector<std::uint8_t>>::Success(std::move(output));
        }
    }
    if (impl_->backend != nullptr && impl_->backend->Info().connected) {
        const auto identity = ValidateDriverIdentity(
            impl_->backend,
            impl_->pid,
            impl_->driver_eprocess,
            impl_->driver_dtb,
            "Win32ProcessMemory::Read");
        if (!identity) {
            return Result<std::vector<std::uint8_t>>::Failure(
                identity.GetError());
        }
        return impl_->backend->ReadProcessVirtual(impl_->pid, address, length);
    }
    return Result<std::vector<std::uint8_t>>::Failure(MakeError(
        GetLastError() == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::ShortRead,
        "Process memory read failed",
        "Win32ProcessMemory::Read",
        GetLastError(),
        length,
        0));
}

Result<std::uint32_t> Win32ProcessMemory::Write(
    std::uint64_t address,
    std::span<const std::uint8_t> data) {
    if (!impl_->writes_armed) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Process writes are locked",
            "Win32ProcessMemory::Write"));
    }
    if (address == 0 || data.empty() ||
        data.size() > std::numeric_limits<std::uint32_t>::max()) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid process write request",
            "Win32ProcessMemory::Write"));
    }
    if (impl_->process != nullptr && impl_->direct_write_access) {
        SIZE_T completed = 0;
        if (WriteProcessMemory(
                impl_->process,
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address)),
                data.data(),
                data.size(),
                &completed) && completed == data.size()) {
            FlushInstructionCache(
                impl_->process,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
                data.size());
            return Result<std::uint32_t>::Success(static_cast<std::uint32_t>(completed));
        }
    }
    if (impl_->backend != nullptr && impl_->backend->Info().connected) {
        const auto identity = ValidateDriverIdentity(
            impl_->backend,
            impl_->pid,
            impl_->driver_eprocess,
            impl_->driver_dtb,
            "Win32ProcessMemory::Write");
        if (!identity) {
            return Result<std::uint32_t>::Failure(identity.GetError());
        }
        return impl_->backend->WriteProcessVirtual(impl_->pid, address, data);
    }
    return Result<std::uint32_t>::Failure(MakeError(
        GetLastError() == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::ShortWrite,
        "Process memory write failed",
        "Win32ProcessMemory::Write",
        GetLastError(),
        data.size(),
        0));
}

Result<std::vector<MemoryRegion>> Win32ProcessMemory::Regions() {
    if (impl_->process == nullptr) {
        return Result<std::vector<MemoryRegion>>::Failure(MakeError(
            ErrorCode::Unsupported,
            "Region enumeration requires a queryable process handle",
            "Win32ProcessMemory::Regions"));
    }
    SYSTEM_INFO system_info{};
    GetNativeSystemInfo(&system_info);
    std::uint64_t address = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);
    std::vector<MemoryRegion> output;
    MEMORY_BASIC_INFORMATION mbi{};
    while (address <= maximum &&
           VirtualQueryEx(
               impl_->process,
               reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
               &mbi,
               sizeof(mbi)) == sizeof(mbi)) {
        MemoryRegion region{};
        region.base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        region.size = mbi.RegionSize;
        region.state = mbi.State;
        region.protection = mbi.Protect;
        region.type = mbi.Type;
        region.committed = mbi.State == MEM_COMMIT;
        region.guard = (mbi.Protect & PAGE_GUARD) != 0;
        region.readable = region.committed && !region.guard && ProtectionReadable(mbi.Protect);
        region.writable = region.committed && !region.guard && ProtectionWritable(mbi.Protect);
        region.executable = region.committed && !region.guard && ProtectionExecutable(mbi.Protect);
        region.copy_on_write = (mbi.Protect & 0xFFU) == PAGE_WRITECOPY ||
            (mbi.Protect & 0xFFU) == PAGE_EXECUTE_WRITECOPY;
        if (region.committed && (mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE)) {
            std::wstring mapped(32768, L'\0');
            const DWORD chars = GetMappedFileNameW(
                impl_->process,
                mbi.BaseAddress,
                mapped.data(),
                static_cast<DWORD>(mapped.size()));
            if (chars != 0) {
                mapped.resize(chars);
                region.mapped_name = WideToUtf8(mapped);
            }
        }
        output.push_back(std::move(region));
        const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) break;
        address = next;
    }
    return Result<std::vector<MemoryRegion>>::Success(std::move(output));
}

Result<std::vector<ProcessModule>> Win32ProcessMemory::Modules() {
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        impl_->pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return Result<std::vector<ProcessModule>>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Module snapshot failed",
            "Win32ProcessMemory::Modules",
            GetLastError()));
    }
    std::vector<ProcessModule> output;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            ProcessModule module{};
            module.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            module.size = entry.modBaseSize;
            module.name = WideToUtf8(entry.szModule);
            module.path = WideToUtf8(entry.szExePath);
            output.push_back(std::move(module));
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    std::sort(
        output.begin(), output.end(),
        [](const ProcessModule& left, const ProcessModule& right) {
            return left.base < right.base;
        });
    return Result<std::vector<ProcessModule>>::Success(std::move(output));
}

}  // namespace kdbg

#else

namespace kdbg {
struct Win32ProcessMemory::Impl {};
Win32ProcessMemory::Win32ProcessMemory() : impl_(std::make_unique<Impl>()) {}
Win32ProcessMemory::~Win32ProcessMemory() = default;
Result<std::unique_ptr<Win32ProcessMemory>> Win32ProcessMemory::Attach(std::uint32_t, KDbgBackend*) { return Result<std::unique_ptr<Win32ProcessMemory>>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "Win32ProcessMemory::Attach")); }
std::uint32_t Win32ProcessMemory::ProcessId() const noexcept { return 0; }
std::uint64_t Win32ProcessMemory::ProcessIdentityToken() const noexcept { return 0; }
std::size_t Win32ProcessMemory::PointerSize() const noexcept { return 8; }
bool Win32ProcessMemory::IsOpen() const noexcept { return false; }
bool Win32ProcessMemory::WritesArmed() const noexcept { return false; }
Result<void> Win32ProcessMemory::SetWritesArmed(bool) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "Win32ProcessMemory::SetWritesArmed")); }
Result<std::vector<std::uint8_t>> Win32ProcessMemory::Read(std::uint64_t, std::uint32_t) { return Result<std::vector<std::uint8_t>>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "Win32ProcessMemory::Read")); }
Result<std::uint32_t> Win32ProcessMemory::Write(std::uint64_t, std::span<const std::uint8_t>) { return Result<std::uint32_t>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "Win32ProcessMemory::Write")); }
Result<std::vector<MemoryRegion>> Win32ProcessMemory::Regions() { return Result<std::vector<MemoryRegion>>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "Win32ProcessMemory::Regions")); }
Result<std::vector<ProcessModule>> Win32ProcessMemory::Modules() { return Result<std::vector<ProcessModule>>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "Win32ProcessMemory::Modules")); }
Result<void> Win32ProcessMemory::Open(std::uint32_t, KDbgBackend*) { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "Win32ProcessMemory::Open")); }
Result<void> Win32ProcessMemory::ReopenForWrite() { return Result<void>::Failure(MakeError(ErrorCode::Unsupported, "Windows-only", "Win32ProcessMemory::ReopenForWrite")); }
}  // namespace kdbg

#endif

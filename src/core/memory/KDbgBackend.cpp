#include "core/memory/KDbgBackend.h"

#include "shared/KDbgIoctl.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <utility>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace kdbg {
namespace {

#ifdef _WIN32
[[nodiscard]] bool TryToPagingLevel(
    std::uint32_t level,
    PagingLevel* output) noexcept {
    if (output == nullptr) return false;
    switch (level) {
    case KDBG_PAGING_LEVEL_PML5: *output = PagingLevel::Pml5; return true;
    case KDBG_PAGING_LEVEL_PML4: *output = PagingLevel::Pml4; return true;
    case KDBG_PAGING_LEVEL_PDPT: *output = PagingLevel::Pdpt; return true;
    case KDBG_PAGING_LEVEL_PD: *output = PagingLevel::Pd; return true;
    case KDBG_PAGING_LEVEL_PT: *output = PagingLevel::Pt; return true;
    default: return false;
    }
}

[[nodiscard]] bool IsNonOverflowingRange(
    std::uint64_t address,
    std::size_t length) noexcept {
    return length != 0 &&
        length <= std::numeric_limits<std::uint64_t>::max() - address;
}

[[nodiscard]] bool IsValidAddressRange(
    std::uint64_t address,
    std::size_t length) noexcept {
    return address != 0 && IsNonOverflowingRange(address, length);
}

[[nodiscard]] bool IsPageBounded(
    std::uint64_t address,
    std::size_t length) noexcept {
    if (!IsNonOverflowingRange(address, length)) return false;
    const auto last = address + static_cast<std::uint64_t>(length) - 1U;
    return (address & ~0xFFFULL) == (last & ~0xFFFULL);
}
#endif

}  // namespace

struct KDbgBackend::Impl {
#ifdef _WIN32
    HANDLE device{INVALID_HANDLE_VALUE};
#endif
    std::wstring device_name;
    bool connected{false};
    bool write_enabled{false};
    bool la57{false};
    std::uint32_t abi_version{0};
    std::uint32_t max_transfer{KDBG_MAX_TRANSFER_SIZE};

#ifdef _WIN32
    Result<std::uint32_t> Ioctl(
        DWORD code,
        void* buffer,
        DWORD input_length,
        DWORD output_length,
        const char* operation) {
        if (device == INVALID_HANDLE_VALUE) {
            return Result<std::uint32_t>::Failure(MakeError(
                ErrorCode::BackendDisconnected,
                "KDBG driver handle is not open",
                operation));
        }
        DWORD returned = 0;
        if (!DeviceIoControl(
                device,
                code,
                buffer,
                input_length,
                buffer,
                output_length,
                &returned,
                nullptr)) {
            const DWORD error = GetLastError();
            return Result<std::uint32_t>::Failure(MakeError(
                error == ERROR_ACCESS_DENIED
                    ? ErrorCode::AccessDenied
                    : ErrorCode::IoFailure,
                "DeviceIoControl failed",
                operation,
                error));
        }
        return Result<std::uint32_t>::Success(returned);
    }
#endif
};

KDbgBackend::KDbgBackend(std::wstring device_name)
    : impl_(std::make_unique<Impl>()) {
    impl_->device_name = std::move(device_name);
}

KDbgBackend::~KDbgBackend() {
    Close();
}

Result<void> KDbgBackend::Open() {
#ifdef _WIN32
    if (impl_->connected) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendAlreadyOpen,
            "KDBG backend is already open",
            "KDbgBackend::Open"));
    }

    impl_->device = CreateFileW(
        impl_->device_name.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (impl_->device == INVALID_HANDLE_VALUE) {
        return Result<void>::Failure(MakeError(
            GetLastError() == ERROR_ACCESS_DENIED
                ? ErrorCode::AccessDenied
                : ErrorCode::IoFailure,
            "Unable to open the KDBG driver device",
            "KDbgBackend::Open",
            GetLastError()));
    }

    KDBG_VERSION_RESPONSE response{};
    auto queried = impl_->Ioctl(
        IOCTL_KDBG_GET_VERSION,
        &response,
        0,
        sizeof(response),
        "KDbgBackend::Open/GET_VERSION");
    if (!queried || queried.Value() != sizeof(response)) {
        const Error error = queried
            ? MakeError(
                ErrorCode::ShortRead,
                "KDBG returned a short version response",
                "KDbgBackend::Open",
                0,
                sizeof(response),
                queried.Value())
            : queried.GetError();
        Close();
        return Result<void>::Failure(error);
    }
    if (response.Size != sizeof(response) ||
        response.AbiVersion != KDBG_ABI_VERSION) {
        const auto actual = response.AbiVersion;
        Close();
        return Result<void>::Failure(MakeError(
            ErrorCode::AbiMismatch,
            "KDBG user/driver ABI versions do not match",
            "KDbgBackend::Open",
            actual,
            KDBG_ABI_VERSION,
            actual));
    }

    constexpr std::uint32_t required_flags =
        KDBG_VERSION_FLAG_PHYSICAL_READ |
        KDBG_VERSION_FLAG_PHYSICAL_WRITE |
        KDBG_VERSION_FLAG_PROCESS_MEMORY |
        KDBG_VERSION_FLAG_VTOP |
        KDBG_VERSION_FLAG_SECURE_OPEN |
        KDBG_VERSION_FLAG_SINGLE_OWNER;
    if (response.MaxTransferSize == 0 ||
        response.MaxTransferSize > KDBG_MAX_TRANSFER_SIZE ||
        (response.Flags & required_flags) != required_flags) {
        Close();
        return Result<void>::Failure(MakeError(
            ErrorCode::AbiMismatch,
            "KDBG driver capabilities or transfer cap are invalid",
            "KDbgBackend::Open"));
    }

    impl_->abi_version = response.AbiVersion;
    impl_->max_transfer = response.MaxTransferSize;
    impl_->la57 = (response.Flags & KDBG_VERSION_FLAG_LA57_ACTIVE) != 0;
    impl_->connected = true;
    impl_->write_enabled = false;
    return Result<void>::Success();
#else
    return Result<void>::Failure(MakeError(
        ErrorCode::Unsupported,
        "The KDBG live backend is available only on Windows",
        "KDbgBackend::Open"));
#endif
}

void KDbgBackend::Close() noexcept {
#ifdef _WIN32
    if (impl_->device != INVALID_HANDLE_VALUE) {
        if (impl_->connected && impl_->write_enabled) {
            KDBG_WRITE_MODE_REQUEST request{};
            request.Size = sizeof(request);
            request.EnableWrite = 0;
            request.Acknowledge = KDBG_WRITE_ACK_MAGIC;
            DWORD ignored = 0;
            static_cast<void>(DeviceIoControl(
                impl_->device,
                IOCTL_KDBG_SET_WRITE_MODE,
                &request,
                sizeof(request),
                nullptr,
                0,
                &ignored,
                nullptr));
        }
        CloseHandle(impl_->device);
        impl_->device = INVALID_HANDLE_VALUE;
    }
#endif
    impl_->write_enabled = false;
    impl_->connected = false;
    impl_->la57 = false;
    impl_->abi_version = 0;
}

BackendInfo KDbgBackend::Info() const {
    BackendInfo info{};
    info.name = "kdbg-live";
    info.abi_version = impl_->abi_version;
    info.connected = impl_->connected;
    info.write_enabled = impl_->write_enabled;
    info.is_mock = false;
    info.supports_process_context = true;
    info.supports_fixture = false;
    info.supports_la57 = impl_->la57;
    return info;
}

Result<BackendSessionStatus> KDbgBackend::QuerySessionStatus() {
#ifdef _WIN32
    KDBG_SESSION_STATUS_RESPONSE response{};
    auto result = impl_->Ioctl(
        IOCTL_KDBG_GET_SESSION_STATUS,
        &response,
        0,
        sizeof(response),
        "KDbgBackend::QuerySessionStatus");
    if (!result) {
        return Result<BackendSessionStatus>::Failure(result.GetError());
    }
    constexpr std::uint32_t valid_flags =
        KDBG_SESSION_FLAG_OWNER_ACTIVE |
        KDBG_SESSION_FLAG_WRITE_ENABLED;
    if (result.Value() != sizeof(response) ||
        response.Size != sizeof(response) || response.Reserved != 0 ||
        response.Reserved2 != 0 ||
        response.LastPhysicalWriteStage >
            KDBG_PHYSICAL_WRITE_STAGE_COMPLETE ||
        (response.Flags & ~valid_flags) != 0 ||
        response.CurrentPid != GetCurrentProcessId() ||
        response.OpenHandleCount == 0 ||
        (response.Flags & KDBG_SESSION_FLAG_OWNER_ACTIVE) == 0 ||
        response.OwnerPid != response.CurrentPid ||
        (((response.Flags & KDBG_SESSION_FLAG_OWNER_ACTIVE) != 0) !=
         (response.OwnerPid != 0))) {
        return Result<BackendSessionStatus>::Failure(MakeError(
            ErrorCode::ShortRead,
            "KDBG returned a short session status",
            "KDbgBackend::QuerySessionStatus",
            0,
            sizeof(response),
            result.Value()));
    }
    BackendSessionStatus status{};
    status.flags = response.Flags;
    status.owner_pid = response.OwnerPid;
    status.current_pid = response.CurrentPid;
    status.open_handle_count = response.OpenHandleCount;
    status.successful_reads = response.SuccessfulReads;
    status.successful_writes = response.SuccessfulWrites;
    status.rejected_writes = response.RejectedWrites;
    status.last_physical_write_status =
        response.LastPhysicalWriteStatus;
    status.last_physical_write_stage =
        response.LastPhysicalWriteStage;
    status.last_physical_write_transferred =
        response.LastPhysicalWriteTransferred;
    status.write_enabled =
        (response.Flags & KDBG_SESSION_FLAG_WRITE_ENABLED) != 0;
    impl_->write_enabled = status.write_enabled;
    return Result<BackendSessionStatus>::Success(status);
#else
    return Result<BackendSessionStatus>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::QuerySessionStatus"));
#endif
}

Result<std::vector<PhysicalRange>> KDbgBackend::GetPhysicalRanges() {
#ifdef _WIN32
    std::vector<std::uint8_t> response_storage(
        sizeof(KDBG_PHYSICAL_RANGES_RESPONSE));
    const auto response_size = static_cast<DWORD>(response_storage.size());
    auto* response = reinterpret_cast<KDBG_PHYSICAL_RANGES_RESPONSE*>(
        response_storage.data());
    auto result = impl_->Ioctl(
        IOCTL_KDBG_GET_PHYSICAL_RANGES,
        response,
        0,
        response_size,
        "KDbgBackend::GetPhysicalRanges");
    if (!result) {
        return Result<std::vector<PhysicalRange>>::Failure(result.GetError());
    }
    if (result.Value() != response_size ||
        response->Size != response_size || response->Flags != 0 ||
        response->Reserved != 0 ||
        response->RangeCount == 0 ||
        response->RangeCount > KDBG_MAX_PHYSICAL_RANGES) {
        return Result<std::vector<PhysicalRange>>::Failure(MakeError(
            ErrorCode::ShortRead,
            "KDBG returned an invalid physical range response",
            "KDbgBackend::GetPhysicalRanges",
            0,
            response_size,
            result.Value()));
    }

    std::vector<PhysicalRange> ranges;
    ranges.reserve(response->RangeCount);
    std::uint64_t total_bytes = 0;
    for (std::uint32_t i = 0; i < response->RangeCount; ++i) {
        const auto& item = response->Ranges[i];
        PhysicalRange range{item.BaseAddress, item.ByteCount};
        if (!range.IsValid() ||
            total_bytes > std::numeric_limits<std::uint64_t>::max() -
                item.ByteCount) {
            return Result<std::vector<PhysicalRange>>::Failure(MakeError(
                ErrorCode::AbiMismatch,
                "KDBG returned an invalid physical range entry",
                "KDbgBackend::GetPhysicalRanges"));
        }
        total_bytes += item.ByteCount;
        ranges.push_back(range);
    }
    if (total_bytes != response->TotalBytes) {
        return Result<std::vector<PhysicalRange>>::Failure(MakeError(
            ErrorCode::AbiMismatch,
            "KDBG physical range total is inconsistent",
            "KDbgBackend::GetPhysicalRanges"));
    }
    return Result<std::vector<PhysicalRange>>::Success(std::move(ranges));
#else
    return Result<std::vector<PhysicalRange>>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::GetPhysicalRanges"));
#endif
}

Result<std::vector<std::uint8_t>> KDbgBackend::ReadPhysical(
    std::uint64_t physical_address,
    std::uint32_t length) {
#ifdef _WIN32
    if (length == 0 || length > impl_->max_transfer ||
        !IsNonOverflowingRange(physical_address, length)) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid physical read length",
            "KDbgBackend::ReadPhysical",
            0,
            impl_->max_transfer,
            length));
    }
    constexpr std::size_t header = offsetof(KDBG_PHYSICAL_READ_REQUEST, Data);
    const std::size_t total = header + length;
    if (total > std::numeric_limits<DWORD>::max()) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Physical read buffer size overflow",
            "KDbgBackend::ReadPhysical"));
    }

    std::vector<std::uint8_t> buffer(total);
    auto* request = reinterpret_cast<KDBG_PHYSICAL_READ_REQUEST*>(buffer.data());
    request->Size = static_cast<KDBG_U32>(header);
    request->PhysicalAddress = physical_address;
    request->Length = length;

    auto result = impl_->Ioctl(
        IOCTL_KDBG_READ_PHYSICAL,
        buffer.data(),
        static_cast<DWORD>(header),
        static_cast<DWORD>(total),
        "KDbgBackend::ReadPhysical");
    if (!result) {
        return Result<std::vector<std::uint8_t>>::Failure(result.GetError());
    }
    const auto copied = request->Transferred;
    if (request->Size != header || request->Flags != 0 ||
        request->PhysicalAddress != physical_address ||
        request->Length != length || copied != length ||
        result.Value() != total) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ShortRead,
            "KDBG returned a short physical read",
            "KDbgBackend::ReadPhysical",
            0,
            length,
            copied));
    }
    std::vector<std::uint8_t> bytes(length);
    std::memcpy(bytes.data(), request->Data, length);
    return Result<std::vector<std::uint8_t>>::Success(std::move(bytes));
#else
    (void)physical_address;
    (void)length;
    return Result<std::vector<std::uint8_t>>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::ReadPhysical"));
#endif
}

Result<void> KDbgBackend::SetWriteEnabled(bool enabled) {
#ifdef _WIN32
    KDBG_WRITE_MODE_REQUEST request{};
    request.Size = sizeof(request);
    request.EnableWrite = enabled ? 1u : 0u;
    request.Acknowledge = KDBG_WRITE_ACK_MAGIC;
    auto result = impl_->Ioctl(
        IOCTL_KDBG_SET_WRITE_MODE,
        &request,
        sizeof(request),
        0,
        "KDbgBackend::SetWriteEnabled");
    if (!result) {
        return Result<void>::Failure(result.GetError());
    }
    if (result.Value() != 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::AbiMismatch,
            "KDBG write-mode response length is invalid",
            "KDbgBackend::SetWriteEnabled",
            0,
            0,
            result.Value()));
    }
    impl_->write_enabled = enabled;
    return Result<void>::Success();
#else
    (void)enabled;
    return Result<void>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::SetWriteEnabled"));
#endif
}

Result<std::uint32_t> KDbgBackend::WritePhysical(
    std::uint64_t physical_address,
    std::span<const std::uint8_t> data) {
#ifdef _WIN32
    if (!impl_->write_enabled) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "KDBG physical write gate is locked",
            "KDbgBackend::WritePhysical"));
    }
    if (data.empty() || data.size() > impl_->max_transfer ||
        !IsPageBounded(physical_address, data.size())) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid physical write length",
            "KDbgBackend::WritePhysical"));
    }
    constexpr std::size_t header = offsetof(KDBG_PHYSICAL_WRITE_REQUEST, Data);
    const std::size_t total = header + data.size();
    if (total > std::numeric_limits<DWORD>::max()) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Physical write buffer size overflow",
            "KDbgBackend::WritePhysical"));
    }

    std::vector<std::uint8_t> buffer(total);
    auto* request = reinterpret_cast<KDBG_PHYSICAL_WRITE_REQUEST*>(buffer.data());
    request->Size = static_cast<KDBG_U32>(total);
    request->PhysicalAddress = physical_address;
    request->Length = static_cast<KDBG_U32>(data.size());
    request->Acknowledge = KDBG_WRITE_ACK_MAGIC;
    std::memcpy(request->Data, data.data(), data.size());

    auto result = impl_->Ioctl(
        IOCTL_KDBG_WRITE_PHYSICAL,
        buffer.data(),
        static_cast<DWORD>(total),
        static_cast<DWORD>(header),
        "KDbgBackend::WritePhysical");
    if (!result) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(result.GetError());
    }
    if (result.Value() != header || request->Size != total ||
        request->Flags != 0 ||
        request->PhysicalAddress != physical_address ||
        request->Length != data.size() ||
        request->Acknowledge != KDBG_WRITE_ACK_MAGIC ||
        request->Transferred != data.size()) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::ShortWrite,
            "KDBG returned a short physical write",
            "KDbgBackend::WritePhysical",
            0,
            data.size(),
            request->Transferred));
    }
    auto readback = ReadPhysical(
        physical_address,
        static_cast<std::uint32_t>(data.size()));
    if (!readback || !std::equal(
            data.begin(), data.end(), readback.Value().begin())) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(
            readback
                ? MakeError(
                    ErrorCode::VerificationMismatch,
                    "KDBG physical write read-back mismatch",
                    "KDbgBackend::WritePhysical",
                    0,
                    data.size(),
                    readback.Value().size())
                : readback.GetError());
    }
    return Result<std::uint32_t>::Success(request->Transferred);
#else
    (void)physical_address;
    (void)data;
    return Result<std::uint32_t>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::WritePhysical"));
#endif
}

Result<ProcessContext> KDbgBackend::GetProcessContext(std::uint32_t pid) {
#ifdef _WIN32
    if (pid == 0) {
        return Result<ProcessContext>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "PID 0 has no process context",
            "KDbgBackend::GetProcessContext"));
    }
    union Buffer {
        KDBG_PROCESS_CONTEXT_REQUEST request;
        KDBG_PROCESS_CONTEXT_RESPONSE response;
    } buffer{};
    buffer.request.Size = sizeof(KDBG_PROCESS_CONTEXT_REQUEST);
    buffer.request.ProcessId = pid;

    auto result = impl_->Ioctl(
        IOCTL_KDBG_GET_PROCESS_CONTEXT,
        &buffer,
        sizeof(KDBG_PROCESS_CONTEXT_REQUEST),
        sizeof(KDBG_PROCESS_CONTEXT_RESPONSE),
        "KDbgBackend::GetProcessContext");
    if (!result) {
        return Result<ProcessContext>::Failure(result.GetError());
    }
    if (result.Value() != sizeof(KDBG_PROCESS_CONTEXT_RESPONSE) ||
        buffer.response.Size != sizeof(KDBG_PROCESS_CONTEXT_RESPONSE) ||
        buffer.response.ProcessId != pid || buffer.response.Reserved != 0 ||
        (buffer.response.Flags &
            ~(KDBG_PROCESS_FLAG_CR3_VALID | KDBG_PROCESS_FLAG_WOW64)) != 0 ||
        (buffer.response.Flags & KDBG_PROCESS_FLAG_CR3_VALID) == 0 ||
        buffer.response.Eprocess == 0 ||
        buffer.response.DirectoryTableBase == 0 ||
        (buffer.response.DirectoryTableBase & 0xFFFULL) != 0) {
        return Result<ProcessContext>::Failure(MakeError(
            ErrorCode::ShortRead,
            "KDBG returned a short process context",
            "KDbgBackend::GetProcessContext"));
    }
    ProcessContext context{};
    context.pid = buffer.response.ProcessId;
    context.flags = buffer.response.Flags;
    context.eprocess = buffer.response.Eprocess;
    context.directory_table_base = buffer.response.DirectoryTableBase;
    context.wow64 = (buffer.response.Flags & KDBG_PROCESS_FLAG_WOW64) != 0;
    return Result<ProcessContext>::Success(context);
#else
    (void)pid;
    return Result<ProcessContext>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::GetProcessContext"));
#endif
}

Result<std::vector<std::uint8_t>> KDbgBackend::ReadProcessVirtual(
    std::uint32_t pid,
    std::uint64_t virtual_address,
    std::uint32_t length) {
#ifdef _WIN32
    if (pid == 0 || length == 0 || length > impl_->max_transfer ||
        !IsValidAddressRange(virtual_address, length)) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid process virtual read request",
            "KDbgBackend::ReadProcessVirtual"));
    }
    constexpr std::size_t header = offsetof(KDBG_PROCESS_MEMORY_REQUEST, Data);
    const std::size_t total = header + length;
    if (total > std::numeric_limits<DWORD>::max()) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Process read buffer size overflow",
            "KDbgBackend::ReadProcessVirtual"));
    }
    std::vector<std::uint8_t> buffer(total);
    auto* request = reinterpret_cast<KDBG_PROCESS_MEMORY_REQUEST*>(buffer.data());
    request->Size = static_cast<KDBG_U32>(header);
    request->ProcessId = pid;
    request->VirtualAddress = virtual_address;
    request->Length = length;

    auto result = impl_->Ioctl(
        IOCTL_KDBG_READ_PROCESS_MEMORY,
        buffer.data(),
        static_cast<DWORD>(header),
        static_cast<DWORD>(total),
        "KDbgBackend::ReadProcessVirtual");
    if (!result) {
        return Result<std::vector<std::uint8_t>>::Failure(result.GetError());
    }
    if (result.Value() != total || request->Size != header ||
        request->Flags != 0 || request->ProcessId != pid ||
        request->Length != length ||
        request->VirtualAddress != virtual_address ||
        request->Acknowledge != 0 || request->Reserved != 0 ||
        request->Transferred != length) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ShortRead,
            "KDBG returned a short process virtual read",
            "KDbgBackend::ReadProcessVirtual",
            0,
            length,
            request->Transferred));
    }
    std::vector<std::uint8_t> output(length);
    std::memcpy(output.data(), request->Data, length);
    return Result<std::vector<std::uint8_t>>::Success(std::move(output));
#else
    (void)pid;
    (void)virtual_address;
    (void)length;
    return Result<std::vector<std::uint8_t>>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::ReadProcessVirtual"));
#endif
}

Result<std::uint32_t> KDbgBackend::WriteProcessVirtual(
    std::uint32_t pid,
    std::uint64_t virtual_address,
    std::span<const std::uint8_t> data) {
#ifdef _WIN32
    if (!impl_->write_enabled) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "KDBG process write gate is locked",
            "KDbgBackend::WriteProcessVirtual"));
    }
    if (pid == 0 || data.empty() || data.size() > impl_->max_transfer ||
        !IsValidAddressRange(virtual_address, data.size())) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid process virtual write request",
            "KDbgBackend::WriteProcessVirtual"));
    }
    constexpr std::size_t header = offsetof(KDBG_PROCESS_MEMORY_REQUEST, Data);
    const std::size_t total = header + data.size();
    if (total > std::numeric_limits<DWORD>::max()) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Process write buffer size overflow",
            "KDbgBackend::WriteProcessVirtual"));
    }
    std::vector<std::uint8_t> buffer(total);
    auto* request = reinterpret_cast<KDBG_PROCESS_MEMORY_REQUEST*>(buffer.data());
    request->Size = static_cast<KDBG_U32>(total);
    request->ProcessId = pid;
    request->VirtualAddress = virtual_address;
    request->Length = static_cast<KDBG_U32>(data.size());
    request->Acknowledge = KDBG_WRITE_ACK_MAGIC;
    std::memcpy(request->Data, data.data(), data.size());

    auto result = impl_->Ioctl(
        IOCTL_KDBG_WRITE_PROCESS_MEMORY,
        buffer.data(),
        static_cast<DWORD>(total),
        static_cast<DWORD>(header),
        "KDbgBackend::WriteProcessVirtual");
    if (!result) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(result.GetError());
    }
    if (result.Value() != header || request->Size != total ||
        request->Flags != 0 || request->ProcessId != pid ||
        request->Length != data.size() ||
        request->VirtualAddress != virtual_address ||
        request->Acknowledge != KDBG_WRITE_ACK_MAGIC ||
        request->Reserved != 0 || request->Transferred != data.size()) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::ShortWrite,
            "KDBG returned a short process virtual write",
            "KDbgBackend::WriteProcessVirtual",
            0,
            data.size(),
            request->Transferred));
    }
    auto readback = ReadProcessVirtual(
        pid,
        virtual_address,
        static_cast<std::uint32_t>(data.size()));
    if (!readback || !std::equal(
            data.begin(), data.end(), readback.Value().begin())) {
        static_cast<void>(SetWriteEnabled(false));
        return Result<std::uint32_t>::Failure(
            readback
                ? MakeError(
                    ErrorCode::VerificationMismatch,
                    "KDBG process write read-back mismatch",
                    "KDbgBackend::WriteProcessVirtual",
                    0,
                    data.size(),
                    readback.Value().size())
                : readback.GetError());
    }
    return Result<std::uint32_t>::Success(request->Transferred);
#else
    (void)pid;
    (void)virtual_address;
    (void)data;
    return Result<std::uint32_t>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::WriteProcessVirtual"));
#endif
}

Result<std::vector<std::uint8_t>> KDbgBackend::ReadKernelVirtual(
    std::uint64_t virtual_address,
    std::uint32_t length) {
#ifdef _WIN32
    if (length == 0 || length > impl_->max_transfer ||
        !IsValidAddressRange(virtual_address, length)) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid kernel virtual read request",
            "KDbgBackend::ReadKernelVirtual"));
    }
    constexpr std::size_t header =
        offsetof(KDBG_KERNEL_VIRTUAL_READ_REQUEST, Data);
    const std::size_t total = header + length;
    if (total > std::numeric_limits<DWORD>::max()) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Kernel read buffer size overflow",
            "KDbgBackend::ReadKernelVirtual"));
    }
    std::vector<std::uint8_t> buffer(total);
    auto* request =
        reinterpret_cast<KDBG_KERNEL_VIRTUAL_READ_REQUEST*>(buffer.data());
    request->Size = static_cast<KDBG_U32>(header);
    request->VirtualAddress = virtual_address;
    request->Length = length;

    auto result = impl_->Ioctl(
        IOCTL_KDBG_READ_KERNEL_VIRTUAL,
        buffer.data(),
        static_cast<DWORD>(header),
        static_cast<DWORD>(total),
        "KDbgBackend::ReadKernelVirtual");
    if (!result) {
        return Result<std::vector<std::uint8_t>>::Failure(result.GetError());
    }
    if (result.Value() != total || request->Size != header ||
        request->Flags != 0 ||
        request->VirtualAddress != virtual_address ||
        request->Length != length || request->Transferred != length) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ShortRead,
            "KDBG returned a short kernel virtual read",
            "KDbgBackend::ReadKernelVirtual",
            0,
            length,
            request->Transferred));
    }
    std::vector<std::uint8_t> output(length);
    std::memcpy(output.data(), request->Data, length);
    return Result<std::vector<std::uint8_t>>::Success(std::move(output));
#else
    (void)virtual_address;
    (void)length;
    return Result<std::vector<std::uint8_t>>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::ReadKernelVirtual"));
#endif
}

Result<TranslationWalk> KDbgBackend::TranslateVirtual(
    std::uint64_t directory_table_base,
    std::uint64_t virtual_address) {
#ifdef _WIN32
    union Buffer {
        KDBG_TRANSLATE_REQUEST request;
        KDBG_TRANSLATE_RESPONSE response;
    } buffer{};
    buffer.request.Size = sizeof(KDBG_TRANSLATE_REQUEST);
    buffer.request.DirectoryTableBase = directory_table_base;
    buffer.request.VirtualAddress = virtual_address;
    buffer.request.Length = 1;

    auto result = impl_->Ioctl(
        IOCTL_KDBG_TRANSLATE_VIRTUAL,
        &buffer,
        sizeof(KDBG_TRANSLATE_REQUEST),
        sizeof(KDBG_TRANSLATE_RESPONSE),
        "KDbgBackend::TranslateVirtual");
    if (!result) {
        return Result<TranslationWalk>::Failure(result.GetError());
    }
    constexpr std::uint32_t valid_flags =
        KDBG_TRANSLATE_FLAG_LA57_ACTIVE |
        KDBG_TRANSLATE_FLAG_LARGE_PAGE |
        KDBG_TRANSLATE_FLAG_PRESENT |
        KDBG_TRANSLATE_FLAG_PROCESS_CR3;
    const auto& response = buffer.response;
    const bool paging_shape_valid =
        (response.PagingLevels == 4 &&
         (response.Flags & KDBG_TRANSLATE_FLAG_LA57_ACTIVE) == 0) ||
        (response.PagingLevels == 5 &&
         (response.Flags & KDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0);
    if (result.Value() != sizeof(KDBG_TRANSLATE_RESPONSE) ||
        response.Size != sizeof(KDBG_TRANSLATE_RESPONSE) ||
        (response.Flags & ~valid_flags) != 0 || !paging_shape_valid ||
        response.StepCount > KDBG_MAX_TRANSLATION_STEPS ||
        response.StepCount > response.PagingLevels ||
        response.StepCount == 0 ||
        response.RequestedLength != 1 ||
        response.VirtualAddress != virtual_address ||
        response.DirectoryTableBase == 0 ||
        (response.DirectoryTableBase & 0xFFFULL) != 0 ||
        (response.Flags & KDBG_TRANSLATE_FLAG_PROCESS_CR3) != 0 ||
        (((response.Flags & KDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0) !=
         impl_->la57) ||
        (directory_table_base != 0 &&
         response.DirectoryTableBase != directory_table_base)) {
        return Result<TranslationWalk>::Failure(MakeError(
            ErrorCode::AbiMismatch,
            "KDBG returned an invalid translation response",
            "KDbgBackend::TranslateVirtual"));
    }

    const bool translated = response.TranslatedLength != 0;
    if (translated) {
        const bool page_size_valid = response.PageSize == KDBG_PAGE_SIZE ||
            response.PageSize == 0x200000ULL ||
            response.PageSize == 0x40000000ULL;
        const bool large_page =
            (response.Flags & KDBG_TRANSLATE_FLAG_LARGE_PAGE) != 0;
        if ((response.Flags & KDBG_TRANSLATE_FLAG_PRESENT) == 0 ||
            response.TranslatedLength != 1 || !page_size_valid ||
            response.PageOffset >= response.PageSize ||
            (response.PhysicalAddress & (response.PageSize - 1ULL)) !=
                response.PageOffset ||
            response.PageBytes != response.PageSize - response.PageOffset ||
            large_page != (response.PageSize != KDBG_PAGE_SIZE)) {
            return Result<TranslationWalk>::Failure(MakeError(
                ErrorCode::AbiMismatch,
                "KDBG returned inconsistent translated-page metadata",
                "KDbgBackend::TranslateVirtual"));
        }
    } else if ((response.Flags &
                    (KDBG_TRANSLATE_FLAG_PRESENT |
                     KDBG_TRANSLATE_FLAG_LARGE_PAGE)) != 0 ||
               response.PhysicalAddress != 0 || response.PageSize != 0 ||
               response.PageOffset != 0 || response.PageBytes != 0) {
        return Result<TranslationWalk>::Failure(MakeError(
            ErrorCode::AbiMismatch,
            "KDBG returned inconsistent non-present translation metadata",
            "KDbgBackend::TranslateVirtual"));
    }

    TranslationWalk walk{};
    walk.directory_table_base = response.DirectoryTableBase;
    walk.virtual_address = response.VirtualAddress;
    walk.physical_address = response.PhysicalAddress;
    walk.page_size = response.PageSize;
    walk.page_offset = response.PageOffset;
    walk.la57 = (response.Flags & KDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
    walk.translated = translated;
    walk.steps.reserve(response.StepCount);

    for (std::uint32_t index = 0;
         index < response.StepCount && index < KDBG_MAX_TRANSLATION_STEPS;
         ++index) {
        const auto& source = response.Steps[index];
        TranslationStep step{};
        const std::uint32_t expected_level = response.PagingLevels - index;
        const std::uint32_t expected_index = static_cast<std::uint32_t>(
            (virtual_address >> (12U + 9U * (expected_level - 1U))) &
            0x1FFULL);
        if (!TryToPagingLevel(source.Level, &step.level) ||
            source.Level != expected_level || source.Index != expected_index ||
            source.Index > 0x1FFU ||
            (source.EntryPhysicalAddress & 0x7ULL) != 0) {
            return Result<TranslationWalk>::Failure(MakeError(
                ErrorCode::AbiMismatch,
                "KDBG returned an invalid translation step",
                "KDbgBackend::TranslateVirtual"));
        }
        step.index = static_cast<std::uint16_t>(source.Index);
        step.entry_physical_address = source.EntryPhysicalAddress;
        step.entry_value = source.EntryValue;
        step.flags = DecodePageEntry(source.EntryValue);
        step.next_pfn = step.flags.pfn;
        walk.steps.push_back(step);
    }
    return Result<TranslationWalk>::Success(std::move(walk));
#else
    (void)directory_table_base;
    (void)virtual_address;
    return Result<TranslationWalk>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Windows only",
        "KDbgBackend::TranslateVirtual"));
#endif
}

}  // namespace kdbg

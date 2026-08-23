#include <ntifs.h>
#include <ntddk.h>
#include <wdmsec.h>
#include <intrin.h>
#include <initguid.h>

#include "../../shared/KDbgIoctl.h"

#pragma intrinsic(__readcr3)
#pragma intrinsic(__readcr4)

DEFINE_GUID(
    GUID_DEVCLASS_KDBG,
    0x2dc4a7b5, 0xebd7, 0x4c83,
    0x95, 0x5d, 0x52, 0x10, 0x8a, 0xb7, 0x2f, 0x61);

namespace {

constexpr ULONG kContextTag = 'CDBK';
constexpr UINT64 kPageMask = 0x000FFFFFFFFFF000ULL;

struct FileContext {
    FAST_MUTEX WriteLock;
    volatile LONG WriteEnabled;
    volatile LONG CleanedUp;
    PEPROCESS OwnerProcess;
    ULONG OwnerPid;
};

struct DriverState {
    PDEVICE_OBJECT DeviceObject;
    FAST_MUTEX OwnerLock;
    PEPROCESS OwnerProcess;
    volatile LONG OwnerPid;
    volatile LONG OpenHandleCount;
    volatile LONG64 SuccessfulReads;
    volatile LONG64 SuccessfulWrites;
    volatile LONG64 RejectedWrites;
    volatile LONG LastPhysicalWriteStatus;
    volatile LONG LastPhysicalWriteStage;
    volatile LONG LastPhysicalWriteTransferred;
};

DriverState g_state{};

class FastMutexGuard {
public:
    explicit FastMutexGuard(PFAST_MUTEX mutex) noexcept : mutex_(mutex) {
        ExAcquireFastMutex(mutex_);
    }
    ~FastMutexGuard() { ExReleaseFastMutex(mutex_); }
    FastMutexGuard(const FastMutexGuard&) = delete;
    FastMutexGuard& operator=(const FastMutexGuard&) = delete;

private:
    PFAST_MUTEX mutex_;
};

NTSTATUS Complete(PIRP irp, NTSTATUS status, ULONG_PTR information = 0) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

FileContext* GetFileContext(PIRP irp) noexcept {
    const auto stack = IoGetCurrentIrpStackLocation(irp);
    return static_cast<FileContext*>(stack->FileObject->FsContext);
}

bool CheckedEnd(UINT64 address, SIZE_T length, UINT64* end_exclusive) noexcept {
    if (length == 0 || end_exclusive == nullptr) {
        return false;
    }
    if (address > MAXUINT64 - static_cast<UINT64>(length)) {
        return false;
    }
    *end_exclusive = address + static_cast<UINT64>(length);
    return true;
}

bool CheckedAddUlong(ULONG left, ULONG right, ULONG* result) noexcept {
    if (result == nullptr || left > MAXULONG - right) {
        return false;
    }
    *result = left + right;
    return true;
}

bool IsPageBounded(UINT64 address, SIZE_T length) noexcept {
    UINT64 end_exclusive = 0;
    return CheckedEnd(address, length, &end_exclusive) &&
        (address & ~0xFFFULL) == ((end_exclusive - 1ULL) & ~0xFFFULL);
}

bool IsControllerContext(FileContext* context) noexcept {
    if (context == nullptr ||
        InterlockedCompareExchange(&context->CleanedUp, 0, 0) != 0) {
        return false;
    }
    return context->OwnerProcess == PsGetCurrentProcess() &&
        context->OwnerPid == HandleToULong(PsGetCurrentProcessId());
}

void SetPhysicalWriteStage(ULONG stage) noexcept {
    InterlockedExchange(
        &g_state.LastPhysicalWriteStage,
        static_cast<LONG>(stage));
}

void SetPhysicalWriteResult(
    NTSTATUS status,
    SIZE_T transferred) noexcept {
    InterlockedExchange(
        &g_state.LastPhysicalWriteStatus,
        static_cast<LONG>(status));
    InterlockedExchange(
        &g_state.LastPhysicalWriteTransferred,
        static_cast<LONG>(min(
            transferred,
            static_cast<SIZE_T>(MAXLONG))));
}

void CleanupFileContext(FileContext* context) noexcept {
    if (context == nullptr ||
        InterlockedCompareExchange(&context->CleanedUp, 1, 0) != 0) {
        return;
    }

    {
        FastMutexGuard write_guard(&context->WriteLock);
        InterlockedExchange(&context->WriteEnabled, 0);
    }
    ExAcquireFastMutex(&g_state.OwnerLock);
    if (g_state.OpenHandleCount > 0) {
        --g_state.OpenHandleCount;
    }
    if (g_state.OpenHandleCount == 0) {
        g_state.OwnerPid = 0;
        g_state.OwnerProcess = nullptr;
    }
    ExReleaseFastMutex(&g_state.OwnerLock);
}

bool IsUserRange(UINT64 address, SIZE_T length) noexcept {
    UINT64 end_exclusive = 0;
    if (address == 0 || !CheckedEnd(address, length, &end_exclusive)) {
        return false;
    }
    const UINT64 highest_user = static_cast<UINT64>(
        reinterpret_cast<ULONG_PTR>(MmHighestUserAddress));
    return address <= highest_user &&
           (end_exclusive - 1ULL) <= highest_user;
}

bool IsPhysicalRamRange(UINT64 address, SIZE_T length) {
    UINT64 end = 0;
    if (!CheckedEnd(address, length, &end)) {
        return false;
    }

    PPHYSICAL_MEMORY_RANGE ranges =
        MmGetPhysicalMemoryRangesEx2(nullptr, 0);
    if (ranges == nullptr) {
        return false;
    }

    bool valid = false;
    for (ULONG index = 0;
         ranges[index].BaseAddress.QuadPart != 0 ||
         ranges[index].NumberOfBytes.QuadPart != 0;
         ++index) {
        const UINT64 base =
            static_cast<UINT64>(ranges[index].BaseAddress.QuadPart);
        const UINT64 bytes =
            static_cast<UINT64>(ranges[index].NumberOfBytes.QuadPart);
        if (bytes == 0 || base > MAXUINT64 - bytes) {
            continue;
        }
        if (address >= base && end <= base + bytes) {
            valid = true;
            break;
        }
    }

    ExFreePool(ranges);
    return valid;
}

NTSTATUS ReadPhysical(
    UINT64 physical_address,
    PVOID destination,
    SIZE_T length,
    PSIZE_T transferred) {
    if (destination == nullptr || transferred == nullptr ||
        length == 0 || length > KDBG_MAX_TRANSFER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    *transferred = 0;
    if (!IsPhysicalRamRange(physical_address, length)) {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    MM_COPY_ADDRESS source{};
    source.PhysicalAddress.QuadPart =
        static_cast<LONGLONG>(physical_address);
    return MmCopyMemory(
        destination,
        source,
        length,
        MM_COPY_MEMORY_PHYSICAL,
        transferred);
}

NTSTATUS ReadPhysicalU64(UINT64 physical_address, UINT64* value) {
    if (value == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T copied = 0;
    const NTSTATUS status =
        ReadPhysical(physical_address, value, sizeof(*value), &copied);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return copied == sizeof(*value) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

NTSTATUS WritePhysical(
    UINT64 physical_address,
    const UCHAR* source,
    SIZE_T length,
    PSIZE_T transferred) {
    if (source == nullptr || transferred == nullptr ||
        length == 0 || length > KDBG_MAX_TRANSFER_SIZE ||
        !IsPageBounded(physical_address, length)) {
        return STATUS_INVALID_PARAMETER;
    }
    *transferred = 0;
    if (!IsPhysicalRamRange(physical_address, length)) {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    SIZE_T remaining = length;
    UINT64 current = physical_address;
    const UCHAR* input = source;

    while (remaining != 0) {
        const SIZE_T page_offset = static_cast<SIZE_T>(current & 0xFFFULL);
        const SIZE_T chunk = min(
            remaining,
            static_cast<SIZE_T>(PAGE_SIZE) - page_offset);

        SetPhysicalWriteStage(KDBG_PHYSICAL_WRITE_STAGE_MAPPING);
        PHYSICAL_ADDRESS exact{};
        exact.QuadPart = static_cast<LONGLONG>(current);
        PVOID mapping = MmMapIoSpaceEx(
            exact,
            chunk,
            PAGE_READWRITE);
        if (mapping == nullptr) {
            return *transferred == 0
                ? STATUS_INSUFFICIENT_RESOURCES
                : STATUS_PARTIAL_COPY;
        }

        SetPhysicalWriteStage(KDBG_PHYSICAL_WRITE_STAGE_COPYING);
        NTSTATUS copy_status = STATUS_SUCCESS;
        __try {
            RtlCopyMemory(mapping, input, chunk);
            KeMemoryBarrier();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            copy_status = GetExceptionCode();
        }

        MmUnmapIoSpace(mapping, chunk);

        if (!NT_SUCCESS(copy_status)) {
            return *transferred == 0 ? copy_status : STATUS_PARTIAL_COPY;
        }

        *transferred += chunk;
        current += chunk;
        input += chunk;
        remaining -= chunk;
    }

    return STATUS_SUCCESS;
}

NTSTATUS ReadProcessMemory(
    PEPROCESS process,
    UINT64 virtual_address,
    PVOID destination,
    SIZE_T length,
    PSIZE_T transferred) {
    if (process == nullptr || destination == nullptr || transferred == nullptr ||
        !IsUserRange(virtual_address, length)) {
        return STATUS_INVALID_PARAMETER;
    }
    *transferred = 0;

    KAPC_STATE apc{};
    KeStackAttachProcess(process, &apc);
    MM_COPY_ADDRESS source{};
    source.VirtualAddress = reinterpret_cast<PVOID>(virtual_address);
    const NTSTATUS status = MmCopyMemory(
        destination,
        source,
        length,
        MM_COPY_MEMORY_VIRTUAL,
        transferred);
    KeUnstackDetachProcess(&apc);
    return status;
}

NTSTATUS WriteProcessMemory(
    PEPROCESS process,
    UINT64 virtual_address,
    const UCHAR* source,
    SIZE_T length,
    PSIZE_T transferred) {
    if (process == nullptr || source == nullptr || transferred == nullptr ||
        length > MAXULONG || !IsUserRange(virtual_address, length)) {
        return STATUS_INVALID_PARAMETER;
    }
    *transferred = 0;

    PMDL mdl = IoAllocateMdl(
        reinterpret_cast<PVOID>(virtual_address),
        static_cast<ULONG>(length),
        FALSE,
        FALSE,
        nullptr);
    if (mdl == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

    KAPC_STATE apc{};
    KeStackAttachProcess(process, &apc);
    NTSTATUS status = STATUS_SUCCESS;
    bool pages_locked = false;
    __try {
        MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
        pages_locked = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (NT_SUCCESS(status)) {
        PVOID mapping = MmGetSystemAddressForMdlSafe(
            mdl,
            NormalPagePriority | MdlMappingNoExecute);
        if (mapping == nullptr) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            RtlCopyMemory(mapping, source, length);
            *transferred = length;
        }
    }

    if (pages_locked) MmUnlockPages(mdl);
    KeUnstackDetachProcess(&apc);
    IoFreeMdl(mdl);
    return status;
}

struct ProcessReference {
    PEPROCESS Value{nullptr};
    ~ProcessReference() {
        if (Value != nullptr) ObDereferenceObject(Value);
    }
};

NTSTATUS ReferenceProcessCr3(
    ULONG process_id,
    PEPROCESS* referenced_process,
    UINT64* directory_table_base,
    ULONG* flags) {
    if (process_id == 0 || referenced_process == nullptr ||
        directory_table_base == nullptr || flags == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

#if !defined(_WIN64)
    UNREFERENCED_PARAMETER(process_id);
    return STATUS_NOT_SUPPORTED;
#else
    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(
        ULongToHandle(process_id),
        &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KAPC_STATE apc{};
    KeStackAttachProcess(process, &apc);
    const UINT64 cr3 = __readcr3() & ~0xFFFULL;
    KeUnstackDetachProcess(&apc);

    *referenced_process = process;
    *directory_table_base = cr3;
    *flags = cr3 != 0 ? KDBG_PROCESS_FLAG_CR3_VALID : 0;
    return cr3 != 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
#endif
}

NTSTATUS GetProcessCr3(
    ULONG process_id,
    UINT64* eprocess,
    UINT64* directory_table_base,
    ULONG* flags) {
    if (eprocess == nullptr) return STATUS_INVALID_PARAMETER;
    ProcessReference process{};
    const NTSTATUS status = ReferenceProcessCr3(
        process_id,
        &process.Value,
        directory_table_base,
        flags);
    if (NT_SUCCESS(status)) {
        *eprocess = reinterpret_cast<UINT64>(process.Value);
    }
    return status;
}

bool IsCanonical(UINT64 address, bool la57) noexcept {
    if (la57) {
        const UINT64 sign = (address >> 56) & 1ULL;
        const UINT64 upper = address >> 57;
        return sign == 0 ? upper == 0 : upper == 0x7FULL;
    }
    const UINT64 sign = (address >> 47) & 1ULL;
    const UINT64 upper = address >> 48;
    return sign == 0 ? upper == 0 : upper == 0xFFFFULL;
}

NTSTATUS TranslateVirtual(
    const KDBG_TRANSLATE_REQUEST* request,
    KDBG_TRANSLATE_RESPONSE* response) {
    if (request == nullptr || response == nullptr ||
        request->Size != sizeof(KDBG_TRANSLATE_REQUEST) ||
        request->Flags != 0 ||
        request->Length == 0 ||
        request->Length > KDBG_MAX_TRANSFER_SIZE ||
        (request->ProcessId != 0 && request->DirectoryTableBase != 0) ||
        (request->DirectoryTableBase & 0xFFFULL) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

#if !defined(_WIN64)
    UNREFERENCED_PARAMETER(request);
    UNREFERENCED_PARAMETER(response);
    return STATUS_NOT_SUPPORTED;
#else
    RtlZeroMemory(response, sizeof(*response));
    response->Size = sizeof(*response);
    response->VirtualAddress = request->VirtualAddress;
    response->RequestedLength = request->Length;

    UINT64 dtb = request->DirectoryTableBase & ~0xFFFULL;
    ProcessReference retained_process{};
    if (dtb == 0 && request->ProcessId != 0) {
        ULONG process_flags = 0;
        NTSTATUS status = ReferenceProcessCr3(
            request->ProcessId,
            &retained_process.Value,
            &dtb,
            &process_flags);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        UNREFERENCED_PARAMETER(process_flags);
        response->Flags |= KDBG_TRANSLATE_FLAG_PROCESS_CR3;
    }
    if (dtb == 0) {
        dtb = __readcr3() & ~0xFFFULL;
    }

    const bool la57 = (__readcr4() & (1ULL << 12)) != 0;
    if (!IsCanonical(request->VirtualAddress, la57)) {
        return STATUS_INVALID_ADDRESS;
    }

    response->DirectoryTableBase = dtb;
    response->PagingLevels = la57 ? 5u : 4u;
    if (la57) {
        response->Flags |= KDBG_TRANSLATE_FLAG_LA57_ACTIVE;
    }

    const ULONG indices[5] = {
        static_cast<ULONG>((request->VirtualAddress >> 48) & 0x1FFULL),
        static_cast<ULONG>((request->VirtualAddress >> 39) & 0x1FFULL),
        static_cast<ULONG>((request->VirtualAddress >> 30) & 0x1FFULL),
        static_cast<ULONG>((request->VirtualAddress >> 21) & 0x1FFULL),
        static_cast<ULONG>((request->VirtualAddress >> 12) & 0x1FFULL)
    };
    const ULONG levels[5] = {
        KDBG_PAGING_LEVEL_PML5,
        KDBG_PAGING_LEVEL_PML4,
        KDBG_PAGING_LEVEL_PDPT,
        KDBG_PAGING_LEVEL_PD,
        KDBG_PAGING_LEVEL_PT
    };
    const ULONG start = la57 ? 0u : 1u;

    UINT64 table = dtb;
    for (ULONG slot = start; slot < RTL_NUMBER_OF(indices); ++slot) {
        const UINT64 entry_address =
            table + static_cast<UINT64>(indices[slot]) * sizeof(UINT64);
        UINT64 entry = 0;
        NTSTATUS status = ReadPhysicalU64(entry_address, &entry);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (response->StepCount >= KDBG_MAX_TRANSLATION_STEPS) {
            return STATUS_INTERNAL_ERROR;
        }
        KDBG_TRANSLATION_STEP& step =
            response->Steps[response->StepCount++];
        step.Level = levels[slot];
        step.Index = indices[slot];
        step.EntryPhysicalAddress = entry_address;
        step.EntryValue = entry;

        if ((entry & 1ULL) == 0) {
            return STATUS_SUCCESS;
        }

        if (levels[slot] == KDBG_PAGING_LEVEL_PDPT &&
            (entry & (1ULL << 7)) != 0) {
            constexpr UINT64 mask = 0x000FFFFFC0000000ULL;
            response->PageSize = 0x40000000ULL;
            response->PageOffset =
                request->VirtualAddress & (response->PageSize - 1ULL);
            response->PhysicalAddress =
                (entry & mask) | response->PageOffset;
            response->Flags |=
                KDBG_TRANSLATE_FLAG_PRESENT |
                KDBG_TRANSLATE_FLAG_LARGE_PAGE;
            response->PageBytes = response->PageSize - response->PageOffset;
            response->TranslatedLength = static_cast<KDBG_U32>(min(
                static_cast<UINT64>(request->Length),
                response->PageBytes));
            return STATUS_SUCCESS;
        }

        if (levels[slot] == KDBG_PAGING_LEVEL_PD &&
            (entry & (1ULL << 7)) != 0) {
            constexpr UINT64 mask = 0x000FFFFFFFE00000ULL;
            response->PageSize = 0x200000ULL;
            response->PageOffset =
                request->VirtualAddress & (response->PageSize - 1ULL);
            response->PhysicalAddress =
                (entry & mask) | response->PageOffset;
            response->Flags |=
                KDBG_TRANSLATE_FLAG_PRESENT |
                KDBG_TRANSLATE_FLAG_LARGE_PAGE;
            response->PageBytes = response->PageSize - response->PageOffset;
            response->TranslatedLength = static_cast<KDBG_U32>(min(
                static_cast<UINT64>(request->Length),
                response->PageBytes));
            return STATUS_SUCCESS;
        }

        if (levels[slot] == KDBG_PAGING_LEVEL_PT) {
            response->PageSize = PAGE_SIZE;
            response->PageOffset = request->VirtualAddress & 0xFFFULL;
            response->PhysicalAddress =
                (entry & kPageMask) | response->PageOffset;
            response->Flags |=
                KDBG_TRANSLATE_FLAG_PRESENT;
            response->PageBytes = response->PageSize - response->PageOffset;
            response->TranslatedLength = static_cast<KDBG_U32>(min(
                static_cast<UINT64>(request->Length),
                response->PageBytes));
            return STATUS_SUCCESS;
        }

        table = entry & kPageMask;
    }

    return STATUS_SUCCESS;
#endif
}

NTSTATUS DispatchUnsupported(PDEVICE_OBJECT, PIRP irp) {
    return Complete(irp, STATUS_INVALID_DEVICE_REQUEST);
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT, PIRP irp) {
    const ULONG pid = HandleToULong(PsGetCurrentProcessId());
    PEPROCESS owner_process = PsGetCurrentProcess();
    auto* context = static_cast<FileContext*>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(FileContext),
        kContextTag));
    if (context == nullptr) {
        return Complete(irp, STATUS_INSUFFICIENT_RESOURCES);
    }
    RtlZeroMemory(context, sizeof(*context));
    ExInitializeFastMutex(&context->WriteLock);
    ObReferenceObject(owner_process);
    context->OwnerProcess = owner_process;
    context->OwnerPid = pid;

    NTSTATUS status = STATUS_SUCCESS;
    ExAcquireFastMutex(&g_state.OwnerLock);
    if (g_state.OwnerProcess != nullptr &&
        g_state.OwnerProcess != owner_process) {
        status = STATUS_SHARING_VIOLATION;
    } else {
        g_state.OwnerProcess = owner_process;
        g_state.OwnerPid = static_cast<LONG>(pid);
        ++g_state.OpenHandleCount;
    }
    ExReleaseFastMutex(&g_state.OwnerLock);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(owner_process);
        ExFreePoolWithTag(context, kContextTag);
        return Complete(irp, status);
    }

    const auto stack = IoGetCurrentIrpStackLocation(irp);
    stack->FileObject->FsContext = context;
    return Complete(irp, STATUS_SUCCESS);
}

NTSTATUS DispatchCleanup(PDEVICE_OBJECT, PIRP irp) {
    CleanupFileContext(GetFileContext(irp));
    return Complete(irp, STATUS_SUCCESS);
}

NTSTATUS DispatchClose(PDEVICE_OBJECT, PIRP irp) {
    const auto stack = IoGetCurrentIrpStackLocation(irp);
    auto* context = static_cast<FileContext*>(stack->FileObject->FsContext);
    if (context != nullptr) {
        CleanupFileContext(context);
        ObDereferenceObject(context->OwnerProcess);
        context->OwnerProcess = nullptr;
        ExFreePoolWithTag(context, kContextTag);
        stack->FileObject->FsContext = nullptr;
    }
    return Complete(irp, STATUS_SUCCESS);
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT, PIRP irp) {
    const auto stack = IoGetCurrentIrpStackLocation(irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG input_length =
        stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG output_length =
        stack->Parameters.DeviceIoControl.OutputBufferLength;
    auto* buffer = static_cast<UCHAR*>(irp->AssociatedIrp.SystemBuffer);
    auto* context = GetFileContext(irp);

    if (!IsControllerContext(context)) {
        if (context != nullptr &&
            (code == IOCTL_KDBG_SET_WRITE_MODE ||
             code == IOCTL_KDBG_WRITE_PHYSICAL ||
             code == IOCTL_KDBG_WRITE_PROCESS_MEMORY)) {
            FastMutexGuard write_guard(&context->WriteLock);
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
        }
        return Complete(irp, STATUS_ACCESS_DENIED);
    }

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    switch (code) {
    case IOCTL_KDBG_GET_VERSION: {
        if (buffer == nullptr || input_length != 0 ||
            output_length != sizeof(KDBG_VERSION_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KDBG_VERSION_RESPONSE response{};
        response.Size = sizeof(response);
        response.AbiVersion = KDBG_ABI_VERSION;
        response.DriverMajor = KDBG_DRIVER_VERSION_MAJOR;
        response.DriverMinor = KDBG_DRIVER_VERSION_MINOR;
        response.MaxTransferSize = KDBG_MAX_TRANSFER_SIZE;
        response.Flags =
            KDBG_VERSION_FLAG_PHYSICAL_READ |
            KDBG_VERSION_FLAG_PHYSICAL_WRITE |
            KDBG_VERSION_FLAG_PROCESS_MEMORY |
            KDBG_VERSION_FLAG_VTOP |
            KDBG_VERSION_FLAG_SECURE_OPEN |
            KDBG_VERSION_FLAG_SINGLE_OWNER;
#if defined(_WIN64)
        if ((__readcr4() & (1ULL << 12)) != 0) {
            response.Flags |= KDBG_VERSION_FLAG_LA57_ACTIVE;
        }
#endif
        RtlCopyMemory(buffer, &response, sizeof(response));
        status = STATUS_SUCCESS;
        information = sizeof(response);
        break;
    }

    case IOCTL_KDBG_GET_SESSION_STATUS: {
        if (buffer == nullptr || input_length != 0 ||
            output_length != sizeof(KDBG_SESSION_STATUS_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KDBG_SESSION_STATUS_RESPONSE response{};
        response.Size = sizeof(response);
        response.OwnerPid = static_cast<KDBG_U32>(
            InterlockedCompareExchange(&g_state.OwnerPid, 0, 0));
        response.CurrentPid = HandleToULong(PsGetCurrentProcessId());
        response.OpenHandleCount = static_cast<KDBG_U32>(
            InterlockedCompareExchange(&g_state.OpenHandleCount, 0, 0));
        if (response.OwnerPid != 0) {
            response.Flags |= KDBG_SESSION_FLAG_OWNER_ACTIVE;
        }
        if (InterlockedCompareExchange(&context->WriteEnabled, 0, 0) != 0) {
            response.Flags |= KDBG_SESSION_FLAG_WRITE_ENABLED;
        }
        response.SuccessfulReads = static_cast<KDBG_U64>(
            InterlockedCompareExchange64(&g_state.SuccessfulReads, 0, 0));
        response.SuccessfulWrites = static_cast<KDBG_U64>(
            InterlockedCompareExchange64(&g_state.SuccessfulWrites, 0, 0));
        response.RejectedWrites = static_cast<KDBG_U64>(
            InterlockedCompareExchange64(&g_state.RejectedWrites, 0, 0));
        response.LastPhysicalWriteStatus = static_cast<KDBG_U32>(
            InterlockedCompareExchange(
                &g_state.LastPhysicalWriteStatus, 0, 0));
        response.LastPhysicalWriteStage = static_cast<KDBG_U32>(
            InterlockedCompareExchange(
                &g_state.LastPhysicalWriteStage, 0, 0));
        response.LastPhysicalWriteTransferred = static_cast<KDBG_U32>(
            InterlockedCompareExchange(
                &g_state.LastPhysicalWriteTransferred, 0, 0));
        RtlCopyMemory(buffer, &response, sizeof(response));
        status = STATUS_SUCCESS;
        information = sizeof(response);
        break;
    }

    case IOCTL_KDBG_SET_WRITE_MODE: {
        FastMutexGuard write_guard(&context->WriteLock);
        if (buffer == nullptr ||
            input_length != sizeof(KDBG_WRITE_MODE_REQUEST) ||
            output_length != 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        const auto* request =
            reinterpret_cast<const KDBG_WRITE_MODE_REQUEST*>(buffer);
        if (request->Size != sizeof(*request) || request->EnableWrite > 1 ||
            request->Acknowledge != KDBG_WRITE_ACK_MAGIC ||
            context == nullptr) {
            if (context != nullptr) {
                InterlockedExchange(&context->WriteEnabled, 0);
            }
            InterlockedIncrement64(&g_state.RejectedWrites);
            status = STATUS_ACCESS_DENIED;
            break;
        }
        InterlockedExchange(
            &context->WriteEnabled,
            request->EnableWrite != 0 ? 1 : 0);
        status = STATUS_SUCCESS;
        information = 0;
        break;
    }

    case IOCTL_KDBG_GET_PHYSICAL_RANGES: {
        if (buffer == nullptr || input_length != 0 ||
            output_length != sizeof(KDBG_PHYSICAL_RANGES_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PPHYSICAL_MEMORY_RANGE ranges =
            MmGetPhysicalMemoryRangesEx2(nullptr, 0);
        if (ranges == nullptr) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        auto* response =
            reinterpret_cast<KDBG_PHYSICAL_RANGES_RESPONSE*>(buffer);
        RtlZeroMemory(response, sizeof(*response));
        response->Size = sizeof(*response);
        bool invalid_ranges = false;
        bool truncated = false;
        for (ULONG index = 0;
             ranges[index].BaseAddress.QuadPart != 0 ||
             ranges[index].NumberOfBytes.QuadPart != 0;
             ++index) {
            if (ranges[index].BaseAddress.QuadPart < 0 ||
                ranges[index].NumberOfBytes.QuadPart < 0) {
                invalid_ranges = true;
                break;
            }
            const UINT64 base =
                static_cast<UINT64>(ranges[index].BaseAddress.QuadPart);
            const UINT64 bytes =
                static_cast<UINT64>(ranges[index].NumberOfBytes.QuadPart);
            if (bytes == 0 || base > MAXUINT64 - bytes ||
                response->TotalBytes > MAXUINT64 - bytes) {
                invalid_ranges = true;
                break;
            }
            response->TotalBytes += bytes;
            if (response->RangeCount != 0) {
                auto& previous =
                    response->Ranges[response->RangeCount - 1];
                const UINT64 previous_end =
                    previous.BaseAddress + previous.ByteCount;
                if (base < previous_end) {
                    invalid_ranges = true;
                    break;
                }
                if (base == previous_end) {
                    previous.ByteCount += bytes;
                    continue;
                }
            }
            if (response->RangeCount >= KDBG_MAX_PHYSICAL_RANGES) {
                truncated = true;
                break;
            }
            auto& item = response->Ranges[response->RangeCount++];
            item.BaseAddress = base;
            item.ByteCount = bytes;
        }
        ExFreePool(ranges);
        if (invalid_ranges) {
            status = STATUS_INTEGER_OVERFLOW;
            break;
        }
        if (truncated) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }
        status = STATUS_SUCCESS;
        information = sizeof(*response);
        break;
    }

    case IOCTL_KDBG_READ_PHYSICAL: {
        const ULONG header = FIELD_OFFSET(KDBG_PHYSICAL_READ_REQUEST, Data);
        if (buffer == nullptr || input_length != header || output_length < header) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto* request =
            reinterpret_cast<KDBG_PHYSICAL_READ_REQUEST*>(buffer);
        ULONG total = 0;
        if (request->Size != header || request->Length == 0 ||
            request->Flags != 0 || request->Transferred != 0 ||
            request->Length > KDBG_MAX_TRANSFER_SIZE ||
            !CheckedAddUlong(header, request->Length, &total) ||
            output_length != total) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        SIZE_T copied = 0;
        status = ReadPhysical(
            request->PhysicalAddress,
            request->Data,
            request->Length,
            &copied);
        request->Transferred = static_cast<KDBG_U32>(copied);
        information = header + copied;
        if (NT_SUCCESS(status) && copied == request->Length) {
            InterlockedIncrement64(&g_state.SuccessfulReads);
        }
        break;
    }

    case IOCTL_KDBG_WRITE_PHYSICAL: {
        FastMutexGuard write_guard(&context->WriteLock);
        SetPhysicalWriteStage(KDBG_PHYSICAL_WRITE_STAGE_VALIDATION);
        SetPhysicalWriteResult(STATUS_PENDING, 0);
        const ULONG header = FIELD_OFFSET(KDBG_PHYSICAL_WRITE_REQUEST, Data);
        if (buffer == nullptr || input_length < header || output_length != header) {
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
            status = STATUS_BUFFER_TOO_SMALL;
            SetPhysicalWriteResult(status, 0);
            break;
        }
        auto* request =
            reinterpret_cast<KDBG_PHYSICAL_WRITE_REQUEST*>(buffer);
        ULONG total = 0;
        if (request->Length == 0 ||
            !CheckedAddUlong(header, request->Length, &total) ||
            request->Size != total || request->Flags != 0 ||
            request->Transferred != 0 ||
            request->Length > KDBG_MAX_TRANSFER_SIZE ||
            input_length != total ||
            !IsPageBounded(request->PhysicalAddress, request->Length)) {
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
            status = STATUS_INVALID_PARAMETER;
            SetPhysicalWriteResult(status, 0);
            break;
        }
        if (InterlockedCompareExchange(&context->WriteEnabled, 0, 0) == 0 ||
            request->Acknowledge != KDBG_WRITE_ACK_MAGIC) {
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
            status = STATUS_ACCESS_DENIED;
            SetPhysicalWriteResult(status, 0);
            break;
        }
        SIZE_T written = 0;
        status = WritePhysical(
            request->PhysicalAddress,
            request->Data,
            request->Length,
            &written);
        request->Transferred = static_cast<KDBG_U32>(written);
        information = header;
        if (NT_SUCCESS(status) && written == request->Length) {
            SetPhysicalWriteStage(KDBG_PHYSICAL_WRITE_STAGE_COMPLETE);
            InterlockedIncrement64(&g_state.SuccessfulWrites);
        } else {
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
            if (NT_SUCCESS(status)) {
                status = STATUS_PARTIAL_COPY;
            }
        }
        SetPhysicalWriteResult(status, written);
        break;
    }

    case IOCTL_KDBG_GET_PROCESS_CONTEXT: {
        if (buffer == nullptr ||
            input_length != sizeof(KDBG_PROCESS_CONTEXT_REQUEST) ||
            output_length != sizeof(KDBG_PROCESS_CONTEXT_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        const auto request =
            *reinterpret_cast<const KDBG_PROCESS_CONTEXT_REQUEST*>(buffer);
        if (request.Size != sizeof(request) || request.ProcessId == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        KDBG_PROCESS_CONTEXT_RESPONSE response{};
        response.Size = sizeof(response);
        response.ProcessId = request.ProcessId;
        status = GetProcessCr3(
            request.ProcessId,
            &response.Eprocess,
            &response.DirectoryTableBase,
            &response.Flags);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(buffer, &response, sizeof(response));
            information = sizeof(response);
        }
        break;
    }

    case IOCTL_KDBG_TRANSLATE_VIRTUAL: {
        if (buffer == nullptr ||
            input_length != sizeof(KDBG_TRANSLATE_REQUEST) ||
            output_length != sizeof(KDBG_TRANSLATE_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        const auto request =
            *reinterpret_cast<const KDBG_TRANSLATE_REQUEST*>(buffer);
        KDBG_TRANSLATE_RESPONSE response{};
        status = TranslateVirtual(&request, &response);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(buffer, &response, sizeof(response));
            information = sizeof(response);
            InterlockedIncrement64(&g_state.SuccessfulReads);
        }
        break;
    }

    case IOCTL_KDBG_READ_PROCESS_MEMORY: {
        const ULONG header = FIELD_OFFSET(KDBG_PROCESS_MEMORY_REQUEST, Data);
        if (buffer == nullptr || input_length != header || output_length < header) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto* request =
            reinterpret_cast<KDBG_PROCESS_MEMORY_REQUEST*>(buffer);
        ULONG total = 0;
        if (request->Size != header || request->ProcessId == 0 ||
            request->Flags != 0 || request->Reserved != 0 ||
            request->Acknowledge != 0 || request->Transferred != 0 ||
            request->Length == 0 ||
            request->Length > KDBG_MAX_TRANSFER_SIZE ||
            !IsUserRange(request->VirtualAddress, request->Length) ||
            !CheckedAddUlong(header, request->Length, &total) ||
            output_length != total) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PEPROCESS process = nullptr;
        status = PsLookupProcessByProcessId(
            ULongToHandle(request->ProcessId),
            &process);
        if (!NT_SUCCESS(status)) {
            break;
        }
        SIZE_T copied = 0;
        status = ReadProcessMemory(
            process,
            request->VirtualAddress,
            request->Data,
            request->Length,
            &copied);
        ObDereferenceObject(process);
        request->Transferred = static_cast<KDBG_U32>(copied);
        information = header + copied;
        if (NT_SUCCESS(status) && copied == request->Length) {
            InterlockedIncrement64(&g_state.SuccessfulReads);
        } else if (NT_SUCCESS(status)) {
            status = STATUS_PARTIAL_COPY;
        }
        break;
    }

    case IOCTL_KDBG_WRITE_PROCESS_MEMORY: {
        FastMutexGuard write_guard(&context->WriteLock);
        const ULONG header = FIELD_OFFSET(KDBG_PROCESS_MEMORY_REQUEST, Data);
        if (buffer == nullptr || input_length < header || output_length != header) {
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto* request =
            reinterpret_cast<KDBG_PROCESS_MEMORY_REQUEST*>(buffer);
        ULONG total = 0;
        if (request->Length == 0 ||
            !CheckedAddUlong(header, request->Length, &total) ||
            request->Size != total || request->Flags != 0 ||
            request->Reserved != 0 || request->Transferred != 0 ||
            request->ProcessId == 0 ||
            request->Length > KDBG_MAX_TRANSFER_SIZE ||
            !IsUserRange(request->VirtualAddress, request->Length) ||
            input_length != total) {
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (InterlockedCompareExchange(&context->WriteEnabled, 0, 0) == 0 ||
            request->Acknowledge != KDBG_WRITE_ACK_MAGIC) {
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
            status = STATUS_ACCESS_DENIED;
            break;
        }
        PEPROCESS process = nullptr;
        status = PsLookupProcessByProcessId(
            ULongToHandle(request->ProcessId),
            &process);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&context->WriteEnabled, 0);
            InterlockedIncrement64(&g_state.RejectedWrites);
            break;
        }
        SIZE_T copied = 0;
        status = WriteProcessMemory(
            process,
            request->VirtualAddress,
            request->Data,
            request->Length,
            &copied);
        ObDereferenceObject(process);
        request->Transferred = static_cast<KDBG_U32>(copied);
        information = header;
        if (NT_SUCCESS(status) && copied == request->Length) {
            InterlockedIncrement64(&g_state.SuccessfulWrites);
        } else {
            InterlockedExchange(&context->WriteEnabled, 0);
            if (NT_SUCCESS(status)) {
                status = STATUS_PARTIAL_COPY;
            }
        }
        break;
    }

    case IOCTL_KDBG_READ_KERNEL_VIRTUAL: {
        const ULONG header = FIELD_OFFSET(KDBG_KERNEL_VIRTUAL_READ_REQUEST, Data);
        if (buffer == nullptr || input_length != header || output_length < header) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto* request =
            reinterpret_cast<KDBG_KERNEL_VIRTUAL_READ_REQUEST*>(buffer);
        ULONG total = 0;
        UINT64 end_exclusive = 0;
        if (request->Size != header || request->Flags != 0 ||
            request->Transferred != 0 || request->Length == 0 ||
            request->Length > KDBG_MAX_TRANSFER_SIZE ||
            request->VirtualAddress == 0 ||
            !CheckedEnd(
                request->VirtualAddress,
                request->Length,
                &end_exclusive) ||
            !CheckedAddUlong(header, request->Length, &total) ||
            output_length != total) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        MM_COPY_ADDRESS source{};
        source.VirtualAddress =
            reinterpret_cast<PVOID>(request->VirtualAddress);
        SIZE_T copied = 0;
        status = MmCopyMemory(
            request->Data,
            source,
            request->Length,
            MM_COPY_MEMORY_VIRTUAL,
            &copied);
        request->Transferred = static_cast<KDBG_U32>(copied);
        information = header + copied;
        if (NT_SUCCESS(status) && copied == request->Length) {
            InterlockedIncrement64(&g_state.SuccessfulReads);
        } else if (NT_SUCCESS(status)) {
            status = STATUS_PARTIAL_COPY;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return Complete(irp, status, information);
}

VOID DriverUnload(PDRIVER_OBJECT) {
    UNICODE_STRING dos_name{};
    RtlInitUnicodeString(&dos_name, KDBG_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dos_name);
    if (g_state.DeviceObject != nullptr) {
        IoDeleteDevice(g_state.DeviceObject);
        g_state.DeviceObject = nullptr;
    }
}

}  // namespace

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT driver_object,
    PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    for (ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        driver_object->MajorFunction[index] = DispatchUnsupported;
    }
    driver_object->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    driver_object->MajorFunction[IRP_MJ_CLEANUP] = DispatchCleanup;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        DispatchDeviceControl;
    driver_object->DriverUnload = DriverUnload;

    UNICODE_STRING device_name{};
    UNICODE_STRING dos_name{};
    UNICODE_STRING sddl{};
    RtlInitUnicodeString(&device_name, KDBG_DEVICE_NAME);
    RtlInitUnicodeString(&dos_name, KDBG_DOS_DEVICE_NAME);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    ExInitializeFastMutex(&g_state.OwnerLock);

    PDEVICE_OBJECT device_object = nullptr;
    NTSTATUS status = IoCreateDeviceSecure(
        driver_object,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &GUID_DEVCLASS_KDBG,
        &device_object);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    device_object->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&dos_name, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
        return status;
    }

    g_state.DeviceObject = device_object;
    device_object->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

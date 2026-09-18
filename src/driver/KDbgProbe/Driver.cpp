#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>

#include "../../shared/KDbgProbeIoctl.h"

DEFINE_GUID(
    GUID_DEVCLASS_KDBG_PROBE,
    0x4ead4ef2, 0x8f10, 0x4d62,
    0x82, 0x57, 0x08, 0x9d, 0x33, 0x67, 0x0f, 0x1a);

namespace {

static_assert(PAGE_SIZE == KDBG_PROBE_PAGE_SIZE, "Probe ABI page size mismatch");
constexpr ULONG kContextTag = 'PDBK';

struct FileContext {
    volatile LONG CleanedUp;
    PEPROCESS OwnerProcess;
    ULONG OwnerPid;
};

struct ProbeState {
    PDEVICE_OBJECT DeviceObject;
    PUCHAR Buffer;
    PHYSICAL_ADDRESS PhysicalAddress;
    FAST_MUTEX BufferLock;
    FAST_MUTEX OwnerLock;
    PEPROCESS OwnerProcess;
    volatile LONG OwnerPid;
    volatile LONG OpenHandleCount;
    volatile LONG Generation;
};

ProbeState g_state{};

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

bool IsControllerContext(FileContext* context) noexcept {
    if (context == nullptr ||
        InterlockedCompareExchange(&context->CleanedUp, 0, 0) != 0) {
        return false;
    }
    return context->OwnerProcess == PsGetCurrentProcess() &&
        context->OwnerPid == HandleToULong(PsGetCurrentProcessId());
}

void CleanupFileContext(FileContext* context) noexcept {
    if (context == nullptr ||
        InterlockedCompareExchange(&context->CleanedUp, 1, 0) != 0) {
        return;
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

void ResetPattern() {
    for (ULONG index = 0; index < KDBG_PROBE_PAGE_SIZE; ++index) {
        g_state.Buffer[index] = static_cast<UCHAR>((index * 17U + 0x3DU) & 0xFFU);
    }
    KeMemoryBarrier();
    InterlockedIncrement(&g_state.Generation);
}

ULONG Crc32(const UCHAR* bytes, SIZE_T size) {
    ULONG crc = 0xFFFFFFFFU;
    for (SIZE_T index = 0; index < size; ++index) {
        crc ^= bytes[index];
        for (int bit = 0; bit < 8; ++bit) {
            const ULONG mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
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

    if (!IsControllerContext(GetFileContext(irp))) {
        return Complete(irp, STATUS_ACCESS_DENIED);
    }

    switch (code) {
    case IOCTL_KDBG_PROBE_GET_INFO: {
        if (buffer == nullptr || input_length != 0 ||
            output_length != sizeof(KDBG_PROBE_INFO_RESPONSE)) {
            return Complete(irp, STATUS_BUFFER_TOO_SMALL);
        }
        KDBG_PROBE_INFO_RESPONSE response{};
        response.Size = sizeof(response);
        response.AbiVersion = KDBG_PROBE_ABI_VERSION;
        ExAcquireFastMutex(&g_state.BufferLock);
        response.Generation = static_cast<KDBG_PROBE_U32>(
            InterlockedCompareExchange(&g_state.Generation, 0, 0));
        response.ByteCount = KDBG_PROBE_PAGE_SIZE;
        response.VirtualAddress = reinterpret_cast<KDBG_PROBE_U64>(g_state.Buffer);
        response.PhysicalAddress =
            static_cast<KDBG_PROBE_U64>(g_state.PhysicalAddress.QuadPart);
        response.Pfn = response.PhysicalAddress >> PAGE_SHIFT;
        response.Crc32 = Crc32(g_state.Buffer, KDBG_PROBE_PAGE_SIZE);
        ExReleaseFastMutex(&g_state.BufferLock);
        RtlCopyMemory(buffer, &response, sizeof(response));
        return Complete(irp, STATUS_SUCCESS, sizeof(response));
    }

    case IOCTL_KDBG_PROBE_CONTROL: {
        if (buffer == nullptr ||
            input_length != sizeof(KDBG_PROBE_CONTROL_REQUEST) ||
            output_length != 0) {
            return Complete(irp, STATUS_BUFFER_TOO_SMALL);
        }
        const auto* request =
            reinterpret_cast<const KDBG_PROBE_CONTROL_REQUEST*>(buffer);
        if (request->Size != sizeof(*request) ||
            request->Reserved != 0 ||
            request->Acknowledge != KDBG_PROBE_WRITE_ACK_MAGIC) {
            return Complete(irp, STATUS_ACCESS_DENIED);
        }
        if (request->Action == KDBG_PROBE_ACTION_RESET &&
            request->FillByte != 0) {
            return Complete(irp, STATUS_INVALID_PARAMETER);
        }
        if (request->Action == KDBG_PROBE_ACTION_FILL &&
            request->FillByte > MAXUCHAR) {
            return Complete(irp, STATUS_INVALID_PARAMETER);
        }
        if (request->Action != KDBG_PROBE_ACTION_RESET &&
            request->Action != KDBG_PROBE_ACTION_FILL) {
            return Complete(irp, STATUS_INVALID_PARAMETER);
        }

        ExAcquireFastMutex(&g_state.BufferLock);
        if (request->Action == KDBG_PROBE_ACTION_RESET) {
            ResetPattern();
        } else {
            RtlFillMemory(
                g_state.Buffer,
                KDBG_PROBE_PAGE_SIZE,
                static_cast<UCHAR>(request->FillByte & 0xFFU));
            KeMemoryBarrier();
            InterlockedIncrement(&g_state.Generation);
        }
        ExReleaseFastMutex(&g_state.BufferLock);
        return Complete(irp, STATUS_SUCCESS);
    }

    default:
        return Complete(irp, STATUS_INVALID_DEVICE_REQUEST);
    }
}

VOID DriverUnload(PDRIVER_OBJECT) {
    UNICODE_STRING dos_name{};
    RtlInitUnicodeString(&dos_name, KDBG_PROBE_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dos_name);
    if (g_state.Buffer != nullptr) {
        MmFreeContiguousMemory(g_state.Buffer);
        g_state.Buffer = nullptr;
    }
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

    ExInitializeFastMutex(&g_state.BufferLock);
    ExInitializeFastMutex(&g_state.OwnerLock);

    PHYSICAL_ADDRESS low{};
    PHYSICAL_ADDRESS high{};
    PHYSICAL_ADDRESS boundary{};
    high.QuadPart = MAXLONGLONG;
    g_state.Buffer = static_cast<PUCHAR>(MmAllocateContiguousMemorySpecifyCache(
         KDBG_PROBE_PAGE_SIZE,
        low,
        high,
        boundary,
        MmCached));
    if (g_state.Buffer == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_state.PhysicalAddress = MmGetPhysicalAddress(g_state.Buffer);
    ResetPattern();

    for (ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        driver_object->MajorFunction[index] = DispatchUnsupported;
    }
    driver_object->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    driver_object->MajorFunction[IRP_MJ_CLEANUP] = DispatchCleanup;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    driver_object->DriverUnload = DriverUnload;

    UNICODE_STRING device_name{};
    UNICODE_STRING dos_name{};
    UNICODE_STRING sddl{};
    RtlInitUnicodeString(&device_name, KDBG_PROBE_DEVICE_NAME);
    RtlInitUnicodeString(&dos_name, KDBG_PROBE_DOS_DEVICE_NAME);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    PDEVICE_OBJECT device_object = nullptr;
    NTSTATUS status = IoCreateDeviceSecure(
        driver_object,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &GUID_DEVCLASS_KDBG_PROBE,
        &device_object);
    if (!NT_SUCCESS(status)) {
        MmFreeContiguousMemory(g_state.Buffer);
        g_state.Buffer = nullptr;
        return status;
    }
    device_object->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&dos_name, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
        MmFreeContiguousMemory(g_state.Buffer);
        g_state.Buffer = nullptr;
        return status;
    }
    g_state.DeviceObject = device_object;
    device_object->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

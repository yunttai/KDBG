#pragma once

#include <stddef.h>

/*
 * KDBG user/kernel ABI.
 *
 * The same packed structures are compiled by the WDK driver and by the
 * user-mode client. Keep this header C-compatible and append-only within an
 * ABI version.
 */

#if defined(_KERNEL_MODE)
#include <ntddk.h>
typedef UCHAR     KDBG_U8;
typedef USHORT    KDBG_U16;
typedef ULONG     KDBG_U32;
typedef ULONGLONG KDBG_U64;
#elif defined(_WIN32)
#include <Windows.h>
typedef unsigned char      KDBG_U8;
typedef unsigned short     KDBG_U16;
typedef unsigned long      KDBG_U32;
typedef unsigned long long KDBG_U64;
#else
#include <stdint.h>
typedef uint8_t  KDBG_U8;
typedef uint16_t KDBG_U16;
typedef uint32_t KDBG_U32;
typedef uint64_t KDBG_U64;
#endif

#define KDBG_DEVICE_NAME      L"\\Device\\KDBG"
#define KDBG_DOS_DEVICE_NAME  L"\\DosDevices\\KDBG"
#define KDBG_USER_DEVICE_NAME L"\\\\.\\KDBG"
#define KDBG_SERVICE_NAME     L"KDBG"
#define KDBG_DISPLAY_NAME     L"KDBG Physical Memory Driver"

#define KDBG_ABI_VERSION          6u
#define KDBG_DRIVER_VERSION_MAJOR 1u
#define KDBG_DRIVER_VERSION_MINOR 1u
#define KDBG_MAX_TRANSFER_SIZE    (1024u * 1024u)
#define KDBG_MAX_PHYSICAL_RANGES  4096u
#define KDBG_MAX_TRANSLATION_STEPS 5u
#define KDBG_PAGE_SIZE            0x1000u
#define KDBG_WRITE_ACK_MAGIC      0x4B44424757524954ull /* "KDBGWRIT" */

#define KDBG_VERSION_FLAG_PHYSICAL_READ   0x00000001u
#define KDBG_VERSION_FLAG_PHYSICAL_WRITE  0x00000002u
#define KDBG_VERSION_FLAG_PROCESS_MEMORY  0x00000004u
#define KDBG_VERSION_FLAG_VTOP            0x00000008u
#define KDBG_VERSION_FLAG_LA57_ACTIVE     0x00000010u
#define KDBG_VERSION_FLAG_SECURE_OPEN     0x00000020u
#define KDBG_VERSION_FLAG_SINGLE_OWNER    0x00000040u
/* Every accepted write IOCTL atomically consumes the per-handle gate. */
#define KDBG_VERSION_FLAG_WRITE_GATE_ONE_SHOT 0x00000080u

#define KDBG_SESSION_FLAG_OWNER_ACTIVE    0x00000001u
#define KDBG_SESSION_FLAG_WRITE_ENABLED   0x00000002u

#define KDBG_PHYSICAL_WRITE_STAGE_NONE       0u
#define KDBG_PHYSICAL_WRITE_STAGE_VALIDATION 1u
#define KDBG_PHYSICAL_WRITE_STAGE_MAPPING    2u
#define KDBG_PHYSICAL_WRITE_STAGE_COPYING    3u
#define KDBG_PHYSICAL_WRITE_STAGE_COMPLETE   4u

#define KDBG_PROCESS_FLAG_CR3_VALID       0x00000001u
#define KDBG_PROCESS_FLAG_WOW64           0x00000002u

#define KDBG_TRANSLATE_FLAG_LA57_ACTIVE   0x00000001u
#define KDBG_TRANSLATE_FLAG_LARGE_PAGE    0x00000002u
#define KDBG_TRANSLATE_FLAG_PRESENT       0x00000004u
#define KDBG_TRANSLATE_FLAG_PROCESS_CR3   0x00000008u

#define KDBG_PAGING_LEVEL_PT    1u
#define KDBG_PAGING_LEVEL_PD    2u
#define KDBG_PAGING_LEVEL_PDPT  3u
#define KDBG_PAGING_LEVEL_PML4  4u
#define KDBG_PAGING_LEVEL_PML5  5u

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif
#ifndef FILE_READ_DATA
#define FILE_READ_DATA 0x0001
#endif
#ifndef FILE_WRITE_DATA
#define FILE_WRITE_DATA 0x0002
#endif

#define IOCTL_KDBG_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KDBG_GET_SESSION_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_KDBG_SET_WRITE_MODE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_KDBG_GET_PHYSICAL_RANGES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_KDBG_READ_PHYSICAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_KDBG_WRITE_PHYSICAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_KDBG_GET_PROCESS_CONTEXT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_KDBG_TRANSLATE_VIRTUAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_KDBG_READ_PROCESS_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_KDBG_WRITE_PROCESS_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x909, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_KDBG_READ_KERNEL_VIRTUAL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90A, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(push, 8)

typedef struct _KDBG_VERSION_RESPONSE {
    KDBG_U32 Size;
    KDBG_U32 AbiVersion;
    KDBG_U32 DriverMajor;
    KDBG_U32 DriverMinor;
    KDBG_U32 MaxTransferSize;
    KDBG_U32 Flags;
} KDBG_VERSION_RESPONSE;

typedef struct _KDBG_SESSION_STATUS_RESPONSE {
    KDBG_U32 Size;
    KDBG_U32 Flags;
    KDBG_U32 OwnerPid;
    KDBG_U32 CurrentPid;
    KDBG_U32 OpenHandleCount;
    KDBG_U32 Reserved;
    KDBG_U64 SuccessfulReads;
    KDBG_U64 SuccessfulWrites;
    KDBG_U64 RejectedWrites;
    KDBG_U32 LastPhysicalWriteStatus;
    KDBG_U32 LastPhysicalWriteStage;
    KDBG_U32 LastPhysicalWriteTransferred;
    KDBG_U32 Reserved2;
} KDBG_SESSION_STATUS_RESPONSE;

typedef struct _KDBG_WRITE_MODE_REQUEST {
    KDBG_U32 Size;
    KDBG_U32 EnableWrite;
    KDBG_U64 Acknowledge;
} KDBG_WRITE_MODE_REQUEST;

typedef struct _KDBG_PHYSICAL_RANGE {
    KDBG_U64 BaseAddress;
    KDBG_U64 ByteCount;
} KDBG_PHYSICAL_RANGE;

typedef struct _KDBG_PHYSICAL_RANGES_RESPONSE {
    KDBG_U32 Size;
    KDBG_U32 Flags;
    KDBG_U32 RangeCount;
    KDBG_U32 Reserved;
    KDBG_U64 TotalBytes;
    KDBG_PHYSICAL_RANGE Ranges[KDBG_MAX_PHYSICAL_RANGES];
} KDBG_PHYSICAL_RANGES_RESPONSE;

typedef struct _KDBG_PHYSICAL_READ_REQUEST {
    KDBG_U32 Size;          /* header size: offset of Data */
    KDBG_U32 Flags;
    KDBG_U64 PhysicalAddress;
    KDBG_U32 Length;
    KDBG_U32 Transferred;
    KDBG_U8 Data[1];
} KDBG_PHYSICAL_READ_REQUEST;

typedef struct _KDBG_PHYSICAL_WRITE_REQUEST {
    KDBG_U32 Size;          /* header + payload */
    KDBG_U32 Flags;
    KDBG_U64 PhysicalAddress;
    KDBG_U32 Length;
    KDBG_U32 Transferred;
    KDBG_U64 Acknowledge;
    KDBG_U8 Data[1];
} KDBG_PHYSICAL_WRITE_REQUEST;

typedef struct _KDBG_PROCESS_CONTEXT_REQUEST {
    KDBG_U32 Size;
    KDBG_U32 ProcessId;
} KDBG_PROCESS_CONTEXT_REQUEST;

typedef struct _KDBG_PROCESS_CONTEXT_RESPONSE {
    KDBG_U32 Size;
    KDBG_U32 Flags;
    KDBG_U32 ProcessId;
    KDBG_U32 Reserved;
    KDBG_U64 Eprocess;
    KDBG_U64 DirectoryTableBase;
} KDBG_PROCESS_CONTEXT_RESPONSE;

typedef struct _KDBG_TRANSLATE_REQUEST {
    KDBG_U32 Size;
    KDBG_U32 Flags;
    KDBG_U32 ProcessId;             /* optional; 0 uses DirectoryTableBase */
    KDBG_U32 Length;
    KDBG_U64 DirectoryTableBase;    /* optional; 0 uses ProcessId/current CR3 */
    KDBG_U64 VirtualAddress;
} KDBG_TRANSLATE_REQUEST;

typedef struct _KDBG_TRANSLATION_STEP {
    KDBG_U32 Level;
    KDBG_U32 Index;
    KDBG_U64 EntryPhysicalAddress;
    KDBG_U64 EntryValue;
} KDBG_TRANSLATION_STEP;

typedef struct _KDBG_TRANSLATE_RESPONSE {
    KDBG_U32 Size;
    KDBG_U32 Flags;
    KDBG_U32 PagingLevels;
    KDBG_U32 StepCount;
    KDBG_U32 RequestedLength;
    KDBG_U32 TranslatedLength;
    KDBG_U64 DirectoryTableBase;
    KDBG_U64 VirtualAddress;
    KDBG_U64 PhysicalAddress;
    KDBG_U64 PageSize;
    KDBG_U64 PageOffset;
    KDBG_U64 PageBytes;
    KDBG_TRANSLATION_STEP Steps[KDBG_MAX_TRANSLATION_STEPS];
} KDBG_TRANSLATE_RESPONSE;

typedef struct _KDBG_PROCESS_MEMORY_REQUEST {
    KDBG_U32 Size;          /* read: header; write: header + payload */
    KDBG_U32 Flags;
    KDBG_U32 ProcessId;
    KDBG_U32 Length;
    KDBG_U64 VirtualAddress;
    KDBG_U64 Acknowledge;   /* required only for write */
    KDBG_U32 Transferred;
    KDBG_U32 Reserved;
    KDBG_U8 Data[1];
} KDBG_PROCESS_MEMORY_REQUEST;

typedef struct _KDBG_KERNEL_VIRTUAL_READ_REQUEST {
    KDBG_U32 Size;
    KDBG_U32 Flags;
    KDBG_U64 VirtualAddress;
    KDBG_U32 Length;
    KDBG_U32 Transferred;
    KDBG_U8 Data[1];
} KDBG_KERNEL_VIRTUAL_READ_REQUEST;

#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(KDBG_VERSION_RESPONSE) == 24u, "KDBG_VERSION_RESPONSE ABI drift");
static_assert(sizeof(KDBG_SESSION_STATUS_RESPONSE) == 64u, "KDBG_SESSION_STATUS_RESPONSE ABI drift");
static_assert(sizeof(KDBG_WRITE_MODE_REQUEST) == 16u, "KDBG_WRITE_MODE_REQUEST ABI drift");
static_assert(sizeof(KDBG_PHYSICAL_RANGE) == 16u, "KDBG_PHYSICAL_RANGE ABI drift");
static_assert(sizeof(KDBG_PHYSICAL_RANGES_RESPONSE) == 65560u, "KDBG_PHYSICAL_RANGES_RESPONSE ABI drift");
static_assert(offsetof(KDBG_PHYSICAL_READ_REQUEST, Data) == 24u, "KDBG_PHYSICAL_READ_REQUEST ABI drift");
static_assert(offsetof(KDBG_PHYSICAL_WRITE_REQUEST, Data) == 32u, "KDBG_PHYSICAL_WRITE_REQUEST ABI drift");
static_assert(sizeof(KDBG_PROCESS_CONTEXT_REQUEST) == 8u, "KDBG_PROCESS_CONTEXT_REQUEST ABI drift");
static_assert(sizeof(KDBG_PROCESS_CONTEXT_RESPONSE) == 32u, "KDBG_PROCESS_CONTEXT_RESPONSE ABI drift");
static_assert(sizeof(KDBG_TRANSLATE_REQUEST) == 32u, "KDBG_TRANSLATE_REQUEST ABI drift");
static_assert(sizeof(KDBG_TRANSLATION_STEP) == 24u, "KDBG_TRANSLATION_STEP ABI drift");
static_assert(sizeof(KDBG_TRANSLATE_RESPONSE) == 192u, "KDBG_TRANSLATE_RESPONSE ABI drift");
static_assert(offsetof(KDBG_PROCESS_MEMORY_REQUEST, Data) == 40u, "KDBG_PROCESS_MEMORY_REQUEST ABI drift");
static_assert(offsetof(KDBG_KERNEL_VIRTUAL_READ_REQUEST, Data) == 24u, "KDBG_KERNEL_VIRTUAL_READ_REQUEST ABI drift");
#endif

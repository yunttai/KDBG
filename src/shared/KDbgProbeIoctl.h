#pragma once

#include <stddef.h>

#if defined(_KERNEL_MODE)
#include <ntddk.h>
typedef UCHAR     KDBG_PROBE_U8;
typedef ULONG     KDBG_PROBE_U32;
typedef ULONGLONG KDBG_PROBE_U64;
#elif defined(_WIN32)
#include <Windows.h>
typedef unsigned char      KDBG_PROBE_U8;
typedef unsigned long      KDBG_PROBE_U32;
typedef unsigned long long KDBG_PROBE_U64;
#else
#include <stdint.h>
typedef uint8_t  KDBG_PROBE_U8;
typedef uint32_t KDBG_PROBE_U32;
typedef uint64_t KDBG_PROBE_U64;
#endif

#define KDBG_PROBE_DEVICE_NAME      L"\\Device\\KDBGProbe"
#define KDBG_PROBE_DOS_DEVICE_NAME  L"\\DosDevices\\KDBGProbe"
#define KDBG_PROBE_USER_DEVICE_NAME L"\\\\.\\KDBGProbe"
#define KDBG_PROBE_SERVICE_NAME     L"KDBGProbe"
#define KDBG_PROBE_ABI_VERSION      1u
#define KDBG_PROBE_PAGE_SIZE        0x1000u
#define KDBG_PROBE_WRITE_ACK_MAGIC  0x4B44424750524F42ull /* KDBGPROB */
#define KDBG_PROBE_ACTION_RESET     1u
#define KDBG_PROBE_ACTION_FILL      2u

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

#define IOCTL_KDBG_PROBE_GET_INFO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x920, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_KDBG_PROBE_CONTROL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#pragma pack(push, 8)
typedef struct _KDBG_PROBE_INFO_RESPONSE {
    KDBG_PROBE_U32 Size;
    KDBG_PROBE_U32 AbiVersion;
    KDBG_PROBE_U32 Generation;
    KDBG_PROBE_U32 ByteCount;
    KDBG_PROBE_U64 VirtualAddress;
    KDBG_PROBE_U64 PhysicalAddress;
    KDBG_PROBE_U64 Pfn;
    KDBG_PROBE_U32 Crc32;
    KDBG_PROBE_U32 Reserved;
} KDBG_PROBE_INFO_RESPONSE;

typedef struct _KDBG_PROBE_CONTROL_REQUEST {
    KDBG_PROBE_U32 Size;
    KDBG_PROBE_U32 Action;
    KDBG_PROBE_U32 FillByte;
    KDBG_PROBE_U32 Reserved;
    KDBG_PROBE_U64 Acknowledge;
} KDBG_PROBE_CONTROL_REQUEST;
#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(KDBG_PROBE_INFO_RESPONSE) == 48u, "KDBG_PROBE_INFO_RESPONSE ABI drift");
static_assert(sizeof(KDBG_PROBE_CONTROL_REQUEST) == 24u, "KDBG_PROBE_CONTROL_REQUEST ABI drift");
#endif

#include "core/memory/ProbeClient.h"

#include "shared/KDbgProbeIoctl.h"

#include <utility>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace kdbg {
namespace {

std::uint32_t UpdateCrc32(std::uint32_t crc, std::uint8_t value) noexcept {
    crc ^= value;
    for (int bit = 0; bit < 8; ++bit) {
        const std::uint32_t mask = 0U - (crc & 1U);
        crc = (crc >> 1U) ^ (0xEDB88320U & mask);
    }
    return crc;
}

std::uint32_t ExpectedResetCrc32() noexcept {
    std::uint32_t crc = 0xFFFFFFFFU;
    for (std::uint32_t index = 0; index < KDBG_PROBE_PAGE_SIZE; ++index) {
        crc = UpdateCrc32(
            crc,
            static_cast<std::uint8_t>((index * 17U + 0x3DU) & 0xFFU));
    }
    return ~crc;
}

std::uint32_t ExpectedFillCrc32(std::uint8_t value) noexcept {
    std::uint32_t crc = 0xFFFFFFFFU;
    for (std::uint32_t index = 0; index < KDBG_PROBE_PAGE_SIZE; ++index) {
        crc = UpdateCrc32(crc, value);
    }
    return ~crc;
}

}  // namespace

struct ProbeClient::Impl {
#ifdef _WIN32
    HANDLE device{INVALID_HANDLE_VALUE};
#endif
    std::wstring device_name;
};

ProbeClient::ProbeClient(std::wstring device_name)
    : impl_(std::make_unique<Impl>()) {
    impl_->device_name = std::move(device_name);
}

ProbeClient::~ProbeClient() {
    Close();
}

Result<void> ProbeClient::Open() {
#ifdef _WIN32
    if (impl_->device != INVALID_HANDLE_VALUE) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendAlreadyOpen,
            "KDBG Probe is already open",
            "ProbeClient::Open"));
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
            "Unable to open KDBG Probe",
            "ProbeClient::Open",
            GetLastError()));
    }
    auto info = Query();
    if (!info) {
        const auto error = info.GetError();
        Close();
        return Result<void>::Failure(error);
    }
    return Result<void>::Success();
#else
    return Result<void>::Failure(MakeError(
        ErrorCode::Unsupported,
        "KDBG Probe is Windows-only",
        "ProbeClient::Open"));
#endif
}

void ProbeClient::Close() noexcept {
#ifdef _WIN32
    if (impl_->device != INVALID_HANDLE_VALUE) {
        CloseHandle(impl_->device);
        impl_->device = INVALID_HANDLE_VALUE;
    }
#endif
}

bool ProbeClient::IsOpen() const noexcept {
#ifdef _WIN32
    return impl_->device != INVALID_HANDLE_VALUE;
#else
    return false;
#endif
}

Result<ProbeInfo> ProbeClient::Query() {
#ifdef _WIN32
    if (!IsOpen()) {
        return Result<ProbeInfo>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "KDBG Probe is not open",
            "ProbeClient::Query"));
    }
    KDBG_PROBE_INFO_RESPONSE response{};
    DWORD returned = 0;
    if (!DeviceIoControl(
            impl_->device,
            IOCTL_KDBG_PROBE_GET_INFO,
            nullptr,
            0,
            &response,
            sizeof(response),
            &returned,
            nullptr)) {
        return Result<ProbeInfo>::Failure(MakeError(
            ErrorCode::IoFailure,
            "KDBG Probe info query failed",
            "ProbeClient::Query",
            GetLastError()));
    }
    if (returned != sizeof(response) || response.Size != sizeof(response) ||
        response.AbiVersion != KDBG_PROBE_ABI_VERSION ||
        response.ByteCount != KDBG_PROBE_PAGE_SIZE ||
        response.VirtualAddress == 0 ||
        response.PhysicalAddress == 0 ||
        (response.PhysicalAddress & (KDBG_PROBE_PAGE_SIZE - 1ULL)) != 0 ||
        response.Pfn != (response.PhysicalAddress >> 12U) ||
        response.Reserved != 0) {
        return Result<ProbeInfo>::Failure(MakeError(
            response.AbiVersion != KDBG_PROBE_ABI_VERSION
                ? ErrorCode::AbiMismatch
                : ErrorCode::ShortRead,
            "KDBG Probe returned an incompatible response",
            "ProbeClient::Query"));
    }
    ProbeInfo info{};
    info.generation = response.Generation;
    info.byte_count = response.ByteCount;
    info.virtual_address = response.VirtualAddress;
    info.physical_address = response.PhysicalAddress;
    info.pfn = response.Pfn;
    info.crc32 = response.Crc32;
    return Result<ProbeInfo>::Success(info);
#else
    return Result<ProbeInfo>::Failure(MakeError(
        ErrorCode::Unsupported,
        "KDBG Probe is Windows-only",
        "ProbeClient::Query"));
#endif
}

Result<void> ProbeClient::Reset() {
#ifdef _WIN32
    if (!IsOpen()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "KDBG Probe is not open",
            "ProbeClient::Reset"));
    }
    auto before = Query();
    if (!before) return Result<void>::Failure(before.GetError());
    KDBG_PROBE_CONTROL_REQUEST request{};
    request.Size = sizeof(request);
    request.Action = KDBG_PROBE_ACTION_RESET;
    request.Acknowledge = KDBG_PROBE_WRITE_ACK_MAGIC;
    DWORD returned = 0;
    if (!DeviceIoControl(
            impl_->device,
            IOCTL_KDBG_PROBE_CONTROL,
            &request,
            sizeof(request),
            nullptr,
            0,
            &returned,
            nullptr)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "KDBG Probe reset failed",
            "ProbeClient::Reset",
            GetLastError()));
    }
    if (returned != 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::AbiMismatch,
            "KDBG Probe reset returned an invalid length",
            "ProbeClient::Reset"));
    }
    auto after = Query();
    if (!after) return Result<void>::Failure(after.GetError());
    if (after.Value().generation == before.Value().generation ||
        after.Value().crc32 != ExpectedResetCrc32()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            "KDBG Probe reset verification failed",
            "ProbeClient::Reset"));
    }
    return Result<void>::Success();
#else
    return Result<void>::Failure(MakeError(
        ErrorCode::Unsupported,
        "KDBG Probe is Windows-only",
        "ProbeClient::Reset"));
#endif
}

Result<void> ProbeClient::Fill(std::uint8_t value) {
#ifdef _WIN32
    if (!IsOpen()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "KDBG Probe is not open",
            "ProbeClient::Fill"));
    }
    auto before = Query();
    if (!before) return Result<void>::Failure(before.GetError());
    KDBG_PROBE_CONTROL_REQUEST request{};
    request.Size = sizeof(request);
    request.Action = KDBG_PROBE_ACTION_FILL;
    request.FillByte = value;
    request.Acknowledge = KDBG_PROBE_WRITE_ACK_MAGIC;
    DWORD returned = 0;
    if (!DeviceIoControl(
            impl_->device,
            IOCTL_KDBG_PROBE_CONTROL,
            &request,
            sizeof(request),
            nullptr,
            0,
            &returned,
            nullptr)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "KDBG Probe fill failed",
            "ProbeClient::Fill",
            GetLastError()));
    }
    if (returned != 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::AbiMismatch,
            "KDBG Probe fill returned an invalid length",
            "ProbeClient::Fill"));
    }
    auto after = Query();
    if (!after) return Result<void>::Failure(after.GetError());
    if (after.Value().generation == before.Value().generation ||
        after.Value().crc32 != ExpectedFillCrc32(value)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            "KDBG Probe fill verification failed",
            "ProbeClient::Fill"));
    }
    return Result<void>::Success();
#else
    (void)value;
    return Result<void>::Failure(MakeError(
        ErrorCode::Unsupported,
        "KDBG Probe is Windows-only",
        "ProbeClient::Fill"));
#endif
}

}  // namespace kdbg

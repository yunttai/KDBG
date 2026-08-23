#include "core/memory/MemoryAccess.h"

namespace kdbg {

Result<std::vector<std::uint8_t>> ReadMemory(
    IMemoryBackend& backend,
    const MemorySpace& space,
    std::uint64_t address,
    std::uint32_t length) {
    switch (space.kind) {
    case MemorySpaceKind::Physical:
        return backend.ReadPhysical(address, length);
    case MemorySpaceKind::ProcessVirtual:
        if (space.pid == 0) {
            return Result<std::vector<std::uint8_t>>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Process virtual reads require a PID",
                "ReadMemory"));
        }
        return backend.ReadProcessVirtual(space.pid, address, length);
    case MemorySpaceKind::KernelVirtual:
        return backend.ReadKernelVirtual(address, length);
    }
    return Result<std::vector<std::uint8_t>>::Failure(MakeError(
        ErrorCode::InternalInvariant,
        "Unknown memory-space kind",
        "ReadMemory"));
}

Result<std::uint32_t> WriteMemory(
    IMemoryBackend& backend,
    const MemorySpace& space,
    std::uint64_t address,
    std::span<const std::uint8_t> data) {
    switch (space.kind) {
    case MemorySpaceKind::Physical:
        return backend.WritePhysical(address, data);
    case MemorySpaceKind::ProcessVirtual:
        if (space.pid == 0) {
            return Result<std::uint32_t>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Process virtual writes require a PID",
                "WriteMemory"));
        }
        return backend.WriteProcessVirtual(space.pid, address, data);
    case MemorySpaceKind::KernelVirtual:
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::Unsupported,
            "KDBG intentionally exposes no arbitrary kernel-virtual write IOCTL",
            "WriteMemory"));
    }
    return Result<std::uint32_t>::Failure(MakeError(
        ErrorCode::InternalInvariant,
        "Unknown memory-space kind",
        "WriteMemory"));
}

}  // namespace kdbg

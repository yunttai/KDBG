#include "core/address/PointerResolver.h"

#include <cstring>
#include <limits>

namespace kdbg {

Result<std::uint64_t> PointerResolver::Resolve(const AddressPointerPath& path) {
    if (path.pointer_size != 4 && path.pointer_size != 8) {
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Pointer size must be 4 or 8 bytes",
            "PointerResolver::Resolve"));
    }
    if (path.base_address == 0 || path.offsets.size() > kMaxDepth ||
        (path.pointer_size == 4 &&
         path.base_address > std::numeric_limits<std::uint32_t>::max())) {
        return Result<std::uint64_t>::Failure(MakeError(
            path.offsets.size() > kMaxDepth
                ? ErrorCode::LimitReached
                : ErrorCode::InvalidArgument,
            "Pointer path has an invalid base address or exceeds the depth cap",
            "PointerResolver::Resolve",
            0,
            kMaxDepth,
            path.offsets.size()));
    }
    switch (path.space.kind) {
    case MemorySpaceKind::Physical:
    case MemorySpaceKind::KernelVirtual:
        if (path.space.pid != 0) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Non-process pointer paths must not carry a PID",
                "PointerResolver::Resolve"));
        }
        break;
    case MemorySpaceKind::ProcessVirtual:
        if (path.space.pid == 0) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Process pointer paths require a non-zero PID",
                "PointerResolver::Resolve"));
        }
        break;
    default:
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Pointer path has an unknown memory-space kind",
            "PointerResolver::Resolve"));
    }
    if (path.offsets.empty()) {
        return Result<std::uint64_t>::Success(path.base_address);
    }

    std::uint64_t current = path.base_address;
    for (std::size_t index = 0; index < path.offsets.size(); ++index) {
        const auto offset = path.offsets[index];
        if (index + 1 == path.offsets.size()) {
            if (offset >= 0) {
                if (current > std::numeric_limits<std::uint64_t>::max() -
                                  static_cast<std::uint64_t>(offset)) {
                    return Result<std::uint64_t>::Failure(MakeError(
                        ErrorCode::AddressOverflow,
                        "Pointer-path final offset overflowed",
                        "PointerResolver::Resolve"));
                }
                current += static_cast<std::uint64_t>(offset);
            } else {
                const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1;
                if (current < magnitude) {
                    return Result<std::uint64_t>::Failure(MakeError(
                        ErrorCode::AddressOverflow,
                        "Pointer-path final offset underflowed",
                        "PointerResolver::Resolve"));
                }
                current -= magnitude;
            }
            if (path.pointer_size == 4 &&
                current > std::numeric_limits<std::uint32_t>::max()) {
                return Result<std::uint64_t>::Failure(MakeError(
                    ErrorCode::AddressOverflow,
                    "32-bit pointer-path result exceeded the address width",
                    "PointerResolver::Resolve"));
            }
            break;
        }

        auto bytes = ReadMemory(
            backend_,
            path.space,
            current,
            path.pointer_size);
        if (!bytes) {
            return Result<std::uint64_t>::Failure(bytes.GetError());
        }
        if (bytes.Value().size() != path.pointer_size) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::ShortRead,
                "Pointer read returned fewer bytes than requested",
                "PointerResolver::Resolve"));
        }

        std::uint64_t pointer = 0;
        if (path.pointer_size == 4) {
            std::uint32_t pointer32 = 0;
            std::memcpy(&pointer32, bytes.Value().data(), sizeof(pointer32));
            pointer = pointer32;
        } else {
            std::memcpy(&pointer, bytes.Value().data(), sizeof(pointer));
        }
        if (pointer == 0) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::NotFound,
                "Pointer path encountered a null intermediate pointer",
                "PointerResolver::Resolve"));
        }

        if (offset >= 0) {
            if (pointer > std::numeric_limits<std::uint64_t>::max() -
                              static_cast<std::uint64_t>(offset)) {
                return Result<std::uint64_t>::Failure(MakeError(
                    ErrorCode::AddressOverflow,
                    "Pointer-path offset overflowed",
                    "PointerResolver::Resolve"));
            }
            current = pointer + static_cast<std::uint64_t>(offset);
        } else {
            const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1;
            if (pointer < magnitude) {
                return Result<std::uint64_t>::Failure(MakeError(
                    ErrorCode::AddressOverflow,
                    "Pointer-path offset underflowed",
                    "PointerResolver::Resolve"));
            }
            current = pointer - magnitude;
        }
        if (path.pointer_size == 4 &&
            current > std::numeric_limits<std::uint32_t>::max()) {
            return Result<std::uint64_t>::Failure(MakeError(
                ErrorCode::AddressOverflow,
                "32-bit pointer-path result exceeded the address width",
                "PointerResolver::Resolve"));
        }
    }

    return Result<std::uint64_t>::Success(current);
}

}  // namespace kdbg

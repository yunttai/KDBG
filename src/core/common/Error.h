#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace kdbg {

enum class ErrorCode {
    None = 0,
    InvalidArgument,
    InvalidPfn,
    AddressOverflow,
    OutsidePhysicalRam,
    BackendDisconnected,
    BackendAlreadyOpen,
    AbiMismatch,
    ShortRead,
    WriteLocked,
    ConcurrentModification,
    ShortWrite,
    VerificationMismatch,
    RollbackFailed,
    BridgeUnavailable,
    Unsupported,
    IoFailure,
    AccessDenied,
    ParseError,
    Cancelled,
    LimitReached,
    NotFound,
    InternalInvariant
};

struct Error {
    ErrorCode code{ErrorCode::None};
    std::string message;
    std::string operation;
    std::uint64_t native_code{0};
    std::uint64_t requested{0};
    std::uint64_t completed{0};
};

inline Error MakeError(
    ErrorCode code,
    std::string message,
    std::string operation = {},
    std::uint64_t native_code = 0,
    std::uint64_t requested = 0,
    std::uint64_t completed = 0) {
    return Error{
        code,
        std::move(message),
        std::move(operation),
        native_code,
        requested,
        completed};
}

}  // namespace kdbg

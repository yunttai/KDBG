#pragma once

#include "core/common/Result.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace kdbg {

struct ProcessInfo {
    std::uint32_t pid{0};
    std::uint32_t parent_pid{0};
    std::string name;
    std::string path;
    bool is_64_bit{true};
};

struct ProcessModule {
    std::uint64_t base{0};
    std::uint64_t size{0};
    std::string name;
    std::string path;

    [[nodiscard]] bool Contains(std::uint64_t address) const noexcept {
        return size != 0 && address >= base && address - base < size;
    }
};

struct MemoryRegion {
    std::uint64_t base{0};
    std::uint64_t size{0};
    std::uint32_t state{0};
    std::uint32_t protection{0};
    std::uint32_t type{0};
    bool committed{false};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool guard{false};
    bool copy_on_write{false};
    std::string mapped_name;

    [[nodiscard]] bool Contains(
        std::uint64_t address,
        std::uint64_t length = 1) const noexcept {
        if (size == 0 || length == 0 || address < base) {
            return false;
        }
        const auto offset = address - base;
        return offset < size && length <= size - offset;
    }
};

class IProcessMemory {
public:
    virtual ~IProcessMemory() = default;

    [[nodiscard]] virtual std::uint32_t ProcessId() const noexcept = 0;
    // Stable token for the lifetime of the attached process (on Windows this
    // is its creation FILETIME).  Zero means the backend cannot supply one.
    [[nodiscard]] virtual std::uint64_t ProcessIdentityToken() const noexcept {
        return 0;
    }
    [[nodiscard]] virtual std::size_t PointerSize() const noexcept = 0;
    [[nodiscard]] virtual bool IsOpen() const noexcept = 0;
    [[nodiscard]] virtual bool WritesArmed() const noexcept = 0;

    // Arming is one-shot: one attempted Write consumes the arm even when the
    // request is malformed, rejected, short, or otherwise fails. Callers that
    // intentionally perform a bounded batch must explicitly re-arm each item.
    virtual Result<void> SetWritesArmed(bool armed) = 0;
    virtual Result<std::vector<std::uint8_t>> Read(
        std::uint64_t address,
        std::uint32_t length) = 0;
    virtual Result<std::uint32_t> Write(
        std::uint64_t address,
        std::span<const std::uint8_t> data) = 0;
    virtual Result<std::vector<MemoryRegion>> Regions() = 0;
    virtual Result<std::vector<ProcessModule>> Modules() = 0;
};

}  // namespace kdbg

#include "core/process/MockProcessMemory.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace kdbg {

MockProcessMemory::MockProcessMemory(
    std::uint64_t base,
    std::size_t size,
    std::size_t pointer_size)
    : base_(base), pointer_size_(pointer_size), bytes_(size) {
    regions_.push_back(MemoryRegion{
        base_,
        static_cast<std::uint64_t>(size),
        0,
        0,
        0,
        true,
        true,
        true,
        false,
        false,
        false,
        "mock"});
}

std::uint32_t MockProcessMemory::ProcessId() const noexcept { return 1337; }
std::size_t MockProcessMemory::PointerSize() const noexcept { return pointer_size_; }
bool MockProcessMemory::IsOpen() const noexcept { return true; }
bool MockProcessMemory::WritesArmed() const noexcept { return writes_armed_; }

Result<void> MockProcessMemory::SetWritesArmed(bool armed) {
    writes_armed_ = armed;
    return Result<void>::Success();
}

Result<std::vector<std::uint8_t>> MockProcessMemory::Read(
    std::uint64_t address,
    std::uint32_t length) {
    if (length == 0 || address < base_) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Mock process read is outside the address range",
            "MockProcessMemory::Read"));
    }
    const auto offset = address - base_;
    if (offset > bytes_.size() || length > bytes_.size() - offset) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Mock process read crosses the address range",
            "MockProcessMemory::Read"));
    }
    return Result<std::vector<std::uint8_t>>::Success(
        std::vector<std::uint8_t>(
            bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
            bytes_.begin() + static_cast<std::ptrdiff_t>(offset + length)));
}

Result<std::uint32_t> MockProcessMemory::Write(
    std::uint64_t address,
    std::span<const std::uint8_t> data) {
    if (!writes_armed_) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Mock process writes are not armed",
            "MockProcessMemory::Write"));
    }
    if (data.empty() || address < base_) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid mock process write",
            "MockProcessMemory::Write"));
    }
    const auto offset = address - base_;
    if (offset > bytes_.size() || data.size() > bytes_.size() - offset) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::ShortWrite,
            "Mock process write crosses the address range",
            "MockProcessMemory::Write"));
    }
    std::memcpy(bytes_.data() + offset, data.data(), data.size());
    return Result<std::uint32_t>::Success(
        static_cast<std::uint32_t>(data.size()));
}

Result<std::vector<MemoryRegion>> MockProcessMemory::Regions() {
    return Result<std::vector<MemoryRegion>>::Success(regions_);
}

Result<std::vector<ProcessModule>> MockProcessMemory::Modules() {
    return Result<std::vector<ProcessModule>>::Success(modules_);
}

std::vector<std::uint8_t>& MockProcessMemory::Bytes() noexcept { return bytes_; }
const std::vector<std::uint8_t>& MockProcessMemory::Bytes() const noexcept { return bytes_; }
std::uint64_t MockProcessMemory::Base() const noexcept { return base_; }
void MockProcessMemory::AddRegion(MemoryRegion region) { regions_.push_back(std::move(region)); }
void MockProcessMemory::SetModules(std::vector<ProcessModule> modules) { modules_ = std::move(modules); }

}  // namespace kdbg

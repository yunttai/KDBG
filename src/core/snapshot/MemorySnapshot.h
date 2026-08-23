#pragma once

#include "core/memory/MemoryAccess.h"
#include "core/process/IProcessMemory.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <stop_token>
#include <string>
#include <vector>

namespace kdbg {

struct SnapshotDiffRun {
    std::uint64_t offset{0};
    std::vector<std::uint8_t> before;
    std::vector<std::uint8_t> after;
};

class MemorySnapshot {
public:
    static constexpr std::uint64_t kMaxSnapshotBytes =
        512ULL * 1024ULL * 1024ULL;
    static constexpr std::uint32_t kMaxChunkBytes = 1024U * 1024U;
    static constexpr std::uint32_t kMaxLabelBytes = 1024U * 1024U;

    static Result<MemorySnapshot> Capture(
        IMemoryBackend& backend,
        MemorySpace space,
        std::uint64_t address,
        std::uint64_t size,
        std::uint32_t chunk_size = 1024U * 1024U,
        std::stop_token stop_token = {});

    // Process scanners can capture through ReadProcessMemory even when the
    // KDBG kernel backend is not connected. The resulting file remains bound
    // to the attached PID and address range.
    static Result<MemorySnapshot> Capture(
        IProcessMemory& memory,
        std::uint64_t address,
        std::uint64_t size,
        std::uint32_t chunk_size = 1024U * 1024U,
        std::stop_token stop_token = {});

    Result<std::vector<SnapshotDiffRun>> Diff(
        const MemorySnapshot& newer,
        std::size_t max_runs = 1'000'000) const;

    Result<void> Save(const std::filesystem::path& path) const;
    static Result<MemorySnapshot> Load(const std::filesystem::path& path);

    [[nodiscard]] const MemorySpace& Space() const noexcept { return space_; }
    [[nodiscard]] std::uint64_t Address() const noexcept { return address_; }
    [[nodiscard]] const std::vector<std::uint8_t>& Bytes() const noexcept {
        return bytes_;
    }
    [[nodiscard]] std::uint32_t Checksum() const noexcept { return checksum_; }

private:
    using Reader = std::function<Result<std::vector<std::uint8_t>>(
        std::uint64_t,
        std::uint32_t)>;

    static Result<MemorySnapshot> CaptureWithReader(
        MemorySpace space,
        std::uint64_t address,
        std::uint64_t size,
        std::uint32_t chunk_size,
        std::stop_token stop_token,
        Reader reader);
    static std::uint32_t Crc32(std::span<const std::uint8_t> bytes) noexcept;

    MemorySpace space_;
    std::uint64_t address_{0};
    std::vector<std::uint8_t> bytes_;
    std::uint32_t checksum_{0};
};

}  // namespace kdbg

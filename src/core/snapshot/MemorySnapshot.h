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
    std::uint64_t length{0};
};

enum class SnapshotProgressPhase {
    CaptureRead,
    CaptureChecksum,
    Diff,
    Save,
    LoadRead,
    LoadChecksum
};

struct SnapshotProgress {
    SnapshotProgressPhase phase{SnapshotProgressPhase::CaptureRead};
    std::uint64_t completed{0};
    std::uint64_t total{0};
    std::size_t runs{0};
};

using SnapshotProgressCallback =
    std::function<void(const SnapshotProgress& progress)>;

enum class SnapshotSaveFault {
    None,
    AfterFlushBeforeReplace,
};

class MemorySnapshot {
public:
    static constexpr std::uint64_t kMaxSnapshotBytes =
        512ULL * 1024ULL * 1024ULL;
    static constexpr std::uint32_t kMaxChunkBytes = 1024U * 1024U;
    static constexpr std::uint32_t kMaxLabelBytes = 1024U * 1024U;
    static constexpr std::size_t kMaxDiffRuns = 1'000'000;

    static Result<MemorySnapshot> Capture(
        IMemoryBackend& backend,
        MemorySpace space,
        std::uint64_t address,
        std::uint64_t size,
        std::uint32_t chunk_size = 1024U * 1024U,
        std::stop_token stop_token = {},
        SnapshotProgressCallback progress = {});

    // Process scanners can capture through ReadProcessMemory even when the
    // KDBG kernel backend is not connected. The resulting file remains bound
    // to the attached PID and address range.
    static Result<MemorySnapshot> Capture(
        IProcessMemory& memory,
        std::uint64_t address,
        std::uint64_t size,
        std::uint32_t chunk_size = 1024U * 1024U,
        std::stop_token stop_token = {},
        SnapshotProgressCallback progress = {});

    Result<std::vector<SnapshotDiffRun>> Diff(
        const MemorySnapshot& newer,
        std::size_t max_runs = kMaxDiffRuns,
        std::uint64_t max_changed_bytes = kMaxSnapshotBytes,
        std::stop_token stop_token = {},
        SnapshotProgressCallback progress = {}) const;

    Result<void> Save(
        const std::filesystem::path& path,
        std::stop_token stop_token = {},
        SnapshotProgressCallback progress = {},
        SnapshotSaveFault fault = SnapshotSaveFault::None) const;
    static Result<MemorySnapshot> Load(
        const std::filesystem::path& path,
        std::stop_token stop_token = {},
        SnapshotProgressCallback progress = {});

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
        SnapshotProgressCallback progress,
        Reader reader);
    static Result<std::uint32_t> Crc32(
        std::span<const std::uint8_t> bytes,
        std::stop_token stop_token,
        const SnapshotProgressCallback& progress,
        SnapshotProgressPhase phase);

    MemorySpace space_;
    std::uint64_t address_{0};
    std::vector<std::uint8_t> bytes_;
    std::uint32_t checksum_{0};
};

}  // namespace kdbg

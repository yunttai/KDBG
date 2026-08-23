#include "core/snapshot/MemorySnapshot.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <new>
#include <stdexcept>
#include <system_error>

namespace kdbg {
namespace {

#pragma pack(push, 1)
struct SnapshotHeader {
    char magic[8];
    std::uint32_t version;
    std::uint32_t kind;
    std::uint32_t pid;
    std::uint32_t reserved;
    std::uint64_t directory_table_base;
    std::uint64_t address;
    std::uint64_t byte_count;
    std::uint32_t checksum;
    std::uint32_t label_size;
};
#pragma pack(pop)

constexpr std::array<char, 8> kMagic{'K', 'D', 'B', 'G', 'S', 'N', 'P', '\0'};

Result<void> ValidateSnapshotSpace(
    const MemorySpace& space,
    std::string operation) {
    if (space.label.size() > MemorySnapshot::kMaxLabelBytes) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot label exceeds the core limit",
            std::move(operation)));
    }
    switch (space.kind) {
    case MemorySpaceKind::Physical:
    case MemorySpaceKind::KernelVirtual:
        if (space.pid != 0 || space.directory_table_base != 0) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Non-process snapshots must not carry a PID or directory-table base",
                std::move(operation)));
        }
        return Result<void>::Success();
    case MemorySpaceKind::ProcessVirtual:
        if (space.pid == 0) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Process snapshots require a non-zero PID",
                std::move(operation)));
        }
        return Result<void>::Success();
    }
    return Result<void>::Failure(MakeError(
        ErrorCode::InvalidArgument,
        "Snapshot contains an unknown memory-space kind",
        std::move(operation)));
}

bool CheckedAdd(std::uint64_t left, std::uint64_t right, std::uint64_t& sum) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return false;
    }
    sum = left + right;
    return true;
}

}  // namespace

Result<MemorySnapshot> MemorySnapshot::Capture(
    IMemoryBackend& backend,
    MemorySpace space,
    std::uint64_t address,
    std::uint64_t size,
    std::uint32_t chunk_size,
    std::stop_token stop_token) {
    const MemorySpace read_space = space;
    return CaptureWithReader(
        std::move(space),
        address,
        size,
        chunk_size,
        stop_token,
        [&backend, read_space](std::uint64_t current, std::uint32_t length) {
            return ReadMemory(backend, read_space, current, length);
        });
}

Result<MemorySnapshot> MemorySnapshot::Capture(
    IProcessMemory& memory,
    std::uint64_t address,
    std::uint64_t size,
    std::uint32_t chunk_size,
    std::stop_token stop_token) {
    if (!memory.IsOpen()) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Cannot capture a snapshot without an attached process",
            "MemorySnapshot::Capture"));
    }
    const auto space = MemorySpace::Process(
        memory.ProcessId(),
        0,
        "PID " + std::to_string(memory.ProcessId()));
    return CaptureWithReader(
        space,
        address,
        size,
        chunk_size,
        stop_token,
        [&memory](std::uint64_t current, std::uint32_t length) {
            return memory.Read(current, length);
        });
}

Result<MemorySnapshot> MemorySnapshot::CaptureWithReader(
    MemorySpace space,
    std::uint64_t address,
    std::uint64_t size,
    std::uint32_t chunk_size,
    std::stop_token stop_token,
    Reader reader) {
    const auto valid_space = ValidateSnapshotSpace(
        space,
        "MemorySnapshot::Capture");
    if (!valid_space) {
        return Result<MemorySnapshot>::Failure(valid_space.GetError());
    }
    if (size == 0 || size > std::numeric_limits<std::size_t>::max()) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Snapshot size is zero or cannot fit in this process",
            "MemorySnapshot::Capture"));
    }
    if (size > kMaxSnapshotBytes) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot size exceeds the 512 MiB core limit",
            "MemorySnapshot::Capture",
            0,
            kMaxSnapshotBytes,
            size));
    }
    std::uint64_t range_end = 0;
    if (!CheckedAdd(address, size, range_end)) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Snapshot address range overflows",
            "MemorySnapshot::Capture"));
    }
    (void)range_end;
    if (chunk_size == 0 || chunk_size > kMaxChunkBytes) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Snapshot chunk size is zero or exceeds the 1 MiB core limit",
            "MemorySnapshot::Capture",
            0,
            kMaxChunkBytes,
            chunk_size));
    }
    chunk_size = std::max<std::uint32_t>(4096, chunk_size);

    try {
        MemorySnapshot snapshot{};
        snapshot.space_ = std::move(space);
        snapshot.address_ = address;
        snapshot.bytes_.reserve(static_cast<std::size_t>(size));

        std::uint64_t offset = 0;
        while (offset < size) {
            if (stop_token.stop_requested()) {
                return Result<MemorySnapshot>::Failure(MakeError(
                    ErrorCode::Cancelled,
                    "Snapshot capture was cancelled",
                    "MemorySnapshot::Capture"));
            }
            const auto remaining = size - offset;
            const auto current = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(remaining, chunk_size));
            auto bytes = reader(address + offset, current);
            if (!bytes) {
                return Result<MemorySnapshot>::Failure(bytes.GetError());
            }
            if (bytes.Value().size() != current) {
                return Result<MemorySnapshot>::Failure(MakeError(
                    ErrorCode::ShortRead,
                    "Snapshot capture returned a short read",
                    "MemorySnapshot::Capture",
                    0,
                    current,
                    bytes.Value().size()));
            }
            snapshot.bytes_.insert(
                snapshot.bytes_.end(),
                bytes.Value().begin(),
                bytes.Value().end());
            offset += current;
        }
        snapshot.checksum_ = Crc32(snapshot.bytes_);
        return Result<MemorySnapshot>::Success(std::move(snapshot));
    } catch (const std::bad_alloc&) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot capture exhausted the allocation budget",
            "MemorySnapshot::Capture"));
    } catch (const std::length_error&) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot capture requested an invalid allocation",
            "MemorySnapshot::Capture"));
    }
}

Result<std::vector<SnapshotDiffRun>> MemorySnapshot::Diff(
    const MemorySnapshot& newer,
    std::size_t max_runs) const {
    if (space_.kind != newer.space_.kind ||
        space_.pid != newer.space_.pid ||
        address_ != newer.address_ ||
        bytes_.size() != newer.bytes_.size()) {
        return Result<std::vector<SnapshotDiffRun>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Snapshots cover different address spaces or ranges",
            "MemorySnapshot::Diff"));
    }

    std::vector<SnapshotDiffRun> runs;
    std::size_t index = 0;
    while (index < bytes_.size()) {
        if (bytes_[index] == newer.bytes_[index]) {
            ++index;
            continue;
        }
        if (runs.size() >= max_runs) {
            return Result<std::vector<SnapshotDiffRun>>::Failure(MakeError(
                ErrorCode::LimitReached,
                "Snapshot diff reached the configured run limit",
                "MemorySnapshot::Diff",
                0,
                max_runs,
                runs.size()));
        }
        const std::size_t start = index;
        while (index < bytes_.size() && bytes_[index] != newer.bytes_[index]) {
            ++index;
        }
        SnapshotDiffRun run{};
        run.offset = start;
        run.before.assign(bytes_.begin() + static_cast<std::ptrdiff_t>(start),
                          bytes_.begin() + static_cast<std::ptrdiff_t>(index));
        run.after.assign(newer.bytes_.begin() + static_cast<std::ptrdiff_t>(start),
                         newer.bytes_.begin() + static_cast<std::ptrdiff_t>(index));
        runs.push_back(std::move(run));
    }
    return Result<std::vector<SnapshotDiffRun>>::Success(std::move(runs));
}

Result<void> MemorySnapshot::Save(const std::filesystem::path& path) const {
    if (bytes_.empty()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Cannot save an empty snapshot",
            "MemorySnapshot::Save"));
    }
    if (bytes_.size() > kMaxSnapshotBytes ||
        space_.label.size() > kMaxLabelBytes) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot label is too long",
            "MemorySnapshot::Save"));
    }
    const auto valid_space = ValidateSnapshotSpace(
        space_,
        "MemorySnapshot::Save");
    if (!valid_space) {
        return valid_space;
    }
    std::uint64_t range_end = 0;
    if (!CheckedAdd(address_, bytes_.size(), range_end)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::AddressOverflow,
            "Snapshot address range overflows",
            "MemorySnapshot::Save"));
    }
    (void)range_end;

    SnapshotHeader header{};
    std::memcpy(header.magic, kMagic.data(), kMagic.size());
    header.version = 1;
    header.kind = static_cast<std::uint32_t>(space_.kind);
    header.pid = space_.pid;
    header.directory_table_base = space_.directory_table_base;
    header.address = address_;
    header.byte_count = bytes_.size();
    header.checksum = checksum_;
    header.label_size = static_cast<std::uint32_t>(space_.label.size());

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to create snapshot file",
            "MemorySnapshot::Save"));
    }
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    output.write(space_.label.data(), static_cast<std::streamsize>(space_.label.size()));
    output.write(
        reinterpret_cast<const char*>(bytes_.data()),
        static_cast<std::streamsize>(bytes_.size()));
    if (!output) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Failed while writing snapshot file",
            "MemorySnapshot::Save"));
    }
    return Result<void>::Success();
}

Result<MemorySnapshot> MemorySnapshot::Load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to open snapshot file",
            "MemorySnapshot::Load"));
    }

    std::error_code file_error;
    const auto file_size = std::filesystem::file_size(path, file_error);
    if (file_error) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to determine snapshot file size",
            "MemorySnapshot::Load",
            static_cast<std::uint64_t>(file_error.value())));
    }

    SnapshotHeader header{};
    input.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (!input ||
        !std::equal(kMagic.begin(), kMagic.end(), header.magic) ||
        header.version != 1 ||
        header.reserved != 0 ||
        header.kind > static_cast<std::uint32_t>(MemorySpaceKind::KernelVirtual) ||
        header.byte_count == 0 ||
        header.byte_count > kMaxSnapshotBytes ||
        header.byte_count > std::numeric_limits<std::size_t>::max() ||
        header.label_size > kMaxLabelBytes) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::ParseError,
            "Snapshot file header is invalid",
            "MemorySnapshot::Load"));
    }

    std::uint64_t payload_size = 0;
    std::uint64_t expected_size = 0;
    std::uint64_t range_end = 0;
    if (!CheckedAdd(header.label_size, header.byte_count, payload_size) ||
        !CheckedAdd(sizeof(SnapshotHeader), payload_size, expected_size) ||
        expected_size != file_size ||
        !CheckedAdd(header.address, header.byte_count, range_end)) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::ParseError,
            "Snapshot file length or address range is invalid",
            "MemorySnapshot::Load"));
    }
    (void)range_end;

    try {
        MemorySnapshot snapshot{};
        snapshot.space_.kind = static_cast<MemorySpaceKind>(header.kind);
        snapshot.space_.pid = header.pid;
        snapshot.space_.directory_table_base = header.directory_table_base;
        const auto valid_space = ValidateSnapshotSpace(
            snapshot.space_,
            "MemorySnapshot::Load");
        if (!valid_space) {
            return Result<MemorySnapshot>::Failure(MakeError(
                ErrorCode::ParseError,
                valid_space.GetError().message,
                "MemorySnapshot::Load"));
        }
        snapshot.space_.label.resize(header.label_size);
        input.read(
            snapshot.space_.label.data(),
            static_cast<std::streamsize>(header.label_size));
        snapshot.address_ = header.address;
        snapshot.bytes_.resize(static_cast<std::size_t>(header.byte_count));
        input.read(
            reinterpret_cast<char*>(snapshot.bytes_.data()),
            static_cast<std::streamsize>(snapshot.bytes_.size()));
        if (!input || input.peek() != std::char_traits<char>::eof()) {
            return Result<MemorySnapshot>::Failure(MakeError(
                ErrorCode::ParseError,
                "Snapshot file is truncated or has trailing data",
                "MemorySnapshot::Load"));
        }
        snapshot.checksum_ = Crc32(snapshot.bytes_);
        if (snapshot.checksum_ != header.checksum) {
            return Result<MemorySnapshot>::Failure(MakeError(
                ErrorCode::VerificationMismatch,
                "Snapshot checksum does not match its payload",
                "MemorySnapshot::Load"));
        }
        return Result<MemorySnapshot>::Success(std::move(snapshot));
    } catch (const std::bad_alloc&) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot file exhausted the allocation budget",
            "MemorySnapshot::Load"));
    } catch (const std::length_error&) {
        return Result<MemorySnapshot>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot file requested an invalid allocation",
            "MemorySnapshot::Load"));
    }
}

std::uint32_t MemorySnapshot::Crc32(
    std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t crc = 0xFFFFFFFFU;
    for (const auto byte : bytes) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}

}  // namespace kdbg

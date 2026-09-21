#include "core/snapshot/MemorySnapshot.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <fstream>
#include <limits>
#include <new>
#include <stdexcept>
#include <system_error>

#if defined(_WIN32)
#include <process.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

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
constexpr std::uint64_t kProgressCheckpointBytes = 64U * 1024U;

void ReportProgress(
    const SnapshotProgressCallback& callback,
    SnapshotProgressPhase phase,
    std::uint64_t completed,
    std::uint64_t total,
    std::size_t runs = 0) {
    if (callback) {
        callback(SnapshotProgress{phase, completed, total, runs});
    }
}

template <typename T>
Result<T> Cancelled(std::string operation, std::string message) {
    return Result<T>::Failure(MakeError(
        ErrorCode::Cancelled,
        std::move(message),
        std::move(operation)));
}

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
    std::stop_token stop_token,
    SnapshotProgressCallback progress) {
    const MemorySpace read_space = space;
    return CaptureWithReader(
        std::move(space),
        address,
        size,
        chunk_size,
        stop_token,
        std::move(progress),
        [&backend, read_space](std::uint64_t current, std::uint32_t length) {
            return ReadMemory(backend, read_space, current, length);
        });
}

Result<MemorySnapshot> MemorySnapshot::Capture(
    IProcessMemory& memory,
    std::uint64_t address,
    std::uint64_t size,
    std::uint32_t chunk_size,
    std::stop_token stop_token,
    SnapshotProgressCallback progress) {
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
        std::move(progress),
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
    SnapshotProgressCallback progress,
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
    if (stop_token.stop_requested()) {
        return Cancelled<MemorySnapshot>(
            "MemorySnapshot::Capture",
            "Snapshot capture was cancelled");
    }

    try {
        MemorySnapshot snapshot{};
        snapshot.space_ = std::move(space);
        snapshot.address_ = address;
        snapshot.bytes_.reserve(static_cast<std::size_t>(size));

        std::uint64_t offset = 0;
        ReportProgress(
            progress, SnapshotProgressPhase::CaptureRead, 0, size);
        while (offset < size) {
            if (stop_token.stop_requested()) {
                return Cancelled<MemorySnapshot>(
                    "MemorySnapshot::Capture",
                    "Snapshot capture was cancelled");
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
            ReportProgress(
                progress,
                SnapshotProgressPhase::CaptureRead,
                offset,
                size);
        }
        auto checksum = Crc32(
            snapshot.bytes_,
            stop_token,
            progress,
            SnapshotProgressPhase::CaptureChecksum);
        if (!checksum) {
            return Result<MemorySnapshot>::Failure(checksum.GetError());
        }
        snapshot.checksum_ = checksum.Value();
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
    std::size_t max_runs,
    std::uint64_t max_changed_bytes,
    std::stop_token stop_token,
    SnapshotProgressCallback progress) const {
    if (space_.kind != newer.space_.kind ||
        space_.pid != newer.space_.pid ||
        address_ != newer.address_ ||
        bytes_.size() != newer.bytes_.size()) {
        return Result<std::vector<SnapshotDiffRun>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Snapshots cover different address spaces or ranges",
            "MemorySnapshot::Diff"));
    }
    if (max_runs == 0 || max_runs > kMaxDiffRuns ||
        max_changed_bytes == 0 || max_changed_bytes > kMaxSnapshotBytes) {
        return Result<std::vector<SnapshotDiffRun>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Snapshot diff budgets are zero or exceed the core limits",
            "MemorySnapshot::Diff"));
    }
    if (stop_token.stop_requested()) {
        return Cancelled<std::vector<SnapshotDiffRun>>(
            "MemorySnapshot::Diff",
            "Snapshot diff was cancelled");
    }

    try {
        std::vector<SnapshotDiffRun> runs;
        runs.reserve(std::min<std::size_t>(max_runs, 4096));
        std::size_t index = 0;
        std::uint64_t changed_bytes = 0;
        std::size_t next_checkpoint = 0;
        ReportProgress(
            progress, SnapshotProgressPhase::Diff, 0, bytes_.size());
        while (index < bytes_.size()) {
            if (index >= next_checkpoint) {
                if (stop_token.stop_requested()) {
                    return Cancelled<std::vector<SnapshotDiffRun>>(
                        "MemorySnapshot::Diff",
                        "Snapshot diff was cancelled");
                }
                ReportProgress(
                    progress,
                    SnapshotProgressPhase::Diff,
                    index,
                    bytes_.size(),
                    runs.size());
                next_checkpoint = index +
                    static_cast<std::size_t>(kProgressCheckpointBytes);
            }
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
                if (index >= next_checkpoint) {
                    if (stop_token.stop_requested()) {
                        return Cancelled<std::vector<SnapshotDiffRun>>(
                            "MemorySnapshot::Diff",
                            "Snapshot diff was cancelled");
                    }
                    ReportProgress(
                        progress,
                        SnapshotProgressPhase::Diff,
                        index,
                        bytes_.size(),
                        runs.size());
                    next_checkpoint = index +
                        static_cast<std::size_t>(kProgressCheckpointBytes);
                }
            }
            const auto length = static_cast<std::uint64_t>(index - start);
            if (length > max_changed_bytes - changed_bytes) {
                return Result<std::vector<SnapshotDiffRun>>::Failure(MakeError(
                    ErrorCode::LimitReached,
                    "Snapshot diff reached the configured changed-byte limit",
                    "MemorySnapshot::Diff",
                    0,
                    max_changed_bytes,
                    changed_bytes + length));
            }
            changed_bytes += length;
            runs.push_back(SnapshotDiffRun{
                static_cast<std::uint64_t>(start), length});
        }
        ReportProgress(
            progress,
            SnapshotProgressPhase::Diff,
            bytes_.size(),
            bytes_.size(),
            runs.size());
        return Result<std::vector<SnapshotDiffRun>>::Success(std::move(runs));
    } catch (const std::bad_alloc&) {
        return Result<std::vector<SnapshotDiffRun>>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot diff exhausted the allocation budget",
            "MemorySnapshot::Diff"));
    } catch (const std::length_error&) {
        return Result<std::vector<SnapshotDiffRun>>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot diff requested an invalid allocation",
            "MemorySnapshot::Diff"));
    }
}

std::filesystem::path TemporarySibling(
    const std::filesystem::path& destination) {
    static std::atomic<std::uint64_t> sequence{0};
#if defined(_WIN32)
    const auto pid = static_cast<std::uint64_t>(_getpid());
#else
    const auto pid = static_cast<std::uint64_t>(getpid());
#endif
    auto parent = destination.parent_path();
    if (parent.empty()) parent = std::filesystem::path{"."};
    for (;;) {
        const auto ordinal = sequence.fetch_add(1, std::memory_order_relaxed);
        const auto candidate = parent /
            (destination.filename().string() + ".kdbg-tmp-" +
             std::to_string(pid) + '-' + std::to_string(ordinal));
        std::error_code error;
        if (!std::filesystem::exists(candidate, error)) return candidate;
    }
}

Result<void> FlushFileToDisk(const std::filesystem::path& path) {
#if defined(_WIN32)
    const auto handle = ::CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to reopen the temporary snapshot for flush",
            "MemorySnapshot::Save",
            ::GetLastError()));
    }
    const bool flushed = ::FlushFileBuffers(handle) != FALSE;
    const auto error = flushed ? ERROR_SUCCESS : ::GetLastError();
    ::CloseHandle(handle);
    if (!flushed) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to flush the temporary snapshot to disk",
            "MemorySnapshot::Save",
            error));
    }
#else
    const int descriptor = ::open(path.c_str(), O_RDONLY);
    if (descriptor < 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to reopen the temporary snapshot for flush",
            "MemorySnapshot::Save"));
    }
    const bool flushed = ::fsync(descriptor) == 0;
    ::close(descriptor);
    if (!flushed) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to flush the temporary snapshot to disk",
            "MemorySnapshot::Save"));
    }
#endif
    return Result<void>::Success();
}

Result<void> ReplaceAtomically(
    const std::filesystem::path& temporary,
    const std::filesystem::path& destination) {
#if defined(_WIN32)
    if (::MoveFileExW(
            temporary.c_str(),
            destination.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to atomically replace the snapshot file",
            "MemorySnapshot::Save",
            ::GetLastError()));
    }
#else
    std::error_code error;
    std::filesystem::rename(temporary, destination, error);
    if (error) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to atomically replace the snapshot file",
            "MemorySnapshot::Save",
            static_cast<std::uint64_t>(error.value())));
    }
#endif
    return Result<void>::Success();
}

Result<void> MemorySnapshot::Save(
    const std::filesystem::path& path,
    std::stop_token stop_token,
    SnapshotProgressCallback progress,
    SnapshotSaveFault fault) const {
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
    if (stop_token.stop_requested()) {
        return Cancelled<void>(
            "MemorySnapshot::Save",
            "Snapshot save was cancelled");
    }
    if (path.empty() || path.filename().empty()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Snapshot destination path is invalid",
            "MemorySnapshot::Save"));
    }

    try {
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

    const auto temporary = TemporarySibling(path);
    struct TemporaryCleanup {
        std::filesystem::path path;
        bool committed{false};
        ~TemporaryCleanup() {
            if (!committed) {
                std::error_code ignored_error;
                std::filesystem::remove(path, ignored_error);
            }
        }
    } cleanup{temporary};

    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to create snapshot file",
            "MemorySnapshot::Save"));
    }
    const auto total = static_cast<std::uint64_t>(sizeof(header)) +
        space_.label.size() + bytes_.size();
    std::uint64_t completed = 0;
    ReportProgress(progress, SnapshotProgressPhase::Save, completed, total);
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    completed += sizeof(header);
    if (stop_token.stop_requested()) {
        return Cancelled<void>(
            "MemorySnapshot::Save",
            "Snapshot save was cancelled");
    }
    output.write(space_.label.data(), static_cast<std::streamsize>(space_.label.size()));
    completed += space_.label.size();
    std::size_t offset = 0;
    while (offset < bytes_.size()) {
        if (stop_token.stop_requested()) {
            return Cancelled<void>(
                "MemorySnapshot::Save",
                "Snapshot save was cancelled");
        }
        const auto count = std::min<std::size_t>(
            bytes_.size() - offset, kMaxChunkBytes);
        output.write(
            reinterpret_cast<const char*>(bytes_.data() + offset),
            static_cast<std::streamsize>(count));
        if (!output) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Failed while writing snapshot file",
                "MemorySnapshot::Save"));
        }
        offset += count;
        completed += count;
        ReportProgress(
            progress, SnapshotProgressPhase::Save, completed, total);
    }
    if (stop_token.stop_requested()) {
        return Cancelled<void>(
            "MemorySnapshot::Save",
            "Snapshot save was cancelled");
    }
    output.flush();
    if (!output) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Failed while flushing the temporary snapshot",
            "MemorySnapshot::Save"));
    }
    output.close();
    if (!output) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Failed while closing the temporary snapshot",
            "MemorySnapshot::Save"));
    }
    const auto durable = FlushFileToDisk(temporary);
    if (!durable) return durable;
    if (stop_token.stop_requested()) {
        return Cancelled<void>(
            "MemorySnapshot::Save",
            "Snapshot save was cancelled before commit");
    }
    if (fault == SnapshotSaveFault::AfterFlushBeforeReplace) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Injected snapshot failure before atomic replacement",
            "MemorySnapshot::Save"));
    }
    const auto replaced = ReplaceAtomically(temporary, path);
    if (!replaced) return replaced;
    cleanup.committed = true;
    return Result<void>::Success();
    } catch (const std::bad_alloc&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot save exhausted the allocation budget",
            "MemorySnapshot::Save"));
    } catch (const std::length_error&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Snapshot save requested an invalid allocation",
            "MemorySnapshot::Save"));
    }
}

Result<MemorySnapshot> MemorySnapshot::Load(
    const std::filesystem::path& path,
    std::stop_token stop_token,
    SnapshotProgressCallback progress) {
    if (stop_token.stop_requested()) {
        return Cancelled<MemorySnapshot>(
            "MemorySnapshot::Load",
            "Snapshot load was cancelled");
    }
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
        const auto payload_total = static_cast<std::uint64_t>(header.label_size) +
            header.byte_count;
        std::uint64_t completed = 0;
        ReportProgress(
            progress, SnapshotProgressPhase::LoadRead, completed, payload_total);
        if (stop_token.stop_requested()) {
            return Cancelled<MemorySnapshot>(
                "MemorySnapshot::Load",
                "Snapshot load was cancelled");
        }
        snapshot.space_.label.resize(header.label_size);
        input.read(
            snapshot.space_.label.data(),
            static_cast<std::streamsize>(header.label_size));
        if (!input) {
            return Result<MemorySnapshot>::Failure(MakeError(
                ErrorCode::ParseError,
                "Snapshot file is truncated",
                "MemorySnapshot::Load"));
        }
        completed += header.label_size;
        snapshot.address_ = header.address;
        snapshot.bytes_.resize(static_cast<std::size_t>(header.byte_count));
        std::size_t offset = 0;
        while (offset < snapshot.bytes_.size()) {
            if (stop_token.stop_requested()) {
                return Cancelled<MemorySnapshot>(
                    "MemorySnapshot::Load",
                    "Snapshot load was cancelled");
            }
            const auto count = std::min<std::size_t>(
                snapshot.bytes_.size() - offset, kMaxChunkBytes);
            input.read(
                reinterpret_cast<char*>(snapshot.bytes_.data() + offset),
                static_cast<std::streamsize>(count));
            if (!input) {
                return Result<MemorySnapshot>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "Snapshot file is truncated",
                    "MemorySnapshot::Load"));
            }
            offset += count;
            completed += count;
            ReportProgress(
                progress,
                SnapshotProgressPhase::LoadRead,
                completed,
                payload_total);
        }
        if (!input || input.peek() != std::char_traits<char>::eof()) {
            return Result<MemorySnapshot>::Failure(MakeError(
                ErrorCode::ParseError,
                "Snapshot file is truncated or has trailing data",
                "MemorySnapshot::Load"));
        }
        auto checksum = Crc32(
            snapshot.bytes_,
            stop_token,
            progress,
            SnapshotProgressPhase::LoadChecksum);
        if (!checksum) {
            return Result<MemorySnapshot>::Failure(checksum.GetError());
        }
        snapshot.checksum_ = checksum.Value();
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

Result<std::uint32_t> MemorySnapshot::Crc32(
    std::span<const std::uint8_t> bytes,
    std::stop_token stop_token,
    const SnapshotProgressCallback& progress,
    SnapshotProgressPhase phase) {
    static constexpr auto kTable = [] {
        std::array<std::uint32_t, 256> table{};
        std::uint32_t seed = 0;
        for (auto& entry : table) {
            std::uint32_t value = seed++;
            for (std::uint32_t bit = 0; bit < 8U; ++bit) {
                const std::uint32_t mask = 0U - (value & 1U);
                value = (value >> 1U) ^ (0xEDB88320U & mask);
            }
            entry = value;
        }
        return table;
    }();

    std::uint32_t crc = 0xFFFFFFFFU;
    ReportProgress(progress, phase, 0, bytes.size());
    std::size_t next_checkpoint = 0;
    for (std::size_t offset = 0; offset < bytes.size(); ++offset) {
        if (offset >= next_checkpoint) {
            if (stop_token.stop_requested()) {
                return Cancelled<std::uint32_t>(
                    phase == SnapshotProgressPhase::CaptureChecksum
                        ? "MemorySnapshot::Capture"
                        : "MemorySnapshot::Load",
                    "Snapshot checksum was cancelled");
            }
            ReportProgress(progress, phase, offset, bytes.size());
            next_checkpoint = offset +
                static_cast<std::size_t>(kProgressCheckpointBytes);
        }
        const auto byte = bytes[offset];
        const auto index = static_cast<std::uint8_t>(crc ^ byte);
        crc = (crc >> 8U) ^ kTable[index];
    }
    ReportProgress(progress, phase, bytes.size(), bytes.size());
    return Result<std::uint32_t>::Success(~crc);
}

}  // namespace kdbg

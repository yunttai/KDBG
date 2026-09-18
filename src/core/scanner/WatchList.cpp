#include "core/scanner/WatchList.h"

#include "core/scanner/ValueCodec.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <fstream>
#include <limits>

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
struct WatchFilePrefix {
    char magic[8];
    std::uint32_t version;
};

struct LegacyWatchFileHeader {
    char magic[8];
    std::uint32_t version;
    std::uint32_t pid;
    std::uint64_t entry_count;
};

struct WatchFileHeader {
    char magic[8];
    std::uint32_t version;
    std::uint32_t pid;
    std::uint64_t process_identity_token;
    std::uint64_t entry_count;
};

struct WatchFileEntryHeader {
    std::uint64_t address;
    std::uint32_t type;
    std::uint32_t flags;
    std::uint32_t description_size;
    std::uint32_t frozen_value_size;
};
#pragma pack(pop)

static_assert(sizeof(WatchFilePrefix) == 12);
static_assert(sizeof(LegacyWatchFileHeader) == 24);
static_assert(sizeof(WatchFileHeader) == 32);
static_assert(sizeof(WatchFileEntryHeader) == 24);

constexpr std::array<char, 8> kWatchMagic{
    'K', 'D', 'B', 'G', 'A', 'L', '\0', '\0'};
constexpr std::uint32_t kLegacyWatchVersion = 1;
constexpr std::uint32_t kWatchVersion = 2;
constexpr std::uint32_t kWatchFlagHexadecimal = 1U << 0U;
constexpr std::uint32_t kWatchFlagWasFrozen = 1U << 1U;
constexpr std::uint64_t kMaxPersistedEntries = 100'000;
constexpr std::uint32_t kMaxDescriptionBytes = 4096U;
constexpr std::uintmax_t kMaxWatchFileBytes = 64ULL * 1024ULL * 1024ULL;

class ProcessWriteArmGuard {
public:
    ProcessWriteArmGuard(IProcessMemory& memory, bool armed)
        : memory_(memory), armed_(armed) {}

    Result<void> Disarm() {
        if (!armed_) return Result<void>::Success();
        auto result = memory_.SetWritesArmed(false);
        if (result) {
            armed_ = false;
            return result;
        }
        const auto retry = memory_.SetWritesArmed(false);
        if (retry) {
            armed_ = false;
            auto error = result.GetError();
            error.message +=
                "; a cleanup retry locked the gate, but the transaction is failed";
            return Result<void>::Failure(std::move(error));
        }
        auto error = result.GetError();
        error.message += "; cleanup retry also failed: " +
            retry.GetError().message;
        return Result<void>::Failure(std::move(error));
    }

    ~ProcessWriteArmGuard() {
        if (armed_) static_cast<void>(memory_.SetWritesArmed(false));
    }

    ProcessWriteArmGuard(const ProcessWriteArmGuard&) = delete;
    ProcessWriteArmGuard& operator=(const ProcessWriteArmGuard&) = delete;

private:
    IProcessMemory& memory_;
    bool armed_{false};
};

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

Result<void> FlushFileToDisk(
    const std::filesystem::path& path,
    std::string_view operation) {
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
            "Unable to reopen the temporary address-list file for flush",
            std::string(operation),
            ::GetLastError()));
    }
    const bool flushed = ::FlushFileBuffers(handle) != FALSE;
    const auto error = flushed ? ERROR_SUCCESS : ::GetLastError();
    ::CloseHandle(handle);
    if (!flushed) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to flush the temporary address-list file to disk",
            std::string(operation),
            error));
    }
#else
    const int descriptor = ::open(path.c_str(), O_RDONLY);
    if (descriptor < 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to reopen the temporary address-list file for flush",
            std::string(operation)));
    }
    const bool flushed = ::fsync(descriptor) == 0;
    ::close(descriptor);
    if (!flushed) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to flush the temporary address-list file to disk",
            std::string(operation)));
    }
#endif
    return Result<void>::Success();
}

Result<void> ReplaceAtomically(
    const std::filesystem::path& temporary,
    const std::filesystem::path& destination,
    std::string_view operation) {
#if defined(_WIN32)
    if (::MoveFileExW(
            temporary.c_str(),
            destination.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to atomically replace the address-list file",
            std::string(operation),
            ::GetLastError()));
    }
#else
    std::error_code error;
    std::filesystem::rename(temporary, destination, error);
    if (error) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to atomically replace the address-list file",
            std::string(operation),
            static_cast<std::uint64_t>(error.value())));
    }
#endif
    return Result<void>::Success();
}

Result<void> FileFailure(std::string message, const char* operation) {
    return Result<void>::Failure(MakeError(
        ErrorCode::IoFailure,
        std::move(message),
        operation));
}

}  // namespace

WatchList::WatchList(IProcessMemory& memory) : memory_(memory) {}

Result<std::uint64_t> WatchList::Add(
    std::uint64_t address,
    ScanValueType type,
    std::string description,
    bool hexadecimal) {
    const auto width = FixedValueWidth(type);
    if (address == 0 || width == 0 ||
        address > std::numeric_limits<std::uint64_t>::max() - width) {
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Watch entries require a non-zero address and fixed-width value type",
            "WatchList::Add"));
    }
    if (entries_.size() >= kMaxPersistedEntries ||
        description.size() > kMaxDescriptionBytes) {
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address-list entry or description limit was reached",
            "WatchList::Add",
            0,
            kMaxPersistedEntries,
            entries_.size()));
    }
    const auto read = memory_.Read(address, static_cast<std::uint32_t>(width));
    if (!read) {
        return Result<std::uint64_t>::Failure(read.GetError());
    }
    if (read.Value().size() != width) {
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Watch entry initial read was incomplete",
            "WatchList::Add",
            0,
            width,
            read.Value().size()));
    }
    WatchEntry entry{};
    entry.id = next_id_++;
    entry.address = address;
    entry.type = type;
    entry.description = std::move(description);
    entry.hexadecimal = hexadecimal;
    entry.value = read.Value();
    entries_.push_back(std::move(entry));
    return Result<std::uint64_t>::Success(entries_.back().id);
}

Result<void> WatchList::Remove(std::uint64_t id) {
    const auto it = std::find_if(
        entries_.begin(),
        entries_.end(),
        [&](const WatchEntry& entry) { return entry.id == id; });
    if (it == entries_.end()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::NotFound,
            "Watch entry was not found",
            "WatchList::Remove"));
    }
    entries_.erase(it);
    return Result<void>::Success();
}

void WatchList::Clear() noexcept { entries_.clear(); }

Result<void> WatchList::Refresh() {
    std::size_t failures = 0;
    for (auto& entry : entries_) {
        const auto width = FixedValueWidth(entry.type);
        const auto read = memory_.Read(
            entry.address,
            static_cast<std::uint32_t>(width));
        if (!read) {
            entry.last_error = read.GetError().message;
            ++failures;
            continue;
        }
        if (read.Value().size() != width) {
            entry.last_error = "Watch refresh returned a short read";
            ++failures;
            continue;
        }
        entry.value = read.Value();
        entry.last_error.clear();
    }
    if (failures != 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ShortRead,
            "One or more address-list values could not be refreshed",
            "WatchList::Refresh",
            0,
            entries_.size(),
            entries_.size() - failures));
    }
    return Result<void>::Success();
}

Result<void> WatchList::WriteValue(
    std::uint64_t id,
    std::string_view value_text) {
    const bool writes_armed = memory_.WritesArmed();
    ProcessWriteArmGuard arm_guard(memory_, writes_armed);
    auto finish = [&](Result<void> outcome) -> Result<void> {
        const auto disarm = arm_guard.Disarm();
        return disarm ? outcome : Result<void>::Failure(disarm.GetError());
    };
    auto* entry = Find(id);
    if (entry == nullptr) {
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::NotFound,
            "Watch entry was not found",
            "WatchList::WriteValue")));
    }
    const auto encoded = EncodeValue(
        entry->type,
        value_text,
        entry->hexadecimal);
    if (!encoded) {
        return finish(Result<void>::Failure(encoded.GetError()));
    }
    if (!writes_armed) {
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Arm process writes before editing an address-list value",
            "WatchList::WriteValue")));
    }
    const auto before = memory_.Read(
        entry->address,
        static_cast<std::uint32_t>(encoded.Value().size()));
    if (!before) {
        entry->last_error = before.GetError().message;
        return finish(Result<void>::Failure(before.GetError()));
    }
    if (before.Value().size() != entry->value.size()) {
        entry->last_error = "Address-list preflight returned a short read";
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::ShortRead,
            entry->last_error,
            "WatchList::WriteValue",
            0,
            entry->value.size(),
            before.Value().size())));
    }
    if (before.Value() != entry->value) {
        entry->last_error =
            "Value changed after it was presented; refresh before writing";
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            entry->last_error,
            "WatchList::WriteValue")));
    }
    const auto written = memory_.Write(entry->address, encoded.Value());
    if (!written) {
        entry->last_error = written.GetError().message;
        return finish(Result<void>::Failure(written.GetError()));
    }
    if (written.Value() != encoded.Value().size()) {
        entry->last_error = "Watch value write was incomplete";
        return finish(Result<void>::Failure(MakeError(
            ErrorCode::ShortWrite,
            entry->last_error,
            "WatchList::WriteValue",
            0,
            encoded.Value().size(),
            written.Value())));
    }
    const auto disarm = arm_guard.Disarm();
    const auto readback = memory_.Read(
        entry->address,
        static_cast<std::uint32_t>(encoded.Value().size()));
    if (!readback) {
        entry->last_error = readback.GetError().message;
        return disarm
            ? Result<void>::Failure(readback.GetError())
            : Result<void>::Failure(disarm.GetError());
    }
    if (readback.Value().size() != encoded.Value().size()) {
        entry->last_error = "Watch value read-back returned a short read";
        return disarm
            ? Result<void>::Failure(MakeError(
                ErrorCode::ShortRead,
                entry->last_error,
                "WatchList::WriteValue",
                0,
                encoded.Value().size(),
                readback.Value().size()))
            : Result<void>::Failure(disarm.GetError());
    }
    if (readback.Value() != encoded.Value()) {
        entry->last_error = "Watch value read-back verification failed";
        return disarm
            ? Result<void>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            entry->last_error,
            "WatchList::WriteValue"))
            : Result<void>::Failure(disarm.GetError());
    }
    entry->value = readback.Value();
    if (entry->frozen) {
        entry->frozen_value = entry->value;
    }
    entry->last_error.clear();
    return disarm ? Result<void>::Success()
                  : Result<void>::Failure(disarm.GetError());
}

Result<void> WatchList::SetFrozen(std::uint64_t id, bool frozen) {
    auto* entry = Find(id);
    if (entry == nullptr) {
        return Result<void>::Failure(MakeError(
            ErrorCode::NotFound,
            "Watch entry was not found",
            "WatchList::SetFrozen"));
    }
    if (frozen && !memory_.WritesArmed()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Arm process writes before freezing an address",
            "WatchList::SetFrozen"));
    }
    entry->frozen = frozen;
    entry->frozen_value = frozen ? entry->value : std::vector<std::uint8_t>{};
    return Result<void>::Success();
}

Result<void> WatchList::FreezeTick() {
    const bool writes_armed = memory_.WritesArmed();
    ProcessWriteArmGuard arm_guard(memory_, writes_armed);
    auto finish = [&](Result<void> outcome) -> Result<void> {
        const auto disarm = arm_guard.Disarm();
        return disarm ? outcome : Result<void>::Failure(disarm.GetError());
    };
    if (!writes_armed) {
        const bool any_frozen = std::any_of(
            entries_.begin(),
            entries_.end(),
            [](const WatchEntry& entry) { return entry.frozen; });
        if (any_frozen) {
            return finish(Result<void>::Failure(MakeError(
                ErrorCode::WriteLocked,
                "Process write gate was closed while frozen entries were active",
                "WatchList::FreezeTick")));
        }
        return finish(Result<void>::Success());
    }
    std::size_t failures = 0;
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        auto& entry = entries_[index];
        if (!entry.frozen) {
            continue;
        }
        const auto width = FixedValueWidth(entry.type);
        if (width == 0 || entry.frozen_value.size() != width) {
            entry.last_error = "Frozen value has an invalid width";
            ++failures;
            continue;
        }
        const auto before = memory_.Read(
            entry.address,
            static_cast<std::uint32_t>(width));
        if (!before || before.Value().size() != width) {
            entry.last_error = before
                ? "Freeze preflight returned a short read"
                : before.GetError().message;
            ++failures;
            continue;
        }
        const auto expected_before = memory_.Read(
            entry.address,
            static_cast<std::uint32_t>(width));
        if (!expected_before || expected_before.Value().size() != width) {
            entry.last_error = expected_before
                ? "Freeze expected-before read was incomplete"
                : expected_before.GetError().message;
            ++failures;
            continue;
        }
        if (expected_before.Value() != before.Value()) {
            entry.last_error =
                "Value changed during freeze preflight; no write was attempted";
            ++failures;
            continue;
        }
        // The initial user arm authorizes this tick. Each actual write still
        // gets a fresh one-shot backend arm so multi-entry Freeze behaves the
        // same through direct Win32 access and the KDBG driver fallback.
        const auto armed = memory_.SetWritesArmed(true);
        if (!armed) {
            entry.last_error = armed.GetError().message;
            ++failures;
            continue;
        }
        ProcessWriteArmGuard write_guard(memory_, true);
        const auto written = memory_.Write(entry.address, entry.frozen_value);
        const auto disarm = write_guard.Disarm();
        if (!written || written.Value() != entry.frozen_value.size()) {
            entry.last_error = written
                ? "Freeze write was incomplete"
                : written.GetError().message;
            ++failures;
            if (!disarm) return finish(Result<void>::Failure(disarm.GetError()));
            continue;
        }
        const auto readback = memory_.Read(
            entry.address,
            static_cast<std::uint32_t>(entry.frozen_value.size()));
        if (!readback) {
            entry.last_error = readback.GetError().message;
            ++failures;
            if (!disarm) return finish(Result<void>::Failure(disarm.GetError()));
            continue;
        }
        if (readback.Value().size() != entry.frozen_value.size()) {
            entry.last_error = "Freeze read-back returned a short read";
            ++failures;
            if (!disarm) return finish(Result<void>::Failure(disarm.GetError()));
            continue;
        }
        if (readback.Value() != entry.frozen_value) {
            entry.last_error = "Freeze read-back verification failed";
            ++failures;
            if (!disarm) return finish(Result<void>::Failure(disarm.GetError()));
            continue;
        }
        entry.value = readback.Value();
        entry.last_error.clear();
        if (!disarm) return finish(Result<void>::Failure(disarm.GetError()));
    }
    const auto disarm = arm_guard.Disarm();
    if (!disarm) return Result<void>::Failure(disarm.GetError());
    if (failures != 0) {
        return Result<void>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            "One or more frozen-address writes failed verification",
            "WatchList::FreezeTick",
            0,
            0,
            failures));
    }
    return Result<void>::Success();
}

Result<void> WatchList::Save(
    const std::filesystem::path& path,
    WatchListSaveFault fault) const {
    if (entries_.size() > kMaxPersistedEntries) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address list exceeds the persistence entry limit",
            "WatchList::Save",
            0,
            kMaxPersistedEntries,
            entries_.size()));
    }

    if (path.empty() || path.filename().empty()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Address-list destination path is invalid",
            "WatchList::Save"));
    }
    for (const auto& entry : entries_) {
        const auto width = FixedValueWidth(entry.type);
        const auto frozen_bytes = entry.frozen ? entry.frozen_value.size() : 0U;
        if (entry.address == 0 || width == 0 ||
            entry.address > std::numeric_limits<std::uint64_t>::max() - width ||
            entry.description.size() > kMaxDescriptionBytes ||
            entry.description.size() > std::numeric_limits<std::uint32_t>::max() ||
            (entry.frozen && frozen_bytes != width)) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Address-list entry is not persistable",
                "WatchList::Save"));
        }
    }

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
        return FileFailure("Unable to create address-list file", "WatchList::Save");
    }

    WatchFileHeader header{};
    std::memcpy(header.magic, kWatchMagic.data(), kWatchMagic.size());
    header.version = kWatchVersion;
    header.pid = memory_.ProcessId();
    header.process_identity_token = memory_.ProcessIdentityToken();
    header.entry_count = entries_.size();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!output) {
        return FileFailure(
            "Failed while writing the address-list header",
            "WatchList::Save");
    }

    for (const auto& entry : entries_) {
        const auto frozen_bytes = entry.frozen ? entry.frozen_value.size() : 0U;

        WatchFileEntryHeader item{};
        item.address = entry.address;
        item.type = static_cast<std::uint32_t>(entry.type);
        item.flags = (entry.hexadecimal ? kWatchFlagHexadecimal : 0U) |
            (entry.frozen ? kWatchFlagWasFrozen : 0U);
        item.description_size = static_cast<std::uint32_t>(entry.description.size());
        item.frozen_value_size = static_cast<std::uint32_t>(frozen_bytes);
        output.write(reinterpret_cast<const char*>(&item), sizeof(item));
        output.write(
            entry.description.data(),
            static_cast<std::streamsize>(entry.description.size()));
        if (frozen_bytes != 0) {
            output.write(
                reinterpret_cast<const char*>(entry.frozen_value.data()),
                static_cast<std::streamsize>(entry.frozen_value.size()));
        }
        if (!output) {
            return FileFailure(
                "Failed while writing address-list entries",
                "WatchList::Save");
        }
    }
    output.flush();
    if (!output) {
        return FileFailure(
            "Failed while flushing the address-list file",
            "WatchList::Save");
    }
    output.close();
    if (!output) {
        return FileFailure(
            "Failed while closing the temporary address-list file",
            "WatchList::Save");
    }
    const auto durable = FlushFileToDisk(temporary, "WatchList::Save");
    if (!durable) return durable;
    if (fault == WatchListSaveFault::AfterFlushBeforeReplace) {
        return FileFailure(
            "Injected address-list failure before atomic replacement",
            "WatchList::Save");
    }
    const auto replaced = ReplaceAtomically(
        temporary,
        path,
        "WatchList::Save");
    if (!replaced) return replaced;
    cleanup.committed = true;
    return Result<void>::Success();
}

Result<void> WatchList::Load(const std::filesystem::path& path) {
    std::error_code size_error;
    const auto file_size = std::filesystem::file_size(path, size_error);
    if (size_error || file_size < sizeof(LegacyWatchFileHeader) ||
        file_size > kMaxWatchFileBytes) {
        return Result<void>::Failure(MakeError(
            size_error ? ErrorCode::IoFailure : ErrorCode::LimitReached,
            "Address-list file size is invalid or exceeds the product cap",
            "WatchList::Load",
            static_cast<std::uint64_t>(size_error.value()),
            kMaxWatchFileBytes,
            size_error ? 0 : file_size));
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return FileFailure("Unable to open address-list file", "WatchList::Load");
    }

    WatchFilePrefix prefix{};
    input.read(reinterpret_cast<char*>(&prefix), sizeof(prefix));
    if (!input ||
        !std::equal(kWatchMagic.begin(), kWatchMagic.end(), prefix.magic) ||
        (prefix.version != kLegacyWatchVersion &&
         prefix.version != kWatchVersion)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ParseError,
            "Address-list header is invalid",
            "WatchList::Load"));
    }

    input.seekg(0, std::ios::beg);
    std::uint32_t persisted_pid = 0;
    std::uint64_t persisted_identity = 0;
    std::uint64_t persisted_entry_count = 0;
    if (prefix.version == kLegacyWatchVersion) {
        LegacyWatchFileHeader header{};
        input.read(reinterpret_cast<char*>(&header), sizeof(header));
        persisted_pid = header.pid;
        persisted_entry_count = header.entry_count;
    } else {
        WatchFileHeader header{};
        input.read(reinterpret_cast<char*>(&header), sizeof(header));
        persisted_pid = header.pid;
        persisted_identity = header.process_identity_token;
        persisted_entry_count = header.entry_count;
    }
    if (!input || persisted_entry_count > kMaxPersistedEntries) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ParseError,
            "Address-list header is invalid or truncated",
            "WatchList::Load"));
    }
    if (persisted_pid != memory_.ProcessId()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Address list belongs to a different PID",
            "WatchList::Load",
            0,
            memory_.ProcessId(),
            persisted_pid));
    }
    const auto current_identity = memory_.ProcessIdentityToken();
    if (persisted_identity != 0 && current_identity != 0 &&
        persisted_identity != current_identity) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Address list belongs to a previous process that reused this PID",
            "WatchList::Load",
            0,
            current_identity,
            persisted_identity));
    }
    const bool identity_unverified =
        persisted_identity == 0 || current_identity == 0;

    std::vector<WatchEntry> loaded;
    loaded.reserve(static_cast<std::size_t>(persisted_entry_count));
    std::uint64_t next_id = 1;
    for (std::uint64_t index = 0; index < persisted_entry_count; ++index) {
        WatchFileEntryHeader item{};
        input.read(reinterpret_cast<char*>(&item), sizeof(item));
        if (!input || item.description_size > kMaxDescriptionBytes) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Address-list entry header is invalid or truncated",
                "WatchList::Load"));
        }
        const auto type = static_cast<ScanValueType>(item.type);
        const auto width = FixedValueWidth(type);
        const bool was_frozen =
            (item.flags & kWatchFlagWasFrozen) != 0;
        if (item.address == 0 || width == 0 ||
            item.address > std::numeric_limits<std::uint64_t>::max() - width ||
            (was_frozen && item.frozen_value_size != width) ||
            (!was_frozen && item.frozen_value_size != 0) ||
            (item.flags & ~(kWatchFlagHexadecimal | kWatchFlagWasFrozen)) != 0) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Address-list entry contains invalid fields",
                "WatchList::Load"));
        }

        std::string description(item.description_size, '\0');
        input.read(description.data(), static_cast<std::streamsize>(description.size()));
        std::vector<std::uint8_t> frozen_value(item.frozen_value_size);
        if (!frozen_value.empty()) {
            input.read(
                reinterpret_cast<char*>(frozen_value.data()),
                static_cast<std::streamsize>(frozen_value.size()));
        }
        if (!input) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Address-list entry payload is truncated",
                "WatchList::Load"));
        }

        const auto current = memory_.Read(
            item.address,
            static_cast<std::uint32_t>(width));
        if (!current || current.Value().size() != width) {
            return Result<void>::Failure(current
                ? MakeError(
                    ErrorCode::ShortRead,
                    "Loaded address cannot be read at its expected width",
                    "WatchList::Load",
                    0,
                    width,
                    current.Value().size())
                : current.GetError());
        }

        WatchEntry entry{};
        entry.id = next_id++;
        entry.address = item.address;
        entry.type = type;
        entry.description = std::move(description);
        entry.hexadecimal = (item.flags & kWatchFlagHexadecimal) != 0;
        entry.frozen = false;
        entry.value = current.Value();
        entry.frozen_value.clear();
        if (was_frozen) {
            entry.last_error =
                "Saved frozen state was loaded disarmed; explicitly arm and freeze again.";
        }
        if (identity_unverified) {
            if (!entry.last_error.empty()) {
                entry.last_error += ' ';
            }
            entry.last_error +=
                "The process identity token was unavailable; verify the target manually.";
        }
        loaded.push_back(std::move(entry));
    }

    if (input.peek() != std::char_traits<char>::eof()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ParseError,
            "Address-list file contains unexpected trailing data",
            "WatchList::Load"));
    }

    entries_ = std::move(loaded);
    next_id_ = next_id;
    return Result<void>::Success();
}

const std::vector<WatchEntry>& WatchList::Entries() const noexcept {
    return entries_;
}

std::vector<WatchEntry>& WatchList::Entries() noexcept { return entries_; }

WatchEntry* WatchList::Find(std::uint64_t id) noexcept {
    const auto it = std::find_if(
        entries_.begin(),
        entries_.end(),
        [&](const WatchEntry& entry) { return entry.id == id; });
    return it == entries_.end() ? nullptr : &*it;
}

const WatchEntry* WatchList::Find(std::uint64_t id) const noexcept {
    const auto it = std::find_if(
        entries_.begin(),
        entries_.end(),
        [&](const WatchEntry& entry) { return entry.id == id; });
    return it == entries_.end() ? nullptr : &*it;
}

}  // namespace kdbg

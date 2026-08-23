#include "core/scanner/WatchList.h"

#include "core/scanner/ValueCodec.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>

namespace kdbg {
namespace {

#pragma pack(push, 1)
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

static_assert(sizeof(WatchFileHeader) == 32);
static_assert(sizeof(WatchFileEntryHeader) == 24);

constexpr std::array<char, 8> kWatchMagic{
    'K', 'D', 'B', 'G', 'A', 'L', '\0', '\0'};
constexpr std::uint32_t kWatchVersion = 2;
constexpr std::uint32_t kWatchFlagHexadecimal = 1U << 0U;
constexpr std::uint32_t kWatchFlagWasFrozen = 1U << 1U;
constexpr std::uint64_t kMaxPersistedEntries = 100'000;
constexpr std::uint32_t kMaxDescriptionBytes = 4096U;
constexpr std::uintmax_t kMaxWatchFileBytes = 64ULL * 1024ULL * 1024ULL;

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
    auto* entry = Find(id);
    if (entry == nullptr) {
        return Result<void>::Failure(MakeError(
            ErrorCode::NotFound,
            "Watch entry was not found",
            "WatchList::WriteValue"));
    }
    const auto encoded = EncodeValue(
        entry->type,
        value_text,
        entry->hexadecimal);
    if (!encoded) {
        return Result<void>::Failure(encoded.GetError());
    }
    if (!memory_.WritesArmed()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Arm process writes before editing an address-list value",
            "WatchList::WriteValue"));
    }
    const auto before = memory_.Read(
        entry->address,
        static_cast<std::uint32_t>(encoded.Value().size()));
    if (!before) {
        entry->last_error = before.GetError().message;
        return Result<void>::Failure(before.GetError());
    }
    if (before.Value().size() != entry->value.size()) {
        entry->last_error = "Address-list preflight returned a short read";
        return Result<void>::Failure(MakeError(
            ErrorCode::ShortRead,
            entry->last_error,
            "WatchList::WriteValue",
            0,
            entry->value.size(),
            before.Value().size()));
    }
    if (before.Value() != entry->value) {
        entry->last_error =
            "Value changed after it was presented; refresh before writing";
        return Result<void>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            entry->last_error,
            "WatchList::WriteValue"));
    }
    const auto written = memory_.Write(entry->address, encoded.Value());
    if (!written) {
        return Result<void>::Failure(written.GetError());
    }
    if (written.Value() != encoded.Value().size()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ShortWrite,
            "Watch value write was incomplete",
            "WatchList::WriteValue",
            0,
            encoded.Value().size(),
            written.Value()));
    }
    const auto readback = memory_.Read(
        entry->address,
        static_cast<std::uint32_t>(encoded.Value().size()));
    if (!readback || readback.Value() != encoded.Value()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            "Watch value read-back verification failed",
            "WatchList::WriteValue"));
    }
    entry->value = readback.Value();
    if (entry->frozen) {
        entry->frozen_value = entry->value;
    }
    entry->last_error.clear();
    return Result<void>::Success();
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
    std::size_t failures = 0;
    for (auto& entry : entries_) {
        if (!entry.frozen) {
            continue;
        }
        if (!memory_.WritesArmed()) {
            return Result<void>::Failure(MakeError(
                ErrorCode::WriteLocked,
                "Process write gate was closed while frozen entries were active",
                "WatchList::FreezeTick"));
        }
        const auto width = FixedValueWidth(entry.type);
        if (width == 0 || entry.frozen_value.size() != width) {
            entry.last_error = "Frozen value has an invalid width";
            ++failures;
            continue;
        }
        const auto written = memory_.Write(entry.address, entry.frozen_value);
        if (!written || written.Value() != entry.frozen_value.size()) {
            entry.last_error = written
                ? "Freeze write was incomplete"
                : written.GetError().message;
            ++failures;
            continue;
        }
        const auto readback = memory_.Read(
            entry.address,
            static_cast<std::uint32_t>(entry.frozen_value.size()));
        if (!readback || readback.Value() != entry.frozen_value) {
            entry.last_error = readback
                ? "Freeze read-back verification failed"
                : readback.GetError().message;
            ++failures;
            continue;
        }
        entry.value = readback.Value();
        entry.last_error.clear();
    }
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

Result<void> WatchList::Save(const std::filesystem::path& path) const {
    if (entries_.size() > kMaxPersistedEntries) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address list exceeds the persistence entry limit",
            "WatchList::Save",
            0,
            kMaxPersistedEntries,
            entries_.size()));
    }

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
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
        const auto width = FixedValueWidth(entry.type);
        if (width == 0 ||
            entry.description.size() > kMaxDescriptionBytes ||
            entry.description.size() > std::numeric_limits<std::uint32_t>::max()) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Address-list entry is not persistable",
                "WatchList::Save"));
        }
        const auto frozen_bytes = entry.frozen ? entry.frozen_value.size() : 0U;
        if (entry.frozen && frozen_bytes != width) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InternalInvariant,
                "Frozen address-list entry has an invalid value width",
                "WatchList::Save"));
        }

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
    return Result<void>::Success();
}

Result<void> WatchList::Load(const std::filesystem::path& path) {
    std::error_code size_error;
    const auto file_size = std::filesystem::file_size(path, size_error);
    if (size_error || file_size < sizeof(WatchFileHeader) ||
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

    WatchFileHeader header{};
    input.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (!input ||
        !std::equal(kWatchMagic.begin(), kWatchMagic.end(), header.magic) ||
        header.version != kWatchVersion ||
        header.entry_count > kMaxPersistedEntries) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ParseError,
            "Address-list header is invalid",
            "WatchList::Load"));
    }
    if (header.pid != memory_.ProcessId()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Address list belongs to a different PID",
            "WatchList::Load",
            0,
            memory_.ProcessId(),
            header.pid));
    }
    const auto current_identity = memory_.ProcessIdentityToken();
    if (header.process_identity_token != 0 && current_identity != 0 &&
        header.process_identity_token != current_identity) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Address list belongs to a previous process that reused this PID",
            "WatchList::Load",
            0,
            current_identity,
            header.process_identity_token));
    }
    const bool identity_unverified =
        header.process_identity_token == 0 || current_identity == 0;

    std::vector<WatchEntry> loaded;
    loaded.reserve(static_cast<std::size_t>(header.entry_count));
    std::uint64_t next_id = 1;
    for (std::uint64_t index = 0; index < header.entry_count; ++index) {
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
        entry.frozen_value = std::move(frozen_value);
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

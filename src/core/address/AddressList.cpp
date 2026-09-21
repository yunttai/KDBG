#include "core/address/AddressList.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <fstream>
#include <iomanip>
#include <limits>
#include <new>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#if defined(_WIN32)
#include <process.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace kdbg {
namespace {

constexpr int kLegacyAddressListVersion = 1;
constexpr int kAddressListVersion = 2;

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

std::string Hex(std::span<const std::uint8_t> bytes) {
    std::ostringstream output;
    output << std::hex << std::uppercase << std::setfill('0');
    for (const auto byte : bytes) {
        output << std::setw(2) << static_cast<unsigned>(byte);
    }
    return output.str();
}

Result<std::vector<std::uint8_t>> Unhex(std::string_view text) {
    if ((text.size() & 1U) != 0) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::ParseError,
            "Address-list hex payload has an odd length",
            "AddressList::Load"));
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(text.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t index = 0; index < text.size(); index += 2) {
        const int high = nibble(text[index]);
        const int low = nibble(text[index + 1]);
        if (high < 0 || low < 0) {
            return Result<std::vector<std::uint8_t>>::Failure(MakeError(
                ErrorCode::ParseError,
                "Address-list hex payload contains a non-hex character",
                "AddressList::Load"));
        }
        bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return Result<std::vector<std::uint8_t>>::Success(std::move(bytes));
}

bool IsValidType(ScanValueType type) noexcept {
    switch (type) {
    case ScanValueType::Int8:
    case ScanValueType::UInt8:
    case ScanValueType::Int16:
    case ScanValueType::UInt16:
    case ScanValueType::Int32:
    case ScanValueType::UInt32:
    case ScanValueType::Int64:
    case ScanValueType::UInt64:
    case ScanValueType::Float:
    case ScanValueType::Double:
    case ScanValueType::Utf8:
    case ScanValueType::Utf16:
    case ScanValueType::ByteArray:
        return true;
    }
    return false;
}

Result<void> ValidateSpace(const MemorySpace& space, std::string_view context) {
    switch (space.kind) {
    case MemorySpaceKind::Physical:
    case MemorySpaceKind::KernelVirtual:
        if (space.pid != 0) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Non-process address-list entries must not carry a PID",
                std::string(context)));
        }
        return Result<void>::Success();
    case MemorySpaceKind::ProcessVirtual:
        if (space.pid == 0) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Process address-list entries require a non-zero PID",
                std::string(context)));
        }
        return Result<void>::Success();
    }
    return Result<void>::Failure(MakeError(
        ErrorCode::InvalidArgument,
        "Address-list entry has an unknown memory-space kind",
        std::string(context)));
}

Result<void> ValidateEntry(const AddressEntry& entry, std::string_view context) {
    const auto valid_space = ValidateSpace(entry.space, context);
    if (!valid_space) {
        return valid_space;
    }
    if (entry.address == 0 ||
        entry.address > std::numeric_limits<std::uint64_t>::max() - entry.width ||
        !IsValidType(entry.type) || entry.width == 0 ||
        entry.width > AddressList::kMaxValueWidth) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Address-list entry has an invalid type or width",
            std::string(context)));
    }
    const auto fixed_width = FixedValueWidth(entry.type);
    if ((fixed_width != 0 && entry.width != fixed_width) ||
        (entry.type == ScanValueType::Utf16 && (entry.width & 1U) != 0)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Address-list width is inconsistent with its value type",
            std::string(context),
            0,
            fixed_width,
            entry.width));
    }
    if (entry.description.size() > AddressList::kMaxDescriptionBytes ||
        entry.description.find_first_of("\r\n") != std::string::npos) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address-list description is too long or contains a line break",
            std::string(context)));
    }
    if ((!entry.current_value.empty() &&
         entry.current_value.size() != entry.width) ||
        (entry.frozen && entry.freeze_value.size() != entry.width) ||
        (!entry.frozen && !entry.freeze_value.empty())) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Address-list entry contains a value with the wrong width",
            std::string(context)));
    }
    if (entry.pointer_path.has_value()) {
        const auto pointer_space = ValidateSpace(
            entry.pointer_path->space,
            context);
        if (!pointer_space) {
            return pointer_space;
        }
        if (entry.pointer_path->pointer_size != 4 &&
            entry.pointer_path->pointer_size != 8) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Address-list pointer size must be 4 or 8 bytes",
                std::string(context)));
        }
        if (entry.pointer_path->base_address == 0 ||
            entry.pointer_path->offsets.size() > PointerResolver::kMaxDepth ||
            entry.pointer_path->space.kind != entry.space.kind ||
            entry.pointer_path->space.pid != entry.space.pid) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Address-list pointer path has an invalid base, depth, or memory space",
                std::string(context)));
        }
    }
    return Result<void>::Success();
}

Result<void> RequireProcessWrite(
    const AddressEntry& entry,
    std::string_view context) {
    const auto valid = ValidateEntry(entry, context);
    if (!valid) {
        return valid;
    }
    if (entry.space.kind != MemorySpaceKind::ProcessVirtual) {
        return Result<void>::Failure(MakeError(
            ErrorCode::Unsupported,
            "Generic address-list writes and freeze are restricted to process virtual memory",
            std::string(context)));
    }
    return Result<void>::Success();
}

}  // namespace

std::uint64_t AddressList::Add(AddressEntry entry) {
    if (entries_.size() >= kMaxEntries) {
        return 0;
    }
    if (entry.id == 0) {
        if (next_id_ == 0 ||
            next_id_ == std::numeric_limits<std::uint64_t>::max()) {
            return 0;
        }
        entry.id = next_id_;
    } else {
        if (entry.id == std::numeric_limits<std::uint64_t>::max() ||
            Find(entry.id) != nullptr) {
            return 0;
        }
    }
    if (entry.width == 0) {
        entry.width = FixedValueWidth(entry.type);
    }
    const auto valid = ValidateEntry(entry, "AddressList::Add");
    if (!valid) {
        return 0;
    }
    next_id_ = std::max(next_id_, entry.id + 1);
    entry.resolved_address = entry.address;
    try {
        entries_.push_back(std::move(entry));
    } catch (const std::bad_alloc&) {
        return 0;
    } catch (const std::length_error&) {
        return 0;
    }
    return entries_.back().id;
}

bool AddressList::Remove(std::uint64_t id) {
    const auto old_size = entries_.size();
    std::erase_if(entries_, [id](const AddressEntry& entry) {
        return entry.id == id;
    });
    return entries_.size() != old_size;
}

void AddressList::Clear() {
    entries_.clear();
    next_id_ = 1;
}

AddressEntry* AddressList::Find(std::uint64_t id) {
    const auto found = std::find_if(
        entries_.begin(), entries_.end(),
        [id](const AddressEntry& entry) { return entry.id == id; });
    return found == entries_.end() ? nullptr : &*found;
}

Result<std::uint64_t> AddressList::ResolveAddress(AddressEntry& entry) {
    if (!entry.pointer_path.has_value()) {
        entry.resolved_address = entry.address;
        return Result<std::uint64_t>::Success(entry.address);
    }
    auto resolved = resolver_.Resolve(*entry.pointer_path);
    if (!resolved) return resolved;
    entry.resolved_address = resolved.Value();
    return resolved;
}

Result<AddressRefreshSummary> AddressList::Refresh() {
    AddressRefreshSummary summary{};
    for (auto& entry : entries_) {
        entry.last_error.reset();
        const auto valid = ValidateEntry(entry, "AddressList::Refresh");
        if (!valid) {
            entry.last_error = valid.GetError();
            ++summary.failed;
            continue;
        }
        auto address = ResolveAddress(entry);
        if (!address) {
            entry.last_error = address.GetError();
            ++summary.failed;
            continue;
        }
        auto bytes = ReadMemory(
            backend_,
            entry.space,
            address.Value(),
            static_cast<std::uint32_t>(entry.width));
        if (!bytes || bytes.Value().size() != entry.width) {
            entry.last_error = bytes
                ? MakeError(
                    ErrorCode::ShortRead,
                    "Address-list refresh returned a short read",
                    "AddressList::Refresh")
                : bytes.GetError();
            ++summary.failed;
            continue;
        }
        entry.current_value = bytes.TakeValue();
        ++summary.refreshed;
    }
    return Result<AddressRefreshSummary>::Success(summary);
}

Result<VerifiedWriteArmToken> AddressList::ArmProcessWrites(
    std::uint32_t confirmed_pid) const {
    return writer_.ArmProcessWrite(confirmed_pid);
}

Result<VerifiedWriteResult> AddressList::Write(
    VerifiedWriteArmToken arm_token,
    std::uint64_t id,
    std::span<const std::uint8_t> value) {
    auto* entry = Find(id);
    if (entry == nullptr) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::NotFound,
            "Address-list entry was not found",
            "AddressList::Write"));
    }
    const auto allowed = RequireProcessWrite(*entry, "AddressList::Write");
    if (!allowed) {
        entry->last_error = allowed.GetError();
        return Result<VerifiedWriteResult>::Failure(allowed.GetError());
    }
    if (value.size() != entry->width) {
        return Result<VerifiedWriteResult>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Write width does not match the address-list entry",
            "AddressList::Write",
            0,
            entry->width,
            value.size()));
    }
    auto address = ResolveAddress(*entry);
    if (!address) return Result<VerifiedWriteResult>::Failure(address.GetError());
    if (entry->current_value.size() != entry->width) {
        entry->last_error = MakeError(
            ErrorCode::InvalidArgument,
            "Refresh the address-list entry before writing so an expected-before value is available",
            "AddressList::Write");
        return Result<VerifiedWriteResult>::Failure(*entry->last_error);
    }
    auto result = writer_.Write(
        std::move(arm_token),
        entry->space,
        address.Value(),
        value,
        std::span<const std::uint8_t>(entry->current_value));
    if (result) {
        entry->current_value = result.Value().readback;
        entry->last_error.reset();
    } else {
        entry->last_error = result.GetError();
    }
    return result;
}

Result<void> AddressList::SetFrozen(
    std::uint64_t id,
    bool frozen,
    std::optional<std::vector<std::uint8_t>> value) {
    auto* entry = Find(id);
    if (entry == nullptr) {
        return Result<void>::Failure(MakeError(
            ErrorCode::NotFound,
            "Address-list entry was not found",
            "AddressList::SetFrozen"));
    }
    if (!frozen) {
        entry->frozen = false;
        entry->freeze_value.clear();
        return Result<void>::Success();
    }
    const auto allowed = RequireProcessWrite(
        *entry,
        "AddressList::SetFrozen");
    if (!allowed) {
        entry->last_error = allowed.GetError();
        return allowed;
    }

    std::vector<std::uint8_t> selected;
    if (value.has_value()) {
        selected = std::move(*value);
    } else if (!entry->current_value.empty()) {
        selected = entry->current_value;
    } else {
        auto address = ResolveAddress(*entry);
        if (!address) return Result<void>::Failure(address.GetError());
        auto bytes = ReadMemory(
            backend_,
            entry->space,
            address.Value(),
            static_cast<std::uint32_t>(entry->width));
        if (!bytes) return Result<void>::Failure(bytes.GetError());
        selected = bytes.TakeValue();
    }
    if (selected.size() != entry->width) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Freeze value width does not match the address-list entry",
            "AddressList::SetFrozen"));
    }
    entry->freeze_value = std::move(selected);
    entry->frozen = true;
    return Result<void>::Success();
}

Result<FreezeSummary> AddressList::TickFreeze(
    VerifiedWriteArmToken arm_token) {
    FreezeSummary summary{};
    std::optional<std::uint32_t> confirmed_pid;
    for (const auto& entry : entries_) {
        if (entry.frozen &&
            entry.space.kind == MemorySpaceKind::ProcessVirtual) {
            confirmed_pid = entry.space.pid;
            break;
        }
    }
    if (!confirmed_pid.has_value()) {
        for (auto& entry : entries_) {
            if (!entry.frozen) continue;
            entry.last_error = MakeError(
                ErrorCode::Unsupported,
                "Freeze writes are process-virtual only",
                "AddressList::TickFreeze");
            ++summary.failed;
        }
        return Result<FreezeSummary>::Success(summary);
    }
    if (!arm_token.Consume(*confirmed_pid)) {
        return Result<FreezeSummary>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Freeze tick requires a fresh matching PID arm token",
            "AddressList::TickFreeze"));
    }
    for (auto& entry : entries_) {
        if (!entry.frozen) continue;
        const auto allowed = RequireProcessWrite(
            entry,
            "AddressList::TickFreeze");
        if (!allowed) {
            entry.last_error = allowed.GetError();
            ++summary.failed;
            continue;
        }
        auto address = ResolveAddress(entry);
        if (!address) {
            entry.last_error = address.GetError();
            ++summary.failed;
            continue;
        }
        if (entry.space.pid != *confirmed_pid) {
            entry.last_error = MakeError(
                ErrorCode::WriteLocked,
                "One freeze transaction cannot cross confirmed PIDs",
                "AddressList::TickFreeze",
                0,
                *confirmed_pid,
                entry.space.pid);
            ++summary.failed;
            continue;
        }
        auto before = ReadMemory(
            backend_,
            entry.space,
            address.Value(),
            static_cast<std::uint32_t>(entry.width));
        if (!before || before.Value().size() != entry.width) {
            entry.last_error = before
                ? MakeError(
                    ErrorCode::ShortRead,
                    "Freeze preflight returned a short read",
                    "AddressList::TickFreeze",
                    0,
                    entry.width,
                    before.Value().size())
                : before.GetError();
            ++summary.failed;
            continue;
        }
        auto write_arm = writer_.ArmProcessWrite(*confirmed_pid);
        if (!write_arm) {
            entry.last_error = write_arm.GetError();
            ++summary.failed;
            continue;
        }
        auto result = writer_.Write(
            write_arm.TakeValue(),
            entry.space,
            address.Value(),
            entry.freeze_value,
            std::span<const std::uint8_t>(before.Value()));
        if (!result) {
            entry.last_error = result.GetError();
            ++summary.failed;
            continue;
        }
        entry.current_value = result.Value().readback;
        entry.last_error.reset();
        ++summary.verified;
    }
    return Result<FreezeSummary>::Success(summary);
}

Result<void> AddressList::Save(
    const std::filesystem::path& path,
    AddressListSaveFault fault) const {
    if (entries_.size() > kMaxEntries) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address list exceeds the persisted entry limit",
            "AddressList::Save",
            0,
            kMaxEntries,
            entries_.size()));
    }
    try {
        std::unordered_set<std::uint64_t> ids;
        ids.reserve(entries_.size());
        for (const auto& entry : entries_) {
            const auto valid = ValidateEntry(entry, "AddressList::Save");
            if (!valid) {
                return valid;
            }
            if (entry.id == 0 ||
                entry.id == std::numeric_limits<std::uint64_t>::max() ||
                !ids.insert(entry.id).second) {
                return Result<void>::Failure(MakeError(
                    ErrorCode::InvalidArgument,
                    "Address list contains an invalid or duplicate entry ID",
                    "AddressList::Save"));
            }
        }

        if (path.empty() || path.filename().empty()) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Address-list destination path is invalid",
                "AddressList::Save"));
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

        std::ofstream output(
            temporary,
            std::ios::binary | std::ios::trunc);
        if (!output) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Unable to create address-list file",
                "AddressList::Save"));
        }
        output << "KDBG_ADDRESS_LIST\t" << kAddressListVersion << '\n';
        for (const auto& entry : entries_) {
            output << entry.id << '\t'
                   << static_cast<int>(entry.space.kind) << '\t'
                   << entry.space.pid << '\t'
                   << entry.address << '\t'
                   << static_cast<int>(entry.type) << '\t'
                   << entry.width << '\t'
                   << (entry.frozen ? 1 : 0) << '\t'
                   << std::quoted(entry.description) << '\t'
                   << (entry.freeze_value.empty()
                           ? std::string{"-"}
                           : Hex(entry.freeze_value))
                   << '\t' << (entry.pointer_path.has_value() ? 1 : 0);
            if (entry.pointer_path.has_value()) {
                const auto& pointer = *entry.pointer_path;
                output << '\t' << static_cast<int>(pointer.space.kind)
                       << '\t' << pointer.space.pid
                       << '\t' << pointer.base_address
                       << '\t' << pointer.pointer_size
                       << '\t' << pointer.offsets.size();
                for (const auto offset : pointer.offsets) {
                    output << '\t' << offset;
                }
            }
            output << '\n';
        }
        if (!output) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Failed while writing address-list file",
                "AddressList::Save"));
        }
        output.flush();
        if (!output) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Failed while flushing the temporary address-list file",
                "AddressList::Save"));
        }
        output.close();
        if (!output) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Failed while closing the temporary address-list file",
                "AddressList::Save"));
        }
        const auto durable = FlushFileToDisk(temporary, "AddressList::Save");
        if (!durable) return durable;
        if (fault == AddressListSaveFault::AfterFlushBeforeReplace) {
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Injected address-list failure before atomic replacement",
                "AddressList::Save"));
        }
        const auto replaced = ReplaceAtomically(
            temporary,
            path,
            "AddressList::Save");
        if (!replaced) return replaced;
        cleanup.committed = true;
        return Result<void>::Success();
    } catch (const std::bad_alloc&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address-list save exhausted the allocation budget",
            "AddressList::Save"));
    } catch (const std::length_error&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address-list save requested an invalid allocation",
            "AddressList::Save"));
    }
}

Result<void> AddressList::Load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to open address-list file",
            "AddressList::Load"));
    }
    std::array<char, 128> header_buffer{};
    input.getline(
        header_buffer.data(),
        static_cast<std::streamsize>(header_buffer.size()));
    std::istringstream header(header_buffer.data());
    std::string magic;
    int version = 0;
    if (!input || !(header >> magic >> version) ||
        magic != "KDBG_ADDRESS_LIST" ||
        (version != kLegacyAddressListVersion &&
         version != kAddressListVersion)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ParseError,
            "Address-list file has an unsupported header",
            "AddressList::Load"));
    }
    header >> std::ws;
    if (!header.eof()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::ParseError,
            "Address-list header contains trailing fields",
            "AddressList::Load"));
    }

    try {
      std::vector<AddressEntry> loaded;
      loaded.reserve(std::min<std::size_t>(kMaxEntries, 4096));
      std::unordered_set<std::uint64_t> ids;
      std::uint64_t highest_id = 0;
      std::vector<char> row_buffer(kMaxRowBytes + 2U, '\0');
      while (input.getline(
          row_buffer.data(),
          static_cast<std::streamsize>(row_buffer.size()))) {
        auto row_size = static_cast<std::size_t>(input.gcount());
        if (row_size != 0 && row_buffer[row_size - 1U] == '\0') {
            --row_size;
        }
        std::string_view raw_line(row_buffer.data(), row_size);
        if (raw_line.size() > kMaxRowBytes) {
            return Result<void>::Failure(MakeError(
                ErrorCode::LimitReached,
                "Address-list row exceeds the length limit",
                "AddressList::Load"));
        }
        if (raw_line.find('\0') != std::string_view::npos) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Address-list row contains an embedded NUL byte",
                "AddressList::Load"));
        }
        std::string line(raw_line);
        if (line.empty()) continue;
        if (loaded.size() >= kMaxEntries) {
            return Result<void>::Failure(MakeError(
                ErrorCode::LimitReached,
                "Address list exceeds the entry limit",
                "AddressList::Load"));
        }
        std::istringstream row(line);
        AddressEntry entry{};
        int kind = 0;
        int type = 0;
        int frozen = 0;
        std::string freeze_hex;
        if (!(row >> entry.id >> kind >> entry.space.pid >> entry.address >>
              type >> entry.width >> frozen >> std::quoted(entry.description))) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Address-list row is malformed",
                "AddressList::Load"));
        }
        row >> std::ws;
        if (version == kLegacyAddressListVersion) {
            if (!row.eof() && !(row >> freeze_hex)) {
                return Result<void>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "Address-list freeze payload is malformed",
                    "AddressList::Load"));
            }
        } else {
            int has_pointer = 0;
            if (!(row >> freeze_hex >> has_pointer) ||
                (has_pointer != 0 && has_pointer != 1)) {
                return Result<void>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "Address-list v2 persistence fields are malformed",
                    "AddressList::Load"));
            }
            if (has_pointer != 0) {
                AddressPointerPath pointer{};
                int pointer_kind = 0;
                std::size_t offset_count = 0;
                if (!(row >> pointer_kind >> pointer.space.pid >>
                      pointer.base_address >> pointer.pointer_size >>
                      offset_count) ||
                    pointer_kind < static_cast<int>(MemorySpaceKind::Physical) ||
                    pointer_kind >
                        static_cast<int>(MemorySpaceKind::KernelVirtual) ||
                    offset_count > PointerResolver::kMaxDepth) {
                    return Result<void>::Failure(MakeError(
                        ErrorCode::ParseError,
                        "Address-list pointer path is malformed",
                        "AddressList::Load"));
                }
                pointer.space.kind =
                    static_cast<MemorySpaceKind>(pointer_kind);
                pointer.offsets.reserve(offset_count);
                for (std::size_t offset_index = 0;
                     offset_index < offset_count;
                     ++offset_index) {
                    std::int64_t offset = 0;
                    if (!(row >> offset)) {
                        return Result<void>::Failure(MakeError(
                            ErrorCode::ParseError,
                            "Address-list pointer offsets are truncated",
                            "AddressList::Load"));
                    }
                    pointer.offsets.push_back(offset);
                }
                entry.pointer_path = std::move(pointer);
            }
        }
        if (!row.eof()) {
            row >> std::ws;
            if (!row.eof()) {
                return Result<void>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "Address-list row contains trailing fields",
                    "AddressList::Load"));
            }
        }
        if (kind < static_cast<int>(MemorySpaceKind::Physical) ||
            kind > static_cast<int>(MemorySpaceKind::KernelVirtual) ||
            type < static_cast<int>(ScanValueType::Int8) ||
            type > static_cast<int>(ScanValueType::ByteArray) ||
            entry.id == 0 ||
            entry.id == std::numeric_limits<std::uint64_t>::max() ||
            (frozen != 0 && frozen != 1)) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Address-list row contains an invalid enum or width",
                "AddressList::Load"));
        }
        entry.space.kind = static_cast<MemorySpaceKind>(kind);
        entry.type = static_cast<ScanValueType>(type);
        entry.frozen = frozen != 0;
        if (!freeze_hex.empty() && freeze_hex != "-") {
            auto bytes = Unhex(freeze_hex);
            if (!bytes) return Result<void>::Failure(bytes.GetError());
            entry.freeze_value = bytes.TakeValue();
        }
        if (entry.frozen && entry.freeze_value.size() != entry.width) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Frozen address-list value has the wrong width",
                "AddressList::Load"));
        }
        if (!entry.frozen && !entry.freeze_value.empty()) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Unfrozen address-list row contains a freeze payload",
                "AddressList::Load"));
        }
        const auto valid = ValidateEntry(entry, "AddressList::Load");
        if (!valid) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                valid.GetError().message,
                "AddressList::Load"));
        }
        if (!ids.insert(entry.id).second) {
            return Result<void>::Failure(MakeError(
                ErrorCode::ParseError,
                "Address-list file contains a duplicate entry ID",
                "AddressList::Load"));
        }
        const bool persisted_frozen = entry.frozen;
        entry.frozen = false;
        entry.freeze_value.clear();
        if (persisted_frozen) {
            entry.last_error = MakeError(
                ErrorCode::WriteLocked,
                "Persisted freeze state was loaded disarmed",
                "AddressList::Load");
        }
        entry.resolved_address = entry.address;
        highest_id = std::max(highest_id, entry.id);
        loaded.push_back(std::move(entry));
      }

      if (input.bad()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Failed while reading the address-list file",
            "AddressList::Load"));
      }
      if (input.fail() && !input.eof()) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address-list row exceeds the length limit",
            "AddressList::Load"));
      }

      entries_ = std::move(loaded);
      next_id_ = highest_id + 1;
      return Result<void>::Success();
    } catch (const std::bad_alloc&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address-list file exhausted the allocation budget",
            "AddressList::Load"));
    } catch (const std::length_error&) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "Address-list file requested an invalid allocation",
            "AddressList::Load"));
    }
}

}  // namespace kdbg

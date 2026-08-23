#pragma once

#include "core/address/PointerResolver.h"
#include "core/memory/VerifiedWriter.h"
#include "core/scanner/ValueCodec.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace kdbg {

struct AddressEntry {
    std::uint64_t id{0};
    std::string description;
    MemorySpace space;
    std::uint64_t address{0};
    ScanValueType type{ScanValueType::UInt32};
    std::size_t width{4};
    std::optional<AddressPointerPath> pointer_path;
    bool frozen{false};
    std::vector<std::uint8_t> freeze_value;
    std::vector<std::uint8_t> current_value;
    std::uint64_t resolved_address{0};
    std::optional<Error> last_error;
};

struct AddressRefreshSummary {
    std::size_t refreshed{0};
    std::size_t failed{0};
};

struct FreezeSummary {
    std::size_t verified{0};
    std::size_t failed{0};
};

class AddressList {
public:
    static constexpr std::size_t kMaxEntries = 100'000;
    static constexpr std::size_t kMaxValueWidth = 1024U * 1024U;
    static constexpr std::size_t kMaxDescriptionBytes = 64U * 1024U;
    static constexpr std::size_t kMaxRowBytes =
        (2U * kMaxValueWidth) + kMaxDescriptionBytes + 1024U;

    explicit AddressList(IMemoryBackend& backend)
        : backend_(backend), writer_(backend), resolver_(backend) {}

    std::uint64_t Add(AddressEntry entry);
    bool Remove(std::uint64_t id);
    void Clear();

    [[nodiscard]] std::vector<AddressEntry>& Entries() noexcept { return entries_; }
    [[nodiscard]] const std::vector<AddressEntry>& Entries() const noexcept {
        return entries_;
    }

    Result<AddressRefreshSummary> Refresh();
    Result<VerifiedWriteResult> Write(
        std::uint64_t id,
        std::span<const std::uint8_t> value);
    Result<void> SetFrozen(
        std::uint64_t id,
        bool frozen,
        std::optional<std::vector<std::uint8_t>> value = std::nullopt);
    Result<FreezeSummary> TickFreeze();

    Result<void> Save(const std::filesystem::path& path) const;
    Result<void> Load(const std::filesystem::path& path);

private:
    AddressEntry* Find(std::uint64_t id);
    Result<std::uint64_t> ResolveAddress(AddressEntry& entry);

    IMemoryBackend& backend_;
    VerifiedWriter writer_;
    PointerResolver resolver_;
    std::vector<AddressEntry> entries_;
    std::uint64_t next_id_{1};
};

}  // namespace kdbg

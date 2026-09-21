#pragma once

#include "core/common/Result.h"
#include "core/process/IProcessMemory.h"
#include "core/scanner/ScanTypes.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace kdbg {

struct WatchEntry {
    std::uint64_t id{0};
    std::uint64_t address{0};
    ScanValueType type{ScanValueType::Int32};
    std::string description;
    bool hexadecimal{false};
    bool frozen{false};
    std::vector<std::uint8_t> value;
    std::vector<std::uint8_t> frozen_value;
    std::string last_error;
};

// Deterministic persistence fault injection used by the core regression suite.
// Production callers should keep the default value.
enum class WatchListSaveFault {
    None,
    AfterFlushBeforeReplace,
};

class WatchList {
public:
    explicit WatchList(IProcessMemory& memory);

    Result<std::uint64_t> Add(
        std::uint64_t address,
        ScanValueType type,
        std::string description = {},
        bool hexadecimal = false);
    Result<void> Remove(std::uint64_t id);
    void Clear() noexcept;

    Result<void> Refresh();
    Result<void> WriteValue(std::uint64_t id, std::string_view value_text);
    Result<void> SetFrozen(std::uint64_t id, bool frozen);
    Result<void> FreezeTick();

    // The v2 table is bound to the source PID and, where available, a stable
    // process-creation token. Frozen state is stored for audit purposes but is
    // always loaded disarmed, so opening a table can never cause an implicit
    // write.
    Result<void> Save(
        const std::filesystem::path& path,
        WatchListSaveFault fault = WatchListSaveFault::None) const;
    Result<void> Load(const std::filesystem::path& path);

    [[nodiscard]] const std::vector<WatchEntry>& Entries() const noexcept;
    [[nodiscard]] std::vector<WatchEntry>& Entries() noexcept;

private:
    WatchEntry* Find(std::uint64_t id) noexcept;
    const WatchEntry* Find(std::uint64_t id) const noexcept;

    IProcessMemory& memory_;
    std::vector<WatchEntry> entries_;
    std::uint64_t next_id_{1};
};

}  // namespace kdbg

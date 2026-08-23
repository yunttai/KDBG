#pragma once

#include "core/memory/ProcessMemorySession.h"
#include "core/process/IProcessMemory.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kdbg {

struct MemoryMapNavigation {
    std::uint64_t address{0};
    std::uint32_t length{0};
};

class MemoryMapPanel {
public:
    void Attach(IProcessMemory* memory);
    void Reset();
    void Draw();
    [[nodiscard]] std::optional<MemoryMapNavigation> ConsumeNavigation();

private:
    void Refresh();
    bool MatchesFilter(const MemoryRegion& region) const;
    static std::string ProtectionText(const MemoryRegion& region);

    IProcessMemory* memory_{nullptr};
    std::vector<MemoryRegion> regions_;
    std::vector<ProcessModule> modules_;
    std::optional<MemoryMapNavigation> navigation_;
    std::array<char, 128> filter_{};
    bool committed_only_{true};
    bool readable_only_{true};
    bool writable_only_{false};
    bool executable_only_{false};
    bool include_guard_{false};
    std::string status_;
};

}  // namespace kdbg

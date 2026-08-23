#pragma once

#include "core/memory/IMemoryBackend.h"
#include "core/paging/X64PageTable.h"
#include "core/pfn/PfnAddress.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace kdbg {

struct VerifiedProcessPhysicalTarget {
    std::uint32_t pid{0};
    std::uint64_t virtual_address{0};
    std::uint64_t directory_table_base{0};
    std::uint64_t physical_address{0};
    std::uint64_t pfn{0};
};

class PageTablePanel {
public:
    void Draw(IMemoryBackend& backend, std::uint32_t attached_pid = 0);
    void SetPid(std::uint32_t pid) noexcept;
    void SetVirtualAddress(std::uint64_t address) noexcept;
    [[nodiscard]] std::optional<PfnAddress> ConsumePhysicalNavigation();
    [[nodiscard]] std::optional<VerifiedProcessPhysicalTarget>
    CurrentProcessTarget(const PfnAddress& page) const noexcept;
    [[nodiscard]] Result<VerifiedProcessPhysicalTarget> RevalidateProcessTarget(
        IMemoryBackend& backend,
        const PfnAddress& page) const;

private:
    std::array<char, 32> pid_{};
    std::array<char, 64> virtual_address_{'0', 'x', '0', '\0'};
    std::optional<ProcessContext> context_;
    std::optional<TranslationWalk> walk_;
    std::optional<PfnAddress> physical_navigation_;
    std::string status_;
};

}  // namespace kdbg

#pragma once

#include "core/model/PhysicalPage.h"
#include "core/pfn/PfnAddress.h"

#include <cstdint>
#include <optional>

namespace kdbg {

enum class PhysicalTargetKind {
    RawPfn,
    ProbeFixture,
    ProcessMapping
};

// Describes why a physical page was selected.  The target owns the exact PFN
// binding so the provenance cannot drift independently from the address while
// a PhysicalPageSession is alive.
struct PhysicalWriteTarget {
    PhysicalTargetKind kind{PhysicalTargetKind::RawPfn};
    PfnAddress address{};
    std::optional<std::uint32_t> process_id;
    std::optional<std::uint64_t> virtual_page_address;

    [[nodiscard]] static PhysicalWriteTarget RawPfn(
        const PfnAddress& address) noexcept {
        return PhysicalWriteTarget{
            PhysicalTargetKind::RawPfn,
            address,
            std::nullopt,
            std::nullopt};
    }

    [[nodiscard]] static PhysicalWriteTarget ProbeFixture(
        const PfnAddress& address) noexcept {
        return PhysicalWriteTarget{
            PhysicalTargetKind::ProbeFixture,
            address,
            std::nullopt,
            std::nullopt};
    }

    [[nodiscard]] static PhysicalWriteTarget ProcessMapping(
        const PfnAddress& address,
        std::uint32_t pid,
        std::uint64_t virtual_page) noexcept {
        return PhysicalWriteTarget{
            PhysicalTargetKind::ProcessMapping,
            address,
            pid,
            virtual_page};
    }

    [[nodiscard]] bool IsConsistent() const noexcept {
        if (!address.IsConsistent()) {
            return false;
        }
        switch (kind) {
        case PhysicalTargetKind::RawPfn:
        case PhysicalTargetKind::ProbeFixture:
            return !process_id.has_value() &&
                !virtual_page_address.has_value();
        case PhysicalTargetKind::ProcessMapping:
            return process_id.has_value() && *process_id != 0U &&
                virtual_page_address.has_value() &&
                (*virtual_page_address % kPhysicalPageSize) == 0U;
        }
        return false;
    }
};

}  // namespace kdbg

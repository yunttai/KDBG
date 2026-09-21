#pragma once

#include "core/memory/PhysicalPageSession.h"
#include "core/model/PhysicalWriteTarget.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace kdbg {

enum class WriteReviewPurpose {
    Apply,
    Rollback
};

class WriteReviewModal {
public:
    void Open(WriteReviewPurpose purpose);
    void Draw(
        PhysicalPageSession& session,
        PhysicalTargetKind target_kind,
        bool target_is_valid,
        std::string_view runtime_host_identity,
        std::string_view provenance,
        std::uint32_t process_pid,
        std::uint64_t process_virtual_address,
        std::uint32_t probe_generation,
        std::uint32_t probe_crc32,
        bool physical_gate_armed);

    [[nodiscard]] bool WasUnlocked() const noexcept;
    void ClearUnlocked() noexcept;

private:
    bool open_requested_{false};
    bool unlocked_{false};
    WriteReviewPurpose purpose_{WriteReviewPurpose::Apply};
    std::array<char, 64> pfn_input_{};
    std::string error_;
};

}  // namespace kdbg

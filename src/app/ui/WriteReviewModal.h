#pragma once

#include "core/memory/PhysicalPageSession.h"

#include <array>
#include <string>

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
        bool target_is_probe_fixture,
        bool target_is_verified_process,
        std::uint32_t process_pid,
        std::uint64_t process_virtual_address,
        std::uint32_t probe_generation,
        std::uint32_t probe_crc32);

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

#include "app/ui/WriteReviewModal.h"

#include "core/pfn/PfnAddress.h"

#include <imgui.h>

namespace kdbg {

void WriteReviewModal::Open(WriteReviewPurpose purpose) {
    purpose_ = purpose;
    open_requested_ = true;
    unlocked_ = false;
    pfn_input_.fill('\0');
    error_.clear();
}

void WriteReviewModal::Draw(
    PhysicalPageSession& session,
    bool target_is_probe_fixture,
    bool target_is_verified_process,
    std::uint32_t process_pid,
    std::uint64_t process_virtual_address,
    std::uint32_t probe_generation,
    std::uint32_t probe_crc32) {
    if (open_requested_) {
        ImGui::OpenPopup("Unlock physical write");
        open_requested_ = false;
    }

    if (ImGui::BeginPopupModal(
            "Unlock physical write",
            nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        const char* action =
            purpose_ == WriteReviewPurpose::Apply ? "apply changes to"
                                                  : "roll back";
        ImGui::TextWrapped(
            "This will %s the actual physical page in a dedicated test VM. "
            "The target must be a verified probe fixture or a revalidated "
            "writable 4 KiB user-process mapping.",
            action);
        ImGui::Separator();
        const bool target_verified =
            target_is_probe_fixture || target_is_verified_process;
        if (!target_verified) {
            ImGui::TextColored(
                ImVec4(1.0F, 0.35F, 0.30F, 1.0F),
                "BLOCKED: no verified write target matches the loaded PFN.");
        } else if (target_is_probe_fixture) {
            ImGui::TextColored(
                ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
                "Verified probe target | generation %u | CRC32 %08X",
                probe_generation,
                probe_crc32);
        } else {
            ImGui::TextColored(
                ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
                "Verified process target | PID %u | VA 0x%016llX",
                process_pid,
                static_cast<unsigned long long>(process_virtual_address));
        }
        if (session.HasPage()) {
            ImGui::Text(
                "PFN: 0x%llX",
                static_cast<unsigned long long>(
                    session.Address().pfn));
            ImGui::Text(
                "Dirty bytes: %llu",
                static_cast<unsigned long long>(
                    session.DirtyCount()));
        }

        ImGui::InputText(
            "Retype current PFN",
            pfn_input_.data(),
            pfn_input_.size());

        if (!error_.empty()) {
            ImGui::TextWrapped("%s", error_.c_str());
        }

        if (!target_verified) ImGui::BeginDisabled();
        if (ImGui::Button("Unlock for one operation")) {
            const auto parsed = PfnAddress::Parse(pfn_input_.data());
            if (!parsed) {
                error_ = parsed.GetError().message;
            } else {
                const auto unlock =
                    purpose_ == WriteReviewPurpose::Apply
                        ? session.UnlockForOneApply(parsed.Value().pfn)
                        : session.UnlockForRollback(parsed.Value().pfn);
                if (!unlock) {
                    error_ = unlock.GetError().message;
                } else {
                    unlocked_ = true;
                    ImGui::CloseCurrentPopup();
                }
            }
        }
        if (!target_verified) ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

bool WriteReviewModal::WasUnlocked() const noexcept {
    return unlocked_;
}

void WriteReviewModal::ClearUnlocked() noexcept {
    unlocked_ = false;
}

}  // namespace kdbg

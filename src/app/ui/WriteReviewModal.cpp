#include "app/ui/WriteReviewModal.h"

#include "app/ui/Localization.h"

#include "core/pfn/PfnAddress.h"

#include <imgui.h>

#include <span>

namespace kdbg {

using ui::UiLabel;
using ui::UiText;

namespace {

constexpr std::uint32_t PageCrc32(
    std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t crc = 0xFFFFFFFFU;
    for (const std::uint8_t byte : bytes) {
        crc ^= byte;
        for (unsigned bit = 0; bit < 8U; ++bit) {
            const auto mask = static_cast<std::uint32_t>(
                -static_cast<std::int32_t>(crc & 1U));
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}

const char* TargetKindName(PhysicalTargetKind kind) noexcept {
    switch (kind) {
    case PhysicalTargetKind::RawPfn: return "RawPfn";
    case PhysicalTargetKind::ProbeFixture: return "ProbeFixture";
    case PhysicalTargetKind::ProcessMapping: return "ProcessMapping";
    }
    return "Unknown";
}

}  // namespace

void WriteReviewModal::Open(WriteReviewPurpose purpose) {
    purpose_ = purpose;
    open_requested_ = true;
    unlocked_ = false;
    pfn_input_.fill('\0');
    error_.clear();
}

void WriteReviewModal::Draw(
    PhysicalPageSession& session,
    PhysicalTargetKind target_kind,
    bool target_is_valid,
    std::string_view runtime_host_identity,
    std::string_view provenance,
    std::uint32_t process_pid,
    std::uint64_t process_virtual_address,
    std::uint32_t probe_generation,
    std::uint32_t probe_crc32,
    bool physical_gate_armed) {
    const auto popup_label =
        UiLabel("Unlock physical write", "Unlock physical write");
    if (open_requested_) {
        ImGui::OpenPopup(popup_label.c_str());
        open_requested_ = false;
    }

    if (ImGui::BeginPopupModal(
            popup_label.c_str(),
            nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        const char* action = purpose_ == WriteReviewPurpose::Apply
            ? UiText("apply changes to")
            : UiText("roll back");
        ImGui::TextColored(
            ImVec4(0.45F, 0.75F, 1.0F, 1.0F),
            "%s", UiText("Local physical RAM — this Windows instance"));
        ImGui::TextWrapped(
            UiText("Runtime host identity: %.*s"),
            static_cast<int>(runtime_host_identity.size()),
            runtime_host_identity.data());
        ImGui::TextWrapped(
            UiText(
                "This will %s a physical RAM page exposed by KDbgDriver in "
                "this Windows instance. Raw PFNs require a complete in-range "
                "4 KiB page; probe and process targets retain provenance "
                "revalidation."),
            action);
        ImGui::Separator();
        ImGui::Text(UiText("Target kind: %s"), TargetKindName(target_kind));
        ImGui::TextWrapped(
            UiText("Provenance: %.*s"),
            static_cast<int>(provenance.size()), provenance.data());
        if (!target_is_valid) {
            ImGui::TextColored(
                ImVec4(1.0F, 0.35F, 0.30F, 1.0F),
                "%s", UiText(
                    "BLOCKED: the selected target no longer satisfies its write prerequisites."));
        } else if (target_kind == PhysicalTargetKind::RawPfn) {
            ImGui::TextColored(
                ImVec4(0.95F, 0.75F, 0.25F, 1.0F),
                "%s", UiText(
                    "RANGE-VALIDATED RAW PFN TARGET — ownership is not implied"));
        } else if (target_kind == PhysicalTargetKind::ProbeFixture) {
            ImGui::TextColored(
                ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
                UiText("Verified probe target | generation %u | CRC32 %08X"),
                probe_generation,
                probe_crc32);
        } else {
            ImGui::TextColored(
                ImVec4(0.35F, 0.90F, 0.45F, 1.0F),
                UiText("Verified process target | PID %u | VA 0x%016llX"),
                process_pid,
                static_cast<unsigned long long>(process_virtual_address));
        }
        if (session.HasPage()) {
            ImGui::Text(
                "PFN: 0x%llX | PA: 0x%016llX",
                static_cast<unsigned long long>(
                    session.Address().pfn),
                static_cast<unsigned long long>(
                    session.Address().physical_address));
            ImGui::Text(UiText("Transfer size: 4096 bytes (one physical page)"));
            ImGui::Text(
                UiText("Dirty bytes: %llu"),
                static_cast<unsigned long long>(
                    session.DirtyCount()));
            ImGui::Text(
                UiText("Session revision: %llu"),
                static_cast<unsigned long long>(session.Revision()));
            ImGui::Text(
                UiText("Baseline CRC32: %08X | Current CRC32: %08X"),
                PageCrc32(session.Baseline()),
                PageCrc32(session.Working()));
        }
        ImGui::Text(
            UiText("Driver physical gate: %s"),
            physical_gate_armed ? "ARMED" : "LOCKED");

        ImGui::InputText(
            UiLabel("Retype current PFN", "Retype current PFN").c_str(),
            pfn_input_.data(),
            pfn_input_.size());

        if (!error_.empty()) {
            ImGui::TextWrapped("%s", error_.c_str());
        }

        const bool can_unlock = target_is_valid && session.HasPage() &&
            (purpose_ == WriteReviewPurpose::Apply
                ? session.IsDirty()
                : session.CanRollback());
        if (!can_unlock) ImGui::BeginDisabled();
        if (ImGui::Button(UiText("Unlock for one operation"))) {
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
        if (!can_unlock) ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button(UiText("Cancel"))) {
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

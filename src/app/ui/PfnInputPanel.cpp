#include "app/ui/PfnInputPanel.h"

#include "app/ui/Localization.h"

#include "core/pfn/PfnAddress.h"

#include <imgui.h>

#include <cstdio>

namespace kdbg {

using ui::UiText;

bool PfnInputPanel::Draw(
    IMemoryBackend& backend,
    PhysicalPageSession& session) {
    ImGui::TextUnformatted(UiText("PFN Navigator"));
    ImGui::TextColored(
        ImVec4(0.45F, 0.75F, 1.0F, 1.0F),
        "%s", UiText("Local physical RAM — this Windows instance"));

    const bool enter = ImGui::InputText(
        "PFN",
        input_.data(),
        input_.size(),
        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    const bool clicked = ImGui::Button(UiText("Read"));

    bool loaded = false;
    if (enter || clicked) {
        if (session.IsDirty()) {
            status_ = UiText(
                "Revert or apply the staged local edits before loading another PFN.");
            return false;
        }
        const auto parsed = PfnAddress::Parse(input_.data());
        if (!parsed) {
            status_ = parsed.GetError().message;
        } else {
            const auto load = session.Load(backend, parsed.Value());
            if (!load) {
                status_ = load.GetError().message;
            } else {
                char buffer[320]{};
                std::snprintf(
                    buffer,
                    sizeof(buffer),
                    UiText(
                        "RawPfn loaded: PFN 0x%llX / PA 0x%016llX; complete 4 KiB page is inside a driver-reported RAM range"),
                    static_cast<unsigned long long>(
                        parsed.Value().pfn),
                    static_cast<unsigned long long>(
                        parsed.Value().physical_address));
                status_ = buffer;
                loaded = true;
            }
        }
    }

    if (session.HasPage()) {
        ImGui::Separator();
        ImGui::Text(
            "PFN: 0x%llX",
            static_cast<unsigned long long>(session.Address().pfn));
        ImGui::Text(
            "PA:  0x%016llX",
            static_cast<unsigned long long>(
                session.Address().physical_address));
        ImGui::Text(UiText("Length: 0x1000"));
        const auto& target = session.Target();
        switch (target.kind) {
        case PhysicalTargetKind::RawPfn:
            ImGui::TextUnformatted(UiText(
                "Target kind: RawPfn | provenance: manual PFN entry"));
            break;
        case PhysicalTargetKind::ProbeFixture:
            ImGui::TextUnformatted(UiText(
                "Target kind: ProbeFixture | provenance: KDbgProbe metadata"));
            break;
        case PhysicalTargetKind::ProcessMapping:
            ImGui::Text(
                UiText(
                    "Target kind: ProcessMapping | PID %u | VA 0x%016llX"),
                target.process_id.value_or(0U),
                static_cast<unsigned long long>(
                    target.virtual_page_address.value_or(0U)));
            break;
        }
        ImGui::TextUnformatted(UiText(
            "Range validation: complete 4096-byte page in local physical RAM"));
        ImGui::Text(
            UiText("Dirty: %llu"),
            static_cast<unsigned long long>(session.DirtyCount()));
    }

    if (!status_.empty()) {
        ImGui::TextWrapped("%s", status_.c_str());
    }
    return loaded;
}

const std::string& PfnInputPanel::Status() const noexcept {
    return status_;
}

void PfnInputPanel::SetPfn(std::uint64_t pfn) noexcept {
    std::snprintf(input_.data(), input_.size(), "0x%llX",
        static_cast<unsigned long long>(pfn));
}

}  // namespace kdbg

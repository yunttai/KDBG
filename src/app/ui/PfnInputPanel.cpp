#include "app/ui/PfnInputPanel.h"

#include "core/pfn/PfnAddress.h"

#include <imgui.h>

#include <cstdio>

namespace kdbg {

bool PfnInputPanel::Draw(
    IMemoryBackend& backend,
    PhysicalPageSession& session) {
    ImGui::TextUnformatted("PFN Navigator");

    const bool enter = ImGui::InputText(
        "PFN",
        input_.data(),
        input_.size(),
        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    const bool clicked = ImGui::Button("Read");

    bool loaded = false;
    if (enter || clicked) {
        if (session.IsDirty()) {
            status_ =
                "Revert or apply the staged local edits before loading another PFN.";
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
                char buffer[160]{};
                std::snprintf(
                    buffer,
                    sizeof(buffer),
                    "PFN 0x%llX / PA 0x%016llX loaded",
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
        ImGui::Text("Length: 0x1000");
        ImGui::Text(
            "Dirty: %llu",
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

#include "app/ui/PageTablePanel.h"

#include <imgui.h>

#include <charconv>
#include <algorithm>
#include <cstdio>
#include <string_view>

namespace kdbg {
namespace {

bool ParseUnsigned(const char* input, std::uint64_t& value) {
    std::string_view text(input == nullptr ? "" : input);
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return false;
    const auto result = std::from_chars(
        text.data(), text.data() + text.size(), value, base);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

const char* LevelName(PagingLevel level) noexcept {
    switch (level) {
    case PagingLevel::Pml5: return "PML5";
    case PagingLevel::Pml4: return "PML4";
    case PagingLevel::Pdpt: return "PDPT";
    case PagingLevel::Pd: return "PD";
    case PagingLevel::Pt: return "PT";
    }
    return "?";
}

bool IsWritableUser4KiBWalk(const TranslationWalk& walk) noexcept {
    return walk.translated && walk.page_size == 0x1000U &&
        !walk.steps.empty() &&
        std::all_of(
            walk.steps.begin(), walk.steps.end(),
            [](const TranslationStep& step) {
                return step.flags.present && step.flags.writable &&
                    step.flags.user;
            });
}

}  // namespace

void PageTablePanel::InvalidateTranslation() noexcept {
    context_.reset();
    walk_.reset();
    physical_navigation_.reset();
}

void PageTablePanel::SetPid(std::uint32_t pid) noexcept {
    std::snprintf(pid_.data(), pid_.size(), "%u", pid);
    InvalidateTranslation();
}

void PageTablePanel::SetVirtualAddress(std::uint64_t address) noexcept {
    std::snprintf(
        virtual_address_.data(),
        virtual_address_.size(),
        "0x%llX",
        static_cast<unsigned long long>(address));
    InvalidateTranslation();
}

void PageTablePanel::Draw(
    IMemoryBackend& backend,
    std::uint32_t attached_pid) {
    if (attached_pid != 0 && pid_[0] == '\0') SetPid(attached_pid);
    ImGui::TextUnformatted("Live VA -> PA Translation");
    ImGui::SetNextItemWidth(120.0F);
    const bool pid_changed = ImGui::InputText(
        "PID", pid_.data(), pid_.size());
    ImGui::SetNextItemWidth(260.0F);
    const bool address_changed = ImGui::InputText(
        "Virtual Address",
        virtual_address_.data(),
        virtual_address_.size());
    if (pid_changed || address_changed) {
        InvalidateTranslation();
        status_ =
            "Translation input changed; translate again before opening a physical page.";
    }

    if (!backend.Info().connected) ImGui::BeginDisabled();
    if (ImGui::Button("Translate with KDBG")) {
        std::uint64_t pid_value = 0;
        std::uint64_t va = 0;
        if (!ParseUnsigned(pid_.data(), pid_value) ||
            pid_value == 0 || pid_value > UINT32_MAX ||
            !ParseUnsigned(virtual_address_.data(), va)) {
            status_ = "PID or virtual address is invalid.";
            context_.reset();
            walk_.reset();
        } else {
            const auto context = backend.GetProcessContext(
                static_cast<std::uint32_t>(pid_value));
            if (!context) {
                status_ = context.GetError().message;
                context_.reset();
                walk_.reset();
            } else {
                context_ = context.Value();
                const auto translated = backend.TranslateVirtual(
                    context_->directory_table_base,
                    va);
                if (!translated) {
                    status_ = translated.GetError().message;
                    walk_.reset();
                } else {
                    walk_ = translated.Value();
                    status_ = walk_->translated
                        ? "Translation completed."
                        : "Page walk completed but the VA is not present.";
                }
            }
        }
    }
    if (!backend.Info().connected) ImGui::EndDisabled();
    if (!backend.Info().connected) {
        ImGui::TextDisabled("Start and connect the KDBG driver first.");
    }
    if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());

    std::uint64_t va = 0;
    if (ParseUnsigned(virtual_address_.data(), va)) {
        const auto indices = VirtualAddressIndices::Decode(
            va,
            walk_.has_value() && walk_->la57);
        if (indices) {
            ImGui::Separator();
            if (indices.Value().la57) ImGui::Text("PML5 index: %u", indices.Value().pml5);
            ImGui::Text("PML4: %u | PDPT: %u | PD: %u | PT: %u | Offset: 0x%03X",
                indices.Value().pml4,
                indices.Value().pdpt,
                indices.Value().pd,
                indices.Value().pt,
                indices.Value().offset);
        }
    }

    if (!context_.has_value() || !walk_.has_value()) return;
    ImGui::Separator();
    ImGui::Text("EPROCESS: 0x%016llX | CR3/DTB: 0x%016llX | %s",
        static_cast<unsigned long long>(context_->eprocess),
        static_cast<unsigned long long>(context_->directory_table_base),
        walk_->la57 ? "LA57" : "4-level");
    ImGui::Text("PA: 0x%016llX | Page size: 0x%llX | Page offset: 0x%llX",
        static_cast<unsigned long long>(walk_->physical_address),
        static_cast<unsigned long long>(walk_->page_size),
        static_cast<unsigned long long>(walk_->page_offset));
    if (walk_->translated) {
        if (ImGui::Button("Open final PA in Physical Memory")) {
            const auto page = PfnAddress::FromPfn(
                walk_->physical_address >> 12U);
            if (page) physical_navigation_ = page.Value();
            else status_ = page.GetError().message;
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy final PA")) {
            char value[32]{};
            std::snprintf(value, sizeof(value), "0x%016llX",
                static_cast<unsigned long long>(walk_->physical_address));
            ImGui::SetClipboardText(value);
        }
    }

    if (ImGui::BeginTable(
            "page-walk", 15,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollX,
            ImVec2(0.0F, 270.0F))) {
        ImGui::TableSetupColumn("Level");
        ImGui::TableSetupColumn("Index");
        ImGui::TableSetupColumn("Entry PA");
        ImGui::TableSetupColumn("Entry Value");
        ImGui::TableSetupColumn("PFN");
        ImGui::TableSetupColumn("P");
        ImGui::TableSetupColumn("RW");
        ImGui::TableSetupColumn("US");
        ImGui::TableSetupColumn("PWT");
        ImGui::TableSetupColumn("PCD");
        ImGui::TableSetupColumn("A");
        ImGui::TableSetupColumn("D");
        ImGui::TableSetupColumn("G");
        ImGui::TableSetupColumn("PS");
        ImGui::TableSetupColumn("NX");
        ImGui::TableHeadersRow();
        for (const auto& step : walk_->steps) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(LevelName(step.level));
            ImGui::TableNextColumn(); ImGui::Text("%u", step.index);
            ImGui::TableNextColumn(); ImGui::Text("0x%016llX", static_cast<unsigned long long>(step.entry_physical_address));
            ImGui::TableNextColumn(); ImGui::Text("0x%016llX", static_cast<unsigned long long>(step.entry_value));
            ImGui::TableNextColumn(); ImGui::Text("0x%llX", static_cast<unsigned long long>(step.flags.pfn));
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.present ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.writable ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.user ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.write_through ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.cache_disable ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.accessed ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.dirty ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.global ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.page_size ? 1U : 0U);
            ImGui::TableNextColumn(); ImGui::Text("%u", step.flags.no_execute ? 1U : 0U);
        }
        ImGui::EndTable();
    }
}

std::optional<PfnAddress> PageTablePanel::ConsumePhysicalNavigation() {
    auto result = physical_navigation_;
    physical_navigation_.reset();
    return result;
}

std::optional<VerifiedProcessPhysicalTarget>
PageTablePanel::CurrentProcessTarget(const PfnAddress& page) const noexcept {
    if (!context_.has_value() || !walk_.has_value() ||
        context_->pid == 0 || !IsWritableUser4KiBWalk(*walk_) ||
        (walk_->physical_address >> 12U) != page.pfn) {
        return std::nullopt;
    }
    return VerifiedProcessPhysicalTarget{
        context_->pid,
        walk_->virtual_address,
        context_->directory_table_base,
        walk_->physical_address,
        page.pfn};
}

Result<VerifiedProcessPhysicalTarget> PageTablePanel::RevalidateProcessTarget(
    IMemoryBackend& backend,
    const PfnAddress& page) const {
    const auto candidate = CurrentProcessTarget(page);
    if (!candidate.has_value()) {
        return Result<VerifiedProcessPhysicalTarget>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "No writable 4 KiB user mapping in the current PTView matches the loaded PFN",
            "PageTablePanel::RevalidateProcessTarget"));
    }
    const auto context = backend.GetProcessContext(candidate->pid);
    if (!context) {
        return Result<VerifiedProcessPhysicalTarget>::Failure(
            context.GetError());
    }
    if (context.Value().directory_table_base !=
        candidate->directory_table_base) {
        return Result<VerifiedProcessPhysicalTarget>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            "The selected process paging context changed",
            "PageTablePanel::RevalidateProcessTarget"));
    }
    const auto translated = backend.TranslateVirtual(
        context.Value().directory_table_base,
        candidate->virtual_address);
    if (!translated) {
        return Result<VerifiedProcessPhysicalTarget>::Failure(
            translated.GetError());
    }
    if (!IsWritableUser4KiBWalk(translated.Value()) ||
        (translated.Value().physical_address >> 12U) != page.pfn) {
        return Result<VerifiedProcessPhysicalTarget>::Failure(MakeError(
            ErrorCode::ConcurrentModification,
            "The selected process VA no longer maps to the loaded writable PFN",
            "PageTablePanel::RevalidateProcessTarget"));
    }
    return Result<VerifiedProcessPhysicalTarget>::Success(
        VerifiedProcessPhysicalTarget{
            candidate->pid,
            candidate->virtual_address,
            context.Value().directory_table_base,
            translated.Value().physical_address,
            page.pfn});
}

std::optional<PageTableEvidenceSnapshot> PageTablePanel::CurrentEvidence(
    std::uint32_t pid,
    std::uint64_t virtual_address,
    std::uint64_t pfn) const {
    if (!context_.has_value() || !walk_.has_value() ||
        context_->pid != pid || walk_->virtual_address != virtual_address ||
        !IsWritableUser4KiBWalk(*walk_) ||
        (walk_->physical_address >> 12U) != pfn) {
        return std::nullopt;
    }
    return PageTableEvidenceSnapshot{*context_, *walk_};
}

}  // namespace kdbg

#include "app/ui/MemoryMapPanel.h"

#include "app/ui/Localization.h"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdio>
#include <limits>

namespace kdbg {

using ui::UiText;
using ui::UiLabel;

namespace {

std::string Lower(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

const ProcessModule* FindModule(
    const std::vector<ProcessModule>& modules,
    std::uint64_t address) {
    const auto it = std::find_if(
        modules.begin(), modules.end(),
        [address](const ProcessModule& module) {
            return module.Contains(address);
        });
    return it == modules.end() ? nullptr : &*it;
}

}  // namespace

void MemoryMapPanel::Attach(IProcessMemory* memory) {
    Reset();
    memory_ = memory;
    if (memory_ != nullptr) Refresh();
}

void MemoryMapPanel::Reset() {
    memory_ = nullptr;
    regions_.clear();
    modules_.clear();
    navigation_.reset();
    status_.clear();
}

void MemoryMapPanel::Refresh() {
    if (memory_ == nullptr || !memory_->IsOpen()) return;
    const auto regions = memory_->Regions();
    if (!regions) {
        status_ = regions.GetError().message;
        return;
    }
    const auto modules = memory_->Modules();
    if (!modules) {
        status_ = modules.GetError().message;
        return;
    }
    regions_ = regions.Value();
    modules_ = modules.Value();
    char status[160]{};
    std::snprintf(
        status,
        sizeof(status),
        UiText("Loaded %llu region(s) and %llu module(s)."),
        static_cast<unsigned long long>(regions_.size()),
        static_cast<unsigned long long>(modules_.size()));
    status_ = status;
}

std::string MemoryMapPanel::ProtectionText(const MemoryRegion& region) {
    std::string text;
    text.push_back(region.readable ? 'R' : '-');
    text.push_back(region.writable ? 'W' : '-');
    text.push_back(region.executable ? 'X' : '-');
    if (region.guard) text += " G";
    if (region.copy_on_write) text += " COW";
    return text;
}

bool MemoryMapPanel::MatchesFilter(const MemoryRegion& region) const {
    if (committed_only_ && !region.committed) return false;
    if (readable_only_ && !region.readable) return false;
    if (writable_only_ && !region.writable) return false;
    if (executable_only_ && !region.executable) return false;
    if (!include_guard_ && region.guard) return false;
    const std::string filter = Lower(filter_.data());
    if (filter.empty()) return true;
    const auto* module = FindModule(modules_, region.base);
    const std::string haystack = Lower(
        region.mapped_name + " " +
        (module == nullptr ? std::string{} : module->name + " " + module->path));
    return haystack.find(filter) != std::string::npos;
}

void MemoryMapPanel::Draw() {
    if (memory_ == nullptr || !memory_->IsOpen()) {
        ImGui::TextDisabled(UiText(
            "Attach to a process to enumerate its virtual memory map."));
        return;
    }
    if (ImGui::Button(UiText("Refresh Map"))) Refresh();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(300.0F);
    ImGui::InputTextWithHint(
        "##map-filter", UiText("filter module or mapped path"),
        filter_.data(), filter_.size());
    ImGui::Checkbox(
        UiLabel("Committed", "Committed").c_str(),
        &committed_only_);
    ImGui::SameLine();
    ImGui::Checkbox(
        UiLabel("Readable", "Readable").c_str(),
        &readable_only_);
    ImGui::SameLine();
    ImGui::Checkbox(
        UiLabel("Writable", "Writable").c_str(),
        &writable_only_);
    ImGui::SameLine();
    ImGui::Checkbox(
        UiLabel("Executable", "Executable").c_str(),
        &executable_only_);
    ImGui::SameLine();
    ImGui::Checkbox(
        UiLabel("Include guard", "Include guard").c_str(),
        &include_guard_);

    std::vector<std::size_t> visible;
    visible.reserve(regions_.size());
    for (std::size_t index = 0; index < regions_.size(); ++index) {
        if (MatchesFilter(regions_[index])) visible.push_back(index);
    }
    ImGui::Text(
        UiText("Visible regions: %llu / %llu"),
        static_cast<unsigned long long>(visible.size()),
        static_cast<unsigned long long>(regions_.size()));

    if (ImGui::BeginTable(
            "process-memory-map", 9,
             ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 390.0F))) {
        ImGui::TableSetupColumn(UiLabel("Base", "Base").c_str());
        ImGui::TableSetupColumn(UiLabel("End", "End").c_str());
        ImGui::TableSetupColumn(UiLabel("Size", "Size").c_str());
        ImGui::TableSetupColumn(UiLabel("Protection", "Protection").c_str());
        ImGui::TableSetupColumn(UiLabel("State", "State").c_str());
        ImGui::TableSetupColumn(UiLabel("Type", "Type").c_str());
        ImGui::TableSetupColumn(UiLabel("Module", "Module").c_str());
        ImGui::TableSetupColumn(UiLabel("Mapped name", "Mapped name").c_str());
        ImGui::TableSetupColumn(UiLabel("Open", "Open").c_str());
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            visible.size(), static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& region = regions_[visible[static_cast<std::size_t>(row)]];
                const auto* module = FindModule(modules_, region.base);
                ImGui::PushID(row);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(region.base));
                ImGui::TableNextColumn();
                const auto end = region.size == 0
                    ? region.base
                    : region.base + region.size - 1U;
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(end));
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(region.size));
                ImGui::TableNextColumn();
                const auto protection = ProtectionText(region);
                ImGui::TextUnformatted(protection.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("0x%X", region.state);
                ImGui::TableNextColumn();
                ImGui::Text("0x%X", region.type);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(module == nullptr ? "" : module->name.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(region.mapped_name.c_str());
                ImGui::TableNextColumn();
                if (!region.readable) ImGui::BeginDisabled();
                if (ImGui::SmallButton("Hex")) {
                    navigation_ = MemoryMapNavigation{
                        region.base,
                        static_cast<std::uint32_t>(std::min<std::uint64_t>(
                            region.size,
                            ProcessMemorySession::kMaximumViewSize))};
                }
                if (!region.readable) ImGui::EndDisabled();
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    if (ImGui::CollapsingHeader(
            UiLabel("Loaded Modules", "Loaded Modules").c_str())) {
        if (ImGui::BeginTable(
                "loaded-modules", 5,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                ImVec2(0.0F, 230.0F))) {
            ImGui::TableSetupColumn(UiLabel("Base", "Base").c_str());
            ImGui::TableSetupColumn(UiLabel("Size", "Size").c_str());
            ImGui::TableSetupColumn(UiLabel("Name", "Name").c_str());
            ImGui::TableSetupColumn(UiLabel("Path", "Path").c_str());
            ImGui::TableSetupColumn(UiLabel("Open", "Open").c_str());
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(std::min<std::size_t>(
                modules_.size(), static_cast<std::size_t>(INT_MAX))));
            while (clipper.Step()) {
                for (int index = clipper.DisplayStart;
                     index < clipper.DisplayEnd; ++index) {
                    const auto& module = modules_[static_cast<std::size_t>(index)];
                    ImGui::PushID(index);
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%016llX", static_cast<unsigned long long>(module.base));
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%llX", static_cast<unsigned long long>(module.size));
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(module.name.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(module.path.c_str());
                    ImGui::TableNextColumn();
                    if (ImGui::SmallButton("Hex")) {
                        navigation_ = MemoryMapNavigation{
                            module.base,
                            static_cast<std::uint32_t>(std::min<std::uint64_t>(
                                module.size,
                                ProcessMemorySession::kMaximumViewSize))};
                    }
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }
    }

    if (!status_.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("%s", status_.c_str());
    }
}

std::optional<MemoryMapNavigation> MemoryMapPanel::ConsumeNavigation() {
    auto result = navigation_;
    navigation_.reset();
    return result;
}

}  // namespace kdbg

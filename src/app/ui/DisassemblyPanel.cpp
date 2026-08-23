#include "app/ui/DisassemblyPanel.h"

#include <imgui.h>

#include <algorithm>
#include <charconv>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace kdbg {
namespace {

bool ParseAddress(const char* input, std::uint64_t& value) {
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

std::string HexBytes(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream stream;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) stream << ' ';
        stream << std::uppercase << std::hex << std::setw(2)
               << std::setfill('0') << static_cast<unsigned>(bytes[i]);
    }
    return stream.str();
}

}  // namespace

void DisassemblyPanel::Attach(IProcessMemory* memory) {
    memory_ = memory;
    instructions_.clear();
    status_.clear();
}

void DisassemblyPanel::Draw() {
    if (memory_ == nullptr || !memory_->IsOpen()) {
        ImGui::TextDisabled("Attach to a process to disassemble memory.");
        return;
    }
    ImGui::TextWrapped(
        "The disassembly view uses Zydis and reads the target through the same "
        "Win32/KDBG fallback process backend as the scanner.");
    ImGui::SetNextItemWidth(260.0F);
    ImGui::InputText("Start Address", address_.data(), address_.size());
    ImGui::SetNextItemWidth(140.0F);
    ImGui::InputInt("Bytes", &byte_count_);
    byte_count_ = std::clamp(byte_count_, 16, 1024 * 1024);
    ImGui::SameLine();
    if (ImGui::Button("Disassemble")) {
        std::uint64_t address = 0;
        if (!ParseAddress(address_.data(), address)) {
            status_ = "Invalid disassembly address.";
        } else {
            const auto decoded = disassembler_.Decode(
                *memory_,
                address,
                static_cast<std::uint32_t>(byte_count_),
                10000);
            if (!decoded) {
                status_ = decoded.GetError().message;
                instructions_.clear();
            } else {
                instructions_ = decoded.Value();
                status_ = "Decoded " + std::to_string(instructions_.size()) + " instruction(s).";
            }
        }
    }
    if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());

    if (instructions_.empty()) return;
    if (ImGui::BeginTable(
            "disassembly", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 650.0F))) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0F);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 240.0F);
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(instructions_.size()));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                const auto& instruction = instructions_[static_cast<std::size_t>(index)];
                const auto bytes = HexBytes(instruction.bytes);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(instruction.address));
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(bytes.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(instruction.text.c_str());
            }
        }
        ImGui::EndTable();
    }
}

}  // namespace kdbg

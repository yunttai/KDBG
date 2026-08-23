#include "app/ui/HexEditorPanel.h"

#include <algorithm>

namespace kdbg {

HexEditorPanel::HexEditorPanel() {
    editor_.Cols = 16;
    editor_.OptShowAscii = true;
    editor_.OptShowDataPreview = true;
    editor_.OptUpperCaseHex = true;
    editor_.ReadFn = &HexEditorPanel::ReadByte;
    editor_.WriteFn = &HexEditorPanel::WriteByte;
    editor_.BgColorFn = &HexEditorPanel::ByteBackground;
}

void HexEditorPanel::Draw(PhysicalPageSession& session) {
    ImGui::TextUnformatted("Physical Page");
    if (!session.HasPage()) {
        ImGui::TextDisabled("Enter a PFN and read a page.");
        return;
    }

    editor_.UserData = &session;
    auto* bytes = const_cast<std::uint8_t*>(session.Working().data());
    editor_.DrawContents(
        bytes,
        session.Working().size(),
        static_cast<std::size_t>(
            session.Address().physical_address));
}

ImU8 HexEditorPanel::ReadByte(
    const ImU8*,
    std::size_t offset,
    void* user_data) {
    const auto* session =
        static_cast<const PhysicalPageSession*>(user_data);
    return session->Working().at(offset);
}

void HexEditorPanel::WriteByte(
    ImU8*,
    std::size_t offset,
    ImU8 value,
    void* user_data) {
    auto* session = static_cast<PhysicalPageSession*>(user_data);
    static_cast<void>(session->EditByte(offset, value));
}

ImU32 HexEditorPanel::ByteBackground(
    const ImU8*,
    std::size_t offset,
    void* user_data) {
    const auto* session =
        static_cast<const PhysicalPageSession*>(user_data);

    if (std::find(
            session->LastMismatchOffsets().begin(),
            session->LastMismatchOffsets().end(),
            offset) != session->LastMismatchOffsets().end()) {
        return IM_COL32(190, 35, 35, 160);
    }
    if (std::find(
            session->LastConflictOffsets().begin(),
            session->LastConflictOffsets().end(),
            offset) != session->LastConflictOffsets().end()) {
        return IM_COL32(210, 125, 20, 150);
    }
    if (session->DirtyBitmap().test(offset)) {
        return IM_COL32(40, 120, 210, 110);
    }
    return 0;
}

}  // namespace kdbg

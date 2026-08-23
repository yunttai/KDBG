#pragma once

#include "app/ui/MemoryEditorDependency.h"
#include "core/memory/PhysicalPageSession.h"

namespace kdbg {

class HexEditorPanel {
public:
    HexEditorPanel();

    void Draw(PhysicalPageSession& session);

private:
    static ImU8 ReadByte(
        const ImU8* memory,
        std::size_t offset,
        void* user_data);
    static void WriteByte(
        ImU8* memory,
        std::size_t offset,
        ImU8 value,
        void* user_data);
    static ImU32 ByteBackground(
        const ImU8* memory,
        std::size_t offset,
        void* user_data);

    MemoryEditor editor_;
};

}  // namespace kdbg

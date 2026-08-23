#pragma once

#include "app/ui/MemoryEditorDependency.h"
#include "core/memory/ProcessMemorySession.h"
#include "core/process/IProcessMemory.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace kdbg {

class ProcessMemoryPanel {
public:
    ProcessMemoryPanel();

    void Attach(IProcessMemory* memory);
    void Reset();
    void Navigate(std::uint64_t address, std::uint32_t length = 0x1000U);
    void Draw();

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

    bool ParseRange(std::uint64_t* address, std::uint32_t* length) const;
    void DrawWriteGateModal();
    void SetStatus(const Result<void>& result, std::string success);

    IProcessMemory* memory_{nullptr};
    ProcessMemorySession session_;
    MemoryEditor editor_;
    std::array<char, 32> address_{};
    int length_{0x1000};
    std::array<char, 32> write_confirmation_{};
    std::string status_;
};

}  // namespace kdbg

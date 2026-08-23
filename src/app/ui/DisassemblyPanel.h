#pragma once

#include "app/disasm/ZydisDisassembler.h"
#include "core/process/IProcessMemory.h"

#include <array>
#include <string>
#include <vector>

namespace kdbg {

class DisassemblyPanel {
public:
    void Attach(IProcessMemory* memory);
    void Draw();

private:
    IProcessMemory* memory_{nullptr};
    ZydisDisassembler disassembler_;
    std::array<char, 64> address_{};
    int byte_count_{1024};
    std::vector<DisassembledInstruction> instructions_;
    std::string status_;
};

}  // namespace kdbg

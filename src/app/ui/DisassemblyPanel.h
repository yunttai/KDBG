#pragma once

#include "app/disasm/ZydisDisassembler.h"
#include "core/process/IProcessMemory.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <future>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace kdbg {

class DisassemblyPanel {
public:
    ~DisassemblyPanel();

    DisassemblyPanel() = default;
    DisassemblyPanel(const DisassemblyPanel&) = delete;
    DisassemblyPanel& operator=(const DisassemblyPanel&) = delete;

    void Attach(IProcessMemory* memory);
    void Draw();
    void Poll();
    [[nodiscard]] bool Busy() const noexcept;
    void RequestCancel() noexcept;
    void CancelAndWait() noexcept;

private:
    struct DecodeOutcome {
        std::uint64_t generation{0};
        std::uint64_t address{0};
        DisassemblyReport report;
        Error error;
    };

    void StartDecode(std::uint64_t address, std::uint32_t byte_count);
    void PollDecode();

    IProcessMemory* memory_{nullptr};
    std::future<DecodeOutcome> decode_future_;
    std::stop_source stop_source_;
    std::atomic_uint32_t progress_{0};
    std::atomic_uint64_t progress_consumed_{0};
    std::atomic_uint64_t progress_total_{0};
    std::atomic_uint64_t progress_instructions_{0};
    std::uint64_t generation_{0};
    std::array<char, 64> address_{};
    int byte_count_{1024};
    std::vector<DisassembledInstruction> instructions_;
    std::optional<std::uint64_t> result_address_;
    DisassemblyReport result_report_;
    std::string status_;
};

}  // namespace kdbg

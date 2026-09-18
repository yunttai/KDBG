#pragma once

#include "app/ui/MemoryEditorDependency.h"
#include "core/memory/ProcessMemorySession.h"
#include "core/process/IProcessMemory.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <future>
#include <optional>
#include <string>
#include <utility>

namespace kdbg {

class ProcessMemoryPanel {
public:
    ProcessMemoryPanel();
    ~ProcessMemoryPanel();

    ProcessMemoryPanel(const ProcessMemoryPanel&) = delete;
    ProcessMemoryPanel& operator=(const ProcessMemoryPanel&) = delete;

    void Attach(IProcessMemory* memory);
    void Reset();
    void Navigate(std::uint64_t address, std::uint32_t length = 0x1000U);
    void Draw();
    void Poll();
    [[nodiscard]] bool Busy() const noexcept;
    void RequestCancel() noexcept;
    void CancelAndWait() noexcept;

private:
    enum class Operation {
        Load,
        Reload,
        Apply,
        Rollback
    };

    struct OperationOutcome {
        std::uint64_t generation{0};
        Operation operation{Operation::Load};
        ProcessMemorySession session;
        bool succeeded{false};
        bool cancel_observed{false};
        Error error;
    };

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
    void StartLoad(
        std::uint64_t address,
        std::uint32_t length,
        Operation operation);
    void StartSessionOperation(Operation operation);
    void PollOperation();
    void PublishOperation(OperationOutcome outcome);
    void DrawWriteGateModal();
    void SetStatus(const Result<void>& result, std::string success);

    IProcessMemory* memory_{nullptr};
    std::uint32_t attached_pid_{0};
    bool cached_writes_armed_{false};
    ProcessMemorySession session_;
    std::future<OperationOutcome> operation_future_;
    std::atomic_bool cancel_requested_{false};
    std::atomic_uint32_t operation_progress_{0};
    std::uint64_t generation_{0};
    std::optional<std::pair<std::uint64_t, std::uint32_t>>
        pending_navigation_;
    MemoryEditor editor_;
    std::array<char, 32> address_{};
    int length_{0x1000};
    std::array<char, 32> write_confirmation_{};
    std::string status_;
};

}  // namespace kdbg

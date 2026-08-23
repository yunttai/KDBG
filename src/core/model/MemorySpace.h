#pragma once

#include <cstdint>
#include <string>

namespace kdbg {

enum class MemorySpaceKind {
    Physical,
    ProcessVirtual,
    KernelVirtual
};

struct MemorySpace {
    MemorySpaceKind kind{MemorySpaceKind::Physical};
    std::uint32_t pid{0};
    std::uint64_t directory_table_base{0};
    std::string label{"Physical memory"};

    [[nodiscard]] static MemorySpace Physical() {
        return MemorySpace{};
    }

    [[nodiscard]] static MemorySpace Process(
        std::uint32_t process_id,
        std::uint64_t dtb = 0,
        std::string display = {}) {
        MemorySpace value{};
        value.kind = MemorySpaceKind::ProcessVirtual;
        value.pid = process_id;
        value.directory_table_base = dtb;
        value.label = display.empty()
            ? "PID " + std::to_string(process_id)
            : std::move(display);
        return value;
    }

    [[nodiscard]] static MemorySpace Kernel() {
        MemorySpace value{};
        value.kind = MemorySpaceKind::KernelVirtual;
        value.label = "Kernel virtual memory";
        return value;
    }
};

struct ProcessContext {
    std::uint32_t pid{0};
    std::uint32_t flags{0};
    std::uint64_t eprocess{0};
    std::uint64_t directory_table_base{0};
    bool wow64{false};
};

struct BackendSessionStatus {
    std::uint32_t flags{0};
    std::uint32_t owner_pid{0};
    std::uint32_t current_pid{0};
    std::uint32_t open_handle_count{0};
    std::uint64_t successful_reads{0};
    std::uint64_t successful_writes{0};
    std::uint64_t rejected_writes{0};
    std::uint32_t last_physical_write_status{0};
    std::uint32_t last_physical_write_stage{0};
    std::uint32_t last_physical_write_transferred{0};
    bool write_enabled{false};
};

}  // namespace kdbg

#pragma once

#include "core/memory/IMemoryBackend.h"
#include "core/model/ProcessUsage.h"
#include "core/pfn/PfnAddress.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace kdbg {

enum class PfnUsageNavigationTarget {
    ProcessMemory,
    PageTables
};

struct PfnUsageNavigation {
    PfnUsageNavigationTarget target{PfnUsageNavigationTarget::PageTables};
    std::uint32_t pid{0};
    std::uint64_t virtual_address{0};
};

class ProcessUsagePanel {
public:
    ProcessUsagePanel();
    ~ProcessUsagePanel();

    ProcessUsagePanel(const ProcessUsagePanel&) = delete;
    ProcessUsagePanel& operator=(const ProcessUsagePanel&) = delete;

    void Draw(
        IMemoryBackend& backend,
        const std::optional<PfnAddress>& page,
        std::uint32_t attached_pid,
        const std::string& attached_name);
    void CancelAndWait();
    [[nodiscard]] bool Busy() const noexcept;
    [[nodiscard]] std::optional<PfnUsageNavigation> ConsumeNavigation();

private:
    void StartMemProcFs(std::uint64_t pfn);
    void StartReverseMap(
        IMemoryBackend& backend,
        std::uint64_t pfn,
        std::uint32_t pid,
        std::string process_name);
    void ConsumeWorkerResult();
    void SetPhase(std::string phase);
    void Publish(Result<PfnUsageResult> result);
    void DrawResults();

    std::array<char, 512> bridge_path_{
        'p','l','u','g','i','n','s','\\','m','e','m','p','r','o','c','f','s','_','b','r','i','d','g','e','\\',
        'k','d','b','g','_','m','e','m','p','r','o','c','f','s','_','b','r','i','d','g','e','.','e','x','e','\0'};
    int table_limit_{250000};
    std::vector<ProcessUsage> mappings_;
    std::string provider_;
    std::string status_;
    std::optional<PfnUsageNavigation> navigation_;

    std::jthread worker_;
    std::atomic_bool running_{false};
    mutable std::mutex worker_mutex_;
    std::optional<PfnUsageResult> pending_result_;
    std::optional<Error> pending_error_;
    std::string phase_;
    std::uint64_t job_pfn_{0};
    std::chrono::steady_clock::time_point job_started_{};
};

}  // namespace kdbg

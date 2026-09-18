#pragma once

#include "core/memory/IMemoryBackend.h"
#include "core/model/ProcessUsage.h"
#include "core/pfn/PfnAddress.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
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

struct PfnOwnershipEvidenceSnapshot {
    std::uint64_t pfn{0};
    std::uint64_t query_generation{0};
    std::string provider;
    ProcessUsage mapping;
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
    void RequestCancel() noexcept;
    void CancelAndWait();
    [[nodiscard]] bool Busy() const noexcept;
    [[nodiscard]] std::optional<PfnUsageNavigation> ConsumeNavigation();
    [[nodiscard]] std::optional<PfnOwnershipEvidenceSnapshot>
    CurrentEvidence(
        std::uint64_t pfn,
        std::uint32_t pid,
        std::uint64_t virtual_address) const;

private:
    void StartMemProcFs(std::uint64_t pfn);
    void StartReverseMap(
        IMemoryBackend& backend,
        std::uint64_t pfn,
        std::uint32_t pid,
        std::string process_name);
    void ConsumeWorkerResult();
    void SetPhase(std::string phase);
    void Publish(
        std::uint64_t generation,
        std::uint64_t requested_pfn,
        Result<PfnUsageResult> result);
    void DrawResults(std::uint64_t current_pfn);

    std::filesystem::path bridge_path_;
    int table_limit_{250000};
    std::vector<ProcessUsage> mappings_;
    std::optional<std::uint64_t> published_pfn_;
    std::uint64_t published_generation_{0};
    std::string provider_;
    std::string status_;
    std::optional<PfnUsageNavigation> navigation_;

    std::jthread worker_;
    std::atomic_bool running_{false};
    std::atomic_uint64_t generation_{0};
    mutable std::mutex worker_mutex_;
    std::optional<PfnUsageResult> pending_result_;
    std::optional<Error> pending_error_;
    std::uint64_t pending_generation_{0};
    std::uint64_t pending_requested_pfn_{0};
    std::string phase_;
    std::uint64_t job_pfn_{0};
    std::chrono::steady_clock::time_point job_started_{};
};

}  // namespace kdbg

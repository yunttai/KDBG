#pragma once

#include "core/process/IProcessMemory.h"
#include "core/snapshot/MemorySnapshot.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace kdbg {

class SnapshotPanel {
public:
    SnapshotPanel();
    ~SnapshotPanel();

    SnapshotPanel(const SnapshotPanel&) = delete;
    SnapshotPanel& operator=(const SnapshotPanel&) = delete;

    void Attach(IProcessMemory* memory);
    void Reset();
    void RequestCancel() noexcept;
    void CancelAndWait();
    [[nodiscard]] bool Busy() const noexcept;
    void Draw();

private:
    enum class CaptureTarget {
        Baseline,
        Current
    };

    enum class WorkerOperation {
        None,
        CaptureBaseline,
        CaptureCurrent,
        SaveBaseline,
        SaveCurrent,
        LoadBaseline,
        LoadCurrent,
        Diff
    };

    struct WorkerResult {
        std::uint64_t generation{0};
        WorkerOperation operation{WorkerOperation::None};
        std::optional<MemorySnapshot> snapshot;
        std::optional<std::vector<SnapshotDiffRun>> diffs;
        std::optional<Error> error;
        std::string success_status;
    };

    using WorkerTask = std::function<WorkerResult(
        std::stop_token,
        const SnapshotProgressCallback&)>;

    void StartCapture(CaptureTarget target);
    void StartWorker(
        WorkerOperation operation,
        std::string status,
        WorkerTask task);
    void ConsumeWorkerResult();
    void StopWorker();
    void DrawSnapshotSummary(
        const char* label,
        const std::optional<MemorySnapshot>& snapshot) const;
    void LoadSnapshot(CaptureTarget target, const char* path);
    void SaveSnapshot(CaptureTarget target, const char* path);
    void ComputeDiff();

    IProcessMemory* memory_{nullptr};
    std::optional<MemorySnapshot> baseline_;
    std::optional<MemorySnapshot> current_;
    std::vector<SnapshotDiffRun> diffs_;

    std::array<char, 32> address_{};
    std::array<char, 32> size_{};
    std::array<char, 512> baseline_path_{};
    std::array<char, 512> current_path_{};
    int max_diff_runs_{100000};

    std::jthread worker_;
    std::atomic_bool running_{false};
    std::atomic_uint64_t generation_{0};
    std::mutex result_mutex_;
    std::optional<WorkerResult> pending_result_;
    SnapshotProgress progress_{};
    std::string status_;
};

}  // namespace kdbg

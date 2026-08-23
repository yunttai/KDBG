#pragma once

#include "core/process/IProcessMemory.h"
#include "core/snapshot/MemorySnapshot.h"

#include <array>
#include <atomic>
#include <cstdint>
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
    void Draw();

private:
    enum class CaptureTarget {
        Baseline,
        Current
    };

    void StartCapture(CaptureTarget target);
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
    std::mutex result_mutex_;
    CaptureTarget pending_target_{CaptureTarget::Baseline};
    std::optional<MemorySnapshot> pending_snapshot_;
    std::optional<Error> pending_error_;
    std::string status_;
};

}  // namespace kdbg

#pragma once

#include "core/process/IProcessMemory.h"
#include "core/scanner/PointerScanner.h"

#include <array>
#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace kdbg {

class PointerScanPanel {
public:
    PointerScanPanel() = default;
    ~PointerScanPanel();

    void Attach(IProcessMemory* memory);
    void Reset();
    void Draw();

private:
    void Start();
    void Cancel();

    IProcessMemory* memory_{nullptr};
    std::unique_ptr<PointerScanner> scanner_;
    std::jthread worker_;
    std::atomic_bool running_{false};
    mutable std::mutex mutex_;
    ScanProgress progress_{};
    std::vector<PointerPath> results_;
    std::optional<Error> error_;

    std::array<char, 64> target_{};
    std::array<char, 64> max_offset_{'0', 'x', '1', '0', '0', '0', '\0'};
    int max_depth_{3};
    int max_results_{100000};
    bool aligned_only_{true};
    bool writable_only_{false};
    bool static_only_{true};
    std::string status_;
};

}  // namespace kdbg

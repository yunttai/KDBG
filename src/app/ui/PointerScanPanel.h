#pragma once

#include "core/process/IProcessMemory.h"
#include "core/scanner/PointerScanner.h"

#include <array>
#include <atomic>
#include <memory>
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
    void RequestCancel() noexcept;
    void CancelAndWait() noexcept;
    [[nodiscard]] bool Busy() const noexcept;
    void Draw();

private:
    struct PublishedResult {
        std::uint64_t generation{0};
        std::uint32_t pid{0};
        std::uint64_t target{0};
        PointerScanOptions options{};
        std::vector<PointerPath> paths;
        std::optional<Error> error;
    };

    void Start();
    [[nodiscard]] std::shared_ptr<const PublishedResult>
    PublishedSnapshot() const;

    IProcessMemory* memory_{nullptr};
    std::unique_ptr<PointerScanner> scanner_;
    std::jthread worker_;
    std::atomic_bool running_{false};
    std::atomic_uint64_t generation_{0};
    mutable std::mutex mutex_;
    ScanProgress progress_{};
    std::shared_ptr<const PublishedResult> published_;

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

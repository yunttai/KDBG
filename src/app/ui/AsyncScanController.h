#pragma once

#include "core/common/Error.h"
#include "core/scanner/MemoryScanner.h"

#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace kdbg {

class AsyncScanController {
public:
    AsyncScanController() = default;
    ~AsyncScanController();
    AsyncScanController(const AsyncScanController&) = delete;
    AsyncScanController& operator=(const AsyncScanController&) = delete;

    void StartFirst(MemoryScanner& scanner, ScanQuery query);
    void StartNext(MemoryScanner& scanner, ScanQuery query);
    void Cancel();
    void Wait();

    [[nodiscard]] bool Running() const noexcept;
    [[nodiscard]] ScanProgress Progress() const;
    [[nodiscard]] std::optional<ScanSummary> Summary() const;
    [[nodiscard]] std::optional<Error> LastError() const;

private:
    void Start(MemoryScanner& scanner, ScanQuery query, bool first);

    mutable std::mutex mutex_;
    std::jthread worker_;
    std::atomic_bool running_{false};
    ScanProgress progress_{};
    std::optional<ScanSummary> summary_;
    std::optional<Error> error_;
};

}  // namespace kdbg

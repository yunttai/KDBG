#include "app/ui/AsyncScanController.h"

namespace kdbg {

AsyncScanController::~AsyncScanController() {
    Cancel();
    Wait();
}

void AsyncScanController::StartFirst(MemoryScanner& scanner, ScanQuery query) {
    Start(scanner, std::move(query), true);
}

void AsyncScanController::StartNext(MemoryScanner& scanner, ScanQuery query) {
    Start(scanner, std::move(query), false);
}

void AsyncScanController::Start(
    MemoryScanner& scanner,
    ScanQuery query,
    bool first) {
    Cancel();
    Wait();
    {
        std::scoped_lock lock(mutex_);
        progress_ = {};
        summary_.reset();
        error_.reset();
    }
    running_.store(true);
    worker_ = std::jthread(
        [this, &scanner, query = std::move(query), first](std::stop_token token) {
            const auto callback = [this](const ScanProgress& value) {
                std::scoped_lock lock(mutex_);
                progress_ = value;
            };
            const auto result = first
                ? scanner.FirstScan(query, callback, token)
                : scanner.NextScan(query, callback, token);
            {
                std::scoped_lock lock(mutex_);
                if (result) {
                    summary_ = result.Value();
                } else {
                    error_ = result.GetError();
                }
            }
            running_.store(false);
        });
}

void AsyncScanController::Cancel() {
    if (worker_.joinable()) {
        worker_.request_stop();
    }
}

void AsyncScanController::Wait() {
    if (worker_.joinable()) {
        worker_.join();
    }
}

bool AsyncScanController::Running() const noexcept { return running_.load(); }

ScanProgress AsyncScanController::Progress() const {
    std::scoped_lock lock(mutex_);
    return progress_;
}

std::optional<ScanSummary> AsyncScanController::Summary() const {
    std::scoped_lock lock(mutex_);
    return summary_;
}

std::optional<Error> AsyncScanController::LastError() const {
    std::scoped_lock lock(mutex_);
    return error_;
}

}  // namespace kdbg

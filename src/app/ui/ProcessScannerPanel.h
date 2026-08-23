#pragma once

#include "app/ui/AsyncScanController.h"
#include "core/process/IProcessMemory.h"
#include "core/scanner/MemoryScanner.h"
#include "core/scanner/WatchList.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace kdbg {

class ProcessScannerPanel {
public:
    ProcessScannerPanel();
    ~ProcessScannerPanel();

    void Attach(IProcessMemory* memory);
    void Draw();
    void Reset();

private:
    ScanQuery BuildQuery() const;
    void DrawScanControls();
    void DrawResults();
    void DrawWatchList();
    void DrawWriteGateModal();
    void SetStatus(const Result<void>& result, std::string success);

    IProcessMemory* memory_{nullptr};
    std::unique_ptr<MemoryScanner> scanner_;
    std::unique_ptr<WatchList> watches_;
    AsyncScanController async_;

    int value_type_index_{4};
    int compare_index_{0};
    std::array<char, 256> value_{};
    std::array<char, 256> second_value_{};
    bool hexadecimal_{false};
    bool writable_only_{false};
    bool include_executable_{true};
    int alignment_{4};
    int max_results_{250000};

    std::uint64_t selected_watch_id_{0};
    std::array<char, 256> watch_value_{};
    std::array<char, 32> manual_address_{};
    std::array<char, 128> manual_description_{};
    std::array<char, 512> address_list_path_{};
    int manual_type_index_{4};
    bool manual_hexadecimal_{false};
    std::array<char, 32> write_confirmation_{};
    std::string status_;
    double next_refresh_time_{0.0};
};

}  // namespace kdbg

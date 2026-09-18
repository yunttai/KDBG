#include "TestHarness.h"

#include "app/ui/KernelExplorerPanel.h"
#include "app/ui/ProcessScannerState.h"
#include "core/address/AddressList.h"
#include "core/memory/MockMemoryBackend.h"
#include "core/process/MockProcessMemory.h"
#include "core/scanner/WatchList.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

namespace {

std::string ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

void WriteSentinel(
    const std::filesystem::path& path,
    std::string_view sentinel) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(
        sentinel.data(),
        static_cast<std::streamsize>(sentinel.size()));
}

void WriteLe16(
    std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFFU);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void WriteLe32(
    std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::uint32_t value) {
    for (std::size_t index = 0; index < 4U; ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(
            (value >> (8U * index)) & 0xFFU);
    }
}

void WriteLe64(
    std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::uint64_t value) {
    for (std::size_t index = 0; index < 8U; ++index) {
        bytes[offset + index] = static_cast<std::uint8_t>(
            (value >> (8U * index)) & 0xFFU);
    }
}

std::vector<std::uint8_t> MakeEvidencePeHeader(
    std::size_t buffer_size = 0x1000U,
    std::uint32_t size_of_headers = 0x400U) {
    constexpr std::size_t pe_offset = 0x80U;
    constexpr std::size_t optional_offset = pe_offset + 24U;
    std::vector<std::uint8_t> bytes(buffer_size, 0U);
    WriteLe32(bytes, 0x3CU, static_cast<std::uint32_t>(pe_offset));
    WriteLe32(bytes, pe_offset, 0x00004550U);
    WriteLe16(bytes, pe_offset + 6U, 3U);
    WriteLe16(bytes, pe_offset + 20U, 0xF0U);
    WriteLe16(bytes, optional_offset, 0x20BU);
    WriteLe64(bytes, optional_offset + 24U, 0x0000000140000000ULL);
    WriteLe32(bytes, optional_offset + 60U, size_of_headers);
    return bytes;
}

class RecordingProcessMemory final : public kdbg::IProcessMemory {
public:
    RecordingProcessMemory()
        : memory_(0x52000000ULL, 0x1000U, 8U) {}

    [[nodiscard]] std::uint32_t ProcessId() const noexcept override {
        return memory_.ProcessId();
    }
    [[nodiscard]] std::size_t PointerSize() const noexcept override {
        return memory_.PointerSize();
    }
    [[nodiscard]] bool IsOpen() const noexcept override {
        return memory_.IsOpen();
    }
    [[nodiscard]] bool WritesArmed() const noexcept override {
        return memory_.WritesArmed();
    }
    kdbg::Result<void> SetWritesArmed(bool armed) override {
        events_.push_back(armed ? "arm" : "lock");
        return memory_.SetWritesArmed(armed);
    }
    kdbg::Result<std::vector<std::uint8_t>> Read(
        std::uint64_t address,
        std::uint32_t length) override {
        events_.push_back("read@" + std::to_string(address - memory_.Base()));
        return memory_.Read(address, length);
    }
    kdbg::Result<std::uint32_t> Write(
        std::uint64_t address,
        std::span<const std::uint8_t> data) override {
        events_.push_back("write@" + std::to_string(address - memory_.Base()));
        return memory_.Write(address, data);
    }
    kdbg::Result<std::vector<kdbg::MemoryRegion>> Regions() override {
        return memory_.Regions();
    }
    kdbg::Result<std::vector<kdbg::ProcessModule>> Modules() override {
        return memory_.Modules();
    }

    [[nodiscard]] std::uint64_t Base() const noexcept {
        return memory_.Base();
    }
    [[nodiscard]] std::vector<std::uint8_t>& Bytes() noexcept {
        return memory_.Bytes();
    }
    [[nodiscard]] const std::vector<std::string>& Events() const noexcept {
        return events_;
    }
    void ClearEvents() { events_.clear(); }

private:
    kdbg::MockProcessMemory memory_;
    std::vector<std::string> events_;
};

}  // namespace

void RunAddressWatchDurabilityTests(kdbg::test::TestRunner& runner) {
    using namespace kdbg;

    const auto valid_pe = MakeEvidencePeHeader();
    const auto valid_header_span = PeHeaderSpanForEvidence(valid_pe);
    KDBG_CHECK(runner, valid_header_span.has_value());
    if (valid_header_span) {
        KDBG_CHECK(runner, *valid_header_span == 0x400U);
    }

    constexpr std::uint64_t loaded_base = 0xFFFFF80255EF0000ULL;
    auto loaded_pe = valid_pe;
    WriteLe64(loaded_pe, 0x80U + 24U + 24U, loaded_base);
    const auto loaded_comparison = CompareLoadedPeHeadersForEvidence(
        loaded_pe, valid_pe, loaded_base);
    KDBG_CHECK(runner, loaded_comparison.has_value());
    if (loaded_comparison) {
        KDBG_CHECK(runner, loaded_comparison->header_span == 0x400U);
        KDBG_CHECK(runner, loaded_comparison->image_base_offset == 0xB0U);
        KDBG_CHECK(runner, loaded_comparison->live_image_base == loaded_base);
        KDBG_CHECK(runner,
            loaded_comparison->local_preferred_image_base ==
                0x0000000140000000ULL);
    }
    KDBG_CHECK(runner, !CompareLoadedPeHeadersForEvidence(
        loaded_pe, valid_pe, loaded_base + 0x1000U).has_value());
    auto changed_loaded_pe = loaded_pe;
    changed_loaded_pe[0x40U] ^= 0x01U;
    KDBG_CHECK(runner, !CompareLoadedPeHeadersForEvidence(
        changed_loaded_pe, valid_pe, loaded_base).has_value());

    KDBG_CHECK(runner, !PeHeaderSpanForEvidence(
        std::span<const std::uint8_t>(valid_pe).first(0x3FU)).has_value());
    auto truncated_header = valid_pe;
    truncated_header.resize(0x300U);
    KDBG_CHECK(runner,
        !PeHeaderSpanForEvidence(truncated_header).has_value());

    auto overflowing_pe_offset = valid_pe;
    WriteLe32(overflowing_pe_offset, 0x3CU, 0xFFFFFFFFU);
    KDBG_CHECK(runner,
        !PeHeaderSpanForEvidence(overflowing_pe_offset).has_value());

    auto section_table_outside_headers = valid_pe;
    WriteLe16(section_table_outside_headers, 0x80U + 6U, 20U);
    KDBG_CHECK(runner,
        !PeHeaderSpanForEvidence(section_table_outside_headers).has_value());

    const auto oversized_headers = MakeEvidencePeHeader(0x2000U, 0x2000U);
    KDBG_CHECK(runner,
        !PeHeaderSpanForEvidence(oversized_headers).has_value());

    const auto address_path = test::UniqueTempPath(
        "kdbg-address-list-atomic.txt");
    const auto watch_path = test::UniqueTempPath(
        "kdbg-watch-list-atomic.kdbgal");

    MockMemoryBackend backend;
    KDBG_CHECK(runner, backend.Open().Ok());
    AddressList addresses(backend);
    AddressEntry address_entry{};
    address_entry.description = "verified value";
    address_entry.space = MemorySpace::Process(MockMemoryBackend::kMockPid);
    address_entry.address = MockMemoryBackend::kVirtualBase + 0x180U;
    address_entry.type = ScanValueType::UInt32;
    address_entry.width = 4U;
    const auto address_id = addresses.Add(std::move(address_entry));
    KDBG_CHECK(runner, address_id != 0U);
    KDBG_CHECK(runner, addresses.Refresh().Ok());
    const std::array<std::uint8_t, 4> desired{0x11U, 0x22U, 0x33U, 0x44U};
    KDBG_CHECK(runner, addresses.SetFrozen(
        address_id,
        true,
        std::vector<std::uint8_t>(desired.begin(), desired.end())).Ok());

    constexpr std::string_view address_sentinel = "existing-address-list";
    WriteSentinel(address_path, address_sentinel);
    const auto address_fault = addresses.Save(
        address_path,
        AddressListSaveFault::AfterFlushBeforeReplace);
    KDBG_CHECK(runner, !address_fault.Ok());
    KDBG_CHECK(runner, ReadFile(address_path) == address_sentinel);
    KDBG_CHECK(runner, addresses.Save(address_path).Ok());
    KDBG_CHECK(runner, ReadFile(address_path) != address_sentinel);

    backend.Mutate(MockMemoryBackend::kBaseAddress + 0x180U, 0x99U);
    const auto write_calls_before = backend.WriteCallCount();
    auto stale_arm = addresses.ArmProcessWrites(MockMemoryBackend::kMockPid);
    KDBG_CHECK(runner, stale_arm.Ok());
    const auto stale_write = stale_arm
        ? addresses.Write(stale_arm.TakeValue(), address_id, desired)
        : Result<VerifiedWriteResult>::Failure(stale_arm.GetError());
    KDBG_CHECK(runner, !stale_write.Ok());
    if (!stale_write) {
        KDBG_CHECK(runner, stale_write.GetError().code ==
            ErrorCode::ConcurrentModification);
    }
    KDBG_CHECK(runner, backend.WriteCallCount() == write_calls_before);
    const auto backend_status = backend.QuerySessionStatus();
    KDBG_CHECK(runner, backend_status.Ok());
    if (backend_status) {
        KDBG_CHECK(runner, !backend_status.Value().write_enabled);
    }

    MockProcessMemory process(0x51000000ULL, 0x1000U, 8U);
    process.Bytes()[0x80U] = 7U;
    WatchList watches(process);
    const auto watch_id = watches.Add(
        process.Base() + 0x80U,
        ScanValueType::UInt8,
        "freeze target");
    KDBG_CHECK(runner, watch_id.Ok());

    constexpr std::string_view watch_sentinel = "existing-watch-list";
    WriteSentinel(watch_path, watch_sentinel);
    const auto watch_fault = watches.Save(
        watch_path,
        WatchListSaveFault::AfterFlushBeforeReplace);
    KDBG_CHECK(runner, !watch_fault.Ok());
    KDBG_CHECK(runner, ReadFile(watch_path) == watch_sentinel);

    KDBG_CHECK(runner, process.SetWritesArmed(true).Ok());
    process.Bytes()[0x80U] = 8U;
    const auto conflict = watches.WriteValue(watch_id.Value(), "9");
    KDBG_CHECK(runner, !conflict.Ok());
    if (!conflict) {
        KDBG_CHECK(runner, conflict.GetError().code ==
            ErrorCode::ConcurrentModification);
    }
    KDBG_CHECK(runner, !process.WritesArmed());
    KDBG_CHECK(runner, process.Bytes()[0x80U] == 8U);

    KDBG_CHECK(runner, watches.Refresh().Ok());
    KDBG_CHECK(runner, process.SetWritesArmed(true).Ok());
    KDBG_CHECK(runner, watches.WriteValue(watch_id.Value(), "9").Ok());
    KDBG_CHECK(runner, !process.WritesArmed());
    KDBG_CHECK(runner, process.Bytes()[0x80U] == 9U);

    KDBG_CHECK(runner, process.SetWritesArmed(true).Ok());
    KDBG_CHECK(runner, watches.SetFrozen(watch_id.Value(), true).Ok());
    KDBG_CHECK(runner, watches.Save(watch_path).Ok());
    process.Bytes()[0x80U] = 2U;
    KDBG_CHECK(runner, watches.FreezeTick().Ok());
    KDBG_CHECK(runner, !process.WritesArmed());
    KDBG_CHECK(runner, process.Bytes()[0x80U] == 9U);

    process.Bytes()[0x90U] = 11U;
    const auto second_watch_id = watches.Add(
        process.Base() + 0x90U,
        ScanValueType::UInt8,
        "second freeze target");
    KDBG_CHECK(runner, second_watch_id.Ok());
    KDBG_CHECK(runner, process.SetWritesArmed(true).Ok());
    KDBG_CHECK(runner,
        watches.SetFrozen(second_watch_id.Value(), true).Ok());
    process.Bytes()[0x80U] = 2U;
    process.Bytes()[0x90U] = 3U;
    KDBG_CHECK(runner, watches.FreezeTick().Ok());
    KDBG_CHECK(runner, !process.WritesArmed());
    KDBG_CHECK(runner, process.Bytes()[0x80U] == 9U);
    KDBG_CHECK(runner, process.Bytes()[0x90U] == 11U);
    KDBG_CHECK(runner, watches.Save(watch_path).Ok());

    WatchList loaded(process);
    KDBG_CHECK(runner, loaded.Load(watch_path).Ok());
    KDBG_CHECK(runner, !process.WritesArmed());
    KDBG_CHECK(runner, loaded.Entries().size() == 2U);
    if (!loaded.Entries().empty()) {
        KDBG_CHECK(runner, !loaded.Entries().front().frozen);
        KDBG_CHECK(runner, loaded.Entries().front().frozen_value.empty());
    }
    process.Bytes()[0x80U] = 3U;
    KDBG_CHECK(runner, loaded.FreezeTick().Ok());
    KDBG_CHECK(runner, process.Bytes()[0x80U] == 3U);

    AddressList loaded_addresses(backend);
    KDBG_CHECK(runner, loaded_addresses.Load(address_path).Ok());
    KDBG_CHECK(runner, loaded_addresses.Entries().size() == 1U);
    if (!loaded_addresses.Entries().empty()) {
        KDBG_CHECK(runner, !loaded_addresses.Entries().front().frozen);
        KDBG_CHECK(runner,
            loaded_addresses.Entries().front().freeze_value.empty());
        KDBG_CHECK(runner,
            loaded_addresses.Entries().front().last_error.has_value());
    }

    // A Freeze pass is a sequence of one-shot writes, not one long-lived
    // authorization. Verify the exact per-entry arm/write/lock/read-back
    // order across multiple entries and multiple scheduler ticks.
    RecordingProcessMemory recording;
    recording.Bytes()[0x80U] = 0x31U;
    recording.Bytes()[0x90U] = 0x42U;
    WatchList ordered_freeze(recording);
    const auto ordered_first = ordered_freeze.Add(
        recording.Base() + 0x80U,
        ScanValueType::UInt8,
        "ordered first");
    const auto ordered_second = ordered_freeze.Add(
        recording.Base() + 0x90U,
        ScanValueType::UInt8,
        "ordered second");
    KDBG_CHECK(runner, ordered_first.Ok());
    KDBG_CHECK(runner, ordered_second.Ok());
    KDBG_CHECK(runner, recording.SetWritesArmed(true).Ok());
    KDBG_CHECK(runner,
        ordered_freeze.SetFrozen(ordered_first.Value(), true).Ok());
    KDBG_CHECK(runner,
        ordered_freeze.SetFrozen(ordered_second.Value(), true).Ok());

    const std::vector<std::string> expected_freeze_events{
        "arm",
        "read@128", "read@128", "arm", "write@128", "lock", "read@128",
        "read@144", "read@144", "arm", "write@144", "lock", "read@144",
        "lock"};
    for (std::size_t tick = 0; tick < 3U; ++tick) {
        recording.Bytes()[0x80U] = static_cast<std::uint8_t>(0x70U + tick);
        recording.Bytes()[0x90U] = static_cast<std::uint8_t>(0x80U + tick);
        recording.ClearEvents();
        KDBG_CHECK(runner, recording.SetWritesArmed(true).Ok());
        KDBG_CHECK(runner, ordered_freeze.FreezeTick().Ok());
        KDBG_CHECK(runner, recording.Events() == expected_freeze_events);
        KDBG_CHECK(runner, !recording.WritesArmed());
        KDBG_CHECK(runner, recording.Bytes()[0x80U] == 0x31U);
        KDBG_CHECK(runner, recording.Bytes()[0x90U] == 0x42U);
    }

    // Exercise the exact helper used by ProcessScannerPanel. The UI keeps
    // typed-PID authorization separately; it must never keep the backend gate
    // open between entries or ticks.
    RecordingProcessMemory gui_recording;
    std::vector<WatchEntry> gui_entries(2);
    gui_entries[0].address = gui_recording.Base() + 0x80U;
    gui_entries[0].type = ScanValueType::UInt8;
    gui_entries[0].frozen = true;
    gui_entries[0].frozen_value = {0x51U};
    gui_entries[1].address = gui_recording.Base() + 0x90U;
    gui_entries[1].type = ScanValueType::UInt8;
    gui_entries[1].frozen = true;
    gui_entries[1].frozen_value = {0x62U};
    const std::vector<std::string> expected_gui_freeze_events{
        "read@128", "read@128", "arm", "write@128", "lock", "read@128",
        "read@144", "read@144", "arm", "write@144", "lock", "read@144"};
    for (std::size_t tick = 0; tick < 3U; ++tick) {
        gui_recording.Bytes()[0x80U] = static_cast<std::uint8_t>(0xA0U + tick);
        gui_recording.Bytes()[0x90U] = static_cast<std::uint8_t>(0xB0U + tick);
        gui_recording.ClearEvents();
        bool pass_ok = true;
        for (auto& entry : gui_entries) {
            pass_ok = RefreshAndMaybeFreezeEntryOneShot(
                gui_recording, entry, true).Ok() && pass_ok;
        }
        KDBG_CHECK(runner, pass_ok);
        KDBG_CHECK(runner,
            gui_recording.Events() == expected_gui_freeze_events);
        KDBG_CHECK(runner, !gui_recording.WritesArmed());
        KDBG_CHECK(runner, gui_recording.Bytes()[0x80U] == 0x51U);
        KDBG_CHECK(runner, gui_recording.Bytes()[0x90U] == 0x62U);
    }

    std::error_code ignored;
    std::filesystem::remove(address_path, ignored);
    std::filesystem::remove(watch_path, ignored);
}

#if defined(KDBG_ADDRESS_WATCH_STANDALONE)
#include <iostream>

int main() {
    kdbg::test::TestRunner runner;
    RunAddressWatchDurabilityTests(runner);
    std::cout << "Checks: " << runner.Checks()
              << ", failures: " << runner.Failures() << '\n';
    return runner.Failures() == 0 ? 0 : 1;
}
#endif

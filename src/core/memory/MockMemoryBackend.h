#pragma once

#include "core/memory/IMemoryBackend.h"

#include <cstdint>
#include <mutex>
#include <vector>

namespace kdbg {

struct MockFaults {
    bool fail_open{false};
    bool fail_range_query{false};
    bool short_read{false};
    bool short_write{false};
    bool ignore_write{false};
    bool mutate_before_next_read{false};
    std::uint64_t mutate_address{0};
    std::uint8_t mutate_value{0};
    std::uint32_t fail_write_enable_count{0};
    std::uint32_t fail_write_disable_count{0};
    bool mutate_after_next_write{false};
    bool fail_compare_write_transport{false};
    bool fail_compare_write_transport_after_write{false};
    bool compare_write_failure{false};
    std::uint32_t compare_write_native_status{0xC0000001U};
};

class MockMemoryBackend final : public IMemoryBackend {
public:
    static constexpr std::uint64_t kBaseAddress = 0x00100000ULL;
    static constexpr std::uint64_t kMemorySize = 0x00100000ULL;
    static constexpr std::uint64_t kVirtualBase = 0x0000000140000000ULL;
    static constexpr std::uint32_t kMockPid = 1337U;

    MockMemoryBackend();

    Result<void> Open() override;
    void Close() noexcept override;
    [[nodiscard]] BackendInfo Info() const override;
    Result<BackendSessionStatus> QuerySessionStatus() override;

    Result<std::vector<PhysicalRange>> GetPhysicalRanges() override;

    Result<std::vector<std::uint8_t>> ReadPhysical(
        std::uint64_t physical_address,
        std::uint32_t length) override;

    Result<void> SetWriteEnabled(bool enabled) override;

    Result<std::uint32_t> WritePhysical(
        std::uint64_t physical_address,
        std::span<const std::uint8_t> data) override;
    Result<PhysicalPageCompareWriteResult> CompareWritePhysicalPage(
        std::uint64_t physical_address,
        std::span<const std::uint8_t> expected_before,
        std::span<const std::uint8_t> desired) override;

    Result<ProcessContext> GetProcessContext(std::uint32_t pid) override;
    Result<std::vector<std::uint8_t>> ReadProcessVirtual(
        std::uint32_t pid,
        std::uint64_t virtual_address,
        std::uint32_t length) override;
    Result<std::uint32_t> WriteProcessVirtual(
        std::uint32_t pid,
        std::uint64_t virtual_address,
        std::span<const std::uint8_t> data) override;
    Result<std::vector<std::uint8_t>> ReadKernelVirtual(
        std::uint64_t virtual_address,
        std::uint32_t length) override;

    Result<TranslationWalk> TranslateVirtual(
        std::uint64_t directory_table_base,
        std::uint64_t virtual_address) override;

    void SetFaults(MockFaults faults);
    void ClearFaults();
    void Mutate(std::uint64_t physical_address, std::uint8_t value);
    [[nodiscard]] std::uint64_t WriteCallCount() const noexcept;
    [[nodiscard]] std::uint64_t ReadCallCount() const noexcept;
    [[nodiscard]] std::uint64_t WriteEnableCallCount() const noexcept;
    [[nodiscard]] std::uint64_t WriteDisableCallCount() const noexcept;
    [[nodiscard]] std::uint64_t CompareWriteCallCount() const noexcept;

private:
    [[nodiscard]] bool Contains(
        std::uint64_t physical_address,
        std::uint64_t length) const noexcept;

    mutable std::mutex mutex_;
    std::vector<std::uint8_t> memory_;
    MockFaults faults_{};
    bool open_{false};
    bool write_enabled_{false};
    std::uint64_t write_call_count_{0};
    std::uint64_t read_call_count_{0};
    std::uint64_t write_enable_call_count_{0};
    std::uint64_t write_disable_call_count_{0};
    std::uint64_t compare_write_call_count_{0};
};

}  // namespace kdbg

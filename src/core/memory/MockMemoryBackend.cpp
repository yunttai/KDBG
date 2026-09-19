#include "core/memory/MockMemoryBackend.h"

#include <algorithm>
#include <limits>

namespace kdbg {

MockMemoryBackend::MockMemoryBackend()
    : memory_(static_cast<std::size_t>(kMemorySize)) {
    for (std::size_t index = 0; index < memory_.size(); ++index) {
        memory_[index] = static_cast<std::uint8_t>(
            (index * 17U + 0x3DU) & 0xFFU);
    }
}

Result<void> MockMemoryBackend::Open() {
    std::scoped_lock lock(mutex_);
    if (faults_.fail_open) {
        return Result<void>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Mock open failure was injected",
            "MockMemoryBackend::Open"));
    }
    if (open_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendAlreadyOpen,
            "Mock backend is already open",
            "MockMemoryBackend::Open"));
    }
    open_ = true;
    write_enabled_ = false;
    return Result<void>::Success();
}

void MockMemoryBackend::Close() noexcept {
    std::scoped_lock lock(mutex_);
    write_enabled_ = false;
    open_ = false;
}

BackendInfo MockMemoryBackend::Info() const {
    std::scoped_lock lock(mutex_);
    BackendInfo info{};
    info.name = "mock";
    info.abi_version = 7;
    info.connected = open_;
    info.write_enabled = write_enabled_;
    info.is_mock = true;
    info.supports_process_context = true;
    info.supports_fixture = true;
    info.supports_la57 = false;
    info.supports_physical_page_compare_write = true;
    return info;
}

Result<BackendSessionStatus> MockMemoryBackend::QuerySessionStatus() {
    std::scoped_lock lock(mutex_);
    if (!open_) {
        return Result<BackendSessionStatus>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Mock backend is not open",
            "MockMemoryBackend::QuerySessionStatus"));
    }
    BackendSessionStatus status{};
    status.owner_pid = kMockPid;
    status.current_pid = kMockPid;
    status.open_handle_count = 1;
    status.write_enabled = write_enabled_;
    status.successful_writes = write_call_count_;
    return Result<BackendSessionStatus>::Success(status);
}

Result<std::vector<PhysicalRange>>
MockMemoryBackend::GetPhysicalRanges() {
    std::scoped_lock lock(mutex_);
    if (!open_) {
        return Result<std::vector<PhysicalRange>>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Mock backend is not open",
            "MockMemoryBackend::GetPhysicalRanges"));
    }
    if (faults_.fail_range_query) {
        return Result<std::vector<PhysicalRange>>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Mock physical-range query failure was injected",
            "MockMemoryBackend::GetPhysicalRanges"));
    }

    return Result<std::vector<PhysicalRange>>::Success(
        std::vector<PhysicalRange>{{kBaseAddress, kMemorySize}});
}

Result<std::vector<std::uint8_t>> MockMemoryBackend::ReadPhysical(
    std::uint64_t physical_address,
    std::uint32_t length) {
    std::scoped_lock lock(mutex_);
    ++read_call_count_;
    if (!open_) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Mock backend is not open",
            "MockMemoryBackend::ReadPhysical"));
    }
    if (length == 0 || !Contains(physical_address, length)) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::OutsidePhysicalRam,
            "Mock read is outside the physical RAM range",
            "MockMemoryBackend::ReadPhysical",
            0,
            length,
            0));
    }

    if (faults_.mutate_before_next_read &&
        Contains(faults_.mutate_address, 1)) {
        const auto mutation_offset = static_cast<std::size_t>(
            faults_.mutate_address - kBaseAddress);
        memory_[mutation_offset] = faults_.mutate_value;
        faults_.mutate_before_next_read = false;
    }

    const auto offset =
        static_cast<std::size_t>(physical_address - kBaseAddress);
    std::size_t completed = static_cast<std::size_t>(length);
    if (faults_.short_read && completed > 1U) {
        completed /= 2U;
    }

    std::vector<std::uint8_t> output(completed);
    std::copy_n(memory_.begin() + static_cast<std::ptrdiff_t>(offset),
                static_cast<std::ptrdiff_t>(completed),
                output.begin());
    return Result<std::vector<std::uint8_t>>::Success(std::move(output));
}

Result<void> MockMemoryBackend::SetWriteEnabled(bool enabled) {
    std::scoped_lock lock(mutex_);
    if (!open_) {
        return Result<void>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Mock backend is not open",
            "MockMemoryBackend::SetWriteEnabled"));
    }
    if (enabled) {
        ++write_enable_call_count_;
        if (faults_.fail_write_enable_count != 0) {
            --faults_.fail_write_enable_count;
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Mock write-gate enable failure was injected",
                "MockMemoryBackend::SetWriteEnabled"));
        }
    } else {
        ++write_disable_call_count_;
        if (faults_.fail_write_disable_count != 0) {
            --faults_.fail_write_disable_count;
            return Result<void>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Mock write-gate disable failure was injected",
                "MockMemoryBackend::SetWriteEnabled"));
        }
    }
    write_enabled_ = enabled;
    return Result<void>::Success();
}

Result<std::uint32_t> MockMemoryBackend::WritePhysical(
    std::uint64_t physical_address,
    std::span<const std::uint8_t> data) {
    std::scoped_lock lock(mutex_);
    ++write_call_count_;

    if (!open_) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Mock backend is not open",
            "MockMemoryBackend::WritePhysical"));
    }
    if (!write_enabled_) {
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Mock write gate is locked",
            "MockMemoryBackend::WritePhysical"));
    }
    if (data.empty() || !Contains(physical_address, data.size())) {
        write_enabled_ = false;
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::OutsidePhysicalRam,
            "Mock write is outside the physical RAM range",
            "MockMemoryBackend::WritePhysical",
            0,
            data.size(),
            0));
    }

    // Match KDBG WRITE_GATE_ONE_SHOT semantics: every structurally
    // valid write attempt consumes the token before memory can be changed.
    write_enabled_ = false;

    std::size_t completed = data.size();
    if (faults_.short_write && completed > 0U) {
        completed /= 2U;
    }

    if (!faults_.ignore_write) {
        const auto offset =
            static_cast<std::size_t>(physical_address - kBaseAddress);
        std::copy_n(data.begin(),
                    static_cast<std::ptrdiff_t>(completed),
                    memory_.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    if (faults_.mutate_after_next_write &&
        Contains(faults_.mutate_address, 1)) {
        const auto mutation_offset = static_cast<std::size_t>(
            faults_.mutate_address - kBaseAddress);
        memory_[mutation_offset] = faults_.mutate_value;
        faults_.mutate_after_next_write = false;
    }

    return Result<std::uint32_t>::Success(
        static_cast<std::uint32_t>(completed));
}

Result<PhysicalPageCompareWriteResult>
MockMemoryBackend::CompareWritePhysicalPage(
    std::uint64_t physical_address,
    std::span<const std::uint8_t> expected_before,
    std::span<const std::uint8_t> desired) {
    std::scoped_lock lock(mutex_);
    ++compare_write_call_count_;

    if (!open_) {
        return Result<PhysicalPageCompareWriteResult>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Mock backend is not open",
            "MockMemoryBackend::CompareWritePhysicalPage"));
    }
    if (!write_enabled_) {
        return Result<PhysicalPageCompareWriteResult>::Failure(MakeError(
            ErrorCode::WriteLocked,
            "Mock write gate is locked",
            "MockMemoryBackend::CompareWritePhysicalPage"));
    }

    // Every well-formed transaction attempt consumes the one-shot gate,
    // including conflict and driver-reported failure outcomes.
    write_enabled_ = false;
    if (physical_address % kPhysicalPageSize != 0U ||
        expected_before.size() != kPhysicalPageSize ||
        desired.size() != kPhysicalPageSize ||
        !Contains(physical_address, kPhysicalPageSize)) {
        return Result<PhysicalPageCompareWriteResult>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Mock compare/write requires one aligned complete physical page",
            "MockMemoryBackend::CompareWritePhysicalPage"));
    }
    if (faults_.fail_compare_write_transport) {
        return Result<PhysicalPageCompareWriteResult>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Mock compare/write transport failure was injected",
            "MockMemoryBackend::CompareWritePhysicalPage"));
    }

    const auto offset =
        static_cast<std::size_t>(physical_address - kBaseAddress);
    if (faults_.mutate_before_next_read &&
        Contains(faults_.mutate_address, 1U)) {
        const auto mutation_offset = static_cast<std::size_t>(
            faults_.mutate_address - kBaseAddress);
        memory_[mutation_offset] = faults_.mutate_value;
        faults_.mutate_before_next_read = false;
    }

    PhysicalPageCompareWriteResult result{};
    const auto mismatch = std::mismatch(
        expected_before.begin(),
        expected_before.end(),
        memory_.begin() + static_cast<std::ptrdiff_t>(offset));
    if (mismatch.first != expected_before.end()) {
        result.outcome = PhysicalPageCompareWriteOutcome::Conflict;
        result.first_mismatch_offset = static_cast<std::uint32_t>(
            std::distance(expected_before.begin(), mismatch.first));
        std::copy_n(
            memory_.begin() + static_cast<std::ptrdiff_t>(offset),
            static_cast<std::ptrdiff_t>(kPhysicalPageSize),
            result.readback.begin());
        return Result<PhysicalPageCompareWriteResult>::Success(
            std::move(result));
    }

    ++write_call_count_;
    std::size_t completed = kPhysicalPageSize;
    if (faults_.short_write) {
        completed /= 2U;
    }
    if (!faults_.ignore_write) {
        std::copy_n(
            desired.begin(),
            static_cast<std::ptrdiff_t>(completed),
            memory_.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    if (faults_.mutate_after_next_write &&
        Contains(faults_.mutate_address, 1U)) {
        const auto mutation_offset = static_cast<std::size_t>(
            faults_.mutate_address - kBaseAddress);
        memory_[mutation_offset] = faults_.mutate_value;
        faults_.mutate_after_next_write = false;
    }
    if (faults_.fail_compare_write_transport_after_write) {
        return Result<PhysicalPageCompareWriteResult>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Mock compare/write post-write transport failure was injected",
            "MockMemoryBackend::CompareWritePhysicalPage"));
    }

    std::copy_n(
        memory_.begin() + static_cast<std::ptrdiff_t>(offset),
        static_cast<std::ptrdiff_t>(kPhysicalPageSize),
        result.readback.begin());
    result.transferred = static_cast<std::uint32_t>(completed);
    const auto readback_mismatch = std::mismatch(
        desired.begin(), desired.end(), result.readback.begin());
    if (faults_.compare_write_failure ||
        readback_mismatch.first != desired.end()) {
        result.outcome = PhysicalPageCompareWriteOutcome::Failure;
        result.native_status = faults_.compare_write_native_status;
        if (readback_mismatch.first != desired.end()) {
            result.first_mismatch_offset = static_cast<std::uint32_t>(
                std::distance(desired.begin(), readback_mismatch.first));
        }
    } else {
        result.outcome = PhysicalPageCompareWriteOutcome::Applied;
        result.first_mismatch_offset =
            std::numeric_limits<std::uint32_t>::max();
    }
    return Result<PhysicalPageCompareWriteResult>::Success(
        std::move(result));
}

Result<ProcessContext> MockMemoryBackend::GetProcessContext(
    std::uint32_t pid) {
    std::scoped_lock lock(mutex_);
    if (!open_) {
        return Result<ProcessContext>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Mock backend is not open",
            "MockMemoryBackend::GetProcessContext"));
    }
    if (pid != kMockPid) {
        return Result<ProcessContext>::Failure(MakeError(
            ErrorCode::NotFound,
            "Mock process was not found",
            "MockMemoryBackend::GetProcessContext"));
    }
    ProcessContext context{};
    context.pid = pid;
    context.flags = 1;
    context.eprocess = 0xFFFF800000001337ULL;
    context.directory_table_base = kBaseAddress;
    return Result<ProcessContext>::Success(context);
}

Result<std::vector<std::uint8_t>> MockMemoryBackend::ReadProcessVirtual(
    std::uint32_t pid,
    std::uint64_t virtual_address,
    std::uint32_t length) {
    if (pid != kMockPid || virtual_address < kVirtualBase ||
        virtual_address - kVirtualBase >= kMemorySize) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::OutsidePhysicalRam,
            "Mock process read is outside the fixture address space",
            "MockMemoryBackend::ReadProcessVirtual"));
    }
    return ReadPhysical(
        kBaseAddress + (virtual_address - kVirtualBase),
        length);
}

Result<std::uint32_t> MockMemoryBackend::WriteProcessVirtual(
    std::uint32_t pid,
    std::uint64_t virtual_address,
    std::span<const std::uint8_t> data) {
    if (pid != kMockPid || virtual_address < kVirtualBase ||
        virtual_address - kVirtualBase >= kMemorySize) {
        const std::scoped_lock lock(mutex_);
        write_enabled_ = false;
        return Result<std::uint32_t>::Failure(MakeError(
            ErrorCode::OutsidePhysicalRam,
            "Mock process write is outside the fixture address space",
            "MockMemoryBackend::WriteProcessVirtual"));
    }
    return WritePhysical(
        kBaseAddress + (virtual_address - kVirtualBase),
        data);
}

Result<std::vector<std::uint8_t>> MockMemoryBackend::ReadKernelVirtual(
    std::uint64_t virtual_address,
    std::uint32_t length) {
    constexpr std::uint64_t kKernelBase = 0xFFFF800000000000ULL;
    if (virtual_address < kKernelBase ||
        virtual_address - kKernelBase >= kMemorySize) {
        return Result<std::vector<std::uint8_t>>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Mock kernel read is outside the fixture address space",
            "MockMemoryBackend::ReadKernelVirtual"));
    }
    return ReadPhysical(
        kBaseAddress + (virtual_address - kKernelBase),
        length);
}

Result<TranslationWalk> MockMemoryBackend::TranslateVirtual(
    std::uint64_t directory_table_base,
    std::uint64_t virtual_address) {
    std::scoped_lock lock(mutex_);
    if (!open_) {
        return Result<TranslationWalk>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Mock backend is not open",
            "MockMemoryBackend::TranslateVirtual"));
    }

    TranslationWalk walk{};
    walk.directory_table_base = directory_table_base & ~0xFFFULL;
    walk.virtual_address = virtual_address;
    walk.physical_address =
        kBaseAddress + (virtual_address & (kMemorySize - 1U));
    walk.page_size = 0x1000;
    walk.page_offset = virtual_address & 0xFFFULL;
    walk.translated = true;
    return Result<TranslationWalk>::Success(std::move(walk));
}

void MockMemoryBackend::SetFaults(MockFaults faults) {
    std::scoped_lock lock(mutex_);
    faults_ = faults;
}

void MockMemoryBackend::ClearFaults() {
    std::scoped_lock lock(mutex_);
    faults_ = {};
}

void MockMemoryBackend::Mutate(
    std::uint64_t physical_address,
    std::uint8_t value) {
    std::scoped_lock lock(mutex_);
    if (!Contains(physical_address, 1)) {
        return;
    }
    const auto offset =
        static_cast<std::size_t>(physical_address - kBaseAddress);
    memory_[offset] = value;
}

std::uint64_t MockMemoryBackend::WriteCallCount() const noexcept {
    std::scoped_lock lock(mutex_);
    return write_call_count_;
}

std::uint64_t MockMemoryBackend::WriteEnableCallCount() const noexcept {
    std::scoped_lock lock(mutex_);
    return write_enable_call_count_;
}

std::uint64_t MockMemoryBackend::WriteDisableCallCount() const noexcept {
    std::scoped_lock lock(mutex_);
    return write_disable_call_count_;
}

std::uint64_t MockMemoryBackend::ReadCallCount() const noexcept {
    std::scoped_lock lock(mutex_);
    return read_call_count_;
}

std::uint64_t MockMemoryBackend::CompareWriteCallCount() const noexcept {
    std::scoped_lock lock(mutex_);
    return compare_write_call_count_;
}

bool MockMemoryBackend::Contains(
    std::uint64_t physical_address,
    std::uint64_t length) const noexcept {
    return PhysicalRange{kBaseAddress, kMemorySize}.Contains(
        physical_address,
        length);
}

}  // namespace kdbg

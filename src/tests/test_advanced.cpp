#include "TestHarness.h"

#include "core/address/AddressList.h"
#include "core/address/PointerResolver.h"
#include "core/memory/MockMemoryBackend.h"
#include "core/memory/VerifiedWriter.h"
#include "core/pfn/PageTableReverseMapper.h"
#include "core/snapshot/MemorySnapshot.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace {

bool WriteBytes(
    kdbg::MockMemoryBackend& backend,
    std::uint64_t address,
    std::span<const std::uint8_t> bytes) {
    const auto armed = backend.SetWriteEnabled(true);
    if (!armed) return false;
    const auto written = backend.WritePhysical(address, bytes);
    const auto locked = backend.SetWriteEnabled(false);
    return written && locked && written.Value() == bytes.size();
}

template <typename T>
bool WriteScalar(
    kdbg::MockMemoryBackend& backend,
    std::uint64_t address,
    const T& value) {
    const auto* begin = reinterpret_cast<const std::uint8_t*>(&value);
    return WriteBytes(
        backend,
        address,
        std::span<const std::uint8_t>(begin, sizeof(value)));
}

template <typename T>
bool PatchFileScalar(
    const std::filesystem::path& path,
    std::streamoff offset,
    const T& value) {
    std::fstream file(
        path,
        std::ios::binary | std::ios::in | std::ios::out);
    if (!file) return false;
    file.seekp(offset);
    file.write(reinterpret_cast<const char*>(&value), sizeof(value));
    return static_cast<bool>(file);
}

}  // namespace

void RunAdvancedCoreTests(kdbg::test::TestRunner& runner) {
    using namespace kdbg;

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        VerifiedWriter writer(backend);
        const std::uint64_t address = MockMemoryBackend::kVirtualBase + 0x80U;
        const auto before = backend.ReadProcessVirtual(
            MockMemoryBackend::kMockPid,
            address,
            4);
        KDBG_CHECK(runner, before.Ok());
        const std::array<std::uint8_t, 4> replacement{0x10, 0x20, 0x30, 0x40};
        const auto result = writer.Write(
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address,
            replacement,
            std::span<const std::uint8_t>(before.Value()));
        KDBG_CHECK(runner, result.Ok());
        if (result) {
            KDBG_CHECK(runner, result.Value().verified);
            KDBG_CHECK(runner, result.Value().readback ==
                std::vector<std::uint8_t>(replacement.begin(), replacement.end()));
        }
        KDBG_CHECK(runner, !backend.Info().write_enabled);

        const std::array<std::uint8_t, 4> wrong_expected{
            0xFF, 0x20, 0x30, 0x40};
        const auto mismatch = writer.Write(
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address,
            replacement,
            std::span<const std::uint8_t>(wrong_expected));
        KDBG_CHECK(runner, !mismatch.Ok());
        if (!mismatch) {
            KDBG_CHECK(runner, mismatch.GetError().code ==
                ErrorCode::ConcurrentModification);
        }

        const std::array<std::uint8_t, 2> wrong_length{0x10, 0x20};
        const auto length_mismatch = writer.Write(
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address,
            replacement,
            std::span<const std::uint8_t>(wrong_length));
        KDBG_CHECK(runner, !length_mismatch.Ok());
        if (!length_mismatch) {
            KDBG_CHECK(runner, length_mismatch.GetError().code ==
                ErrorCode::InvalidArgument);
        }

        const auto physical_rejected = writer.Write(
            MemorySpace::Physical(),
            MockMemoryBackend::kBaseAddress + 0x80U,
            replacement);
        KDBG_CHECK(runner, !physical_rejected.Ok());
        if (!physical_rejected) {
            KDBG_CHECK(runner, physical_rejected.GetError().code ==
                ErrorCode::Unsupported);
        }

        const auto writes_before_limits = backend.WriteCallCount();
        const std::vector<std::uint8_t> oversized(
            VerifiedWriter::kMaxWriteLength + 1U,
            0x5A);
        const auto oversized_result = writer.Write(
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address,
            oversized);
        KDBG_CHECK(runner, !oversized_result.Ok());
        if (!oversized_result) {
            KDBG_CHECK(runner, oversized_result.GetError().code ==
                ErrorCode::LimitReached);
        }
        const auto overflow_result = writer.Write(
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            std::numeric_limits<std::uint64_t>::max() - 1U,
            replacement);
        KDBG_CHECK(runner, !overflow_result.Ok());
        if (!overflow_result) {
            KDBG_CHECK(runner, overflow_result.GetError().code ==
                ErrorCode::AddressOverflow);
        }
        KDBG_CHECK(runner, backend.WriteCallCount() == writes_before_limits);

        const auto disables_before = backend.WriteDisableCallCount();
        MockFaults disable_fault{};
        disable_fault.fail_write_disable_count = 1;
        backend.SetFaults(disable_fault);
        const auto disable_failure = writer.Write(
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address + 0x20U,
            replacement);
        KDBG_CHECK(runner, !disable_failure.Ok());
        if (!disable_failure) {
            KDBG_CHECK(runner, disable_failure.GetError().code ==
                ErrorCode::IoFailure);
        }
        KDBG_CHECK(runner, backend.WriteDisableCallCount() ==
            disables_before + 2U);
        KDBG_CHECK(runner, !backend.Info().write_enabled);
        backend.ClearFaults();
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const std::uint64_t pointer_storage =
            MockMemoryBackend::kBaseAddress + 0x200U;
        const std::uint64_t pointed =
            MockMemoryBackend::kBaseAddress + 0x500U;
        KDBG_CHECK(runner, WriteScalar(backend, pointer_storage, pointed));

        PointerResolver resolver(backend);
        AddressPointerPath path{};
        path.space = MemorySpace::Physical();
        path.base_address = pointer_storage;
        path.pointer_size = 8;
        path.offsets = {0x10, 0x20};
        const auto resolved = resolver.Resolve(path);
        KDBG_CHECK(runner, resolved.Ok());
        if (resolved) {
            KDBG_CHECK(runner, resolved.Value() == pointed + 0x30U);
        }

        AddressPointerPath too_deep = path;
        too_deep.offsets.assign(PointerResolver::kMaxDepth + 1U, 0);
        const auto depth_result = resolver.Resolve(too_deep);
        KDBG_CHECK(runner, !depth_result.Ok());
        if (!depth_result) {
            KDBG_CHECK(runner, depth_result.GetError().code ==
                ErrorCode::LimitReached);
        }

        AddressPointerPath zero_base = path;
        zero_base.base_address = 0;
        KDBG_CHECK(runner, !resolver.Resolve(zero_base).Ok());

        AddressPointerPath missing_pid = path;
        missing_pid.space = MemorySpace::Process(0);
        KDBG_CHECK(runner, !resolver.Resolve(missing_pid).Ok());

        AddressPointerPath stray_pid = path;
        stray_pid.space = MemorySpace::Physical();
        stray_pid.space.pid = MockMemoryBackend::kMockPid;
        KDBG_CHECK(runner, !resolver.Resolve(stray_pid).Ok());

        const std::uint64_t null_storage =
            MockMemoryBackend::kBaseAddress + 0x280U;
        KDBG_CHECK(runner, WriteScalar(
            backend,
            null_storage,
            std::uint64_t{0}));
        AddressPointerPath null_path{};
        null_path.space = MemorySpace::Physical();
        null_path.base_address = null_storage;
        null_path.pointer_size = 8;
        null_path.offsets = {0, 0};
        const auto null_result = resolver.Resolve(null_path);
        KDBG_CHECK(runner, !null_result.Ok());
        if (!null_result) {
            KDBG_CHECK(runner, null_result.GetError().code ==
                ErrorCode::NotFound);
        }

        AddressPointerPath narrow_overflow{};
        narrow_overflow.space = MemorySpace::Physical();
        narrow_overflow.base_address =
            std::numeric_limits<std::uint32_t>::max() - 0xFU;
        narrow_overflow.pointer_size = 4;
        narrow_overflow.offsets = {0x20};
        const auto narrow_result = resolver.Resolve(narrow_overflow);
        KDBG_CHECK(runner, !narrow_result.Ok());
        if (!narrow_result) {
            KDBG_CHECK(runner, narrow_result.GetError().code ==
                ErrorCode::AddressOverflow);
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const std::uint64_t pointer_storage =
            MockMemoryBackend::kVirtualBase + 0x600U;
        const std::uint64_t target =
            MockMemoryBackend::kVirtualBase + 0x700U;
        KDBG_CHECK(runner, WriteScalar(
            backend,
            MockMemoryBackend::kBaseAddress + 0x600U,
            target));

        AddressEntry valid{};
        valid.description = "matching process pointer";
        valid.space = MemorySpace::Process(MockMemoryBackend::kMockPid);
        valid.address = MockMemoryBackend::kVirtualBase + 0x500U;
        valid.type = ScanValueType::UInt32;
        valid.width = 4;
        valid.pointer_path = AddressPointerPath{
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            pointer_storage,
            {0, 0},
            8};

        AddressList pointer_list(backend);
        const auto valid_id = pointer_list.Add(valid);
        KDBG_CHECK(runner, valid_id != 0);
        const auto refresh = pointer_list.Refresh();
        KDBG_CHECK(runner, refresh.Ok());
        if (refresh) {
            KDBG_CHECK(runner, refresh.Value().refreshed == 1U);
            KDBG_CHECK(runner, refresh.Value().failed == 0U);
        }
        if (!pointer_list.Entries().empty()) {
            KDBG_CHECK(runner,
                pointer_list.Entries().front().resolved_address == target);
            KDBG_CHECK(runner,
                pointer_list.Entries().front().current_value.size() == 4U);
        }

        AddressEntry overflowing = valid;
        overflowing.id = 0;
        overflowing.pointer_path.reset();
        overflowing.address = std::numeric_limits<std::uint64_t>::max() - 1U;
        KDBG_CHECK(runner, pointer_list.Add(std::move(overflowing)) == 0);

        AddressEntry mismatched_kind = valid;
        mismatched_kind.id = 0;
        mismatched_kind.pointer_path->space = MemorySpace::Physical();
        mismatched_kind.pointer_path->base_address =
            MockMemoryBackend::kBaseAddress + 0x600U;
        KDBG_CHECK(runner, pointer_list.Add(std::move(mismatched_kind)) == 0);

        AddressEntry mismatched_pid = valid;
        mismatched_pid.id = 0;
        mismatched_pid.pointer_path->space = MemorySpace::Process(
            MockMemoryBackend::kMockPid + 1U);
        KDBG_CHECK(runner, pointer_list.Add(std::move(mismatched_pid)) == 0);

        AddressEntry excessive_depth = valid;
        excessive_depth.id = 0;
        excessive_depth.pointer_path->offsets.assign(
            PointerResolver::kMaxDepth + 1U,
            0);
        KDBG_CHECK(runner, pointer_list.Add(std::move(excessive_depth)) == 0);

        AddressEntry zero_pointer_base = valid;
        zero_pointer_base.id = 0;
        zero_pointer_base.pointer_path->base_address = 0;
        KDBG_CHECK(runner, pointer_list.Add(std::move(zero_pointer_base)) == 0);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        AddressList list(backend);
        AddressEntry entry{};
        entry.description = "process u32";
        entry.space = MemorySpace::Process(MockMemoryBackend::kMockPid);
        entry.address = MockMemoryBackend::kVirtualBase + 0x300U;
        entry.type = ScanValueType::UInt32;
        entry.width = 4;
        const auto id = list.Add(std::move(entry));
        KDBG_CHECK(runner, id != 0);
        const auto refreshed = list.Refresh();
        KDBG_CHECK(runner, refreshed.Ok());
        if (refreshed) {
            KDBG_CHECK(runner, refreshed.Value().refreshed == 1U);
            KDBG_CHECK(runner, refreshed.Value().failed == 0U);
        }

        const std::array<std::uint8_t, 4> desired{0xAA, 0xBB, 0xCC, 0xDD};
        KDBG_CHECK(runner, list.Write(id, desired).Ok());
        KDBG_CHECK(runner, list.SetFrozen(
            id,
            true,
            std::vector<std::uint8_t>(desired.begin(), desired.end())).Ok());
        backend.Mutate(MockMemoryBackend::kBaseAddress + 0x300U, 0x11U);
        const auto frozen = list.TickFreeze();
        KDBG_CHECK(runner, frozen.Ok());
        if (frozen) {
            KDBG_CHECK(runner, frozen.Value().verified == 1U);
            KDBG_CHECK(runner, frozen.Value().failed == 0U);
        }
        const auto readback = backend.ReadPhysical(
            MockMemoryBackend::kBaseAddress + 0x300U,
            4);
        KDBG_CHECK(runner, readback.Ok());
        if (readback) {
            KDBG_CHECK(runner, readback.Value() ==
                std::vector<std::uint8_t>(desired.begin(), desired.end()));
        }

        const auto path = std::filesystem::temp_directory_path() /
            "kdbg-address-list-test.txt";
        AddressEntry unfrozen_entry{};
        unfrozen_entry.description = "unfrozen";
        unfrozen_entry.space = MemorySpace::Process(
            MockMemoryBackend::kMockPid);
        unfrozen_entry.address = MockMemoryBackend::kVirtualBase + 0x380U;
        unfrozen_entry.type = ScanValueType::UInt32;
        unfrozen_entry.width = 4;
        KDBG_CHECK(runner, list.Add(std::move(unfrozen_entry)) != 0);
        KDBG_CHECK(runner, list.Save(path).Ok());
        AddressList loaded(backend);
        KDBG_CHECK(runner, loaded.Load(path).Ok());
        KDBG_CHECK(runner, loaded.Entries().size() == 2U);
        if (!loaded.Entries().empty()) {
            KDBG_CHECK(runner, loaded.Entries().front().description ==
                "process u32");
            KDBG_CHECK(runner, !loaded.Entries().front().frozen);
            KDBG_CHECK(runner, loaded.Entries().front().freeze_value.empty());
            KDBG_CHECK(runner, loaded.Entries().front().last_error.has_value());
        }
        if (loaded.Entries().size() == 2U) {
            KDBG_CHECK(runner, !loaded.Entries()[1].frozen);
            KDBG_CHECK(runner, loaded.Entries()[1].freeze_value.empty());
        }

        AddressEntry physical{};
        physical.description = "read only physical";
        physical.space = MemorySpace::Physical();
        physical.address = MockMemoryBackend::kBaseAddress + 0x500U;
        physical.type = ScanValueType::UInt32;
        physical.width = 4;
        const auto physical_id = loaded.Add(std::move(physical));
        KDBG_CHECK(runner, physical_id != 0);
        const auto writes_before = backend.WriteCallCount();
        const auto physical_write = loaded.Write(physical_id, desired);
        KDBG_CHECK(runner, !physical_write.Ok());
        if (!physical_write) {
            KDBG_CHECK(runner, physical_write.GetError().code ==
                ErrorCode::Unsupported);
        }
        const auto physical_freeze = loaded.SetFrozen(
            physical_id,
            true,
            std::vector<std::uint8_t>(desired.begin(), desired.end()));
        KDBG_CHECK(runner, !physical_freeze.Ok());
        KDBG_CHECK(runner, backend.WriteCallCount() == writes_before);

        AddressEntry kernel{};
        kernel.description = "read only kernel";
        kernel.space = MemorySpace::Kernel();
        kernel.address = 0xFFFF800000000500ULL;
        kernel.type = ScanValueType::UInt32;
        kernel.width = 4;
        const auto kernel_id = loaded.Add(std::move(kernel));
        KDBG_CHECK(runner, kernel_id != 0);
        const auto kernel_write = loaded.Write(kernel_id, desired);
        KDBG_CHECK(runner, !kernel_write.Ok());
        if (!kernel_write) {
            KDBG_CHECK(runner, kernel_write.GetError().code ==
                ErrorCode::Unsupported);
        }
        KDBG_CHECK(runner, !loaded.SetFrozen(
            kernel_id,
            true,
            std::vector<std::uint8_t>(desired.begin(), desired.end())).Ok());
        KDBG_CHECK(runner, backend.WriteCallCount() == writes_before);

        const auto legacy_path = std::filesystem::temp_directory_path() /
            "kdbg-address-list-unfrozen-legacy.txt";
        {
            std::ofstream legacy(legacy_path, std::ios::binary | std::ios::trunc);
            legacy << "KDBG_ADDRESS_LIST\t1\n"
                   << "1\t1\t1337\t5368709120\t5\t4\t0\t\"legacy\"\t\n";
        }
        AddressList legacy_loaded(backend);
        KDBG_CHECK(runner, legacy_loaded.Load(legacy_path).Ok());
        KDBG_CHECK(runner, legacy_loaded.Entries().size() == 1U);

        const auto invalid_path = std::filesystem::temp_directory_path() /
            "kdbg-address-list-invalid.txt";
        {
            std::ofstream invalid(invalid_path, std::ios::binary | std::ios::trunc);
            invalid << "KDBG_ADDRESS_LIST\t1\n"
                    << "1\t1\t0\t4096\t5\t4\t0\t\"bad pid\"\t-\n";
        }
        AddressList invalid_loaded(backend);
        KDBG_CHECK(runner, !invalid_loaded.Load(invalid_path).Ok());

        const auto wide_path = std::filesystem::temp_directory_path() /
            "kdbg-address-list-wide.txt";
        {
            std::ofstream wide(wide_path, std::ios::binary | std::ios::trunc);
            wide << "KDBG_ADDRESS_LIST\t1\n"
                 << "1\t1\t1337\t4096\t12\t"
                 << (AddressList::kMaxValueWidth + 1U)
                 << "\t0\t\"wide\"\t-\n";
        }
        AddressList wide_loaded(backend);
        KDBG_CHECK(runner, !wide_loaded.Load(wide_path).Ok());

        AddressEntry invalid_entry{};
        invalid_entry.space = MemorySpace::Process(0);
        invalid_entry.address = 0x1000;
        invalid_entry.type = ScanValueType::UInt32;
        invalid_entry.width = 4;
        KDBG_CHECK(runner, loaded.Add(std::move(invalid_entry)) == 0);

        const auto long_row_path = std::filesystem::temp_directory_path() /
            "kdbg-address-list-long-row.txt";
        {
            std::ofstream long_row(
                long_row_path,
                std::ios::binary | std::ios::trunc);
            long_row << "KDBG_ADDRESS_LIST\t1\n"
                     << std::string(AddressList::kMaxRowBytes + 1U, 'X')
                     << '\n';
        }
        AddressList long_row_loaded(backend);
        KDBG_CHECK(runner, !long_row_loaded.Load(long_row_path).Ok());

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        std::filesystem::remove(legacy_path, ignored);
        std::filesystem::remove(invalid_path, ignored);
        std::filesystem::remove(wide_path, ignored);
        std::filesystem::remove(long_row_path, ignored);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const std::uint64_t address = MockMemoryBackend::kBaseAddress + 0x400U;
        const auto first = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            64,
            17);
        KDBG_CHECK(runner, first.Ok());
        const std::array<std::uint8_t, 3> change{0x31, 0x32, 0x33};
        KDBG_CHECK(runner, WriteBytes(backend, address + 10U, change));
        const auto second = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            64,
            13);
        KDBG_CHECK(runner, second.Ok());
        if (first && second) {
            const auto diff = first.Value().Diff(second.Value());
            KDBG_CHECK(runner, diff.Ok());
            if (diff) {
                KDBG_CHECK(runner, diff.Value().size() == 1U);
                if (!diff.Value().empty()) {
                    KDBG_CHECK(runner, diff.Value().front().offset == 10U);
                    KDBG_CHECK(runner, diff.Value().front().after ==
                        std::vector<std::uint8_t>(change.begin(), change.end()));
                }
            }

            const auto path = std::filesystem::temp_directory_path() /
                "kdbg-snapshot-test.kdbgmem";
            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const auto loaded = MemorySnapshot::Load(path);
            KDBG_CHECK(runner, loaded.Ok());
            if (loaded) {
                KDBG_CHECK(runner, loaded.Value().Bytes() == first.Value().Bytes());
                KDBG_CHECK(runner, loaded.Value().Checksum() == first.Value().Checksum());
            }

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const std::uint32_t nonzero_reserved = 1;
            KDBG_CHECK(runner, PatchFileScalar(path, 20, nonzero_reserved));
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const std::uint64_t huge_count =
                MemorySnapshot::kMaxSnapshotBytes + 1U;
            KDBG_CHECK(runner, PatchFileScalar(path, 40, huge_count));
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            {
                std::ofstream trailing(path, std::ios::binary | std::ios::app);
                trailing.put('X');
            }
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const std::uint64_t overflowing_address =
                std::numeric_limits<std::uint64_t>::max();
            KDBG_CHECK(runner, PatchFileScalar(path, 32, overflowing_address));
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const std::uint32_t process_kind =
                static_cast<std::uint32_t>(MemorySpaceKind::ProcessVirtual);
            KDBG_CHECK(runner, PatchFileScalar(path, 12, process_kind));
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        const auto too_large = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            MemorySnapshot::kMaxSnapshotBytes + 1U,
            4096);
        KDBG_CHECK(runner, !too_large.Ok());
        if (!too_large) {
            KDBG_CHECK(runner, too_large.GetError().code == ErrorCode::LimitReached);
        }
        const auto invalid_space = MemorySnapshot::Capture(
            backend,
            MemorySpace::Process(0),
            address,
            64,
            4096);
        KDBG_CHECK(runner, !invalid_space.Ok());
        const auto invalid_chunk = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            64,
            MemorySnapshot::kMaxChunkBytes + 1U);
        KDBG_CHECK(runner, !invalid_chunk.Ok());
        const auto overflow_capture = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            std::numeric_limits<std::uint64_t>::max(),
            2,
            4096);
        KDBG_CHECK(runner, !overflow_capture.Ok());
        if (!overflow_capture) {
            KDBG_CHECK(runner, overflow_capture.GetError().code ==
                ErrorCode::AddressOverflow);
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        constexpr std::uint64_t root_pfn = 0x100U;
        constexpr std::uint64_t pdpt_pfn = 0x101U;
        constexpr std::uint64_t pd_pfn = 0x102U;
        constexpr std::uint64_t pt_pfn = 0x103U;
        constexpr std::uint64_t target_pfn = 0x104U;
        const std::vector<std::uint8_t> zero(0x1000U);
        KDBG_CHECK(runner, WriteBytes(backend, root_pfn << 12U, zero));
        KDBG_CHECK(runner, WriteBytes(backend, pdpt_pfn << 12U, zero));
        KDBG_CHECK(runner, WriteBytes(backend, pd_pfn << 12U, zero));
        KDBG_CHECK(runner, WriteBytes(backend, pt_pfn << 12U, zero));
        constexpr std::uint64_t flags = 0x7U;
        const std::uint64_t pml4e = (pdpt_pfn << 12U) | flags;
        const std::uint64_t pdpte = (pd_pfn << 12U) | flags;
        const std::uint64_t pde = (pt_pfn << 12U) | flags;
        const std::uint64_t pte = (target_pfn << 12U) | flags;
        KDBG_CHECK(runner, WriteScalar(backend, root_pfn << 12U, pml4e));
        KDBG_CHECK(runner, WriteScalar(backend, pdpt_pfn << 12U, pdpte));
        KDBG_CHECK(runner, WriteScalar(backend, pd_pfn << 12U, pde));
        KDBG_CHECK(runner, WriteScalar(
            backend,
            (pt_pfn << 12U) + 5U * sizeof(std::uint64_t),
            pte));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{
            .max_table_pages = 16,
            .max_results = 16,
            .include_page_table_pages = true,
            .continue_on_read_error = false});
        mapper.SetTargets({ProcessScanTarget{
            MockMemoryBackend::kMockPid,
            "mock.exe",
            root_pfn << 12U,
            false}});
        const auto result = mapper.Query(target_pfn, {});
        KDBG_CHECK(runner, result.Ok());
        if (result) {
            KDBG_CHECK(runner, result.Value().mappings.size() == 1U);
            if (!result.Value().mappings.empty()) {
                const auto& mapping = result.Value().mappings.front();
                KDBG_CHECK(runner, mapping.pid == MockMemoryBackend::kMockPid);
                KDBG_CHECK(runner, mapping.virtual_address == 0x5000U);
                KDBG_CHECK(runner, mapping.pte_address ==
                    (pt_pfn << 12U) + 5U * sizeof(std::uint64_t));
                KDBG_CHECK(runner, mapping.page_size == 0x1000U);
                KDBG_CHECK(runner, mapping.writable);
                KDBG_CHECK(runner, mapping.user_accessible);
            }
        }
    }
}

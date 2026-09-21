#include "TestHarness.h"

#include "core/address/AddressList.h"
#include "core/memory/MockMemoryBackend.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

void RunPersistenceMigrationTests(kdbg::test::TestRunner& runner) {
    using namespace kdbg;

    MockMemoryBackend backend;
    KDBG_CHECK(runner, backend.Open().Ok());

    AddressList source(backend);
    AddressEntry entry{};
    entry.description = "pointer-backed frozen value";
    entry.space = MemorySpace::Process(MockMemoryBackend::kMockPid);
    entry.address = MockMemoryBackend::kVirtualBase + 0x300U;
    entry.type = ScanValueType::UInt32;
    entry.width = 4U;
    entry.frozen = true;
    entry.freeze_value = {0x11U, 0x22U, 0x33U, 0x44U};
    entry.pointer_path = AddressPointerPath{
        MemorySpace::Process(MockMemoryBackend::kMockPid),
        MockMemoryBackend::kVirtualBase + 0x900U,
        {0x20, -0x10},
        8U};
    KDBG_CHECK(runner, source.Add(std::move(entry)) == 1U);

    const auto v2_path = test::UniqueTempPath(
        "kdbg-address-list-persistence-v2.txt");
    const auto v1_path = test::UniqueTempPath(
        "kdbg-address-list-persistence-v1.txt");
    const auto invalid_path = test::UniqueTempPath(
        "kdbg-address-list-persistence-invalid.txt");

    KDBG_CHECK(runner, source.Save(v2_path).Ok());
    {
        std::ifstream saved(v2_path, std::ios::binary);
        std::string header;
        std::getline(saved, header);
        KDBG_CHECK(runner, header == "KDBG_ADDRESS_LIST\t2");
    }

    const auto writes_before_load = backend.WriteCallCount();
    AddressList loaded(backend);
    KDBG_CHECK(runner, loaded.Load(v2_path).Ok());
    KDBG_CHECK(runner, loaded.Entries().size() == 1U);
    if (!loaded.Entries().empty()) {
        const auto& restored = loaded.Entries().front();
        KDBG_CHECK(runner, restored.description ==
            "pointer-backed frozen value");
        KDBG_CHECK(runner, !restored.frozen);
        KDBG_CHECK(runner, restored.freeze_value.empty());
        KDBG_CHECK(runner, restored.last_error.has_value());
        KDBG_CHECK(runner, restored.pointer_path.has_value());
        if (restored.pointer_path.has_value()) {
            const auto& pointer = *restored.pointer_path;
            KDBG_CHECK(runner, pointer.space.kind ==
                MemorySpaceKind::ProcessVirtual);
            KDBG_CHECK(runner,
                pointer.space.pid == MockMemoryBackend::kMockPid);
            KDBG_CHECK(runner, pointer.base_address ==
                MockMemoryBackend::kVirtualBase + 0x900U);
            KDBG_CHECK(runner, pointer.pointer_size == 8U);
            KDBG_CHECK(runner, pointer.offsets ==
                std::vector<std::int64_t>({0x20, -0x10}));
        }
    }
    auto freeze_arm = loaded.ArmProcessWrites(MockMemoryBackend::kMockPid);
    KDBG_CHECK(runner, freeze_arm.Ok());
    const auto freeze_tick = freeze_arm
        ? loaded.TickFreeze(freeze_arm.TakeValue())
        : Result<FreezeSummary>::Failure(freeze_arm.GetError());
    KDBG_CHECK(runner, freeze_tick.Ok());
    if (freeze_tick) {
        KDBG_CHECK(runner, freeze_tick.Value().verified == 0U);
        KDBG_CHECK(runner, freeze_tick.Value().failed == 0U);
    }
    KDBG_CHECK(runner, backend.WriteCallCount() == writes_before_load);
    KDBG_CHECK(runner, loaded.Load(v2_path).Ok());
    KDBG_CHECK(runner, loaded.Entries().size() == 1U);
    KDBG_CHECK(runner, !loaded.Entries().front().frozen);
    KDBG_CHECK(runner, backend.WriteCallCount() == writes_before_load);

    {
        std::ofstream legacy(v1_path, std::ios::binary | std::ios::trunc);
        legacy << "KDBG_ADDRESS_LIST\t1\n"
               << "7\t1\t" << MockMemoryBackend::kMockPid << '\t'
               << (MockMemoryBackend::kVirtualBase + 0x380U)
               << "\t5\t4\t1\t\"legacy frozen\"\t01020304\n";
    }
    KDBG_CHECK(runner, loaded.Load(v1_path).Ok());
    KDBG_CHECK(runner, loaded.Entries().size() == 1U);
    if (!loaded.Entries().empty()) {
        KDBG_CHECK(runner, loaded.Entries().front().id == 7U);
        KDBG_CHECK(runner, !loaded.Entries().front().frozen);
        KDBG_CHECK(runner, loaded.Entries().front().freeze_value.empty());
        KDBG_CHECK(runner, !loaded.Entries().front().pointer_path.has_value());
    }
    KDBG_CHECK(runner, loaded.Save(v1_path).Ok());
    {
        std::ifstream migrated(v1_path, std::ios::binary);
        std::string header;
        std::getline(migrated, header);
        KDBG_CHECK(runner, header == "KDBG_ADDRESS_LIST\t2");
    }

    {
        std::ofstream invalid(
            invalid_path,
            std::ios::binary | std::ios::trunc);
        invalid << "KDBG_ADDRESS_LIST\t2\n"
                << "1\t1\t0\t4096\t5\t4\t0\t\"bad pid\"\t-\t0\n";
    }
    const auto retained_id = loaded.Entries().front().id;
    const auto failed_load = loaded.Load(invalid_path);
    KDBG_CHECK(runner, !failed_load.Ok());
    KDBG_CHECK(runner, loaded.Entries().size() == 1U);
    KDBG_CHECK(runner, loaded.Entries().front().id == retained_id);
    KDBG_CHECK(runner, !loaded.Entries().front().frozen);

    std::error_code ignored;
    std::filesystem::remove(v2_path, ignored);
    std::filesystem::remove(v1_path, ignored);
    std::filesystem::remove(invalid_path, ignored);
}

#include "TestHarness.h"

#include "core/memory/MockMemoryBackend.h"
#include "core/paging/X64PageTable.h"
#include "core/pfn/MemProcFsProvider.h"
#include "core/pfn/PageTableReverseMapper.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace {

constexpr std::uint64_t kPresent = 1ULL << 0U;
constexpr std::uint64_t kWritable = 1ULL << 1U;
constexpr std::uint64_t kUser = 1ULL << 2U;
constexpr std::uint64_t kPageSize = 1ULL << 7U;
constexpr std::uint64_t kNx = 1ULL << 63U;

bool WriteBytes(
    kdbg::IMemoryBackend& backend,
    std::uint64_t address,
    std::span<const std::uint8_t> bytes) {
    const auto result = backend.WritePhysical(address, bytes);
    return result && result.Value() == bytes.size();
}

bool ClearTable(kdbg::IMemoryBackend& backend, std::uint64_t pfn) {
    const std::array<std::uint8_t, 0x1000> zero{};
    return WriteBytes(backend, pfn << 12U, zero);
}

bool WriteEntry(
    kdbg::IMemoryBackend& backend,
    std::uint64_t table_pfn,
    std::uint16_t index,
    std::uint64_t entry) {
    std::array<std::uint8_t, sizeof(entry)> bytes{};
    std::memcpy(bytes.data(), &entry, sizeof(entry));
    return WriteBytes(
        backend,
        (table_pfn << 12U) +
            static_cast<std::uint64_t>(index) * sizeof(entry),
        bytes);
}

bool OpenWritable(kdbg::MockMemoryBackend& backend) {
    const auto opened = backend.Open();
    if (!opened) return false;
    return backend.SetWriteEnabled(true).Ok();
}

class StopAfterReadBackend final : public kdbg::IMemoryBackend {
public:
    StopAfterReadBackend(std::stop_source& source, std::size_t stop_after)
        : source_(source), stop_after_(stop_after) {}

    kdbg::Result<void> Open() override { return base_.Open(); }
    void Close() noexcept override { base_.Close(); }
    [[nodiscard]] kdbg::BackendInfo Info() const override {
        return base_.Info();
    }
    kdbg::Result<std::vector<kdbg::PhysicalRange>> GetPhysicalRanges() override {
        return base_.GetPhysicalRanges();
    }
    kdbg::Result<std::vector<std::uint8_t>> ReadPhysical(
        std::uint64_t address,
        std::uint32_t length) override {
        auto result = base_.ReadPhysical(address, length);
        ++read_count_;
        if (read_count_ == stop_after_) source_.request_stop();
        return result;
    }
    kdbg::Result<void> SetWriteEnabled(bool enabled) override {
        return base_.SetWriteEnabled(enabled);
    }
    kdbg::Result<std::uint32_t> WritePhysical(
        std::uint64_t address,
        std::span<const std::uint8_t> data) override {
        return base_.WritePhysical(address, data);
    }
    kdbg::Result<kdbg::TranslationWalk> TranslateVirtual(
        std::uint64_t directory_table_base,
        std::uint64_t virtual_address) override {
        return base_.TranslateVirtual(directory_table_base, virtual_address);
    }

private:
    kdbg::MockMemoryBackend base_;
    std::stop_source& source_;
    std::size_t stop_after_{0};
    std::size_t read_count_{0};
};

void RunProtocolTests(kdbg::test::TestRunner& runner) {
    using kdbg::ErrorCode;
    using kdbg::MappingConfidence;
    using kdbg::MemProcFsProvider;

    const std::string valid =
        "KDBG_PFN_RESULT\t1\t291\n"
        "MAP\t1337\t4096\t8192\t4096\t3\t1\t1\t0\t1\t"
        "\"process-private\"\t\"fixture.exe\"\n"
        "END\n";
    const auto parsed = MemProcFsProvider::ParseOutput(291, valid);
    KDBG_CHECK(runner, parsed.Ok());
    if (parsed) {
        KDBG_CHECK(runner, parsed.Value().pfn == 291U);
        KDBG_CHECK(runner, parsed.Value().provider == "memprocfs-bridge");
        KDBG_CHECK(runner, parsed.Value().mappings.size() == 1U);
        if (!parsed.Value().mappings.empty()) {
            const auto& usage = parsed.Value().mappings.front();
            KDBG_CHECK(runner, usage.pid == 1337U);
            KDBG_CHECK(runner, usage.virtual_address == 4096U);
            KDBG_CHECK(runner, usage.pte_address == 8192U);
            KDBG_CHECK(runner, usage.page_size == 4096U);
            KDBG_CHECK(runner, usage.confidence == MappingConfidence::High);
            KDBG_CHECK(runner, usage.shared);
            KDBG_CHECK(runner, usage.writable);
            KDBG_CHECK(runner, !usage.user_accessible);
            KDBG_CHECK(runner, usage.no_execute);
        }
    }

    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, "KDBG_PFN_RESULT 2 291\nEND\n").Ok());
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, "KDBG_PFN_RESULT 1 292\nEND\n").Ok());
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, "KDBG_PFN_RESULT 1 291 extra\nEND\n").Ok());
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, "KDBG_PFN_RESULT 1 291\n").Ok());
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, "KDBG_PFN_RESULT 1 291\nEND extra\n").Ok());
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291,
        "KDBG_PFN_RESULT 1 291\nEND\n"
        "MAP 1 0 0 4096 0 0 0 0 0 \"x\" \"y\"\n").Ok());

    const std::string invalid_boolean =
        "KDBG_PFN_RESULT 1 291\n"
        "MAP 1 0 0 4096 3 2 0 0 0 \"x\" \"y\"\nEND\n";
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, invalid_boolean).Ok());
    const std::string invalid_confidence =
        "KDBG_PFN_RESULT 1 291\n"
        "MAP 1 0 0 4096 4 0 0 0 0 \"x\" \"y\"\nEND\n";
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, invalid_confidence).Ok());
    const std::string invalid_page_size =
        "KDBG_PFN_RESULT 1 291\n"
        "MAP 1 0 0 8192 1 0 0 0 0 \"x\" \"y\"\nEND\n";
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, invalid_page_size).Ok());
    const std::string trailing_map_field =
        "KDBG_PFN_RESULT 1 291\n"
        "MAP 1 0 0 4096 1 0 0 0 0 \"x\" \"y\" extra\nEND\n";
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, trailing_map_field).Ok());
    const std::string unquoted_strings =
        "KDBG_PFN_RESULT 1 291\n"
        "MAP 1 0 0 4096 1 0 0 0 0 x y\nEND\n";
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, unquoted_strings).Ok());
    const std::string negative_pid =
        "KDBG_PFN_RESULT 1 291\n"
        "MAP -1 0 0 4096 1 0 0 0 0 \"x\" \"y\"\nEND\n";
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(
        291, negative_pid).Ok());

    const std::string two_mappings =
        "KDBG_PFN_RESULT 1 291\n"
        "MAP 1 0 0 4096 1 0 0 0 0 \"x\" \"a\"\n"
        "MAP 2 0 0 4096 1 0 0 0 0 \"x\" \"b\"\nEND\n";
    const auto limited = MemProcFsProvider::ParseOutput(291, two_mappings, 1);
    KDBG_CHECK(runner, !limited.Ok());
    if (!limited) {
        KDBG_CHECK(runner, limited.GetError().code == ErrorCode::LimitReached);
    }
    KDBG_CHECK(runner, !MemProcFsProvider::ParseOutput(291, valid, 0).Ok());
}

void RunReverseMapTests(kdbg::test::TestRunner& runner) {
    using kdbg::CanonicalizeVirtualAddress;
    using kdbg::ErrorCode;
    using kdbg::MockFaults;
    using kdbg::MockMemoryBackend;
    using kdbg::PageTableReverseMapper;
    using kdbg::ProcessScanTarget;
    using kdbg::ReverseMapLimits;

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, OpenWritable(backend));
        constexpr std::uint64_t root = 0x100U;
        constexpr std::uint64_t pdpt = 0x101U;
        constexpr std::uint64_t pd = 0x102U;
        constexpr std::uint64_t pt = 0x103U;
        constexpr std::uint64_t target = 0x104U;
        KDBG_CHECK(runner, ClearTable(backend, root));
        KDBG_CHECK(runner, ClearTable(backend, pdpt));
        KDBG_CHECK(runner, ClearTable(backend, pd));
        KDBG_CHECK(runner, ClearTable(backend, pt));
        KDBG_CHECK(runner, WriteEntry(
            backend, root, 0x1FFU,
            (pdpt << 12U) | kPresent | kWritable | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, pdpt, 1, (pd << 12U) | kPresent | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, pd, 2, (pt << 12U) | kPresent | kWritable | kNx));
        KDBG_CHECK(runner, WriteEntry(
            backend, pt, 3,
            (target << 12U) | kPresent | kWritable | kUser));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{16, 4, false, false});
        const ProcessScanTarget process{
            MockMemoryBackend::kMockPid,
            "fixture.exe",
            root << 12U,
            false};
        mapper.SetTargets({process, process});
        const auto result = mapper.Query(target, {});
        KDBG_CHECK(runner, result.Ok());
        if (result) {
            KDBG_CHECK(runner, result.Value().mappings.size() == 1U);
            if (!result.Value().mappings.empty()) {
                const auto& usage = result.Value().mappings.front();
                const std::uint64_t raw =
                    (0x1FFULL << 39U) | (1ULL << 30U) |
                    (2ULL << 21U) | (3ULL << 12U);
                KDBG_CHECK(runner, usage.virtual_address ==
                    CanonicalizeVirtualAddress(raw, false));
                KDBG_CHECK(runner, !usage.writable);
                KDBG_CHECK(runner, !usage.user_accessible);
                KDBG_CHECK(runner, usage.no_execute);
                KDBG_CHECK(runner, usage.page_size == 0x1000U);
            }
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, OpenWritable(backend));
        constexpr std::array<std::uint64_t, 5> tables{
            0x110U, 0x111U, 0x112U, 0x113U, 0x114U};
        constexpr std::uint64_t target = 0x115U;
        for (const auto table : tables) {
            KDBG_CHECK(runner, ClearTable(backend, table));
        }
        KDBG_CHECK(runner, WriteEntry(
            backend, tables[0], 0x1FFU,
            (tables[1] << 12U) | kPresent | kWritable | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, tables[1], 2,
            (tables[2] << 12U) | kPresent | kWritable | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, tables[2], 3,
            (tables[3] << 12U) | kPresent | kWritable | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, tables[3], 4,
            (tables[4] << 12U) | kPresent | kWritable | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, tables[4], 5,
            (target << 12U) | kPresent | kWritable | kUser));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{8, 2, false, false});
        mapper.SetTargets({ProcessScanTarget{
            MockMemoryBackend::kMockPid,
            "la57.exe",
            tables[0] << 12U,
            true}});
        const auto result = mapper.Query(target, {});
        KDBG_CHECK(runner, result.Ok());
        if (result && !result.Value().mappings.empty()) {
            const std::uint64_t raw =
                (0x1FFULL << 48U) | (2ULL << 39U) |
                (3ULL << 30U) | (4ULL << 21U) | (5ULL << 12U);
            KDBG_CHECK(runner, result.Value().mappings.front().virtual_address ==
                CanonicalizeVirtualAddress(raw, true));
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, OpenWritable(backend));
        constexpr std::uint64_t root = 0x120U;
        constexpr std::uint64_t pdpt = 0x121U;
        constexpr std::uint64_t pd = 0x122U;
        constexpr std::uint64_t base = 0x400U;
        constexpr std::uint64_t target = base + 0x12U;
        KDBG_CHECK(runner, ClearTable(backend, root));
        KDBG_CHECK(runner, ClearTable(backend, pdpt));
        KDBG_CHECK(runner, ClearTable(backend, pd));
        KDBG_CHECK(runner, WriteEntry(
            backend, root, 0, (pdpt << 12U) | kPresent | kWritable | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, pdpt, 0, (pd << 12U) | kPresent | kWritable | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, pd, 7,
            (base << 12U) | kPresent | kWritable | kUser | kPageSize));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{8, 2, false, false});
        mapper.SetTargets({ProcessScanTarget{
            MockMemoryBackend::kMockPid, "large2m.exe", root << 12U, false}});
        const auto result = mapper.Query(target, {});
        KDBG_CHECK(runner, result.Ok());
        if (result && !result.Value().mappings.empty()) {
            const auto& usage = result.Value().mappings.front();
            KDBG_CHECK(runner, usage.page_size == 0x200000U);
            KDBG_CHECK(runner, usage.virtual_address ==
                (7ULL << 21U) + ((target - base) << 12U));
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, OpenWritable(backend));
        constexpr std::uint64_t root = 0x130U;
        constexpr std::uint64_t pdpt = 0x131U;
        constexpr std::uint64_t base = 0x80000U;
        constexpr std::uint64_t target = base + 0x123U;
        KDBG_CHECK(runner, ClearTable(backend, root));
        KDBG_CHECK(runner, ClearTable(backend, pdpt));
        KDBG_CHECK(runner, WriteEntry(
            backend, root, 0x1FFU,
            (pdpt << 12U) | kPresent | kWritable | kUser));
        KDBG_CHECK(runner, WriteEntry(
            backend, pdpt, 6,
            (base << 12U) | kPresent | kWritable | kUser | kPageSize));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{4, 2, false, false});
        mapper.SetTargets({ProcessScanTarget{
            MockMemoryBackend::kMockPid, "large1g.exe", root << 12U, false}});
        const auto result = mapper.Query(target, {});
        KDBG_CHECK(runner, result.Ok());
        if (result && !result.Value().mappings.empty()) {
            const auto& usage = result.Value().mappings.front();
            KDBG_CHECK(runner, usage.page_size == 0x40000000U);
            const std::uint64_t raw =
                (0x1FFULL << 39U) | (6ULL << 30U) |
                ((target - base) << 12U);
            KDBG_CHECK(runner, usage.virtual_address ==
                CanonicalizeVirtualAddress(raw, false));
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, OpenWritable(backend));
        constexpr std::uint64_t root = 0x140U;
        constexpr std::uint64_t pdpt = 0x141U;
        constexpr std::uint64_t pd = 0x142U;
        constexpr std::uint64_t pt = 0x143U;
        constexpr std::uint64_t target = 0x144U;
        KDBG_CHECK(runner, ClearTable(backend, root));
        KDBG_CHECK(runner, ClearTable(backend, pdpt));
        KDBG_CHECK(runner, ClearTable(backend, pd));
        KDBG_CHECK(runner, ClearTable(backend, pt));
        KDBG_CHECK(runner, WriteEntry(
            backend, root, 0, (pdpt << 12U) | kPresent));
        KDBG_CHECK(runner, WriteEntry(
            backend, pdpt, 0, (pd << 12U) | kPresent));
        KDBG_CHECK(runner, WriteEntry(
            backend, pd, 0, (pt << 12U) | kPresent));
        KDBG_CHECK(runner, WriteEntry(
            backend, pt, 0, (target << 12U) | kPresent));
        KDBG_CHECK(runner, WriteEntry(
            backend, pt, 1, (target << 12U) | kPresent));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{8, 1, false, false});
        mapper.SetTargets({ProcessScanTarget{
            MockMemoryBackend::kMockPid, "limit.exe", root << 12U, false}});
        const auto result = mapper.Query(target, {});
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(runner, result.GetError().code == ErrorCode::LimitReached);
            KDBG_CHECK(runner, result.GetError().requested == 1U);
            KDBG_CHECK(runner, result.GetError().completed == 2U);
        }

        mapper.SetLimits(ReverseMapLimits{1, 4, false, false});
        const auto table_limited = mapper.Query(target, {});
        KDBG_CHECK(runner, !table_limited.Ok());
        if (!table_limited) {
            KDBG_CHECK(runner,
                table_limited.GetError().code == ErrorCode::LimitReached);
        }

        std::stop_source cancelled;
        cancelled.request_stop();
        const auto cancelled_result = mapper.Query(target, cancelled.get_token());
        KDBG_CHECK(runner, !cancelled_result.Ok());
        if (!cancelled_result) {
            KDBG_CHECK(runner,
                cancelled_result.GetError().code == ErrorCode::Cancelled);
        }

        backend.SetFaults(MockFaults{.short_read = true});
        mapper.SetLimits(ReverseMapLimits{8, 4, false, false});
        const auto short_read = mapper.Query(target, {});
        KDBG_CHECK(runner, !short_read.Ok());
        if (!short_read) {
            KDBG_CHECK(runner, short_read.GetError().code == ErrorCode::ShortRead);
        }
        mapper.SetLimits(ReverseMapLimits{8, 4, false, true});
        const auto skipped_short_read = mapper.Query(target, {});
        KDBG_CHECK(runner, skipped_short_read.Ok());
        if (skipped_short_read) {
            KDBG_CHECK(runner, skipped_short_read.Value().mappings.empty());
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, OpenWritable(backend));
        constexpr std::uint64_t root = 0x150U;
        KDBG_CHECK(runner, ClearTable(backend, root));
        KDBG_CHECK(runner, WriteEntry(
            backend, root, 0, (root << 12U) | kPresent));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{2, 2, true, false});
        mapper.SetTargets({ProcessScanTarget{
            MockMemoryBackend::kMockPid, "cycle.exe", root << 12U, false}});
        const auto root_result = mapper.Query(root, {});
        KDBG_CHECK(runner, root_result.Ok());
        if (root_result) {
            KDBG_CHECK(runner, root_result.Value().mappings.size() == 2U);
        }
    }

    {
        std::stop_source source;
        StopAfterReadBackend backend(source, 1);
        KDBG_CHECK(runner, backend.Open().Ok());
        KDBG_CHECK(runner, backend.SetWriteEnabled(true).Ok());
        constexpr std::uint64_t root = 0x160U;
        constexpr std::uint64_t child = 0x161U;
        KDBG_CHECK(runner, ClearTable(backend, root));
        KDBG_CHECK(runner, ClearTable(backend, child));
        KDBG_CHECK(runner, WriteEntry(
            backend, root, 0, (child << 12U) | kPresent));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{4, 2, false, false});
        mapper.SetTargets({ProcessScanTarget{
            MockMemoryBackend::kMockPid, "cancel.exe", root << 12U, false}});
        const auto result = mapper.Query(0x170U, source.get_token());
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(runner, result.GetError().code == ErrorCode::Cancelled);
        }
    }
}

}  // namespace

void RunPageTableTests(kdbg::test::TestRunner& runner) {
    using kdbg::CanonicalizeVirtualAddress;
    using kdbg::DecodePageEntry;
    using kdbg::LeafPhysicalAddress;
    using kdbg::PagingLevel;
    using kdbg::VirtualAddressIndices;

    constexpr std::uint64_t user_va = 0x00007FFF12345678ULL;
    const auto decoded = VirtualAddressIndices::Decode(user_va, false);
    KDBG_CHECK(runner, decoded.Ok());
    if (decoded) {
        KDBG_CHECK(runner, decoded.Value().pml4 == 0x0FFU);
        KDBG_CHECK(runner, decoded.Value().pdpt == 0x1FCU);
        KDBG_CHECK(runner, decoded.Value().pd == 0x091U);
        KDBG_CHECK(runner, decoded.Value().pt == 0x145U);
        KDBG_CHECK(runner, decoded.Value().offset == 0x678U);
    }

    KDBG_CHECK(runner,
        VirtualAddressIndices::Decode(0xFFFF800000001234ULL, false).Ok());
    KDBG_CHECK(runner,
        !VirtualAddressIndices::Decode(0x0000800000000000ULL, false).Ok());
    KDBG_CHECK(runner,
        VirtualAddressIndices::Decode(0x0000800000000000ULL, true).Ok());
    KDBG_CHECK(runner,
        VirtualAddressIndices::Decode(0x00FFFFFFFFFFFFFFULL, true).Ok());
    KDBG_CHECK(runner,
        VirtualAddressIndices::Decode(0xFF00000000000000ULL, true).Ok());
    KDBG_CHECK(runner,
        !VirtualAddressIndices::Decode(0x0100000000000000ULL, true).Ok());
    KDBG_CHECK(runner,
        CanonicalizeVirtualAddress(0x0000800000001234ULL, false) ==
            0xFFFF800000001234ULL);
    KDBG_CHECK(runner,
        CanonicalizeVirtualAddress(0x0100000000001234ULL, true) ==
            0xFF00000000001234ULL);

    constexpr std::uint64_t pfn = 0x12345ULL;
    const std::uint64_t entry =
        (pfn << 12U) | kPresent | kWritable | kUser |
        (1ULL << 3U) | (1ULL << 4U) | (1ULL << 5U) |
        (1ULL << 6U) | kPageSize | (1ULL << 8U) |
        (0xAULL << 59U) | kNx;
    const auto flags = DecodePageEntry(entry);
    KDBG_CHECK(runner, flags.present);
    KDBG_CHECK(runner, flags.writable);
    KDBG_CHECK(runner, flags.user);
    KDBG_CHECK(runner, flags.write_through);
    KDBG_CHECK(runner, flags.cache_disable);
    KDBG_CHECK(runner, flags.accessed);
    KDBG_CHECK(runner, flags.dirty);
    KDBG_CHECK(runner, flags.page_size);
    KDBG_CHECK(runner, flags.global);
    KDBG_CHECK(runner, flags.no_execute);
    KDBG_CHECK(runner, flags.protection_key == 0xAU);
    KDBG_CHECK(runner, flags.pfn == pfn);

    const auto pa4k = LeafPhysicalAddress(
        PagingLevel::Pt,
        (0xABCDEULL << 12U) | 1ULL,
        0x123456789ABCULL);
    KDBG_CHECK(runner, pa4k.Ok());
    if (pa4k) KDBG_CHECK(runner, pa4k.Value() == 0xABCDEABCULL);

    const auto pa2m = LeafPhysicalAddress(
        PagingLevel::Pd,
        0x0000000123400000ULL | kPageSize | kPresent,
        0x00000000001ABCDEULL);
    KDBG_CHECK(runner, pa2m.Ok());
    if (pa2m) {
        KDBG_CHECK(runner, pa2m.Value() ==
            ((0x0000000123400000ULL & 0x000FFFFFFFE00000ULL) |
             (0x00000000001ABCDEULL & 0x1FFFFFULL)));
    }

    const auto pa1g = LeafPhysicalAddress(
        PagingLevel::Pdpt,
        0x0000000180000000ULL | kPageSize | kPresent,
        0x000000003ABCDEF0ULL);
    KDBG_CHECK(runner, pa1g.Ok());
    if (pa1g) {
        KDBG_CHECK(runner, pa1g.Value() ==
            ((0x0000000180000000ULL & 0x000FFFFFC0000000ULL) |
             (0x000000003ABCDEF0ULL & 0x3FFFFFFFULL)));
    }

    KDBG_CHECK(runner, !LeafPhysicalAddress(
        PagingLevel::Pd, 0x0000000123400000ULL | kPresent, 0).Ok());
    KDBG_CHECK(runner, !LeafPhysicalAddress(
        PagingLevel::Pdpt, 0x0000000180000000ULL | kPageSize, 0).Ok());
    KDBG_CHECK(runner,
        !LeafPhysicalAddress(PagingLevel::Pml4, kPresent, 0).Ok());

    RunProtocolTests(runner);
    RunReverseMapTests(runner);
}

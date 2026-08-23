#include "TestHarness.h"

#include "core/process/MockProcessMemory.h"
#include "core/scanner/MemoryScanner.h"
#include "core/scanner/PointerScanner.h"
#include "core/scanner/ValueCodec.h"
#include "core/scanner/WatchList.h"
#include "core/snapshot/MemorySnapshot.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

template <typename T>
void Store(kdbg::MockProcessMemory& memory, std::size_t offset, T value) {
    std::memcpy(memory.Bytes().data() + offset, &value, sizeof(value));
}

template <typename T>
std::array<std::uint8_t, sizeof(T)> ScalarBytes(T value) {
    std::array<std::uint8_t, sizeof(T)> bytes{};
    std::memcpy(bytes.data(), &value, sizeof(value));
    return bytes;
}

class FaultingProcessMemory final : public kdbg::IProcessMemory {
public:
    enum class Mode {
        None,
        ShortFirst,
        FailSecond,
    };

    FaultingProcessMemory(std::uint64_t base, std::size_t size, Mode mode)
        : memory_(base, size, 8), mode_(mode) {}

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
        return memory_.SetWritesArmed(armed);
    }
    kdbg::Result<std::vector<std::uint8_t>> Read(
        std::uint64_t address,
        std::uint32_t length) override {
        const auto call = read_calls_++;
        if (mode_ == Mode::FailSecond && call == 1U) {
            return kdbg::Result<std::vector<std::uint8_t>>::Failure(
                kdbg::MakeError(
                    kdbg::ErrorCode::IoFailure,
                    "Injected unread chunk",
                    "FaultingProcessMemory::Read"));
        }
        auto result = memory_.Read(address, length);
        if (result && mode_ == Mode::ShortFirst && call == 0U &&
            !result.Value().empty()) {
            result.Value().resize(result.Value().size() / 2U);
        }
        return result;
    }
    kdbg::Result<std::uint32_t> Write(
        std::uint64_t address,
        std::span<const std::uint8_t> data) override {
        return memory_.Write(address, data);
    }
    kdbg::Result<std::vector<kdbg::MemoryRegion>> Regions() override {
        return memory_.Regions();
    }
    kdbg::Result<std::vector<kdbg::ProcessModule>> Modules() override {
        return memory_.Modules();
    }

    std::vector<std::uint8_t>& Bytes() noexcept { return memory_.Bytes(); }
    void SetMode(Mode mode) noexcept {
        mode_ = mode;
        read_calls_ = 0;
    }

private:
    kdbg::MockProcessMemory memory_;
    Mode mode_{Mode::None};
    std::size_t read_calls_{0};
};

}  // namespace

void RunScannerTests(kdbg::test::TestRunner& runner) {
    using namespace kdbg;

    MockProcessMemory memory(0x10000000, 0x10000, 8);
    Store<std::int32_t>(memory, 0x100, 1337);
    Store<std::int32_t>(memory, 0x200, 1337);
    Store<std::int32_t>(memory, 0x300, -5);

    MemoryScanner scanner(memory);
    ScanQuery exact{};
    exact.type = ScanValueType::Int32;
    exact.comparison = ScanCompare::Exact;
    exact.value = "1337";
    exact.max_results = 100;
    const auto first = scanner.FirstScan(exact);
    KDBG_CHECK(runner, first.Ok());
    KDBG_CHECK(runner, first.Value().result_count == 2U);
    KDBG_CHECK(runner, scanner.Candidates()[0].address == memory.Base() + 0x100);

    Store<std::int32_t>(memory, 0x200, 1400);
    ScanQuery changed = exact;
    changed.comparison = ScanCompare::Changed;
    changed.value.clear();
    const auto next = scanner.NextScan(changed);
    KDBG_CHECK(runner, next.Ok());
    KDBG_CHECK(runner, next.Value().result_count == 1U);
    KDBG_CHECK(runner, scanner.Candidates()[0].address == memory.Base() + 0x200);

    scanner.Reset();
    ScanQuery unknown{};
    unknown.type = ScanValueType::Int32;
    unknown.comparison = ScanCompare::UnknownInitial;
    unknown.max_results = 20000;
    const auto all = scanner.FirstScan(unknown);
    KDBG_CHECK(runner, all.Ok());
    KDBG_CHECK(runner, all.Value().result_count == 0x10000U / 4U);

    Store<std::int32_t>(memory, 0x300, 123);
    ScanQuery increased = unknown;
    increased.comparison = ScanCompare::Increased;
    const auto increased_result = scanner.NextScan(increased);
    KDBG_CHECK(runner, increased_result.Ok());
    KDBG_CHECK(runner, std::any_of(
        scanner.Candidates().begin(), scanner.Candidates().end(),
        [&](const ScanCandidate& candidate) {
            return candidate.address == memory.Base() + 0x300;
        }));

    memory.Bytes()[0x700] = 0x48;
    memory.Bytes()[0x701] = 0x8B;
    memory.Bytes()[0x702] = 0xAA;
    memory.Bytes()[0x703] = 0xFF;
    ScanQuery aob{};
    aob.type = ScanValueType::ByteArray;
    aob.comparison = ScanCompare::Exact;
    aob.value = "48 8B ?? FF";
    aob.max_results = 10;
    const auto aob_result = scanner.FirstScan(aob);
    KDBG_CHECK(runner, aob_result.Ok());
    KDBG_CHECK(runner, aob_result.Value().result_count == 1U);
    KDBG_CHECK(runner, scanner.Candidates()[0].address == memory.Base() + 0x700);

    {
        const auto positive_overflow = EncodeValue(
            ScanValueType::Float,
            "3.5e38");
        KDBG_CHECK(runner, !positive_overflow.Ok());
        if (!positive_overflow) {
            KDBG_CHECK(runner, positive_overflow.GetError().code ==
                ErrorCode::ParseError);
        }
        const auto negative_overflow = EncodeValue(
            ScanValueType::Float,
            "-3.5e38");
        KDBG_CHECK(runner, !negative_overflow.Ok());
        const auto finite_float = EncodeValue(
            ScanValueType::Float,
            "3.4e38");
        KDBG_CHECK(runner, finite_float.Ok());
    }

    {
        ScanQuery increased_by{};
        increased_by.type = ScanValueType::UInt64;
        increased_by.comparison = ScanCompare::IncreasedBy;
        increased_by.value = "1";
        const auto unsigned_increased = CompileScanQuery(increased_by);
        KDBG_CHECK(runner, unsigned_increased.Ok());
        if (unsigned_increased) {
            const auto previous = ScalarBytes(
                std::numeric_limits<std::uint64_t>::max());
            const auto wrapped = ScalarBytes(std::uint64_t{0});
            KDBG_CHECK(runner, !MatchNextValue(
                unsigned_increased.Value(),
                previous,
                wrapped));
            const auto ordinary_previous = ScalarBytes(std::uint64_t{41});
            const auto ordinary_current = ScalarBytes(std::uint64_t{42});
            KDBG_CHECK(runner, MatchNextValue(
                unsigned_increased.Value(),
                ordinary_previous,
                ordinary_current));
        }

        ScanQuery unsigned_decreased_by = increased_by;
        unsigned_decreased_by.comparison = ScanCompare::DecreasedBy;
        const auto unsigned_decreased = CompileScanQuery(unsigned_decreased_by);
        KDBG_CHECK(runner, unsigned_decreased.Ok());
        if (unsigned_decreased) {
            const auto previous = ScalarBytes(std::uint64_t{0});
            const auto wrapped = ScalarBytes(
                std::numeric_limits<std::uint64_t>::max());
            KDBG_CHECK(runner, !MatchNextValue(
                unsigned_decreased.Value(),
                previous,
                wrapped));
        }

        ScanQuery signed_increased_by{};
        signed_increased_by.type = ScanValueType::Int64;
        signed_increased_by.comparison = ScanCompare::IncreasedBy;
        signed_increased_by.value = "1";
        const auto signed_increased = CompileScanQuery(signed_increased_by);
        KDBG_CHECK(runner, signed_increased.Ok());
        if (signed_increased) {
            const auto previous = ScalarBytes(
                std::numeric_limits<std::int64_t>::max());
            const auto wrapped = ScalarBytes(
                std::numeric_limits<std::int64_t>::lowest());
            KDBG_CHECK(runner, !MatchNextValue(
                signed_increased.Value(),
                previous,
                wrapped));
        }

        ScanQuery signed_decreased_by = signed_increased_by;
        signed_decreased_by.comparison = ScanCompare::DecreasedBy;
        const auto signed_decreased = CompileScanQuery(signed_decreased_by);
        KDBG_CHECK(runner, signed_decreased.Ok());
        if (signed_decreased) {
            const auto previous = ScalarBytes(
                std::numeric_limits<std::int64_t>::lowest());
            const auto wrapped = ScalarBytes(
                std::numeric_limits<std::int64_t>::max());
            KDBG_CHECK(runner, !MatchNextValue(
                signed_decreased.Value(),
                previous,
                wrapped));
        }
    }

    {
        constexpr std::size_t kTextCap = 1024U * 1024U;
        const auto utf8_too_large = EncodeValue(
            ScanValueType::Utf8,
            std::string(kTextCap + 1U, 'A'));
        KDBG_CHECK(runner, !utf8_too_large.Ok());
        if (!utf8_too_large) {
            KDBG_CHECK(runner, utf8_too_large.GetError().code ==
                ErrorCode::LimitReached);
        }
        const auto utf16_output_too_large = EncodeValue(
            ScanValueType::Utf16,
            std::string((kTextCap / 2U) + 1U, 'A'));
        KDBG_CHECK(runner, !utf16_output_too_large.Ok());
        if (!utf16_output_too_large) {
            KDBG_CHECK(runner, utf16_output_too_large.GetError().code ==
                ErrorCode::LimitReached);
        }

        std::string oversized_aob;
        oversized_aob.reserve((kMaxAobPatternBytes + 1U) * 3U);
        for (std::size_t index = 0;
             index <= kMaxAobPatternBytes;
             ++index) {
            oversized_aob += "AA ";
        }
        const auto aob_too_large = ParseAobPattern(oversized_aob);
        KDBG_CHECK(runner, !aob_too_large.Ok());
        if (!aob_too_large) {
            KDBG_CHECK(runner, aob_too_large.GetError().code ==
                ErrorCode::LimitReached);
        }
    }

    {
        const std::array<std::uint8_t, 1> input{0xAA};
        AobPattern missing_mask{};
        missing_mask.bytes = {0xAA};
        KDBG_CHECK(runner, !missing_mask.Matches(input));

        AobPattern oversized_mask{};
        oversized_mask.bytes = {0xAA};
        oversized_mask.exact = {true, false};
        KDBG_CHECK(runner, !oversized_mask.Matches(input));
    }

    {
        FaultingProcessMemory short_memory(
            0x20000000,
            8,
            FaultingProcessMemory::Mode::ShortFirst);
        short_memory.Bytes()[0] = 0xAA;
        short_memory.Bytes()[1] = 0xBB;
        short_memory.Bytes()[2] = 0xCC;
        short_memory.Bytes()[3] = 0xDD;
        MemoryScanner short_scanner(short_memory);
        ScanQuery short_query{};
        short_query.type = ScanValueType::ByteArray;
        short_query.comparison = ScanCompare::Exact;
        short_query.value = "AA BB CC DD";
        short_query.chunk_size = 4;
        short_query.max_results = 10;
        const auto short_result = short_scanner.FirstScan(short_query);
        KDBG_CHECK(runner, !short_result.Ok());
        if (!short_result) {
            KDBG_CHECK(runner, short_result.GetError().code ==
                ErrorCode::ShortRead);
        }
        KDBG_CHECK(runner, !short_scanner.HasScan());
    }

    {
        FaultingProcessMemory gap_memory(
            0x30000000,
            12,
            FaultingProcessMemory::Mode::FailSecond);
        gap_memory.Bytes()[2] = 0xAA;
        gap_memory.Bytes()[3] = 0xBB;
        gap_memory.Bytes()[8] = 0xCC;
        gap_memory.Bytes()[9] = 0xDD;
        MemoryScanner gap_scanner(gap_memory);
        ScanQuery gap_query{};
        gap_query.type = ScanValueType::ByteArray;
        gap_query.comparison = ScanCompare::Exact;
        gap_query.value = "AA BB CC DD";
        gap_query.chunk_size = 4;
        gap_query.max_results = 10;
        const auto gap_result = gap_scanner.FirstScan(gap_query);
        KDBG_CHECK(runner, gap_result.Ok());
        if (gap_result) {
            KDBG_CHECK(runner, gap_result.Value().result_count == 0U);
            KDBG_CHECK(runner, gap_result.Value().bytes_scanned == 8U);
        }
    }

    {
        FaultingProcessMemory next_memory(
            0x31000000,
            8,
            FaultingProcessMemory::Mode::None);
        const std::int32_t next_value = 4242;
        std::memcpy(
            next_memory.Bytes().data(),
            &next_value,
            sizeof(next_value));
        MemoryScanner next_scanner(next_memory);
        ScanQuery next_query{};
        next_query.type = ScanValueType::Int32;
        next_query.comparison = ScanCompare::Exact;
        next_query.value = "4242";
        next_query.chunk_size = 4;
        next_query.max_results = 10;
        KDBG_CHECK(runner, next_scanner.FirstScan(next_query).Ok());
        KDBG_CHECK(runner, next_scanner.Candidates().size() == 1U);
        const auto generation_before = next_scanner.Generation();
        next_memory.SetMode(FaultingProcessMemory::Mode::ShortFirst);
        const auto short_next = next_scanner.NextScan(next_query);
        KDBG_CHECK(runner, !short_next.Ok());
        if (!short_next) {
            KDBG_CHECK(runner, short_next.GetError().code ==
                ErrorCode::ShortRead);
        }
        KDBG_CHECK(runner, next_scanner.Candidates().size() == 1U);
        KDBG_CHECK(runner, next_scanner.Generation() == generation_before);
    }

    {
        ScanQuery excessive = exact;
        excessive.max_results = MemoryScanner::kMaxResults + 1U;
        KDBG_CHECK(runner, !scanner.FirstScan(excessive).Ok());
        excessive = exact;
        excessive.chunk_size = MemoryScanner::kMaxChunkBytes + 1U;
        KDBG_CHECK(runner, !scanner.FirstScan(excessive).Ok());
    }

    WatchList watches(memory);
    KDBG_CHECK(runner, memory.SetWritesArmed(true).Ok());
    const auto watch_id = watches.Add(
        memory.Base() + 0x100,
        ScanValueType::Int32,
        "score");
    KDBG_CHECK(runner, watch_id.Ok());
    Store<std::int32_t>(memory, 0x100, 42);
    const auto watch_conflict = watches.WriteValue(watch_id.Value(), "9001");
    KDBG_CHECK(runner, !watch_conflict.Ok());
    if (!watch_conflict) {
        KDBG_CHECK(runner, watch_conflict.GetError().code ==
            ErrorCode::ConcurrentModification);
    }
    KDBG_CHECK(runner, watches.Refresh().Ok());
    KDBG_CHECK(runner, watches.WriteValue(watch_id.Value(), "9001").Ok());
    KDBG_CHECK(runner, watches.SetFrozen(watch_id.Value(), true).Ok());
    Store<std::int32_t>(memory, 0x100, 1);
    KDBG_CHECK(runner, watches.FreezeTick().Ok());
    std::int32_t frozen = 0;
    std::memcpy(&frozen, memory.Bytes().data() + 0x100, sizeof(frozen));
    KDBG_CHECK(runner, frozen == 9001);

    const auto watch_path = std::filesystem::temp_directory_path() /
        "kdbg-watch-list-test.kdbgal";
    KDBG_CHECK(runner, watches.Save(watch_path).Ok());
    WatchList loaded_watches(memory);
    KDBG_CHECK(runner, loaded_watches.Load(watch_path).Ok());
    KDBG_CHECK(runner, loaded_watches.Entries().size() == 1U);
    if (!loaded_watches.Entries().empty()) {
        KDBG_CHECK(runner, loaded_watches.Entries().front().description == "score");
        KDBG_CHECK(runner, !loaded_watches.Entries().front().frozen);
        KDBG_CHECK(runner, !loaded_watches.Entries().front().last_error.empty());
    }

    {
        std::ofstream trailing(watch_path, std::ios::binary | std::ios::app);
        trailing.put('X');
    }
    WatchList trailing_watches(memory);
    KDBG_CHECK(runner, !trailing_watches.Load(watch_path).Ok());

    KDBG_CHECK(runner, watches.Save(watch_path).Ok());
    {
        std::fstream malformed(
            watch_path,
            std::ios::binary | std::ios::in | std::ios::out);
        const std::uint32_t unknown_flag = 4;
        malformed.seekp(44);
        malformed.write(
            reinterpret_cast<const char*>(&unknown_flag),
            sizeof(unknown_flag));
        KDBG_CHECK(runner, static_cast<bool>(malformed));
    }
    WatchList malformed_watches(memory);
    KDBG_CHECK(runner, !malformed_watches.Load(watch_path).Ok());
    std::error_code ignored_watch_remove;
    std::filesystem::remove(watch_path, ignored_watch_remove);

    const auto process_snapshot = MemorySnapshot::Capture(
        memory, memory.Base() + 0x100, 0x80, 0x20);
    KDBG_CHECK(runner, process_snapshot.Ok());
    if (process_snapshot) {
        KDBG_CHECK(runner, process_snapshot.Value().Space().pid == memory.ProcessId());
        KDBG_CHECK(runner, process_snapshot.Value().Address() == memory.Base() + 0x100);
        KDBG_CHECK(runner, process_snapshot.Value().Bytes().size() == 0x80U);
    }

    const std::uint64_t target = memory.Base() + 0x5000;
    const std::uint64_t level_one_pointer = target - 0x20;
    Store<std::uint64_t>(memory, 0x900, level_one_pointer);
    const std::uint64_t level_two_pointer = (memory.Base() + 0x900) - 0x10;
    Store<std::uint64_t>(memory, 0xA00, level_two_pointer);
    memory.SetModules({ProcessModule{
        memory.Base(), 0x1000, "mock.exe", "mock.exe"}});

    PointerScanner pointer_scanner(memory);
    PointerScanOptions pointer_options{};
    pointer_options.max_depth = 2;
    pointer_options.max_offset = 0x40;
    pointer_options.max_results = 100;
    const auto paths = pointer_scanner.Scan(target, pointer_options);
    KDBG_CHECK(runner, paths.Ok());
    KDBG_CHECK(runner, std::any_of(
        paths.Value().begin(), paths.Value().end(),
        [&](const PointerPath& path) {
            return path.root_address == memory.Base() + 0x900 &&
                path.offsets == std::vector<std::uint64_t>{0x20};
        }));
    KDBG_CHECK(runner, std::any_of(
        paths.Value().begin(), paths.Value().end(),
        [&](const PointerPath& path) {
            return path.root_address == memory.Base() + 0xA00 &&
                path.offsets == std::vector<std::uint64_t>{0x10, 0x20};
        }));

    {
        MockProcessMemory boundary_memory(0x40000000, 0x100, 8);
        const std::uint64_t boundary_target = boundary_memory.Base() + 0x80;
        Store<std::uint64_t>(boundary_memory, 6, boundary_target - 0x18);
        PointerScanner boundary_scanner(boundary_memory);
        PointerScanOptions options{};
        options.max_depth = 1;
        options.max_offset = 0x40;
        options.max_results = 10;
        options.chunk_size = 10;
        options.aligned_only = false;
        const auto boundary_paths = boundary_scanner.Scan(
            boundary_target,
            options);
        KDBG_CHECK(runner, boundary_paths.Ok());
        if (boundary_paths) {
            KDBG_CHECK(runner, std::any_of(
                boundary_paths.Value().begin(),
                boundary_paths.Value().end(),
                [&](const PointerPath& path) {
                    return path.root_address == boundary_memory.Base() + 6U &&
                        path.offsets == std::vector<std::uint64_t>{0x18};
                }));
        }
    }

    {
        MockProcessMemory aligned_memory(0x50000003, 0x100, 8);
        const std::uint64_t aligned_target = aligned_memory.Base() + 0x80;
        Store<std::uint64_t>(aligned_memory, 5, aligned_target - 0x20);
        PointerScanner aligned_scanner(aligned_memory);
        PointerScanOptions options{};
        options.max_depth = 1;
        options.max_offset = 0x40;
        options.max_results = 10;
        options.chunk_size = 16;
        options.aligned_only = true;
        const auto aligned_paths = aligned_scanner.Scan(aligned_target, options);
        KDBG_CHECK(runner, aligned_paths.Ok());
        if (aligned_paths) {
            KDBG_CHECK(runner, std::any_of(
                aligned_paths.Value().begin(),
                aligned_paths.Value().end(),
                [&](const PointerPath& path) {
                    return path.root_address == 0x50000008ULL;
                }));
        }
    }

    {
        MockProcessMemory branching_memory(0x60000000, 0x10000, 8);
        const std::uint64_t branching_target = branching_memory.Base() + 0x5000;
        Store<std::uint64_t>(
            branching_memory,
            0x1000,
            branching_target - 0x10);
        Store<std::uint64_t>(
            branching_memory,
            0x1100,
            branching_target - 0x20);
        Store<std::uint64_t>(
            branching_memory,
            0x800,
            branching_memory.Base() + 0x700);
        PointerScanner branching_scanner(branching_memory);
        PointerScanOptions options{};
        options.max_depth = 2;
        options.max_offset = 0x1000;
        options.max_results = 100;
        const auto branching_paths = branching_scanner.Scan(
            branching_target,
            options);
        KDBG_CHECK(runner, branching_paths.Ok());
        if (branching_paths) {
            KDBG_CHECK(runner, std::any_of(
                branching_paths.Value().begin(),
                branching_paths.Value().end(),
                [&](const PointerPath& path) {
                    return path.root_address == branching_memory.Base() + 0x800 &&
                        path.offsets ==
                            std::vector<std::uint64_t>{0x900, 0x10};
                }));
            KDBG_CHECK(runner, std::any_of(
                branching_paths.Value().begin(),
                branching_paths.Value().end(),
                [&](const PointerPath& path) {
                    return path.root_address == branching_memory.Base() + 0x800 &&
                        path.offsets ==
                            std::vector<std::uint64_t>{0xA00, 0x20};
                }));
        }
    }

    {
        PointerScanOptions invalid{};
        invalid.max_depth = PointerScanner::kMaxDepth + 1U;
        KDBG_CHECK(runner, !pointer_scanner.Scan(target, invalid).Ok());
        invalid = {};
        invalid.max_results = PointerScanner::kMaxResults + 1U;
        KDBG_CHECK(runner, !pointer_scanner.Scan(target, invalid).Ok());
        invalid = {};
        invalid.chunk_size = PointerScanner::kMaxChunkSize + 1U;
        KDBG_CHECK(runner, !pointer_scanner.Scan(target, invalid).Ok());
        invalid = {};
        invalid.chunk_size = 0;
        KDBG_CHECK(runner, !pointer_scanner.Scan(target, invalid).Ok());
    }

    {
        FaultingProcessMemory short_pointer_memory(
            0x70000000,
            12,
            FaultingProcessMemory::Mode::ShortFirst);
        const std::uint64_t short_pointer_target = 0x70010000;
        const std::uint64_t split_pointer = short_pointer_target - 0x20;
        std::memcpy(
            short_pointer_memory.Bytes().data(),
            &split_pointer,
            4);
        std::memcpy(
            short_pointer_memory.Bytes().data() + 8,
            reinterpret_cast<const std::uint8_t*>(&split_pointer) + 4,
            4);
        PointerScanner short_pointer_scanner(short_pointer_memory);
        PointerScanOptions options{};
        options.max_depth = 1;
        options.max_offset = 0x40;
        options.max_results = 10;
        options.chunk_size = 8;
        options.aligned_only = false;
        std::uint64_t last_progress = 0;
        const auto short_pointer_paths = short_pointer_scanner.Scan(
            short_pointer_target,
            options,
            [&](const ScanProgress& progress) {
                last_progress = progress.bytes_scanned;
            });
        KDBG_CHECK(runner, short_pointer_paths.Ok());
        if (short_pointer_paths) {
            KDBG_CHECK(runner, short_pointer_paths.Value().empty());
        }
        KDBG_CHECK(runner, last_progress == 8U);
    }
}

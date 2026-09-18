#include "TestHarness.h"

#include "app/ui/ProcessScannerState.h"
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
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace {

#pragma pack(push, 1)
struct LegacyWatchHeaderFixture {
    char magic[8];
    std::uint32_t version;
    std::uint32_t pid;
    std::uint64_t entry_count;
};

struct WatchEntryHeaderFixture {
    std::uint64_t address;
    std::uint32_t type;
    std::uint32_t flags;
    std::uint32_t description_size;
    std::uint32_t frozen_value_size;
};
#pragma pack(pop)

static_assert(sizeof(LegacyWatchHeaderFixture) == 24U);
static_assert(sizeof(WatchEntryHeaderFixture) == 24U);

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
        FailWideReads,
        FailAddress,
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
        if (!armed && disarm_failures_remaining_ != 0U) {
            --disarm_failures_remaining_;
            return kdbg::Result<void>::Failure(kdbg::MakeError(
                kdbg::ErrorCode::IoFailure,
                "Injected write-gate lock failure",
                "FaultingProcessMemory::SetWritesArmed"));
        }
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
        if (mode_ == Mode::FailWideReads && length > 1U) {
            return kdbg::Result<std::vector<std::uint8_t>>::Failure(
                kdbg::MakeError(
                    kdbg::ErrorCode::IoFailure,
                    "Injected wide-read failure",
                    "FaultingProcessMemory::Read"));
        }
        if (mode_ == Mode::FailAddress && address == fail_address_) {
            return kdbg::Result<std::vector<std::uint8_t>>::Failure(
                kdbg::MakeError(
                    kdbg::ErrorCode::AccessDenied,
                    "Injected unread candidate",
                    "FaultingProcessMemory::Read",
                    5,
                    length,
                    0));
        }
        auto result = memory_.Read(address, length);
        if (result && cancel_source_ != nullptr) {
            cancel_source_->request_stop();
            cancel_source_ = nullptr;
        }
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
    [[nodiscard]] std::size_t ReadCalls() const noexcept { return read_calls_; }
    void SetMode(Mode mode) noexcept {
        mode_ = mode;
        read_calls_ = 0;
    }
    void FailAt(std::uint64_t address) noexcept {
        fail_address_ = address;
        SetMode(Mode::FailAddress);
    }
    void CancelOnNextSuccessfulRead(std::stop_source& source) noexcept {
        cancel_source_ = &source;
    }
    void FailNextDisarmAttempts(std::size_t count) noexcept {
        disarm_failures_remaining_ = count;
    }

private:
    kdbg::MockProcessMemory memory_;
    Mode mode_{Mode::None};
    std::size_t read_calls_{0};
    std::uint64_t fail_address_{0};
    std::stop_source* cancel_source_{nullptr};
    std::size_t disarm_failures_remaining_{0};
};

}  // namespace

void RunScannerTests(kdbg::test::TestRunner& runner) {
    using namespace kdbg;

    {
        ScanReadReport complete_report{};
        complete_report.items_attempted = 2U;
        complete_report.items_completed = 2U;
        complete_report.requested_bytes = 8U;
        complete_report.completed_bytes = 8U;
        KDBG_CHECK(runner, ClassifyScanPublication(true, complete_report) ==
            ScanPublicationState::Complete);

        auto partial_report = complete_report;
        partial_report.short_reads = 1U;
        KDBG_CHECK(runner, ClassifyScanPublication(true, partial_report) ==
            ScanPublicationState::Partial);
        KDBG_CHECK(runner, ClassifyScanPublication(false, complete_report) ==
            ScanPublicationState::Failed);

        MockProcessMemory freeze_memory(0x0F000000, 64U, 8U);
        KDBG_CHECK(runner, freeze_memory.SetWritesArmed(true).Ok());
        std::vector<WatchEntry> frozen_entries(2U);
        frozen_entries[0].frozen = true;
        frozen_entries[0].frozen_value = {1U, 2U, 3U, 4U};
        frozen_entries[1].frozen = true;
        frozen_entries[1].frozen_value = {5U, 6U, 7U, 8U};
        KDBG_CHECK(runner, HasFrozenEntries(frozen_entries));
        const auto cleanup = FailCloseFreeze(freeze_memory, frozen_entries);
        KDBG_CHECK(runner, cleanup.gate_locked);
        KDBG_CHECK(runner, cleanup.disarmed_entries == 2U);
        KDBG_CHECK(runner, !cleanup.cleanup_error.has_value());
        KDBG_CHECK(runner, !freeze_memory.WritesArmed());
        KDBG_CHECK(runner, !HasFrozenEntries(frozen_entries));
        KDBG_CHECK(runner, std::all_of(
            frozen_entries.begin(), frozen_entries.end(),
            [](const WatchEntry& entry) {
                return entry.frozen_value.empty() && !entry.last_error.empty();
            }));

        FaultingProcessMemory retry_memory(
            0x0F100000, 64U, FaultingProcessMemory::Mode::None);
        KDBG_CHECK(runner, retry_memory.SetWritesArmed(true).Ok());
        retry_memory.FailNextDisarmAttempts(1U);
        frozen_entries[0].frozen = true;
        frozen_entries[0].frozen_value = {1U};
        const auto retry_cleanup = FailCloseFreeze(
            retry_memory, frozen_entries);
        KDBG_CHECK(runner, retry_cleanup.gate_locked);
        KDBG_CHECK(runner, retry_cleanup.cleanup_retry_used);
        KDBG_CHECK(runner, !retry_cleanup.cleanup_error.has_value());

        KDBG_CHECK(runner, retry_memory.SetWritesArmed(true).Ok());
        retry_memory.FailNextDisarmAttempts(2U);
        frozen_entries[0].frozen = true;
        frozen_entries[0].frozen_value = {1U};
        const auto failed_cleanup = FailCloseFreeze(
            retry_memory, frozen_entries);
        KDBG_CHECK(runner, !failed_cleanup.gate_locked);
        KDBG_CHECK(runner, failed_cleanup.cleanup_retry_used);
        KDBG_CHECK(runner, failed_cleanup.cleanup_error.has_value());
        KDBG_CHECK(runner, !HasFrozenEntries(frozen_entries));
    }

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
        constexpr std::array<ScanCompare, 7> kInvalidTextComparisons{
            ScanCompare::GreaterThan,
            ScanCompare::LessThan,
            ScanCompare::Between,
            ScanCompare::Increased,
            ScanCompare::Decreased,
            ScanCompare::IncreasedBy,
            ScanCompare::DecreasedBy};
        for (const auto type : {ScanValueType::Utf8, ScanValueType::Utf16}) {
            for (const auto comparison : kInvalidTextComparisons) {
                ScanQuery invalid_text{};
                invalid_text.type = type;
                invalid_text.comparison = comparison;
                invalid_text.value = "Alpha";
                invalid_text.second_value = "Omega";
                const auto rejected = CompileScanQuery(invalid_text);
                KDBG_CHECK(runner, !rejected.Ok());
                if (!rejected) {
                    KDBG_CHECK(runner, rejected.GetError().code ==
                        ErrorCode::InvalidArgument);
                }
            }
        }

        for (const auto type : {ScanValueType::Utf8, ScanValueType::Utf16}) {
            ScanQuery sensitive{};
            sensitive.type = type;
            sensitive.comparison = ScanCompare::Exact;
            sensitive.value = "AbC";
            sensitive.case_sensitive = true;
            const auto sensitive_query = CompileScanQuery(sensitive);
            const auto differently_cased = EncodeValue(type, "aBc");
            KDBG_CHECK(runner, sensitive_query.Ok());
            KDBG_CHECK(runner, differently_cased.Ok());
            if (sensitive_query && differently_cased) {
                KDBG_CHECK(runner, !MatchInitialValue(
                    sensitive_query.Value(), differently_cased.Value()));
            }

            sensitive.case_sensitive = false;
            const auto insensitive_query = CompileScanQuery(sensitive);
            KDBG_CHECK(runner, insensitive_query.Ok());
            if (insensitive_query && differently_cased) {
                KDBG_CHECK(runner, MatchInitialValue(
                    insensitive_query.Value(), differently_cased.Value()));
                KDBG_CHECK(runner, MatchNextValue(
                    insensitive_query.Value(),
                    insensitive_query.Value().first,
                    differently_cased.Value()));
            }

            MockProcessMemory text_memory(0x18000000, 32U, 8U);
            if (differently_cased) {
                std::copy(
                    differently_cased.Value().begin(),
                    differently_cased.Value().end(),
                    text_memory.Bytes().begin() + 8);
            }
            MemoryScanner text_scanner(text_memory);
            sensitive.case_sensitive = true;
            sensitive.max_results = 10U;
            const auto sensitive_scan = text_scanner.FirstScan(sensitive);
            KDBG_CHECK(runner, sensitive_scan.Ok());
            if (sensitive_scan) {
                KDBG_CHECK(runner, sensitive_scan.Value().result_count == 0U);
            }
            sensitive.case_sensitive = false;
            const auto insensitive_scan = text_scanner.FirstScan(sensitive);
            KDBG_CHECK(runner, insensitive_scan.Ok());
            if (insensitive_scan) {
                KDBG_CHECK(runner, insensitive_scan.Value().result_count == 1U);
                KDBG_CHECK(runner,
                    text_scanner.Candidates().front().address ==
                        text_memory.Base() + 8U);
            }
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
        const auto gap_report = gap_scanner.LastReadReport();
        KDBG_CHECK(runner, gap_report.partial);
        KDBG_CHECK(runner, gap_report.items_attempted == 3U);
        KDBG_CHECK(runner, gap_report.items_completed == 2U);
        KDBG_CHECK(runner, gap_report.items_skipped == 1U);
        KDBG_CHECK(runner, gap_report.failed_reads == 1U);
        KDBG_CHECK(runner, gap_report.requested_bytes == 12U);
        KDBG_CHECK(runner, gap_report.completed_bytes == 8U);
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
        KDBG_CHECK(runner, short_next.Ok());
        if (short_next) {
            KDBG_CHECK(runner, short_next.Value().result_count == 0U);
        }
        const auto short_report = next_scanner.LastReadReport();
        KDBG_CHECK(runner, short_report.partial);
        KDBG_CHECK(runner, short_report.items_attempted == 1U);
        KDBG_CHECK(runner, short_report.items_skipped == 1U);
        KDBG_CHECK(runner, short_report.short_reads == 1U);
        KDBG_CHECK(runner, short_report.first_error.code ==
            ErrorCode::ShortRead);
        KDBG_CHECK(runner, next_scanner.Candidates().empty());
        KDBG_CHECK(runner, next_scanner.Generation() == generation_before + 1U);
    }

    {
        FaultingProcessMemory partial_memory(
            0x31500000,
            64,
            FaultingProcessMemory::Mode::None);
        partial_memory.Bytes()[0] = 0x7F;
        partial_memory.Bytes()[32] = 0x7F;
        partial_memory.Bytes()[63] = 0x7F;
        MemoryScanner partial_scanner(partial_memory);
        ScanQuery partial_query{};
        partial_query.type = ScanValueType::UInt8;
        partial_query.comparison = ScanCompare::Exact;
        partial_query.value = "127";
        partial_query.chunk_size = 64U;
        partial_query.max_results = 10U;
        KDBG_CHECK(runner, partial_scanner.FirstScan(partial_query).Ok());
        KDBG_CHECK(runner, partial_scanner.Candidates().size() == 3U);
        partial_memory.FailAt(0x31500000ULL + 32U);
        partial_query.comparison = ScanCompare::Unchanged;
        bool callback_observed_partial = false;
        const auto partial_next = partial_scanner.NextScan(
            partial_query,
            [&](const ScanProgress&) {
                callback_observed_partial = callback_observed_partial ||
                    partial_scanner.LastReadReport().partial;
            });
        KDBG_CHECK(runner, partial_next.Ok());
        if (partial_next) {
            KDBG_CHECK(runner, partial_next.Value().result_count == 2U);
        }
        const auto report = partial_scanner.LastReadReport();
        KDBG_CHECK(runner, report.partial);
        KDBG_CHECK(runner, report.items_attempted == 3U);
        KDBG_CHECK(runner, report.items_completed == 2U);
        KDBG_CHECK(runner, report.items_skipped == 1U);
        KDBG_CHECK(runner, report.failed_reads == 1U);
        KDBG_CHECK(runner, report.short_reads == 0U);
        KDBG_CHECK(runner, report.first_error.code == ErrorCode::AccessDenied);
        KDBG_CHECK(runner, callback_observed_partial);
        KDBG_CHECK(runner, std::all_of(
            partial_scanner.Candidates().begin(),
            partial_scanner.Candidates().end(),
            [](const ScanCandidate& candidate) {
                return candidate.address != 0x31500020ULL;
            }));
    }

    {
        FaultingProcessMemory cancel_memory(
            0x31800000,
            64U * 1024U,
            FaultingProcessMemory::Mode::None);
        MemoryScanner cancel_scanner(cancel_memory);
        ScanQuery cancel_query{};
        cancel_query.type = ScanValueType::UInt8;
        cancel_query.comparison = ScanCompare::UnknownInitial;
        cancel_query.chunk_size = 64U * 1024U;
        cancel_query.max_results = 100000U;
        std::stop_source cancel_source;
        cancel_memory.CancelOnNextSuccessfulRead(cancel_source);
        const auto cancelled = cancel_scanner.FirstScan(
            cancel_query,
            {},
            cancel_source.get_token());
        KDBG_CHECK(runner, !cancelled.Ok());
        if (!cancelled) {
            KDBG_CHECK(runner, cancelled.GetError().code ==
                ErrorCode::Cancelled);
        }
        const auto cancel_report = cancel_scanner.LastReadReport();
        KDBG_CHECK(runner, cancel_report.cancelled);
        KDBG_CHECK(runner, cancel_report.partial);
        KDBG_CHECK(runner, cancel_report.items_attempted == 1U);
        KDBG_CHECK(runner, cancel_report.items_completed == 1U);
        KDBG_CHECK(runner, !cancel_scanner.HasScan());
    }

    {
        FaultingProcessMemory batched_memory(
            0x32000003,
            64,
            FaultingProcessMemory::Mode::None);
        const std::int32_t aligned_value = 0x12345678;
        std::memcpy(
            batched_memory.Bytes().data() + 1U,
            &aligned_value,
            sizeof(aligned_value));
        std::memcpy(
            batched_memory.Bytes().data() + 8U,
            &aligned_value,
            sizeof(aligned_value));
        MemoryScanner batched_scanner(batched_memory);
        ScanQuery batched_query{};
        batched_query.type = ScanValueType::Int32;
        batched_query.comparison = ScanCompare::Exact;
        batched_query.value = std::to_string(aligned_value);
        batched_query.alignment = 4U;
        batched_query.chunk_size = 16U;
        batched_query.max_results = 10U;
        const auto batched_first = batched_scanner.FirstScan(batched_query);
        KDBG_CHECK(runner, batched_first.Ok());
        if (batched_first) {
            KDBG_CHECK(runner, batched_first.Value().result_count == 1U);
            KDBG_CHECK(runner,
                batched_scanner.Candidates().front().address == 0x32000004ULL);
        }

        batched_scanner.Reset();
        ScanQuery bytes_query{};
        bytes_query.type = ScanValueType::UInt8;
        bytes_query.comparison = ScanCompare::UnknownInitial;
        bytes_query.alignment = 1U;
        bytes_query.chunk_size = 64U;
        bytes_query.max_results = 64U;
        KDBG_CHECK(runner, batched_scanner.FirstScan(bytes_query).Ok());
        batched_memory.SetMode(FaultingProcessMemory::Mode::None);
        ScanQuery unchanged_query = bytes_query;
        unchanged_query.comparison = ScanCompare::Unchanged;
        const auto batched_next = batched_scanner.NextScan(unchanged_query);
        KDBG_CHECK(runner, batched_next.Ok());
        if (batched_next) {
            KDBG_CHECK(runner, batched_next.Value().result_count == 64U);
            KDBG_CHECK(runner, batched_memory.ReadCalls() == 1U);
        }

        // A range read can cross an inaccessible hole even though each saved
        // candidate remains readable. The optimization must fall back to the
        // exact candidate reads without changing Next Scan semantics.
        batched_memory.SetMode(FaultingProcessMemory::Mode::FailWideReads);
        const auto fallback_next =
            batched_scanner.NextScan(unchanged_query);
        KDBG_CHECK(runner, fallback_next.Ok());
        if (fallback_next) {
            KDBG_CHECK(runner, fallback_next.Value().result_count == 64U);
            KDBG_CHECK(runner, batched_memory.ReadCalls() == 65U);
        }
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
    KDBG_CHECK(runner, memory.SetWritesArmed(true).Ok());
    KDBG_CHECK(runner, watches.WriteValue(watch_id.Value(), "9001").Ok());
    KDBG_CHECK(runner, memory.SetWritesArmed(true).Ok());
    KDBG_CHECK(runner, watches.SetFrozen(watch_id.Value(), true).Ok());
    Store<std::int32_t>(memory, 0x100, 1);
    KDBG_CHECK(runner, watches.FreezeTick().Ok());
    std::int32_t frozen = 0;
    std::memcpy(&frozen, memory.Bytes().data() + 0x100, sizeof(frozen));
    KDBG_CHECK(runner, frozen == 9001);

    const auto watch_path = test::UniqueTempPath(
        "kdbg-watch-list-test.kdbgal");
    KDBG_CHECK(runner, watches.Save(watch_path).Ok());
    WatchList loaded_watches(memory);
    KDBG_CHECK(runner, loaded_watches.Load(watch_path).Ok());
    KDBG_CHECK(runner, loaded_watches.Entries().size() == 1U);
    if (!loaded_watches.Entries().empty()) {
        KDBG_CHECK(runner, loaded_watches.Entries().front().description == "score");
        KDBG_CHECK(runner, !loaded_watches.Entries().front().frozen);
        KDBG_CHECK(runner,
            loaded_watches.Entries().front().frozen_value.empty());
        KDBG_CHECK(runner, !loaded_watches.Entries().front().last_error.empty());
    }
    Store<std::int32_t>(memory, 0x100, 1234);
    KDBG_CHECK(runner, loaded_watches.FreezeTick().Ok());
    std::int32_t load_disarmed_value = 0;
    std::memcpy(
        &load_disarmed_value,
        memory.Bytes().data() + 0x100,
        sizeof(load_disarmed_value));
    KDBG_CHECK(runner, load_disarmed_value == 1234);
    KDBG_CHECK(runner, loaded_watches.Load(watch_path).Ok());
    KDBG_CHECK(runner, loaded_watches.Entries().size() == 1U);
    KDBG_CHECK(runner, !loaded_watches.Entries().front().frozen);

    {
        std::ofstream trailing(watch_path, std::ios::binary | std::ios::app);
        trailing.put('X');
    }
    KDBG_CHECK(runner, !loaded_watches.Load(watch_path).Ok());
    KDBG_CHECK(runner, loaded_watches.Entries().size() == 1U);
    KDBG_CHECK(runner, !loaded_watches.Entries().front().frozen);
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

    const auto legacy_watch_path = test::UniqueTempPath(
        "kdbg-watch-list-v1.kdbgal");
    {
        LegacyWatchHeaderFixture header{};
        const std::array<char, 8> magic{
            'K', 'D', 'B', 'G', 'A', 'L', '\0', '\0'};
        std::copy(magic.begin(), magic.end(), header.magic);
        header.version = 1U;
        header.pid = memory.ProcessId();
        header.entry_count = 1U;
        const std::string description = "legacy score";
        WatchEntryHeaderFixture entry{};
        entry.address = memory.Base() + 0x100U;
        entry.type = static_cast<std::uint32_t>(ScanValueType::Int32);
        entry.flags = 3U;
        entry.description_size =
            static_cast<std::uint32_t>(description.size());
        entry.frozen_value_size = sizeof(std::int32_t);
        const auto legacy_frozen = ScalarBytes<std::int32_t>(9001);
        std::ofstream legacy(
            legacy_watch_path,
            std::ios::binary | std::ios::trunc);
        legacy.write(reinterpret_cast<const char*>(&header), sizeof(header));
        legacy.write(reinterpret_cast<const char*>(&entry), sizeof(entry));
        legacy.write(
            description.data(),
            static_cast<std::streamsize>(description.size()));
        legacy.write(
            reinterpret_cast<const char*>(legacy_frozen.data()),
            static_cast<std::streamsize>(legacy_frozen.size()));
        KDBG_CHECK(runner, static_cast<bool>(legacy));
    }
    WatchList legacy_watches(memory);
    KDBG_CHECK(runner, legacy_watches.Load(legacy_watch_path).Ok());
    KDBG_CHECK(runner, legacy_watches.Entries().size() == 1U);
    if (!legacy_watches.Entries().empty()) {
        const auto& legacy_entry = legacy_watches.Entries().front();
        KDBG_CHECK(runner, legacy_entry.id == 1U);
        KDBG_CHECK(runner, legacy_entry.description == "legacy score");
        KDBG_CHECK(runner, legacy_entry.hexadecimal);
        KDBG_CHECK(runner, !legacy_entry.frozen);
        KDBG_CHECK(runner, legacy_entry.frozen_value.empty());
        KDBG_CHECK(runner, !legacy_entry.last_error.empty());
    }
    KDBG_CHECK(runner, legacy_watches.Save(legacy_watch_path).Ok());
    {
        std::ifstream migrated(legacy_watch_path, std::ios::binary);
        migrated.seekg(8, std::ios::beg);
        std::uint32_t migrated_version = 0;
        migrated.read(
            reinterpret_cast<char*>(&migrated_version),
            sizeof(migrated_version));
        KDBG_CHECK(runner, static_cast<bool>(migrated));
        KDBG_CHECK(runner, migrated_version == 2U);
    }
    std::error_code ignored_watch_remove;
    std::filesystem::remove(watch_path, ignored_watch_remove);
    std::filesystem::remove(legacy_watch_path, ignored_watch_remove);

    const auto process_snapshot = MemorySnapshot::Capture(
        memory, memory.Base() + 0x100, 0x80, 0x20);
    KDBG_CHECK(runner, process_snapshot.Ok());
    if (process_snapshot) {
        KDBG_CHECK(runner, process_snapshot.Value().Space().pid == memory.ProcessId());
        KDBG_CHECK(runner, process_snapshot.Value().Address() == memory.Base() + 0x100);
        KDBG_CHECK(runner, process_snapshot.Value().Bytes().size() == 0x80U);
    }

    {
        MockProcessMemory crc_memory(0x39000000, 9U, 8U);
        constexpr std::array<std::uint8_t, 9> kCrcFixture{
            '1', '2', '3', '4', '5', '6', '7', '8', '9'};
        std::copy(
            kCrcFixture.begin(),
            kCrcFixture.end(),
            crc_memory.Bytes().begin());
        const auto crc_snapshot = MemorySnapshot::Capture(
            crc_memory,
            crc_memory.Base(),
            kCrcFixture.size(),
            4096U);
        KDBG_CHECK(runner, crc_snapshot.Ok());
        if (crc_snapshot) {
            KDBG_CHECK(runner,
                crc_snapshot.Value().Checksum() == 0xCBF43926U);
        }
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
        PointerScanOptions short_options{};
        short_options.max_depth = 1;
        short_options.max_offset = 0x40;
        short_options.max_results = 10;
        short_options.chunk_size = 8;
        short_options.aligned_only = false;
        std::uint64_t last_progress = 0;
        const auto short_pointer_paths = short_pointer_scanner.Scan(
            short_pointer_target,
            short_options,
            [&](const ScanProgress& progress) {
                last_progress = progress.bytes_scanned;
            });
        KDBG_CHECK(runner, short_pointer_paths.Ok());
        if (short_pointer_paths) {
            KDBG_CHECK(runner, short_pointer_paths.Value().empty());
        }
        KDBG_CHECK(runner, last_progress == 8U);
        const auto& short_report = short_pointer_scanner.LastReport();
        KDBG_CHECK(runner, short_report.partial);
        KDBG_CHECK(runner, short_report.short_reads == 1U);
        KDBG_CHECK(runner, short_report.failed_reads == 0U);
        KDBG_CHECK(runner, short_report.reads_attempted == 2U);
        KDBG_CHECK(runner, short_report.requested_bytes == 12U);
        KDBG_CHECK(runner, short_report.completed_bytes == 8U);
        KDBG_CHECK(runner,
            short_report.first_error.code == ErrorCode::ShortRead);
    }

    {
        FaultingProcessMemory failed_pointer_memory(
            0x71000000,
            24,
            FaultingProcessMemory::Mode::FailSecond);
        PointerScanner failed_pointer_scanner(failed_pointer_memory);
        PointerScanOptions failed_options{};
        failed_options.max_depth = 1;
        failed_options.max_offset = 0x40;
        failed_options.max_results = 10;
        failed_options.chunk_size = 8;
        const auto failed_pointer_paths =
            failed_pointer_scanner.Scan(0x71010000, failed_options);
        KDBG_CHECK(runner, failed_pointer_paths.Ok());
        const auto& failed_report = failed_pointer_scanner.LastReport();
        KDBG_CHECK(runner, failed_report.partial);
        KDBG_CHECK(runner, failed_report.failed_reads == 1U);
        KDBG_CHECK(runner, failed_report.short_reads == 0U);
        KDBG_CHECK(runner, failed_report.reads_attempted == 3U);
        KDBG_CHECK(runner,
            failed_report.first_error.code == ErrorCode::IoFailure);
    }

    {
        MockProcessMemory deep_memory(0x72000000, 0x400, 8);
        const auto deep_target = deep_memory.Base() + 0x300U;
        const auto intermediate = deep_memory.Base() + 0x200U;
        Store<std::uint64_t>(deep_memory, 0x200U, deep_target - 0x20U);
        Store<std::uint64_t>(deep_memory, 0x80U, intermediate - 0x10U);
        deep_memory.SetModules({ProcessModule{
            deep_memory.Base() + 0x80U,
            8U,
            "static-root",
            "mock"}});
        PointerScanner deep_scanner(deep_memory);
        PointerScanOptions options{};
        options.max_depth = 2;
        options.max_offset = 0x40;
        options.max_results = 1;
        options.chunk_size = 0x100;
        options.static_roots_only = true;
        const auto deep_paths = deep_scanner.Scan(deep_target, options);
        KDBG_CHECK(runner, deep_paths.Ok());
        if (deep_paths) {
            KDBG_CHECK(runner, deep_paths.Value().size() == 1U);
            if (!deep_paths.Value().empty()) {
                KDBG_CHECK(runner, deep_paths.Value().front().root_address ==
                    deep_memory.Base() + 0x80U);
                KDBG_CHECK(runner, deep_paths.Value().front().offsets ==
                    std::vector<std::uint64_t>({0x10U, 0x20U}));
            }
        }

        std::stop_source stopped;
        stopped.request_stop();
        const auto cancelled = deep_scanner.Scan(
            deep_target,
            options,
            {},
            stopped.get_token());
        KDBG_CHECK(runner, !cancelled.Ok());
        KDBG_CHECK(runner, deep_scanner.LastReport().cancelled);
        KDBG_CHECK(runner, deep_scanner.LastReport().partial);
    }
}

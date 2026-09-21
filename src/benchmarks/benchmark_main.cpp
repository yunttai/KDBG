#include "core/common/Error.h"
#include "core/memory/MockMemoryBackend.h"
#include "core/memory/PhysicalPageSession.h"
#include "core/pfn/PfnAddress.h"
#include "core/process/MockProcessMemory.h"
#include "core/scanner/MemoryScanner.h"
#include "core/scanner/PointerScanner.h"
#include "core/snapshot/MemorySnapshot.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <locale>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#elif defined(__unix__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

namespace {

using Clock = std::chrono::steady_clock;
using MetricValue = std::variant<bool, std::uint64_t, double, std::string>;

struct Metric {
    explicit Metric(std::string metric_name) : name(std::move(metric_name)) {}

    std::string name;
    bool pass{false};
    std::vector<std::pair<std::string, MetricValue>> values;

    template <typename T>
    void Add(std::string key, T value) {
        values.emplace_back(std::move(key), MetricValue(std::move(value)));
    }
};

constexpr std::size_t kMeasurementRepeats = 7U;
constexpr std::size_t kWarmupRepeats = 1U;
constexpr std::uint64_t kFixtureRevision = 2U;

constexpr std::string_view BuildConfiguration() noexcept {
#if defined(NDEBUG)
    return "release";
#else
    return "debug";
#endif
}

constexpr std::string_view CompilerFamily() noexcept {
#if defined(__clang__)
    return "clang";
#elif defined(_MSC_VER)
    return "msvc";
#elif defined(__GNUC__)
    return "gcc";
#else
    return "unknown";
#endif
}

double Milliseconds(Clock::duration duration) {
    return std::chrono::duration<double, std::milli>(duration).count();
}

double MebibytesPerSecond(std::uint64_t bytes, Clock::duration duration) {
    const double seconds = std::chrono::duration<double>(duration).count();
    if (seconds <= 0.0) {
        return 0.0;
    }
    return (static_cast<double>(bytes) / (1024.0 * 1024.0)) / seconds;
}

double Percentile(std::vector<double> samples, double percentile) {
    if (samples.empty()) {
        return 0.0;
    }
    std::sort(samples.begin(), samples.end());
    const double scaled = percentile * static_cast<double>(samples.size() - 1U);
    const auto lower = static_cast<std::size_t>(std::floor(scaled));
    const auto upper = static_cast<std::size_t>(std::ceil(scaled));
    const double fraction = scaled - static_cast<double>(lower);
    return samples[lower] + (samples[upper] - samples[lower]) * fraction;
}

std::optional<std::uint64_t> PeakResidentBytes() {
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS counters{};
    counters.cb = sizeof(counters);
    if (GetProcessMemoryInfo(
            GetCurrentProcess(),
            &counters,
            static_cast<DWORD>(sizeof(counters))) == FALSE) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(counters.PeakWorkingSetSize);
#elif defined(__unix__) || defined(__APPLE__)
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return std::nullopt;
    }
#if defined(__APPLE__)
    return static_cast<std::uint64_t>(usage.ru_maxrss);
#else
    return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024ULL;
#endif
#else
    return std::nullopt;
#endif
}

std::string JsonEscape(std::string_view text) {
    std::string escaped;
    escaped.reserve(text.size() + 8U);
    constexpr char kHex[] = "0123456789abcdef";
    for (const char source_character : text) {
        const auto character = static_cast<unsigned char>(source_character);
        switch (character) {
        case '\"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (character < 0x20U) {
                escaped += "\\u00";
                escaped.push_back(kHex[(character >> 4U) & 0xFU]);
                escaped.push_back(kHex[character & 0xFU]);
            } else {
                escaped.push_back(static_cast<char>(character));
            }
            break;
        }
    }
    return escaped;
}

void PrintJsonValue(const MetricValue& value) {
    std::visit([](const auto& item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, bool>) {
            std::cout << (item ? "true" : "false");
        } else if constexpr (std::is_same_v<T, std::string>) {
            std::cout << '\"' << JsonEscape(item) << '\"';
        } else {
            std::cout << item;
        }
    }, value);
}

std::string ErrorMessage(const kdbg::Error& error) {
    return error.operation + ": " + error.message;
}

template <typename T>
void Store(std::vector<std::uint8_t>& bytes, std::size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void FillDeterministic(std::vector<std::uint8_t>& bytes) {
    std::uint32_t state = 0xC001D00DU;
    for (auto& byte : bytes) {
        state ^= state << 13U;
        state ^= state >> 17U;
        state ^= state << 5U;
        byte = static_cast<std::uint8_t>(state & 0xFFU);
    }
}

Metric BenchmarkPhysicalTransaction() {
    Metric metric{"physical_4k_transaction"};
    constexpr std::size_t kIterations = 200U;

    kdbg::MockMemoryBackend backend;
    const auto opened = backend.Open();
    const auto address = kdbg::PfnAddress::FromPfn(
        kdbg::MockMemoryBackend::kBaseAddress >> 12U);
    if (!opened || !address) {
        metric.Add("error", !opened ? ErrorMessage(opened.GetError())
                                     : ErrorMessage(address.GetError()));
        return metric;
    }

    std::vector<double> samples;
    samples.reserve(kIterations);
    for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
        const auto started = Clock::now();
        auto session_storage = std::make_unique<kdbg::PhysicalPageSession>();
        auto& session = *session_storage;
        const auto loaded = session.Load(backend, address.Value());
        if (!loaded) {
            metric.Add("error", ErrorMessage(loaded.GetError()));
            return metric;
        }
        const std::size_t offset = iteration % kdbg::kPhysicalPageSize;
        const auto edited = session.EditByte(
            offset,
            static_cast<std::uint8_t>(session.Working()[offset] ^ 0x5AU));
        const auto unlocked = edited
            ? session.UnlockForOneApply(address.Value().pfn)
            : kdbg::Result<void>::Failure(edited.GetError());
        const auto applied = unlocked
            ? session.ApplyAndVerify(backend)
            : kdbg::Result<void>::Failure(unlocked.GetError());
        if (!applied) {
            metric.Add("error", ErrorMessage(applied.GetError()));
            return metric;
        }
        samples.push_back(Milliseconds(Clock::now() - started));
    }

    metric.pass = backend.WriteCallCount() == kIterations &&
        !backend.Info().write_enabled;
    metric.Add("iterations", static_cast<std::uint64_t>(kIterations));
    metric.Add("median_ms", Percentile(samples, 0.50));
    metric.Add("p95_ms", Percentile(samples, 0.95));
    metric.Add("max_ms", *std::max_element(samples.begin(), samples.end()));
    metric.Add("write_calls", backend.WriteCallCount());
    metric.Add("gate_closed", !backend.Info().write_enabled);
    return metric;
}

struct ScannerFixture {
    static constexpr std::size_t kSize = 32U * 1024U * 1024U;
    static constexpr std::int32_t kNeedle = 0x13572468;
    static constexpr std::size_t kStride = 4096U;

    kdbg::MockProcessMemory memory{0x10000000ULL, kSize, 8U};

    ScannerFixture() {
        FillDeterministic(memory.Bytes());
        for (std::size_t offset = 0; offset < kSize; offset += kStride) {
            Store(memory.Bytes(), offset, kNeedle);
        }
    }
};

class CountingProcessMemory final : public kdbg::IProcessMemory {
public:
    CountingProcessMemory(
        std::uint64_t base,
        std::size_t size,
        std::size_t pointer_size)
        : inner_(base, size, pointer_size) {}

    [[nodiscard]] std::uint32_t ProcessId() const noexcept override {
        return inner_.ProcessId();
    }
    [[nodiscard]] std::size_t PointerSize() const noexcept override {
        return inner_.PointerSize();
    }
    [[nodiscard]] bool IsOpen() const noexcept override { return inner_.IsOpen(); }
    [[nodiscard]] bool WritesArmed() const noexcept override {
        return inner_.WritesArmed();
    }
    kdbg::Result<void> SetWritesArmed(bool armed) override {
        return inner_.SetWritesArmed(armed);
    }
    kdbg::Result<std::vector<std::uint8_t>> Read(
        std::uint64_t address,
        std::uint32_t length) override {
        ++read_calls_;
        return inner_.Read(address, length);
    }
    kdbg::Result<std::uint32_t> Write(
        std::uint64_t address,
        std::span<const std::uint8_t> data) override {
        return inner_.Write(address, data);
    }
    kdbg::Result<std::vector<kdbg::MemoryRegion>> Regions() override {
        return inner_.Regions();
    }
    kdbg::Result<std::vector<kdbg::ProcessModule>> Modules() override {
        return inner_.Modules();
    }

    [[nodiscard]] std::uint64_t Base() const noexcept { return inner_.Base(); }
    [[nodiscard]] std::size_t ReadCalls() const noexcept { return read_calls_; }
    std::vector<std::uint8_t>& Bytes() noexcept { return inner_.Bytes(); }
    void ResetReadCalls() noexcept { read_calls_ = 0; }

private:
    kdbg::MockProcessMemory inner_;
    std::size_t read_calls_{0};
};

std::size_t CandidateStorageEstimate(const kdbg::MemoryScanner& scanner) {
    const auto& candidates = scanner.Candidates();
    std::size_t bytes = candidates.capacity() * sizeof(kdbg::ScanCandidate);
    for (const auto& candidate : candidates) {
        bytes += candidate.previous.capacity();
        bytes += candidate.current.capacity();
    }
    return bytes;
}

std::pair<Metric, Metric> BenchmarkScannerAndNextScan() {
    Metric first_metric{"scanner_first_scan"};
    Metric next_metric{"scanner_next_scan"};
    kdbg::ScanQuery query{};
    query.type = kdbg::ScanValueType::Int32;
    query.comparison = kdbg::ScanCompare::Exact;
    query.value = std::to_string(ScannerFixture::kNeedle);
    query.alignment = alignof(std::int32_t);
    query.chunk_size = 1024U * 1024U;
    query.max_results = (ScannerFixture::kSize / ScannerFixture::kStride) + 1024U;

    const auto expected = ScannerFixture::kSize / ScannerFixture::kStride;
    const auto before_rss = PeakResidentBytes();
    std::vector<double> first_elapsed_samples;
    std::vector<double> first_throughput_samples;
    std::vector<double> next_elapsed_samples;
    std::vector<double> next_candidate_rate_samples;
    first_elapsed_samples.reserve(kMeasurementRepeats);
    first_throughput_samples.reserve(kMeasurementRepeats);
    next_elapsed_samples.reserve(kMeasurementRepeats);
    next_candidate_rate_samples.reserve(kMeasurementRepeats);
    std::size_t storage_estimate = 0;
    bool correct = true;

    for (std::size_t repeat = 0;
         repeat < kWarmupRepeats + kMeasurementRepeats;
         ++repeat) {
        ScannerFixture fixture;
        kdbg::MemoryScanner scanner(fixture.memory);
        const auto first_started = Clock::now();
        const auto first = scanner.FirstScan(query);
        const auto first_elapsed = Clock::now() - first_started;
        if (!first) {
            first_metric.Add("error", ErrorMessage(first.GetError()));
            next_metric.Add("error", "first scan failed");
            return {std::move(first_metric), std::move(next_metric)};
        }
        correct = correct && first.Value().result_count == expected &&
            !first.Value().truncated;
        storage_estimate = std::max(
            storage_estimate,
            CandidateStorageEstimate(scanner));

        for (std::size_t offset = 0; offset < ScannerFixture::kSize;
             offset += ScannerFixture::kStride * 2U) {
            Store(fixture.memory.Bytes(), offset, ScannerFixture::kNeedle + 1);
        }
        kdbg::ScanQuery changed = query;
        changed.comparison = kdbg::ScanCompare::Changed;
        changed.value.clear();
        const auto next_started = Clock::now();
        const auto next = scanner.NextScan(changed);
        const auto next_elapsed = Clock::now() - next_started;
        if (!next) {
            next_metric.Add("error", ErrorMessage(next.GetError()));
            return {std::move(first_metric), std::move(next_metric)};
        }
        correct = correct && next.Value().result_count == expected / 2U;
        if (repeat >= kWarmupRepeats) {
            first_elapsed_samples.push_back(Milliseconds(first_elapsed));
            first_throughput_samples.push_back(MebibytesPerSecond(
                first.Value().bytes_scanned,
                first_elapsed));
            next_elapsed_samples.push_back(Milliseconds(next_elapsed));
            const auto next_seconds =
                std::chrono::duration<double>(next_elapsed).count();
            next_candidate_rate_samples.push_back(
                next_seconds > 0.0
                    ? static_cast<double>(expected) / next_seconds
                    : 0.0);
        }
    }
    const auto after_rss = PeakResidentBytes();

    first_metric.pass = correct;
    first_metric.Add("repeat_count", static_cast<std::uint64_t>(kMeasurementRepeats));
    first_metric.Add("warmup_count", static_cast<std::uint64_t>(kWarmupRepeats));
    first_metric.Add("bytes_scanned", static_cast<std::uint64_t>(ScannerFixture::kSize));
    first_metric.Add("result_count", static_cast<std::uint64_t>(
        expected));
    first_metric.Add("elapsed_median_ms", Percentile(first_elapsed_samples, 0.50));
    first_metric.Add("elapsed_p95_ms", Percentile(first_elapsed_samples, 0.95));
    first_metric.Add("throughput_median_mib_s", Percentile(
        first_throughput_samples, 0.50));
    first_metric.Add("throughput_p05_mib_s", Percentile(
        first_throughput_samples, 0.05));
    first_metric.Add("candidate_storage_estimate_bytes", static_cast<std::uint64_t>(
        storage_estimate));
    if (after_rss) {
        first_metric.Add("observed_peak_rss_bytes", *after_rss);
        const auto delta = before_rss && *after_rss > *before_rss
            ? *after_rss - *before_rss
            : 0ULL;
        first_metric.Add("observed_peak_rss_delta_bytes", delta);
    } else {
        first_metric.Add("observed_peak_rss", std::string("unavailable"));
    }

    next_metric.pass = correct;
    next_metric.Add("repeat_count", static_cast<std::uint64_t>(kMeasurementRepeats));
    next_metric.Add("warmup_count", static_cast<std::uint64_t>(kWarmupRepeats));
    next_metric.Add("input_candidates", static_cast<std::uint64_t>(expected));
    next_metric.Add("result_count", static_cast<std::uint64_t>(
        expected / 2U));
    next_metric.Add("elapsed_median_ms", Percentile(next_elapsed_samples, 0.50));
    next_metric.Add("elapsed_p95_ms", Percentile(next_elapsed_samples, 0.95));
    next_metric.Add("candidates_per_second_median", Percentile(
        next_candidate_rate_samples, 0.50));
    next_metric.Add("candidates_per_second_p05", Percentile(
        next_candidate_rate_samples, 0.05));
    return {std::move(first_metric), std::move(next_metric)};
}

Metric BenchmarkDenseNextScan() {
    Metric metric{"scanner_dense_next_scan"};
    constexpr std::size_t kSize = 1024U * 1024U;
    constexpr std::size_t kWidth = sizeof(std::uint32_t);
    constexpr std::size_t kCandidates = kSize / kWidth;
    std::vector<double> elapsed_samples;
    std::vector<double> candidate_rate_samples;
    std::vector<double> read_call_samples;
    elapsed_samples.reserve(kMeasurementRepeats);
    candidate_rate_samples.reserve(kMeasurementRepeats);
    read_call_samples.reserve(kMeasurementRepeats);
    bool correct = true;

    kdbg::ScanQuery query{};
    query.type = kdbg::ScanValueType::UInt32;
    query.comparison = kdbg::ScanCompare::UnknownInitial;
    query.alignment = kWidth;
    query.chunk_size = kSize;
    query.max_results = kCandidates + 1U;

    for (std::size_t repeat = 0;
         repeat < kWarmupRepeats + kMeasurementRepeats;
         ++repeat) {
        CountingProcessMemory memory{0x18000000ULL, kSize, 8U};
        FillDeterministic(memory.Bytes());
        kdbg::MemoryScanner scanner(memory);
        const auto first = scanner.FirstScan(query);
        if (!first) {
            metric.Add("error", ErrorMessage(first.GetError()));
            return metric;
        }
        memory.ResetReadCalls();
        kdbg::ScanQuery unchanged = query;
        unchanged.comparison = kdbg::ScanCompare::Unchanged;
        const auto started = Clock::now();
        const auto next = scanner.NextScan(unchanged);
        const auto elapsed = Clock::now() - started;
        if (!next) {
            metric.Add("error", ErrorMessage(next.GetError()));
            return metric;
        }
        correct = correct && next.Value().result_count == kCandidates &&
            memory.ReadCalls() == 1U;
        if (repeat >= kWarmupRepeats) {
            elapsed_samples.push_back(Milliseconds(elapsed));
            const auto seconds = std::chrono::duration<double>(elapsed).count();
            candidate_rate_samples.push_back(
                seconds > 0.0
                    ? static_cast<double>(kCandidates) / seconds
                    : 0.0);
            read_call_samples.push_back(static_cast<double>(memory.ReadCalls()));
        }
    }

    metric.pass = correct;
    metric.Add("repeat_count", static_cast<std::uint64_t>(kMeasurementRepeats));
    metric.Add("warmup_count", static_cast<std::uint64_t>(kWarmupRepeats));
    metric.Add("input_candidates", static_cast<std::uint64_t>(kCandidates));
    metric.Add("result_count", static_cast<std::uint64_t>(kCandidates));
    metric.Add("candidate_bytes", static_cast<std::uint64_t>(kCandidates * kWidth));
    metric.Add("backend_read_calls_median", Percentile(read_call_samples, 0.50));
    metric.Add("elapsed_median_ms", Percentile(elapsed_samples, 0.50));
    metric.Add("elapsed_p95_ms", Percentile(elapsed_samples, 0.95));
    metric.Add("candidates_per_second_median", Percentile(
        candidate_rate_samples, 0.50));
    metric.Add("candidates_per_second_p05", Percentile(
        candidate_rate_samples, 0.05));
    return metric;
}

Metric BenchmarkPointerCap() {
    Metric metric{"pointer_scan_cap"};
    constexpr std::size_t kSize = 4U * 1024U * 1024U;
    constexpr std::size_t kCap = 32768U;

    kdbg::PointerScanOptions options{};
    options.max_depth = 2U;
    options.max_offset = 0x40U;
    options.max_results = kCap;
    options.chunk_size = 256U * 1024U;
    options.aligned_only = true;

    std::vector<double> elapsed_samples;
    std::vector<double> candidate_rate_samples;
    elapsed_samples.reserve(kMeasurementRepeats);
    candidate_rate_samples.reserve(kMeasurementRepeats);
    bool correct = true;
    for (std::size_t repeat = 0;
         repeat < kWarmupRepeats + kMeasurementRepeats;
         ++repeat) {
        kdbg::MockProcessMemory memory{0x20000000ULL, kSize, 8U};
        FillDeterministic(memory.Bytes());
        const std::uint64_t target = memory.Base() + kSize - 0x1000U;
        for (std::size_t offset = 0; offset + sizeof(target) <= kSize;
             offset += sizeof(target)) {
            Store(memory.Bytes(), offset, target);
        }
        kdbg::PointerScanner scanner(memory);
        const auto started = Clock::now();
        const auto result = scanner.Scan(target, options);
        const auto elapsed = Clock::now() - started;
        if (!result) {
            metric.Add("error", ErrorMessage(result.GetError()));
            return metric;
        }
        correct = correct && result.Value().size() == kCap;
        if (repeat >= kWarmupRepeats) {
            elapsed_samples.push_back(Milliseconds(elapsed));
            const auto seconds = std::chrono::duration<double>(elapsed).count();
            candidate_rate_samples.push_back(
                seconds > 0.0
                    ? static_cast<double>(result.Value().size()) / seconds
                    : 0.0);
        }
    }
    metric.pass = correct;
    metric.Add("repeat_count", static_cast<std::uint64_t>(kMeasurementRepeats));
    metric.Add("warmup_count", static_cast<std::uint64_t>(kWarmupRepeats));
    metric.Add("configured_cap", static_cast<std::uint64_t>(kCap));
    metric.Add("result_count", static_cast<std::uint64_t>(kCap));
    metric.Add("cap_honored", correct);
    metric.Add("elapsed_median_ms", Percentile(elapsed_samples, 0.50));
    metric.Add("elapsed_p95_ms", Percentile(elapsed_samples, 0.95));
    metric.Add("candidates_per_second_median", Percentile(
        candidate_rate_samples, 0.50));
    metric.Add("candidates_per_second_p05", Percentile(
        candidate_rate_samples, 0.05));
    return metric;
}

std::filesystem::path TemporarySnapshotPath() {
    const auto stamp = static_cast<std::uint64_t>(
        Clock::now().time_since_epoch().count());
    return std::filesystem::temp_directory_path() /
        ("kdbg-benchmark-" + std::to_string(stamp) + ".kdbgmem");
}

Metric BenchmarkSnapshot() {
    Metric metric{"snapshot_io"};
    constexpr std::size_t kSize = 16U * 1024U * 1024U;
    std::vector<double> capture_elapsed_samples;
    std::vector<double> save_elapsed_samples;
    std::vector<double> load_elapsed_samples;
    std::vector<double> capture_throughput_samples;
    std::vector<double> save_throughput_samples;
    std::vector<double> load_throughput_samples;
    bool integrity = true;
    bool files_removed = true;
    for (std::size_t repeat = 0;
         repeat < kWarmupRepeats + kMeasurementRepeats;
         ++repeat) {
        kdbg::MockProcessMemory memory{0x30000000ULL, kSize, 8U};
        FillDeterministic(memory.Bytes());
        const auto capture_started = Clock::now();
        const auto captured = kdbg::MemorySnapshot::Capture(
            memory, memory.Base(), kSize, 1024U * 1024U);
        const auto capture_elapsed = Clock::now() - capture_started;
        if (!captured) {
            metric.Add("error", ErrorMessage(captured.GetError()));
            return metric;
        }

        const auto path = TemporarySnapshotPath();
        const auto save_started = Clock::now();
        const auto saved = captured.Value().Save(path);
        const auto save_elapsed = Clock::now() - save_started;
        if (!saved) {
            metric.Add("error", ErrorMessage(saved.GetError()));
            return metric;
        }

        const auto load_started = Clock::now();
        const auto loaded = kdbg::MemorySnapshot::Load(path);
        const auto load_elapsed = Clock::now() - load_started;
        std::error_code remove_error;
        const bool removed = std::filesystem::remove(path, remove_error);
        files_removed = files_removed && removed && !remove_error;
        if (!loaded) {
            metric.Add("error", ErrorMessage(loaded.GetError()));
            metric.Add("temporary_file_removed", removed && !remove_error);
            return metric;
        }
        integrity = integrity && loaded.Value().Bytes().size() == kSize &&
            loaded.Value().Checksum() == captured.Value().Checksum() &&
            loaded.Value().Bytes() == captured.Value().Bytes();
        if (repeat >= kWarmupRepeats) {
            capture_elapsed_samples.push_back(Milliseconds(capture_elapsed));
            save_elapsed_samples.push_back(Milliseconds(save_elapsed));
            load_elapsed_samples.push_back(Milliseconds(load_elapsed));
            capture_throughput_samples.push_back(MebibytesPerSecond(
                kSize, capture_elapsed));
            save_throughput_samples.push_back(MebibytesPerSecond(
                kSize, save_elapsed));
            load_throughput_samples.push_back(MebibytesPerSecond(
                kSize, load_elapsed));
        }
    }

    metric.pass = integrity && files_removed;
    metric.Add("repeat_count", static_cast<std::uint64_t>(kMeasurementRepeats));
    metric.Add("warmup_count", static_cast<std::uint64_t>(kWarmupRepeats));
    metric.Add("bytes", static_cast<std::uint64_t>(kSize));
    metric.Add("capture_median_ms", Percentile(capture_elapsed_samples, 0.50));
    metric.Add("capture_p95_ms", Percentile(capture_elapsed_samples, 0.95));
    metric.Add("capture_median_mib_s", Percentile(capture_throughput_samples, 0.50));
    metric.Add("save_median_ms", Percentile(save_elapsed_samples, 0.50));
    metric.Add("save_p95_ms", Percentile(save_elapsed_samples, 0.95));
    metric.Add("save_median_mib_s", Percentile(save_throughput_samples, 0.50));
    metric.Add("load_median_ms", Percentile(load_elapsed_samples, 0.50));
    metric.Add("load_p95_ms", Percentile(load_elapsed_samples, 0.95));
    metric.Add("load_median_mib_s", Percentile(load_throughput_samples, 0.50));
    metric.Add("integrity_verified", integrity);
    metric.Add("temporary_files_removed", files_removed);
    return metric;
}

class SlowProcessMemory final : public kdbg::IProcessMemory {
public:
    explicit SlowProcessMemory(std::chrono::milliseconds delay)
        : inner_(0x40000000ULL, 64U * 1024U * 1024U, 8U), delay_(delay) {
        FillDeterministic(inner_.Bytes());
    }

    [[nodiscard]] std::uint32_t ProcessId() const noexcept override {
        return inner_.ProcessId();
    }
    [[nodiscard]] std::size_t PointerSize() const noexcept override {
        return inner_.PointerSize();
    }
    [[nodiscard]] bool IsOpen() const noexcept override { return inner_.IsOpen(); }
    [[nodiscard]] bool WritesArmed() const noexcept override {
        return inner_.WritesArmed();
    }
    kdbg::Result<void> SetWritesArmed(bool armed) override {
        return inner_.SetWritesArmed(armed);
    }
    kdbg::Result<std::vector<std::uint8_t>> Read(
        std::uint64_t address,
        std::uint32_t length) override {
        std::this_thread::sleep_for(delay_);
        return inner_.Read(address, length);
    }
    kdbg::Result<std::uint32_t> Write(
        std::uint64_t address,
        std::span<const std::uint8_t> data) override {
        return inner_.Write(address, data);
    }
    kdbg::Result<std::vector<kdbg::MemoryRegion>> Regions() override {
        return inner_.Regions();
    }
    kdbg::Result<std::vector<kdbg::ProcessModule>> Modules() override {
        return inner_.Modules();
    }

private:
    kdbg::MockProcessMemory inner_;
    std::chrono::milliseconds delay_;
};

Metric BenchmarkCancellation() {
    Metric metric{"async_cancellation"};
    SlowProcessMemory memory(std::chrono::milliseconds(2));
    kdbg::ScanQuery query{};
    query.type = kdbg::ScanValueType::Int32;
    query.comparison = kdbg::ScanCompare::Exact;
    query.value = "2147483647";
    query.alignment = 4U;
    query.chunk_size = 4096U;
    query.max_results = 1000U;

    std::vector<double> cancellation_samples;
    std::vector<double> worker_samples;
    cancellation_samples.reserve(kMeasurementRepeats);
    worker_samples.reserve(kMeasurementRepeats);
    bool cancelled = true;
    for (std::size_t repeat = 0;
         repeat < kWarmupRepeats + kMeasurementRepeats;
         ++repeat) {
        kdbg::MemoryScanner scanner(memory);
        std::optional<kdbg::Result<kdbg::ScanSummary>> result;
        const auto worker_started = Clock::now();
        std::jthread worker([&](std::stop_token token) {
            result.emplace(scanner.FirstScan(query, {}, token));
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        const auto cancellation_requested = Clock::now();
        worker.request_stop();
        worker.join();
        const auto completed = Clock::now();
        cancelled = cancelled && result.has_value() && !result->Ok() &&
            result->GetError().code == kdbg::ErrorCode::Cancelled;
        if (repeat >= kWarmupRepeats) {
            cancellation_samples.push_back(Milliseconds(
                completed - cancellation_requested));
            worker_samples.push_back(Milliseconds(completed - worker_started));
        }
    }
    metric.pass = cancelled;
    metric.Add("repeat_count", static_cast<std::uint64_t>(kMeasurementRepeats));
    metric.Add("warmup_count", static_cast<std::uint64_t>(kWarmupRepeats));
    metric.Add("cancelled", cancelled);
    metric.Add("request_to_completion_median_ms", Percentile(
        cancellation_samples, 0.50));
    metric.Add("request_to_completion_p95_ms", Percentile(
        cancellation_samples, 0.95));
    metric.Add("worker_total_median_ms", Percentile(worker_samples, 0.50));
    metric.Add("worker_total_p95_ms", Percentile(worker_samples, 0.95));
    return metric;
}

void PrintReport(const std::vector<Metric>& metrics, bool overall_pass) {
    std::cout.imbue(std::locale::classic());
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "{\n"
              << "  \"schema_version\": 2,\n"
              << "  \"mode\": \"mock_only\",\n"
              << "  \"live_driver_access\": false,\n"
              << "  \"timing_represents_product_runtime\": false,\n"
              << "  \"environment_contract\": {\n"
              << "    \"build_configuration\": \"" << BuildConfiguration() << "\",\n"
              << "    \"compiler_family\": \"" << CompilerFamily() << "\",\n"
              << "    \"process_pointer_bits\": " << (sizeof(void*) * 8U) << ",\n"
              << "    \"hardware_threads\": " << std::thread::hardware_concurrency() << ",\n"
              << "    \"fixture_revision\": " << kFixtureRevision << "\n"
              << "  },\n"
              << "  \"measurement_contract\": {\n"
              << "    \"repeat_count\": " << kMeasurementRepeats << ",\n"
              << "    \"warmup_count\": " << kWarmupRepeats << ",\n"
              << "    \"summaries\": [\"median\", \"p95\"],\n"
              << "    \"timing_pass_thresholds_applied\": false,\n"
              << "    \"regression_basis\": \"relative before/after only on the same machine, power mode, compiler, configuration, and fixture\",\n"
              << "    \"absolute_timing_claims_allowed\": false\n"
              << "  },\n"
              << "  \"metrics\": [\n";
    for (std::size_t index = 0; index < metrics.size(); ++index) {
        const auto& metric = metrics[index];
        std::cout << "    {\"name\": \"" << JsonEscape(metric.name)
                  << "\", \"pass\": " << (metric.pass ? "true" : "false");
        for (const auto& [key, value] : metric.values) {
            std::cout << ", \"" << JsonEscape(key) << "\": ";
            PrintJsonValue(value);
        }
        std::cout << '}';
        if (index + 1U != metrics.size()) {
            std::cout << ',';
        }
        std::cout << '\n';
    }
    std::cout << "  ],\n"
              << "  \"pass_scope\": \"correctness, bounds, integrity, and cancellation only\",\n"
              << "  \"overall_pass\": " << (overall_pass ? "true" : "false")
              << "\n}\n";
}

}  // namespace

int main() {
    std::vector<Metric> metrics;
    metrics.push_back(BenchmarkPhysicalTransaction());
    auto [scanner, next_scan] = BenchmarkScannerAndNextScan();
    metrics.push_back(std::move(scanner));
    metrics.push_back(std::move(next_scan));
    metrics.push_back(BenchmarkDenseNextScan());
    metrics.push_back(BenchmarkPointerCap());
    metrics.push_back(BenchmarkSnapshot());
    metrics.push_back(BenchmarkCancellation());

    const bool overall_pass = std::all_of(
        metrics.begin(), metrics.end(), [](const Metric& metric) {
            return metric.pass;
        });
    PrintReport(metrics, overall_pass);
    return overall_pass ? 0 : 1;
}

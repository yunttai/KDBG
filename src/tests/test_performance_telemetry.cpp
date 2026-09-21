#include "TestHarness.h"

#include "app/PerformanceTelemetry.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#if defined(_WIN32)
#include <Windows.h>
#endif

namespace {

#if defined(_WIN32)
std::string ReadText(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::in | std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

void WriteText(const std::filesystem::path& path, std::string_view text) {
    std::ofstream output(path, std::ios::out | std::ios::binary | std::ios::trunc);
    output << text;
}

std::size_t CountTemporarySiblings(const std::filesystem::path& output) {
    const auto prefix = output.filename().native() +
#if defined(_WIN32)
        std::wstring(L".tmp-");
#else
        std::string(".tmp-");
#endif
    std::size_t count = 0;
    std::error_code error;
    for (std::filesystem::directory_iterator iterator(
             output.parent_path(), error), end;
         !error && iterator != end;
         iterator.increment(error)) {
        if (iterator->path().filename().native().starts_with(prefix)) ++count;
    }
    return count;
}
#endif

}  // namespace

void RunPerformanceTelemetryTests(kdbg::test::TestRunner& runner) {
    using namespace std::chrono_literals;

    kdbg::PerformanceTelemetry invalid;
    KDBG_CHECK(runner, !invalid.Start({}));
    KDBG_CHECK(runner,
        invalid.LastStartStatus() ==
            kdbg::TelemetryStartStatus::InvalidConfiguration);

#if !defined(_WIN32)
    kdbg::PerformanceTelemetry unsupported;
    kdbg::PerformanceTelemetry::Config unsupported_config{};
    unsupported_config.output_path = "/tmp/kdbg-runtime-telemetry.json";
    KDBG_CHECK(runner, !unsupported.Start(unsupported_config));
    KDBG_CHECK(runner,
        unsupported.LastStartStatus() ==
            kdbg::TelemetryStartStatus::UnsupportedPlatform);
    return;
#else
    static_cast<void>(_wputenv_s(L"KDBG_RUNTIME_TELEMETRY", L""));
    kdbg::PerformanceTelemetry not_requested;
    KDBG_CHECK(runner, !not_requested.StartFromEnvironment());
    KDBG_CHECK(runner,
        not_requested.LastStartStatus() ==
            kdbg::TelemetryStartStatus::NotRequested);
    static_cast<void>(_wputenv_s(
        L"KDBG_RUNTIME_TELEMETRY", L"relative-telemetry.json"));
    kdbg::PerformanceTelemetry rejected_request;
    KDBG_CHECK(runner, !rejected_request.StartFromEnvironment());
    KDBG_CHECK(runner,
        rejected_request.LastStartStatus() ==
            kdbg::TelemetryStartStatus::PathNotAbsolute);
    static_cast<void>(_wputenv_s(L"KDBG_RUNTIME_TELEMETRY", L""));

    auto rejected_config = kdbg::PerformanceTelemetry::Config{};
    rejected_config.output_path = L"relative-telemetry.json";
    KDBG_CHECK(runner, !invalid.Start(rejected_config));
    KDBG_CHECK(runner,
        invalid.LastStartStatus() ==
            kdbg::TelemetryStartStatus::PathNotAbsolute);

    rejected_config.output_path = L"C:relative-telemetry.json";
    KDBG_CHECK(runner, !invalid.Start(rejected_config));
    KDBG_CHECK(runner,
        invalid.LastStartStatus() ==
            kdbg::TelemetryStartStatus::PathNotAbsolute);

    rejected_config.output_path = L"\\\\server\\share\\telemetry.json";
    KDBG_CHECK(runner, !invalid.Start(rejected_config));
    KDBG_CHECK(runner,
        invalid.LastStartStatus() ==
            kdbg::TelemetryStartStatus::PathNotLocalFixedDrive);

    rejected_config.output_path = L"\\\\?\\C:\\telemetry.json";
    KDBG_CHECK(runner, !invalid.Start(rejected_config));
    KDBG_CHECK(runner,
        invalid.LastStartStatus() ==
            kdbg::TelemetryStartStatus::PathNotLocalFixedDrive);

    rejected_config.output_path = L"\\\\.\\C:\\telemetry.json";
    KDBG_CHECK(runner, !invalid.Start(rejected_config));
    KDBG_CHECK(runner,
        invalid.LastStartStatus() ==
            kdbg::TelemetryStartStatus::PathNotLocalFixedDrive);

    const auto output = kdbg::test::UniqueTempPath(
        "kdbg-runtime-telemetry.json");
    std::error_code cleanup_error;
    std::filesystem::remove(output, cleanup_error);

    kdbg::PerformanceTelemetry telemetry;
    kdbg::PerformanceTelemetry::Config config{};
    config.output_path = output;
    config.frame_stall_threshold = 50ms;
    config.flush_interval = 24h;
    config.max_scan_records = 3;
    KDBG_CHECK(runner, telemetry.Start(config));
    KDBG_CHECK(runner, telemetry.Enabled());
    KDBG_CHECK(runner,
        telemetry.LastStartStatus() == kdbg::TelemetryStartStatus::Started);
    // Start cannot report success until an independently readable first
    // snapshot has been atomically installed at the requested destination.
    KDBG_CHECK(runner, std::filesystem::is_regular_file(output));
    KDBG_CHECK(runner,
        ReadText(output).find("\"schema\":\"kdbg.runtime-telemetry.v1\"") !=
            std::string::npos);

    telemetry.RecordFrameInterval(16ms);
    telemetry.RecordFrameInterval(51ms);
    telemetry.RecordFrameInterval(80ms);

    kdbg::ScanProgress progress{};
    progress.regions_total = 4;
    progress.regions_scanned = 4;
    progress.bytes_scanned = 4096;
    kdbg::ScanReadReport complete_report{};
    complete_report.items_attempted = 4;
    complete_report.items_completed = 4;
    complete_report.requested_bytes = 4096;
    complete_report.completed_bytes = 4096;

    const auto first_id = telemetry.BeginProcessScanAt(true, 10us);
    telemetry.RecordProcessScanProgress(first_id, progress);
    telemetry.FinishProcessScanAt(
        first_id, progress, complete_report, true, false, 30us);

    const auto second_id = telemetry.BeginProcessScanAt(false, 40us);
    progress.regions_total = 2;
    progress.regions_scanned = 2;
    complete_report.items_attempted = 2;
    complete_report.items_completed = 2;
    complete_report.requested_bytes = 2048;
    complete_report.completed_bytes = 2048;
    telemetry.RecordProcessScanProgress(second_id, progress);
    telemetry.FinishProcessScanAt(
        second_id, progress, complete_report, true, false, 60us);

    const auto partial_id = telemetry.BeginProcessScanAt(true, 70us);
    progress.regions_total = 4;
    progress.regions_scanned = 3;
    kdbg::ScanReadReport partial_report{};
    partial_report.items_attempted = 4;
    partial_report.items_completed = 3;
    partial_report.items_skipped = 1;
    partial_report.requested_bytes = 4096;
    partial_report.completed_bytes = 3072;
    partial_report.failed_reads = 1;
    partial_report.partial = true;
    telemetry.RecordProcessScanProgress(partial_id, progress);
    telemetry.FinishProcessScanAt(
        partial_id, progress, partial_report, true, false, 90us);

    const auto cancelled_id = telemetry.BeginProcessScanAt(true, 100us);
    progress.regions_total = 5;
    progress.regions_scanned = 3;
    progress.bytes_scanned = 3072;
    telemetry.RecordProcessScanProgress(cancelled_id, progress);
    telemetry.RequestProcessScanCancellationAt(cancelled_id, 150us);
    kdbg::ScanReadReport cancelled_report{};
    cancelled_report.items_attempted = 3;
    cancelled_report.items_completed = 2;
    cancelled_report.items_skipped = 1;
    cancelled_report.requested_bytes = 3072;
    cancelled_report.completed_bytes = 2048;
    cancelled_report.failed_reads = 1;
    cancelled_report.partial = true;
    cancelled_report.cancelled = true;
    telemetry.FinishProcessScanAt(
        cancelled_id, progress, cancelled_report, false, true, 250us);

    telemetry.Stop();
    KDBG_CHECK(runner, !telemetry.Enabled());
    const auto json = ReadText(output);
    KDBG_CHECK(runner,
        json.find("\"target_memory_contents\":false") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"filesystem_paths\":false") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"frames_observed\":3") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"stall_count\":2") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"max_interval_us\":80000") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"started\":4") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"succeeded\":2") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"partial\":1") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"failed\":0") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"cancelled\":1") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"records_evicted\":1") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"max_cancellation_latency_us\":100") !=
            std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"id\":1,") == std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"id\":3,\"kind\":\"first\","
                  "\"outcome\":\"partial\"") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"id\":4,\"kind\":\"first\","
                  "\"outcome\":\"cancelled\"") != std::string::npos);
    KDBG_CHECK(runner,
        json.find("\"cancellation_latency_us\":100") != std::string::npos);
    KDBG_CHECK(runner, json.find(output.string()) == std::string::npos);
    KDBG_CHECK(runner, CountTemporarySiblings(output) == 0);

    // An atomic replacement failure must leave the prior report byte-for-byte
    // intact and must remove only this session's unique temporary file.
    const auto locked_output = kdbg::test::UniqueTempPath(
        "kdbg-runtime-telemetry-locked.json");
    WriteText(locked_output, "last-good");
    HANDLE locked = CreateFileW(
        locked_output.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    KDBG_CHECK(runner, locked != INVALID_HANDLE_VALUE);
    if (locked != INVALID_HANDLE_VALUE) {
        kdbg::PerformanceTelemetry replacement_failure;
        auto locked_config = config;
        locked_config.output_path = locked_output;
        KDBG_CHECK(runner, !replacement_failure.Start(locked_config));
        KDBG_CHECK(runner,
            replacement_failure.LastStartStatus() ==
                kdbg::TelemetryStartStatus::InitialSnapshotWriteFailed);
        KDBG_CHECK(runner, replacement_failure.LastStartNativeCode() != 0);
        KDBG_CHECK(runner, ReadText(locked_output) == "last-good");
        KDBG_CHECK(runner, CountTemporarySiblings(locked_output) == 0);
        CloseHandle(locked);
    }

    const auto shared_output = kdbg::test::UniqueTempPath(
        "kdbg-runtime-telemetry-shared.json");
    auto shared_config = config;
    shared_config.output_path = shared_output;
    kdbg::PerformanceTelemetry first_session;
    kdbg::PerformanceTelemetry second_session;
    KDBG_CHECK(runner, first_session.Start(shared_config));
    KDBG_CHECK(runner, second_session.Start(shared_config));
    first_session.RecordFrameInterval(20ms);
    second_session.RecordFrameInterval(30ms);
    first_session.Stop();
    second_session.Stop();
    KDBG_CHECK(runner,
        ReadText(shared_output).find(
            "\"schema\":\"kdbg.runtime-telemetry.v1\"") !=
            std::string::npos);
    KDBG_CHECK(runner, CountTemporarySiblings(shared_output) == 0);

    std::filesystem::remove(output, cleanup_error);
    std::filesystem::remove(locked_output, cleanup_error);
    std::filesystem::remove(shared_output, cleanup_error);
#endif
}

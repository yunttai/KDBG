#include "LiveVerify.h"

#include "core/memory/MockMemoryBackend.h"
#include "core/model/PhysicalPage.h"

#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

int g_failures = 0;

void Check(bool condition, std::string_view message) {
    if (!condition) {
        ++g_failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

kdbg::ProbeInfo MockProbe() {
    kdbg::ProbeInfo probe{};
    probe.generation = 7;
    probe.byte_count = kdbg::kPhysicalPageSize;
    probe.virtual_address = 0x0000000140000000ULL;
    probe.physical_address = kdbg::MockMemoryBackend::kBaseAddress;
    probe.pfn = probe.physical_address >> 12U;
    probe.crc32 = 0xDEADBEEFU;
    return probe;
}

kdbg::Result<kdbg::ProbeInfo> QueryCurrentProbe(
    kdbg::MockMemoryBackend& backend,
    kdbg::ProbeInfo probe) {
    const auto page = backend.ReadPhysical(
        probe.physical_address, kdbg::kPhysicalPageSize);
    if (!page) {
        return kdbg::Result<kdbg::ProbeInfo>::Failure(page.GetError());
    }
    std::uint32_t crc = 0xFFFFFFFFU;
    for (const auto value : page.Value()) {
        crc ^= value;
        for (int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    probe.crc32 = ~crc;
    return kdbg::Result<kdbg::ProbeInfo>::Success(probe);
}

kdbg::live_verify::SystemRecord MockSystem() {
    kdbg::live_verify::SystemRecord system{};
    system.generated_utc = "2026-09-16T00:00:00.000Z";
    system.os_name = "Windows";
    system.os_build = kdbg::live_verify::kMinimumWindowsBuild;
    system.architecture = "x64";
    return system;
}

kdbg::live_verify::RuntimeIdentityRecord MockRuntimeIdentity() {
    constexpr std::string_view hash =
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef";
    kdbg::live_verify::RuntimeIdentityRecord identity{};
    identity.verified = true;
    identity.verifier.package_relative_path =
        "tools/kdbg_live_verify.exe";
    identity.verifier.sha256 = hash;
    identity.kdbg_service.name = "KDBG";
    identity.kdbg_service.binary.package_relative_path =
        "drivers/KDbgDriver.sys";
    identity.kdbg_service.binary.sha256 = hash;
    identity.kdbg_service.service_type = 1;
    identity.kdbg_service.current_state = 4;
    identity.kdbg_service.running_kernel_driver = true;
    identity.probe_service.name = "KDBGProbe";
    identity.probe_service.binary.package_relative_path =
        "drivers/KDbgProbe.sys";
    identity.probe_service.binary.sha256 = hash;
    identity.probe_service.service_type = 1;
    identity.probe_service.current_state = 4;
    identity.probe_service.running_kernel_driver = true;
    return identity;
}

kdbg::live_verify::Options WriteOptions() {
    kdbg::live_verify::Options options{};
    options.write = true;
    options.confirm_disposable_vm = true;
    options.snapshot_id = "checkpoint-123";
    options.confirm_probe_pfn = MockProbe().pfn;
    options.read_samples = 3;
    return options;
}

void TestOptionsAreFailClosed() {
    const std::vector<std::string_view> no_arguments;
    const auto defaults = kdbg::live_verify::ParseOptions(no_arguments);
    Check(defaults && !defaults.Value().write &&
              defaults.Value().output_path.empty() &&
              !defaults.Value().output_explicit,
          "default invocation must be read-only");

    const std::vector<std::string_view> empty_output{"--output", ""};
    Check(!kdbg::live_verify::ParseOptions(empty_output),
          "an explicitly empty evidence path must be rejected");

    const std::vector<std::string_view> external_output{
        "--output", "C:/evidence/live.json"};
    const auto output = kdbg::live_verify::ParseOptions(external_output);
    Check(output && output.Value().output_explicit &&
              output.Value().output_path == "C:/evidence/live.json",
          "an explicit external evidence path must remain distinguishable");

    const std::vector<std::string_view> write_only{"--write"};
    const auto rejected = kdbg::live_verify::ParseOptions(write_only);
    Check(!rejected, "write without three confirmations must be rejected");

    const std::vector<std::string_view> complete{
        "--write", "--confirm-disposable-vm",
        "--snapshot-id", "checkpoint-123",
        "--confirm-probe-pfn", "0x100"};
    const auto accepted = kdbg::live_verify::ParseOptions(complete);
    Check(accepted && accepted.Value().write &&
              accepted.Value().confirm_probe_pfn == 0x100ULL,
          "complete write confirmation must parse");
}

void TestReadOnlyNeverOpensWriteGate() {
    kdbg::MockMemoryBackend backend;
    Check(static_cast<bool>(backend.Open()), "mock backend must open");
    kdbg::live_verify::Options options{};
    options.read_samples = 3;
    const auto probe = MockProbe();
    const auto report = kdbg::live_verify::Run(
        backend,
        [probe]() { return kdbg::Result<kdbg::ProbeInfo>::Success(probe); },
        options,
        MockSystem(),
        MockRuntimeIdentity());
    Check(report.success, "read-only verification must pass");
    Check(backend.WriteEnableCallCount() == 0,
          "read-only verification must never enable writes");
    Check(backend.WriteCallCount() == 0,
          "read-only verification must never issue writes");
    Check(report.final_gate_locked, "read-only final gate must be locked");
    Check(report.comparisons.size() == 3,
          "each independent read must have a full-page comparison");
    backend.Close();
}

void TestRunRevalidatesWriteAuthorization() {
    kdbg::MockMemoryBackend backend;
    Check(static_cast<bool>(backend.Open()), "mock backend must open");
    auto options = WriteOptions();
    options.confirm_disposable_vm = false;
    const auto probe = MockProbe();
    const auto report = kdbg::live_verify::Run(
        backend,
        [probe]() { return kdbg::Result<kdbg::ProbeInfo>::Success(probe); },
        options,
        MockSystem(),
        MockRuntimeIdentity());
    Check(!report.success, "Run must independently reject incomplete consent");
    Check(backend.WriteEnableCallCount() == 0 && backend.WriteCallCount() == 0,
          "rejected consent must not touch the write gate or memory");
    backend.Close();
}

void TestWriteRollbackAndEvidence() {
    kdbg::MockMemoryBackend backend;
    Check(static_cast<bool>(backend.Open()), "mock backend must open");
    const auto probe = MockProbe();
    auto query = [probe, &backend]() {
        return QueryCurrentProbe(backend, probe);
    };
    const auto report = kdbg::live_verify::Run(
        backend, query, WriteOptions(), MockSystem(), MockRuntimeIdentity());
    Check(report.success, "write verification must pass with mock fixture");
    Check(report.apply_requested_bytes == 8,
          "apply must be one bounded eight-byte dirty run");
    Check(report.edit_offset == 0x100 && report.edit_length == 8,
          "report must bind the exact edited byte range");
    Check(report.rollback_requested_bytes == kdbg::kPhysicalPageSize,
          "rollback must restore the full page");
    Check(report.rollback_verified && report.final_gate_locked,
          "rollback and final relock must be verified");
    Check(backend.WriteEnableCallCount() == 2,
          "apply and rollback must use separate one-shot gates");
    const auto json = kdbg::live_verify::ToJson(report);
    Check(json.find("\"schema\":\"kdbg.live-verify.v1\"") !=
              std::string::npos,
          "JSON must contain the evidence schema");
    Check(json.find("\"read_p95_ms\"") != std::string::npos,
          "JSON must contain p95 latency");
    Check(json.find("\"edit_offset\":256,\"edit_length\":8") !=
              std::string::npos,
          "JSON must bind the exact edited byte range");
    Check(json.find(
              "\"package_relative_path\":\"tools/kdbg_live_verify.exe\"") !=
              std::string::npos &&
          json.find("\"kdbg_service\"") != std::string::npos &&
          json.find("\"probe_service\"") != std::string::npos &&
          json.find("\"running_kernel_driver\":true") != std::string::npos,
          "JSON must serialize safe package-relative runtime identity fields");
    Check(json.find("canonical_path") == std::string::npos &&
              json.find("configured_binary_path") == std::string::npos,
          "JSON must not serialize private canonical or configured paths");
    backend.Close();
}

void TestProbeMetadataMustRemainStable() {
    {
        kdbg::MockMemoryBackend backend;
        Check(static_cast<bool>(backend.Open()), "mock backend must open");
        const auto probe = MockProbe();
        int queries = 0;
        const auto report = kdbg::live_verify::Run(
            backend,
            [&backend, probe, &queries]() {
                auto current = QueryCurrentProbe(backend, probe);
                if (current && ++queries == 2) {
                    ++current.Value().generation;
                }
                return current;
            },
            WriteOptions(),
            MockSystem(),
            MockRuntimeIdentity());
        Check(!report.success,
              "Probe generation changes after physical write must fail");
        Check(report.rollback_attempted && report.rollback_verified,
              "metadata failure after apply must still roll back");
        backend.Close();
    }

    {
        kdbg::MockMemoryBackend backend;
        Check(static_cast<bool>(backend.Open()), "mock backend must open");
        const auto probe = MockProbe();
        int queries = 0;
        const auto report = kdbg::live_verify::Run(
            backend,
            [&backend, probe, &queries]() {
                auto current = QueryCurrentProbe(backend, probe);
                if (current && ++queries == 3) {
                    ++current.Value().generation;
                    current.Value().physical_address +=
                        kdbg::kPhysicalPageSize;
                    current.Value().byte_count /= 2U;
                }
                return current;
            },
            WriteOptions(),
            MockSystem(),
            MockRuntimeIdentity());
        Check(!report.success,
              "Probe physical identity and size changes after rollback must fail");
        Check(report.rollback_verified && report.final_gate_locked,
              "rollback metadata failure must retain memory and gate evidence");
        backend.Close();
    }
}

void TestCancellationAfterApplyRollsBack() {
    kdbg::MockMemoryBackend backend;
    Check(static_cast<bool>(backend.Open()), "mock backend must open");
    const auto probe = MockProbe();
    int checks = 0;
    const auto report = kdbg::live_verify::Run(
        backend,
        [probe]() { return kdbg::Result<kdbg::ProbeInfo>::Success(probe); },
        WriteOptions(),
        MockSystem(),
        MockRuntimeIdentity(),
        [&checks]() { return ++checks >= 5; });
    Check(!report.success && report.cancelled,
          "post-apply cancellation must fail the run as cancelled");
    Check(report.rollback_attempted && report.rollback_verified,
          "post-apply cancellation must roll back");
    Check(report.final_gate_locked,
          "post-apply cancellation must prove final relock");
    backend.Close();
}

void TestShortWriteAttemptsRecovery() {
    kdbg::MockMemoryBackend backend;
    Check(static_cast<bool>(backend.Open()), "mock backend must open");
    kdbg::MockFaults faults{};
    faults.short_write = true;
    backend.SetFaults(faults);
    const auto probe = MockProbe();
    const auto report = kdbg::live_verify::Run(
        backend,
        [probe]() { return kdbg::Result<kdbg::ProbeInfo>::Success(probe); },
        WriteOptions(),
        MockSystem(),
        MockRuntimeIdentity());
    Check(!report.success, "short write must fail verification");
    Check(report.rollback_attempted,
          "short write must trigger rollback recovery");
    Check(report.final_gate_locked,
          "short write recovery must prove final relock");
    backend.Close();
}

void TestGateCloseFailureStillRollsBack() {
    kdbg::MockMemoryBackend backend;
    Check(static_cast<bool>(backend.Open()), "mock backend must open");
    kdbg::MockFaults faults{};
    faults.fail_write_disable_count = 1;
    backend.SetFaults(faults);
    const auto probe = MockProbe();
    const auto report = kdbg::live_verify::Run(
        backend,
        [probe]() { return kdbg::Result<kdbg::ProbeInfo>::Success(probe); },
        WriteOptions(),
        MockSystem(),
        MockRuntimeIdentity());
    Check(!report.success, "gate-close failure must fail verification");
    Check(report.rollback_attempted && report.rollback_verified,
          "gate-close failure must still restore the fixture page");
    Check(report.final_gate_locked,
          "gate-close failure recovery must prove final relock");
    backend.Close();
}

void TestMissingRuntimeIdentityFailsClosed() {
    kdbg::MockMemoryBackend backend;
    Check(static_cast<bool>(backend.Open()), "mock backend must open");
    const auto probe = MockProbe();
    bool probe_queried = false;
    const auto report = kdbg::live_verify::Run(
        backend,
        [probe, &probe_queried]() {
            probe_queried = true;
            return kdbg::Result<kdbg::ProbeInfo>::Success(probe);
        },
        kdbg::live_verify::Options{},
        MockSystem(),
        kdbg::live_verify::RuntimeIdentityRecord{});
    Check(!report.success,
          "missing runtime identity attestation must fail closed");
    Check(!probe_queried && backend.WriteCallCount() == 0,
          "identity rejection must happen before memory device operations");
    backend.Close();
}

void TestUnsupportedSystemFailsBeforeDeviceOperations() {
    kdbg::MockMemoryBackend backend;
    Check(static_cast<bool>(backend.Open()), "mock backend must open");
    const auto probe = MockProbe();
    bool probe_queried = false;
    auto system = MockSystem();
    system.os_build = kdbg::live_verify::kMinimumWindowsBuild - 1U;
    const auto report = kdbg::live_verify::Run(
        backend,
        [probe, &probe_queried]() {
            probe_queried = true;
            return kdbg::Result<kdbg::ProbeInfo>::Success(probe);
        },
        kdbg::live_verify::Options{},
        system,
        MockRuntimeIdentity());
    Check(!report.success,
          "unsupported Windows builds must fail closed");
    Check(!probe_queried && backend.WriteEnableCallCount() == 0 &&
              backend.WriteCallCount() == 0,
          "unsupported-system rejection must precede device operations");
    backend.Close();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--emit-json") {
        kdbg::MockMemoryBackend backend;
        if (!backend.Open()) return 2;
        kdbg::live_verify::Options options{};
        options.read_samples = 2;
        const auto probe = MockProbe();
        const auto report = kdbg::live_verify::Run(
            backend,
            [probe]() {
                return kdbg::Result<kdbg::ProbeInfo>::Success(probe);
            },
            options,
            MockSystem(),
            MockRuntimeIdentity());
        std::cout << kdbg::live_verify::ToJson(report) << '\n';
        backend.Close();
        return report.success ? 0 : 1;
    }
    TestOptionsAreFailClosed();
    TestReadOnlyNeverOpensWriteGate();
    TestRunRevalidatesWriteAuthorization();
    TestWriteRollbackAndEvidence();
    TestProbeMetadataMustRemainStable();
    TestCancellationAfterApplyRollsBack();
    TestShortWriteAttemptsRecovery();
    TestGateCloseFailureStillRollsBack();
    TestMissingRuntimeIdentityFailsClosed();
    TestUnsupportedSystemFailsBeforeDeviceOperations();
    if (g_failures == 0) {
        std::cout << "live_verify tests: PASS\n";
        return 0;
    }
    std::cerr << "live_verify tests: " << g_failures << " failures\n";
    return 1;
}

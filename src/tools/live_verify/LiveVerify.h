#pragma once

#include "core/common/Result.h"
#include "core/memory/IMemoryBackend.h"
#include "core/memory/ProbeClient.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kdbg::live_verify {

inline constexpr std::uint32_t kMinimumWindowsBuild = 19041U;

struct Options {
    bool help{false};
    bool write{false};
    bool confirm_disposable_vm{false};
    std::optional<std::uint64_t> confirm_probe_pfn;
    std::string snapshot_id;
    std::string output_path;
    bool output_explicit{false};
    std::string build_id{"development"};
    std::uint32_t read_samples{5};
};

struct SystemRecord {
    std::string generated_utc;
    std::string os_name;
    std::uint32_t os_major{0};
    std::uint32_t os_minor{0};
    std::uint32_t os_build{0};
    std::string architecture;
    std::string tool_version{"1.1.0"};
    std::string build_id{"development"};
};

struct FileIdentityRecord {
    std::string package_relative_path;
    std::string sha256;
};

struct ServiceIdentityRecord {
    std::string name;
    FileIdentityRecord binary;
    std::uint32_t service_type{0};
    std::uint32_t current_state{0};
    bool running_kernel_driver{false};
};

struct RuntimeIdentityRecord {
    bool verified{false};
    FileIdentityRecord verifier;
    ServiceIdentityRecord kdbg_service;
    ServiceIdentityRecord probe_service;
};

bool IsSupportedSystem(const SystemRecord& system) noexcept;

struct ProbeRecord {
    std::uint32_t generation{0};
    std::uint32_t byte_count{0};
    std::uint64_t virtual_address{0};
    std::uint64_t physical_address{0};
    std::uint64_t pfn{0};
    std::uint32_t crc32{0};
};

struct SessionRecord {
    std::uint32_t flags{0};
    std::uint32_t owner_pid{0};
    std::uint32_t current_pid{0};
    std::uint32_t open_handle_count{0};
    std::uint64_t successful_reads{0};
    std::uint64_t successful_writes{0};
    std::uint64_t rejected_writes{0};
    std::uint32_t last_physical_write_status{0};
    std::uint32_t last_physical_write_stage{0};
    std::uint32_t last_physical_write_transferred{0};
    bool write_enabled{false};
};

struct OperationRecord {
    std::string name;
    std::uint64_t requested_bytes{0};
    std::uint64_t completed_bytes{0};
    double latency_ms{0.0};
    bool passed{false};
};

struct ComparisonRecord {
    std::string name;
    std::uint64_t byte_count{0};
    std::uint64_t mismatch_count{0};
    std::uint32_t expected_crc32{0};
    std::uint32_t actual_crc32{0};
    bool match{false};
};

struct ErrorRecord {
    std::string code;
    std::string operation;
    std::string message;
    std::uint64_t native_code{0};
    std::uint64_t requested{0};
    std::uint64_t completed{0};
};

struct VerificationReport {
    std::string schema{"kdbg.live-verify.v1"};
    std::string mode{"read-only"};
    bool success{false};
    bool cancelled{false};
    bool operator_confirmed_disposable_vm{false};
    std::string snapshot_id;
    SystemRecord system;
    RuntimeIdentityRecord runtime_identity;
    BackendInfo backend;
    std::optional<ProbeRecord> probe_before;
    std::optional<ProbeRecord> probe_after_write;
    std::optional<ProbeRecord> probe_after_rollback;
    std::optional<SessionRecord> session_before;
    std::optional<SessionRecord> session_after_apply;
    std::optional<SessionRecord> session_final;
    std::vector<OperationRecord> operations;
    std::vector<ComparisonRecord> comparisons;
    std::vector<double> read_latency_samples_ms;
    double read_latency_median_ms{0.0};
    double read_latency_p95_ms{0.0};
    std::uint64_t edit_offset{0};
    std::uint64_t edit_length{0};
    std::uint64_t apply_requested_bytes{0};
    std::uint64_t rollback_requested_bytes{0};
    bool rollback_attempted{false};
    bool rollback_verified{false};
    bool final_relock_attempted{false};
    bool final_gate_locked{false};
    std::vector<ErrorRecord> errors;
};

using ProbeQuery = std::function<Result<ProbeInfo>()>;
using CancellationQuery = std::function<bool()>;

Result<Options> ParseOptions(std::span<const std::string_view> arguments);
std::string Usage();

VerificationReport Run(
    IMemoryBackend& backend,
    const ProbeQuery& query_probe,
    const Options& options,
    SystemRecord system,
    RuntimeIdentityRecord runtime_identity,
    const CancellationQuery& is_cancelled = {});

VerificationReport FailureReport(
    const Options& options,
    SystemRecord system,
    RuntimeIdentityRecord runtime_identity,
    const Error& error);

std::string ToJson(const VerificationReport& report);

}  // namespace kdbg::live_verify

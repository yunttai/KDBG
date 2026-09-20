#include "LiveVerify.h"

#include "core/memory/PhysicalPageSession.h"
#include "core/memory/ProbeEvidencePattern.h"
#include "core/model/PhysicalPage.h"
#include "core/pfn/PfnAddress.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <exception>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <utility>

namespace kdbg::live_verify {
namespace {

using Clock = std::chrono::steady_clock;

double ElapsedMilliseconds(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start)
        .count();
}

std::string ErrorCodeName(ErrorCode code) {
    switch (code) {
    case ErrorCode::None: return "none";
    case ErrorCode::InvalidArgument: return "invalid_argument";
    case ErrorCode::InvalidPfn: return "invalid_pfn";
    case ErrorCode::AddressOverflow: return "address_overflow";
    case ErrorCode::OutsidePhysicalRam: return "outside_physical_ram";
    case ErrorCode::BackendDisconnected: return "backend_disconnected";
    case ErrorCode::BackendAlreadyOpen: return "backend_already_open";
    case ErrorCode::AbiMismatch: return "abi_mismatch";
    case ErrorCode::ShortRead: return "short_read";
    case ErrorCode::WriteLocked: return "write_locked";
    case ErrorCode::ConcurrentModification: return "concurrent_modification";
    case ErrorCode::ShortWrite: return "short_write";
    case ErrorCode::VerificationMismatch: return "verification_mismatch";
    case ErrorCode::RollbackFailed: return "rollback_failed";
    case ErrorCode::BridgeUnavailable: return "bridge_unavailable";
    case ErrorCode::Unsupported: return "unsupported";
    case ErrorCode::IoFailure: return "io_failure";
    case ErrorCode::AccessDenied: return "access_denied";
    case ErrorCode::ParseError: return "parse_error";
    case ErrorCode::Cancelled: return "cancelled";
    case ErrorCode::LimitReached: return "limit_reached";
    case ErrorCode::NotFound: return "not_found";
    case ErrorCode::InternalInvariant: return "internal_invariant";
    }
    return "unknown";
}

ErrorRecord ToRecord(const Error& error) {
    return ErrorRecord{
        ErrorCodeName(error.code), error.operation, error.message,
        error.native_code, error.requested, error.completed};
}

ProbeRecord ToRecord(const ProbeInfo& info) {
    return ProbeRecord{
        info.generation, info.byte_count, info.virtual_address,
        info.physical_address, info.pfn, info.crc32};
}

bool SameProbeIdentity(const ProbeInfo& current, const ProbeRecord& expected) {
    return current.generation == expected.generation &&
        current.byte_count == expected.byte_count &&
        current.physical_address == expected.physical_address &&
        current.pfn == expected.pfn;
}

SessionRecord ToRecord(const BackendSessionStatus& status) {
    return SessionRecord{
        status.flags,
        status.owner_pid,
        status.current_pid,
        status.open_handle_count,
        status.successful_reads,
        status.successful_writes,
        status.rejected_writes,
        status.last_physical_write_status,
        status.last_physical_write_stage,
        status.last_physical_write_transferred,
        status.write_enabled};
}

std::uint32_t Crc32(std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t crc = 0xFFFFFFFFU;
    for (const std::uint8_t value : bytes) {
        crc ^= value;
        for (int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}

template <typename Left, typename Right>
ComparisonRecord ComparePages(
    std::string name,
    const Left& expected,
    const Right& actual) {
    std::uint64_t mismatches = 0;
    for (std::size_t index = 0; index < kPhysicalPageSize; ++index) {
        if (expected[index] != actual[index]) {
            ++mismatches;
        }
    }
    return ComparisonRecord{
        std::move(name),
        kPhysicalPageSize,
        mismatches,
        Crc32(std::span<const std::uint8_t>(
            expected.data(), expected.size())),
        Crc32(std::span<const std::uint8_t>(actual.data(), actual.size())),
        mismatches == 0};
}

bool IsCancelled(const CancellationQuery& query) {
    return query && query();
}

bool HasVisibleText(std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](char character) {
        return character != ' ' && character != '\t' &&
            character != '\r' && character != '\n';
    });
}

bool IsLocalEvidence(const Options& options) noexcept {
    return options.baremetal_evidence || options.raw_pfn_evidence;
}

Error UnsupportedSystemError() {
    return MakeError(
        ErrorCode::Unsupported,
        "KDBG live verification requires Windows x64 build 19041 or newer",
        "live_verify::system_contract");
}

bool IsLowerHexSha256(std::string_view value) {
    return value.size() == 64U &&
        std::all_of(value.begin(), value.end(), [](char character) {
            return (character >= '0' && character <= '9') ||
                (character >= 'a' && character <= 'f');
        });
}

bool HasVerifiedRuntimeIdentity(const RuntimeIdentityRecord& identity) {
    constexpr std::uint32_t kWindowsKernelDriverType = 1U;
    constexpr std::uint32_t kWindowsServiceRunning = 4U;
    const auto valid_file = [](const FileIdentityRecord& file,
                               std::string_view expected_path) {
        return file.package_relative_path == expected_path &&
            IsLowerHexSha256(file.sha256);
    };
    const auto valid_service = [&](const ServiceIdentityRecord& service,
                                   std::string_view expected_name,
                                   std::string_view expected_path) {
        return service.name == expected_name &&
            valid_file(service.binary, expected_path) &&
            service.service_type == kWindowsKernelDriverType &&
            service.current_state == kWindowsServiceRunning &&
            service.running_kernel_driver;
    };
    return identity.verified && valid_file(
        identity.verifier, "tools/kdbg_live_verify.exe") &&
        valid_service(
            identity.kdbg_service, "KDBG", "drivers/KDbgDriver.sys") &&
        valid_service(
            identity.probe_service, "KDBGProbe", "drivers/KDbgProbe.sys");
}

class EmergencyRecoveryGuard {
public:
    EmergencyRecoveryGuard(
        IMemoryBackend& backend,
        PhysicalPageSession& session,
        VerificationReport& report,
        bool enabled,
        bool automatic_rollback_allowed) noexcept
        : backend_(backend),
          session_(session),
          report_(report),
          enabled_(enabled),
          automatic_rollback_allowed_(automatic_rollback_allowed),
          exceptions_(std::uncaught_exceptions()) {}

    void SetProbePfn(std::uint64_t pfn) noexcept { probe_pfn_ = pfn; }

    ~EmergencyRecoveryGuard() {
        if (!enabled_ || std::uncaught_exceptions() <= exceptions_) return;
        static_cast<void>(backend_.SetWriteEnabled(false));
        if (automatic_rollback_allowed_ && !report_.rollback_attempted &&
            session_.CanRollback() &&
            probe_pfn_.has_value()) {
            const auto unlocked = session_.UnlockForRollback(*probe_pfn_);
            if (unlocked) {
                static_cast<void>(session_.RollbackBaseline(backend_));
            }
        }
        static_cast<void>(backend_.SetWriteEnabled(false));
    }

    EmergencyRecoveryGuard(const EmergencyRecoveryGuard&) = delete;
    EmergencyRecoveryGuard& operator=(const EmergencyRecoveryGuard&) = delete;

private:
    IMemoryBackend& backend_;
    PhysicalPageSession& session_;
    VerificationReport& report_;
    bool enabled_{false};
    bool automatic_rollback_allowed_{false};
    int exceptions_{0};
    std::optional<std::uint64_t> probe_pfn_;
};

void AddError(VerificationReport& report, const Error& error) {
    report.errors.push_back(ToRecord(error));
    report.success = false;
    if (error.code == ErrorCode::Cancelled) {
        report.cancelled = true;
    }
}

Error CancelledError(std::string operation) {
    return MakeError(
        ErrorCode::Cancelled,
        "Live verification was cancelled; rollback and relock were requested",
        std::move(operation));
}

Result<std::uint64_t> ParseUnsigned(std::string_view text) {
    int base = 10;
    if (text.size() > 2 && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }
    if (text.empty() || text.front() == '-' || text.front() == '+') {
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::ParseError,
            "Expected an unsigned decimal or 0x-prefixed hexadecimal value",
            "live_verify::ParseUnsigned"));
    }
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), value, base);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != text.data() + text.size()) {
        return Result<std::uint64_t>::Failure(MakeError(
            ErrorCode::ParseError,
            "Expected an unsigned decimal or 0x-prefixed hexadecimal value",
            "live_verify::ParseUnsigned"));
    }
    return Result<std::uint64_t>::Success(value);
}

void CalculateLatencySummary(VerificationReport& report) {
    if (report.read_latency_samples_ms.empty()) return;
    auto sorted = report.read_latency_samples_ms;
    std::sort(sorted.begin(), sorted.end());
    const std::size_t count = sorted.size();
    if ((count & 1U) == 0U) {
        report.read_latency_median_ms =
            (sorted[count / 2U - 1U] + sorted[count / 2U]) / 2.0;
    } else {
        report.read_latency_median_ms = sorted[count / 2U];
    }
    const auto rank = static_cast<std::size_t>(
        std::ceil(0.95 * static_cast<double>(count)));
    report.read_latency_p95_ms = sorted[std::max<std::size_t>(rank, 1U) - 1U];
}

std::string Escape(std::string_view value) {
    std::ostringstream stream;
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        switch (byte) {
        case '\"': stream << "\\\""; break;
        case '\\': stream << "\\\\"; break;
        case '\b': stream << "\\b"; break;
        case '\f': stream << "\\f"; break;
        case '\n': stream << "\\n"; break;
        case '\r': stream << "\\r"; break;
        case '\t': stream << "\\t"; break;
        default:
            if (byte < 0x20U) {
                stream << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0') << static_cast<unsigned>(byte)
                       << std::dec;
            } else {
                stream << static_cast<char>(byte);
            }
        }
    }
    return stream.str();
}

void WriteString(std::ostringstream& stream, std::string_view value) {
    stream << '\"' << Escape(value) << '\"';
}

void WriteProbe(
    std::ostringstream& stream,
    const std::optional<ProbeRecord>& probe) {
    if (!probe) {
        stream << "null";
        return;
    }
    stream << "{\"generation\":" << probe->generation
           << ",\"byte_count\":" << probe->byte_count
           << ",\"virtual_address\":" << probe->virtual_address
           << ",\"physical_address\":" << probe->physical_address
           << ",\"pfn\":" << probe->pfn
           << ",\"crc32\":" << probe->crc32 << '}';
}

void WriteSession(
    std::ostringstream& stream,
    const std::optional<SessionRecord>& session) {
    if (!session) {
        stream << "null";
        return;
    }
    stream << "{\"flags\":" << session->flags
           << ",\"owner_pid\":" << session->owner_pid
           << ",\"current_pid\":" << session->current_pid
           << ",\"open_handle_count\":" << session->open_handle_count
           << ",\"successful_reads\":" << session->successful_reads
           << ",\"successful_writes\":" << session->successful_writes
           << ",\"rejected_writes\":" << session->rejected_writes
           << ",\"last_physical_write_status\":"
           << session->last_physical_write_status
           << ",\"last_physical_write_stage\":"
           << session->last_physical_write_stage
           << ",\"last_physical_write_transferred\":"
           << session->last_physical_write_transferred
           << ",\"write_enabled\":"
           << (session->write_enabled ? "true" : "false") << '}';
}

}  // namespace

bool IsSupportedSystem(const SystemRecord& system) noexcept {
    return system.os_name == "Windows" &&
        system.architecture == "x64" &&
        system.os_build >= kMinimumWindowsBuild;
}

Result<Options> ParseOptions(std::span<const std::string_view> arguments) {
    Options options{};
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const auto argument = arguments[index];
        const auto require_value = [&](std::string_view option)
            -> Result<std::string_view> {
            if (index + 1U >= arguments.size()) {
                return Result<std::string_view>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "Missing value for " + std::string(option),
                    "live_verify::ParseOptions"));
            }
            ++index;
            return Result<std::string_view>::Success(arguments[index]);
        };

        if (argument == "--help" || argument == "-h") {
            options.help = true;
        } else if (argument == "--write") {
            options.write = true;
        } else if (argument == "--baremetal-evidence") {
            options.baremetal_evidence = true;
        } else if (argument == "--raw-pfn-evidence") {
            options.raw_pfn_evidence = true;
        } else if (argument == "--confirm-disposable-vm") {
            options.confirm_disposable_vm = true;
        } else if (argument == "--snapshot-id") {
            const auto value = require_value(argument);
            if (!value) return Result<Options>::Failure(value.GetError());
            options.snapshot_id = std::string(value.Value());
        } else if (argument == "--confirm-probe-pfn") {
            const auto text = require_value(argument);
            if (!text) return Result<Options>::Failure(text.GetError());
            const auto value = ParseUnsigned(text.Value());
            if (!value) return Result<Options>::Failure(value.GetError());
            options.confirm_probe_pfn = value.Value();
        } else if (argument == "--raw-pfn") {
            const auto text = require_value(argument);
            if (!text) return Result<Options>::Failure(text.GetError());
            const auto value = ParseUnsigned(text.Value());
            if (!value) return Result<Options>::Failure(value.GetError());
            options.raw_pfn = value.Value();
        } else if (argument == "--confirm-raw-pfn") {
            const auto text = require_value(argument);
            if (!text) return Result<Options>::Failure(text.GetError());
            const auto value = ParseUnsigned(text.Value());
            if (!value) return Result<Options>::Failure(value.GetError());
            options.confirm_raw_pfn = value.Value();
        } else if (argument == "--artifact-directory") {
            const auto value = require_value(argument);
            if (!value) return Result<Options>::Failure(value.GetError());
            options.artifact_directory = std::string(value.Value());
        } else if (argument == "--output") {
            const auto value = require_value(argument);
            if (!value) return Result<Options>::Failure(value.GetError());
            options.output_path = std::string(value.Value());
            options.output_explicit = true;
        } else if (argument == "--build-id") {
            const auto value = require_value(argument);
            if (!value) return Result<Options>::Failure(value.GetError());
            options.build_id = std::string(value.Value());
        } else if (argument == "--read-samples") {
            const auto text = require_value(argument);
            if (!text) return Result<Options>::Failure(text.GetError());
            const auto value = ParseUnsigned(text.Value());
            if (!value || value.Value() >
                    static_cast<std::uint64_t>(
                        std::numeric_limits<std::uint32_t>::max())) {
                return Result<Options>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "Invalid --read-samples value",
                    "live_verify::ParseOptions"));
            }
            options.read_samples = static_cast<std::uint32_t>(value.Value());
        } else {
            return Result<Options>::Failure(MakeError(
                ErrorCode::ParseError,
                "Unknown option: " + std::string(argument),
                "live_verify::ParseOptions"));
        }
    }

    if (options.help) return Result<Options>::Success(std::move(options));
    if ((options.output_explicit && options.output_path.empty()) ||
        options.output_path.size() > 32767U ||
        options.build_id.empty() || options.build_id.size() > 128U ||
        options.read_samples == 0 || options.read_samples > 64U) {
        return Result<Options>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Output, build id, or read sample limit is invalid",
            "live_verify::ParseOptions"));
    }
    if (options.write) {
        if (options.raw_pfn_evidence) {
            if (options.baremetal_evidence ||
                options.confirm_disposable_vm ||
                !options.snapshot_id.empty() ||
                options.confirm_probe_pfn.has_value() ||
                !options.raw_pfn.has_value() ||
                !options.confirm_raw_pfn.has_value() ||
                options.raw_pfn != options.confirm_raw_pfn ||
                !HasVisibleText(options.artifact_directory) ||
                options.artifact_directory.size() > 32767U) {
                return Result<Options>::Failure(MakeError(
                    ErrorCode::WriteLocked,
                    "Raw-PFN evidence mode requires --write, matching "
                    "--raw-pfn and --confirm-raw-pfn values, and "
                    "--artifact-directory; VM and Probe confirmations are "
                    "mutually exclusive",
                    "live_verify::ParseOptions"));
            }
        } else if (options.baremetal_evidence) {
            if (options.confirm_disposable_vm ||
                !options.snapshot_id.empty() ||
                !options.confirm_probe_pfn.has_value() ||
                options.raw_pfn.has_value() ||
                options.confirm_raw_pfn.has_value() ||
                !HasVisibleText(options.artifact_directory) ||
                options.artifact_directory.size() > 32767U) {
                return Result<Options>::Failure(MakeError(
                    ErrorCode::WriteLocked,
                    "Bare-metal evidence mode requires --write, "
                    "--confirm-probe-pfn, and --artifact-directory; "
                    "VM confirmations "
                "are mutually exclusive",
                "live_verify::ParseOptions"));
            }
        } else if (!options.confirm_disposable_vm ||
                   !HasVisibleText(options.snapshot_id) ||
                   options.snapshot_id.size() > 256U ||
                   !options.confirm_probe_pfn.has_value() ||
                   options.raw_pfn.has_value() ||
                   options.confirm_raw_pfn.has_value()) {
            return Result<Options>::Failure(MakeError(
                ErrorCode::WriteLocked,
                "Write mode requires --confirm-disposable-vm, a non-empty "
                "--snapshot-id, and --confirm-probe-pfn",
                "live_verify::ParseOptions"));
        }
    } else if (options.baremetal_evidence ||
               options.raw_pfn_evidence ||
               options.confirm_disposable_vm ||
               options.confirm_probe_pfn.has_value() ||
               options.raw_pfn.has_value() ||
               options.confirm_raw_pfn.has_value() ||
               !options.snapshot_id.empty() ||
               !options.artifact_directory.empty()) {
        return Result<Options>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Write confirmations are accepted only together with --write",
            "live_verify::ParseOptions"));
    }
    return Result<Options>::Success(std::move(options));
}

std::string Usage() {
    return
        "KDBG live verification (read-only by default)\n"
        "Usage: kdbg_live_verify [--output FILE] [--build-id ID] "
        "[--read-samples 1..64]\n"
        "Default output: unique JSON under %LOCALAPPDATA%\\KDBG\\evidence\n"
        "Write mode (disposable snapshot VM and KDbgProbe only):\n"
        "  --write --confirm-disposable-vm --snapshot-id ID "
        "--confirm-probe-pfn PFN\n"
        "Bare-metal evidence mode (local KDbgProbe PFN only):\n"
        "  --write --baremetal-evidence --confirm-probe-pfn PFN "
        "--artifact-directory DIR\n"
        "Raw-PFN evidence mode (manual PFN bound to the live Probe fixture):\n"
        "  --write --raw-pfn-evidence --raw-pfn PFN "
        "--confirm-raw-pfn PFN --artifact-directory DIR\n"
        "This tool never installs or starts a driver. Both write modes use "
        "only a PFN validated against the running KDbgProbe fixture.\n";
}

VerificationReport FailureReport(
    const Options& options,
    SystemRecord system,
    RuntimeIdentityRecord runtime_identity,
    const Error& error) {
    VerificationReport report{};
    report.schema = options.raw_pfn_evidence
        ? "kdbg.live-verify.raw-pfn.v1"
        : (options.baremetal_evidence
            ? "kdbg.live-verify.v2" : "kdbg.live-verify.v1");
    report.mode = options.raw_pfn_evidence
        ? "baremetal-raw-pfn-write-rollback"
        : (options.baremetal_evidence
            ? "baremetal-probe-write-rollback"
            : (options.write ? "probe-write-rollback" : "read-only"));
    report.operator_confirmed_disposable_vm =
        options.confirm_disposable_vm;
    report.snapshot_id = options.snapshot_id;
    report.target_profile = IsLocalEvidence(options)
        ? "LocalHost" : "DisposableVm";
    if (options.raw_pfn_evidence) {
        report.target_kind = "RawPfn";
        report.target_provenance = "manual PFN entry";
        report.raw_pfn_derived_from_probe = true;
        report.target_pfn = options.raw_pfn.value_or(0U);
    }
    report.system = std::move(system);
    report.system.build_id = options.build_id;
    report.runtime_identity = std::move(runtime_identity);
    AddError(report, error);
    return report;
}

VerificationReport Run(
    IMemoryBackend& backend,
    const ProbeQuery& query_probe,
    const Options& options,
    SystemRecord system,
    RuntimeIdentityRecord runtime_identity,
    const CancellationQuery& is_cancelled) {
    VerificationReport report{};
    report.schema = options.raw_pfn_evidence
        ? "kdbg.live-verify.raw-pfn.v1"
        : (options.baremetal_evidence
            ? "kdbg.live-verify.v2" : "kdbg.live-verify.v1");
    report.mode = options.raw_pfn_evidence
        ? "baremetal-raw-pfn-write-rollback"
        : (options.baremetal_evidence
            ? "baremetal-probe-write-rollback"
            : (options.write ? "probe-write-rollback" : "read-only"));
    report.operator_confirmed_disposable_vm =
        options.confirm_disposable_vm;
    report.snapshot_id = options.snapshot_id;
    report.target_profile = IsLocalEvidence(options)
        ? "LocalHost" : "DisposableVm";
    if (options.raw_pfn_evidence) {
        report.target_kind = "RawPfn";
        report.target_provenance = "manual PFN entry";
        report.raw_pfn_derived_from_probe = true;
        report.target_pfn = options.raw_pfn.value_or(0U);
    }
    report.system = std::move(system);
    report.system.build_id = options.build_id;
    report.runtime_identity = std::move(runtime_identity);
    report.backend = backend.Info();

    auto session = std::make_unique<PhysicalPageSession>();
    EmergencyRecoveryGuard emergency_recovery{
        backend, *session, report, options.write,
        !IsLocalEvidence(options)};
    std::array<std::uint8_t, kPhysicalPageSize> original{};
    bool have_original = false;

    if (!IsSupportedSystem(report.system)) {
        AddError(report, UnsupportedSystemError());
        return report;
    }

    if (!HasVerifiedRuntimeIdentity(report.runtime_identity)) {
        AddError(report, MakeError(
            ErrorCode::AccessDenied,
            "Runtime identity attestation is incomplete or unverified",
            "live_verify::Run"));
        return report;
    }

    if (IsLocalEvidence(options) &&
        (report.backend.abi_version != 7U ||
         !report.backend.supports_physical_page_compare_write)) {
        AddError(report, MakeError(
            ErrorCode::AbiMismatch,
            "Bare-metal evidence requires ABI 7 and the serialized exact-page compare-write capability",
            "live_verify::baremetal_backend_contract"));
        return report;
    }

    if (options.baremetal_evidence &&
        (!options.write || !options.confirm_probe_pfn.has_value() ||
         !HasVisibleText(options.artifact_directory))) {
        AddError(report, MakeError(
            ErrorCode::WriteLocked,
            "Bare-metal evidence write confirmation is incomplete",
            "live_verify::Run"));
        return report;
    }

    if (options.raw_pfn_evidence &&
        (!options.write || !options.raw_pfn.has_value() ||
         !options.confirm_raw_pfn.has_value() ||
         options.raw_pfn != options.confirm_raw_pfn ||
         !HasVisibleText(options.artifact_directory))) {
        AddError(report, MakeError(
            ErrorCode::WriteLocked,
            "Raw-PFN evidence confirmation is incomplete",
            "live_verify::Run"));
        return report;
    }

    if (options.write && !IsLocalEvidence(options) &&
        (!options.confirm_disposable_vm ||
         !HasVisibleText(options.snapshot_id) ||
         !options.confirm_probe_pfn.has_value())) {
        AddError(report, MakeError(
            ErrorCode::WriteLocked,
            "Write authorization is incomplete; disposable VM, snapshot, "
            "and Probe PFN confirmations are all mandatory",
            "live_verify::Run"));
        return report;
    }

    const auto query_session = [&](std::optional<SessionRecord>& destination,
                                   std::string_view operation) -> bool {
        const auto status = backend.QuerySessionStatus();
        if (!status) {
            Error error = status.GetError();
            error.operation = std::string(operation);
            AddError(report, error);
            return false;
        }
        destination = ToRecord(status.Value());
        return true;
    };

    const auto final_relock = [&]() {
        report.final_relock_attempted = true;
        const auto relocked = backend.SetWriteEnabled(false);
        if (!relocked) AddError(report, relocked.GetError());
    };

    const auto capture_evidence = [&]() {
        const auto& evidence = session->Evidence();
        auto replace = [&](ComparisonRecord comparison) {
            const auto found = std::find_if(
                report.comparisons.begin(), report.comparisons.end(),
                [&](const ComparisonRecord& existing) {
                    return existing.name == comparison.name;
                });
            if (found == report.comparisons.end()) {
                report.comparisons.push_back(std::move(comparison));
            } else {
                *found = std::move(comparison);
            }
        };
        if (evidence.baseline && evidence.preflight) {
            replace(ComparePages(
                "baseline_vs_preflight", *evidence.baseline,
                *evidence.preflight));
        }
        if (evidence.expected_after && evidence.readback) {
            replace(ComparePages(
                "expected_vs_write_readback", *evidence.expected_after,
                *evidence.readback));
        }
        if (evidence.expected_after && evidence.independent_reload) {
            replace(ComparePages(
                "expected_vs_independent_reload", *evidence.expected_after,
                *evidence.independent_reload));
        }
        if (evidence.baseline && evidence.rollback) {
            replace(ComparePages(
                "baseline_vs_rollback_readback", *evidence.baseline,
                *evidence.rollback));
        }
        if (IsLocalEvidence(options)) {
            const auto capture_page = [&]<typename Page>(
                std::string_view role,
                std::string_view file_name,
                const std::optional<Page>& page) {
                if (!page) return;
                const auto found = std::find_if(
                    report.raw_page_artifacts.begin(),
                    report.raw_page_artifacts.end(),
                    [&](const RawPageArtifactRecord& existing) {
                        return existing.role == role;
                    });
                RawPageArtifactRecord artifact{};
                artifact.role = role;
                artifact.file_name = file_name;
                artifact.bytes = *page;
                if (found == report.raw_page_artifacts.end()) {
                    report.raw_page_artifacts.push_back(std::move(artifact));
                } else {
                    *found = std::move(artifact);
                }
            };
            capture_page("baseline", "baseline.bin", evidence.baseline);
            capture_page("preflight", "preflight.bin", evidence.preflight);
            capture_page(
                "expected_after", "expected-after.bin",
                evidence.expected_after);
            capture_page("readback", "readback.bin", evidence.readback);
            capture_page(
                "independent_reload", "independent-reload.bin",
                evidence.independent_reload);
            capture_page("rollback", "rollback.bin", evidence.rollback);
        }
    };

    const auto rollback = [&]() -> bool {
        if (IsLocalEvidence(options)) {
            if (report.rollback_suppressed_stale_identity) return false;
            const auto identity_start = Clock::now();
            const auto current_probe = query_probe();
            const bool fresh = current_probe &&
                report.probe_before.has_value() &&
                SameProbeIdentity(current_probe.Value(), *report.probe_before);
            report.operations.push_back(OperationRecord{
                "probe_query_before_rollback", 0,
                current_probe ? sizeof(ProbeInfo) : 0,
                ElapsedMilliseconds(identity_start), fresh});
            report.probe_identity_fresh_at_rollback = fresh;
            if (!current_probe) {
                report.rollback_suppressed_stale_identity = true;
                AddError(report, current_probe.GetError());
                return false;
            }
            if (!fresh) {
                report.rollback_suppressed_stale_identity = true;
                AddError(report, MakeError(
                    ErrorCode::ConcurrentModification,
                    "KDbgProbe identity became stale; rollback was suppressed",
                    "live_verify::probe_identity_before_rollback"));
                return false;
            }
        }
        report.rollback_attempted = true;
        if (!session->CanRollback()) {
            AddError(report, MakeError(
                ErrorCode::RollbackFailed,
                "No rollback snapshot is available after the write attempt",
                "live_verify::rollback"));
            return false;
        }
        const auto unlocked = session->UnlockForRollback(report.target_pfn);
        if (!unlocked) {
            AddError(report, unlocked.GetError());
            return false;
        }
        const auto start = Clock::now();
        const auto result = session->RollbackBaseline(backend);
        report.operations.push_back(OperationRecord{
            "rollback_full_page", kPhysicalPageSize,
            result ? kPhysicalPageSize : result.GetError().completed,
            ElapsedMilliseconds(start), static_cast<bool>(result)});
        report.rollback_requested_bytes = kPhysicalPageSize;
        if (!result) {
            AddError(report, result.GetError());
            capture_evidence();
            return false;
        }
        report.rollback_verified = true;
        report.rollback_driver_transferred_bytes = kPhysicalPageSize;
        capture_evidence();
        return true;
    };

    const auto finish_after_write_failure = [&](const Error& error) {
        AddError(report, error);
        if (!report.session_after_apply.has_value()) {
            static_cast<void>(query_session(
                report.session_after_apply,
                "live_verify::failure_session_status"));
        }
        if (report.session_after_apply.has_value()) {
            const auto operation = std::find_if(
                report.operations.rbegin(), report.operations.rend(),
                [](const OperationRecord& candidate) {
                    return candidate.name == "one_shot_apply";
                });
            if (operation != report.operations.rend() &&
                report.session_after_apply->last_physical_write_transferred <=
                    report.apply_requested_bytes) {
                operation->completed_bytes =
                    report.session_after_apply->last_physical_write_transferred;
            }
        }
        final_relock();
        if (session->CanRollback()) {
            static_cast<void>(rollback());
        }
        final_relock();
        static_cast<void>(query_session(
            report.session_final, "live_verify::final_session_status"));
        if (report.session_final.has_value() && report.rollback_attempted &&
            report.session_final->last_physical_write_transferred != 0U) {
            report.rollback_driver_transferred_bytes =
                report.session_final->last_physical_write_transferred;
        }
        report.final_gate_locked = report.session_final.has_value() &&
            !report.session_final->write_enabled;
        if (!report.final_gate_locked) {
            AddError(report, MakeError(
                ErrorCode::WriteLocked,
                "Final driver session did not prove that the gate is locked",
                "live_verify::final_relock"));
        }
    };

    if (!query_probe) {
        AddError(report, MakeError(
            ErrorCode::InvalidArgument,
            "Probe query callback is missing",
            "live_verify::Run"));
        return report;
    }
    const auto probe_start = Clock::now();
    const auto probe = query_probe();
    report.operations.push_back(OperationRecord{
        "probe_query_before", 0, probe ? sizeof(ProbeInfo) : 0,
        ElapsedMilliseconds(probe_start), static_cast<bool>(probe)});
    if (!probe) {
        AddError(report, probe.GetError());
        return report;
    }
    report.probe_before = ToRecord(probe.Value());
    std::uint64_t target_pfn = probe.Value().pfn;
    if (options.raw_pfn_evidence) {
        if (!options.raw_pfn.has_value() ||
            options.raw_pfn.value() != probe.Value().pfn) {
            AddError(report, MakeError(
                ErrorCode::ConcurrentModification,
                "The manually entered Raw-PFN target must match the current "
                "KDbgProbe fixture PFN for this deterministic evidence run",
                "live_verify::raw_pfn_probe_binding"));
            return report;
        }
        report.target_kind = "RawPfn";
        report.target_provenance = "manual PFN entry";
        report.raw_pfn_derived_from_probe = true;
        target_pfn = options.raw_pfn.value();
    }
    report.target_pfn = target_pfn;
    emergency_recovery.SetProbePfn(target_pfn);
    const auto address = PfnAddress::FromPfn(target_pfn);
    if (!address || probe.Value().byte_count != kPhysicalPageSize ||
        !address.Value().IsConsistent() ||
        address.Value().physical_address != probe.Value().physical_address) {
        AddError(report, MakeError(
            ErrorCode::AbiMismatch,
            "KDbgProbe did not identify one aligned 4 KiB PFN",
            "live_verify::probe_validation",
            0, kPhysicalPageSize, probe.Value().byte_count));
        return report;
    }
    report.target_physical_address = address.Value().physical_address;
    if (options.write && !options.raw_pfn_evidence &&
        options.confirm_probe_pfn != probe.Value().pfn) {
        AddError(report, MakeError(
            ErrorCode::WriteLocked,
            "Confirmed Probe PFN does not match the live KDbgProbe PFN",
            "live_verify::probe_confirmation"));
        return report;
    }
    if (!query_session(report.session_before,
                       "live_verify::initial_session_status")) {
        return report;
    }
    if (report.session_before->write_enabled) {
        AddError(report, MakeError(
            ErrorCode::WriteLocked,
            "Initial driver session has an unexpectedly open write gate",
            "live_verify::initial_session_status"));
        return report;
    }

    const auto load_start = Clock::now();
    const auto loaded = session->Load(backend, address.Value());
    report.operations.push_back(OperationRecord{
        "load_baseline", kPhysicalPageSize,
        loaded ? kPhysicalPageSize : loaded.GetError().completed,
        ElapsedMilliseconds(load_start), static_cast<bool>(loaded)});
    if (!loaded) {
        AddError(report, loaded.GetError());
        return report;
    }
    original = session->Baseline();
    have_original = true;

    for (std::uint32_t sample = 0; sample < options.read_samples; ++sample) {
        if (IsCancelled(is_cancelled)) {
            AddError(report, CancelledError("live_verify::read_samples"));
            CalculateLatencySummary(report);
            return report;
        }
        const auto start = Clock::now();
        const auto read = backend.ReadPhysical(
            address.Value().physical_address, kPhysicalPageSize);
        const double latency = ElapsedMilliseconds(start);
        report.read_latency_samples_ms.push_back(latency);
        const bool exact = read && read.Value().size() == kPhysicalPageSize;
        report.operations.push_back(OperationRecord{
            "independent_read_sample", kPhysicalPageSize,
            read ? read.Value().size() : read.GetError().completed,
            latency, exact});
        if (!exact) {
            AddError(report, read
                ? MakeError(
                    ErrorCode::ShortRead,
                    "Independent 4 KiB read returned a short byte count",
                    "live_verify::read_sample",
                    0, kPhysicalPageSize, read.Value().size())
                : read.GetError());
            CalculateLatencySummary(report);
            return report;
        }
        const auto comparison = ComparePages(
            "baseline_vs_read_sample_" + std::to_string(sample + 1U),
            original, read.Value());
        report.comparisons.push_back(comparison);
        if (!comparison.match) {
            AddError(report, MakeError(
                ErrorCode::ConcurrentModification,
                "Probe page changed during read sampling",
                "live_verify::read_sample",
                0, kPhysicalPageSize,
                kPhysicalPageSize - comparison.mismatch_count));
            CalculateLatencySummary(report);
            return report;
        }
    }
    CalculateLatencySummary(report);

    if (!options.write) {
        if (!query_session(report.session_final,
                           "live_verify::final_session_status")) {
            return report;
        }
        report.final_gate_locked = !report.session_final->write_enabled;
        if (!report.final_gate_locked) {
            AddError(report, MakeError(
                ErrorCode::WriteLocked,
                "Read-only verification ended with an open write gate",
                "live_verify::final_session_status"));
            return report;
        }
        report.success = true;
        return report;
    }

    if (IsCancelled(is_cancelled)) {
        AddError(report, CancelledError("live_verify::before_edit"));
        return report;
    }
    report.edit_offset = kProbeEvidenceEditOffset;
    report.edit_length = kProbeEvidenceEditMask.size();
    for (std::size_t index = 0;
         index < kProbeEvidenceEditMask.size(); ++index) {
        const auto edited = session->EditByte(
            kProbeEvidenceEditOffset + index,
            static_cast<std::uint8_t>(
                original[kProbeEvidenceEditOffset + index] ^
                kProbeEvidenceEditMask[index]));
        if (!edited) {
            AddError(report, edited.GetError());
            return report;
        }
    }
    const auto runs = session->DiffRuns();
    for (const auto& run : runs) {
        report.apply_requested_bytes += run.after.size();
    }
    const auto unlocked = session->UnlockForOneApply(report.target_pfn);
    if (!unlocked) {
        AddError(report, unlocked.GetError());
        return report;
    }

    const auto apply_start = Clock::now();
    const auto applied = session->ApplyAndVerify(backend);
    report.operations.push_back(OperationRecord{
        "one_shot_apply", report.apply_requested_bytes,
        applied ? report.apply_requested_bytes : applied.GetError().completed,
        ElapsedMilliseconds(apply_start), static_cast<bool>(applied)});
    capture_evidence();
    if (!applied) {
        finish_after_write_failure(applied.GetError());
        return report;
    }
    if (!query_session(report.session_after_apply,
                       "live_verify::post_apply_session_status")) {
        finish_after_write_failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to capture the post-apply session counters",
            "live_verify::post_apply_session_status"));
        return report;
    }
    if (report.session_after_apply->write_enabled) {
        finish_after_write_failure(MakeError(
            ErrorCode::WriteLocked,
            "One-shot apply did not close the driver write gate",
            "live_verify::post_apply_session_status"));
        return report;
    }
    report.apply_driver_transferred_bytes = kPhysicalPageSize;
    if (IsCancelled(is_cancelled)) {
        finish_after_write_failure(CancelledError(
            "live_verify::after_apply"));
        return report;
    }

    const auto after_write_start = Clock::now();
    const auto after_write = query_probe();
    report.operations.push_back(OperationRecord{
        "probe_query_after_write", 0,
        after_write ? sizeof(ProbeInfo) : 0,
        ElapsedMilliseconds(after_write_start),
        static_cast<bool>(after_write)});
    if (!after_write) {
        finish_after_write_failure(after_write.GetError());
        return report;
    }
    report.probe_after_write = ToRecord(after_write.Value());
    const auto expected_after_crc = Crc32(std::span<const std::uint8_t>(
        session->Baseline().data(), session->Baseline().size()));
    if (!SameProbeIdentity(after_write.Value(), *report.probe_before)) {
        if (IsLocalEvidence(options)) {
            report.rollback_suppressed_stale_identity = true;
        }
        finish_after_write_failure(MakeError(
            ErrorCode::VerificationMismatch,
            "KDbgProbe generation or physical identity became stale",
            "live_verify::probe_after_write"));
        return report;
    }
    if (after_write.Value().crc32 != expected_after_crc) {
        finish_after_write_failure(MakeError(
            ErrorCode::VerificationMismatch,
            "KDbgProbe CRC does not match the verified page",
            "live_verify::probe_after_write"));
        return report;
    }

    if (IsCancelled(is_cancelled)) {
        finish_after_write_failure(CancelledError(
            "live_verify::after_apply"));
        return report;
    }
    const auto reload_start = Clock::now();
    const auto reloaded = session->ReloadPreservingRollback(backend);
    report.operations.push_back(OperationRecord{
        "independent_reload_after_write", kPhysicalPageSize,
        reloaded ? kPhysicalPageSize : reloaded.GetError().completed,
        ElapsedMilliseconds(reload_start), static_cast<bool>(reloaded)});
    capture_evidence();
    if (!reloaded) {
        finish_after_write_failure(reloaded.GetError());
        return report;
    }

    if (IsCancelled(is_cancelled)) {
        AddError(report, CancelledError("live_verify::before_rollback"));
    }
    const bool rollback_ok = rollback();

    if (have_original) {
        const auto post_start = Clock::now();
        const auto post = backend.ReadPhysical(
            address.Value().physical_address, kPhysicalPageSize);
        const bool exact = post && post.Value().size() == kPhysicalPageSize;
        report.operations.push_back(OperationRecord{
            "independent_read_after_rollback", kPhysicalPageSize,
            post ? post.Value().size() : post.GetError().completed,
            ElapsedMilliseconds(post_start), exact});
        if (exact) {
            const auto comparison = ComparePages(
                "baseline_vs_post_rollback_read", original, post.Value());
            report.comparisons.push_back(comparison);
            if (!comparison.match) {
                AddError(report, MakeError(
                    ErrorCode::RollbackFailed,
                    "Independent read after rollback differs from baseline",
                    "live_verify::post_rollback_read"));
            }
        } else {
            AddError(report, post
                ? MakeError(
                    ErrorCode::ShortRead,
                    "Post-rollback read returned a short byte count",
                    "live_verify::post_rollback_read",
                    0, kPhysicalPageSize, post.Value().size())
                : post.GetError());
        }
    }

    const auto after_rollback_start = Clock::now();
    const auto after_rollback = query_probe();
    report.operations.push_back(OperationRecord{
        "probe_query_after_rollback", 0,
        after_rollback ? sizeof(ProbeInfo) : 0,
        ElapsedMilliseconds(after_rollback_start),
        static_cast<bool>(after_rollback)});
    if (after_rollback) {
        report.probe_after_rollback = ToRecord(after_rollback.Value());
        if (after_rollback.Value().generation != probe.Value().generation ||
            after_rollback.Value().byte_count != probe.Value().byte_count ||
            after_rollback.Value().physical_address !=
                probe.Value().physical_address ||
            after_rollback.Value().pfn != probe.Value().pfn ||
            after_rollback.Value().crc32 != probe.Value().crc32) {
            AddError(report, MakeError(
                ErrorCode::RollbackFailed,
                "KDbgProbe generation, physical identity, size, or CRC was "
                "not restored",
                "live_verify::probe_after_rollback"));
        }
    } else {
        AddError(report, after_rollback.GetError());
    }

    final_relock();
    static_cast<void>(query_session(
        report.session_final, "live_verify::final_session_status"));
    if (report.session_final.has_value() && report.rollback_attempted &&
        report.session_final->last_physical_write_transferred != 0U) {
        report.rollback_driver_transferred_bytes =
            report.session_final->last_physical_write_transferred;
    }
    report.final_gate_locked = report.session_final.has_value() &&
        !report.session_final->write_enabled;
    if (!report.final_gate_locked) {
        AddError(report, MakeError(
            ErrorCode::WriteLocked,
            "Final driver session did not prove that the gate is locked",
            "live_verify::final_session_status"));
    }
    report.success = rollback_ok && report.errors.empty() &&
        report.rollback_verified && report.final_gate_locked;
    return report;
}

std::string ToJson(const VerificationReport& report) {
    std::ostringstream stream;
    stream << std::fixed << std::setprecision(6);
    stream << '{';
    stream << "\"schema\":"; WriteString(stream, report.schema);
    stream << ",\"mode\":"; WriteString(stream, report.mode);
    stream << ",\"success\":" << (report.success ? "true" : "false")
           << ",\"cancelled\":" << (report.cancelled ? "true" : "false")
           << ",\"operator_confirmed_disposable_vm\":"
           << (report.operator_confirmed_disposable_vm ? "true" : "false")
           << ",\"snapshot_id\":";
    WriteString(stream, report.snapshot_id);
    if (report.schema == "kdbg.live-verify.v2" ||
        report.schema == "kdbg.live-verify.raw-pfn.v1") {
        if (report.schema == "kdbg.live-verify.raw-pfn.v1") {
            stream << ",\"raw_pfn_contract\":{";
        } else {
            stream << ",\"baremetal_contract\":{";
        }
        stream << "\"target_profile\":";
        WriteString(stream, report.target_profile);
        if (report.schema == "kdbg.live-verify.raw-pfn.v1") {
            stream << ",\"target_kind\":";
            WriteString(stream, report.target_kind);
            stream << ",\"target_provenance\":";
            WriteString(stream, report.target_provenance);
            stream << ",\"raw_pfn_derived_from_probe\":"
                   << (report.raw_pfn_derived_from_probe
                           ? "true" : "false")
                   << ",\"pfn\":" << report.target_pfn
                   << ",\"physical_address\":"
                   << report.target_physical_address;
        }
        stream << ",\"probe_identity_fresh_at_rollback\":"
               << (report.probe_identity_fresh_at_rollback
                       ? "true" : "false")
               << ",\"rollback_suppressed_stale_identity\":"
               << (report.rollback_suppressed_stale_identity
                       ? "true" : "false")
               << '}';
        stream << ",\"raw_page_artifacts\":[";
        for (std::size_t index = 0;
             index < report.raw_page_artifacts.size(); ++index) {
            if (index != 0) stream << ',';
            const auto& artifact = report.raw_page_artifacts[index];
            stream << "{\"role\":";
            WriteString(stream, artifact.role);
            stream << ",\"file_name\":";
            WriteString(stream, artifact.file_name);
            stream << ",\"sha256\":";
            WriteString(stream, artifact.sha256);
            stream << ",\"byte_count\":" << artifact.bytes.size()
                   << ",\"written\":"
                   << (artifact.written ? "true" : "false") << '}';
        }
        stream << ']';
    }

    stream << ",\"system\":{\"generated_utc\":";
    WriteString(stream, report.system.generated_utc);
    stream << ",\"os_name\":"; WriteString(stream, report.system.os_name);
    stream << ",\"os_major\":" << report.system.os_major
           << ",\"os_minor\":" << report.system.os_minor
           << ",\"os_build\":" << report.system.os_build
           << ",\"architecture\":";
    WriteString(stream, report.system.architecture);
    stream << ",\"tool_version\":";
    WriteString(stream, report.system.tool_version);
    stream << ",\"build_id\":";
    WriteString(stream, report.system.build_id);
    stream << '}';

    const auto write_file_identity = [&](const FileIdentityRecord& file) {
        stream << "{\"package_relative_path\":";
        WriteString(stream, file.package_relative_path);
        stream << ",\"sha256\":";
        WriteString(stream, file.sha256);
        stream << '}';
    };
    const auto write_service_identity = [&](
        const ServiceIdentityRecord& service) {
        stream << "{\"name\":";
        WriteString(stream, service.name);
        stream << ",\"binary\":";
        write_file_identity(service.binary);
        stream << ",\"service_type\":" << service.service_type
               << ",\"current_state\":" << service.current_state
               << ",\"running_kernel_driver\":"
               << (service.running_kernel_driver ? "true" : "false")
               << '}';
    };

    stream << ",\"runtime_identity\":{\"verified\":"
           << (report.runtime_identity.verified ? "true" : "false")
           << ",\"verifier\":";
    write_file_identity(report.runtime_identity.verifier);
    stream << ",\"kdbg_service\":";
    write_service_identity(report.runtime_identity.kdbg_service);
    stream << ",\"probe_service\":";
    write_service_identity(report.runtime_identity.probe_service);
    stream << '}';

    stream << ",\"backend\":{\"name\":";
    WriteString(stream, report.backend.name);
    stream << ",\"abi_version\":" << report.backend.abi_version
           << ",\"connected\":"
           << (report.backend.connected ? "true" : "false")
           << ",\"write_enabled\":"
           << (report.backend.write_enabled ? "true" : "false")
           << ",\"is_mock\":"
           << (report.backend.is_mock ? "true" : "false")
           << ",\"supports_physical_page_compare_write\":"
           << (report.backend.supports_physical_page_compare_write
                   ? "true" : "false");
    stream << '}';

    stream << ",\"probe_before\":"; WriteProbe(stream, report.probe_before);
    stream << ",\"probe_after_write\":";
    WriteProbe(stream, report.probe_after_write);
    stream << ",\"probe_after_rollback\":";
    WriteProbe(stream, report.probe_after_rollback);
    stream << ",\"session_before\":";
    WriteSession(stream, report.session_before);
    stream << ",\"session_after_apply\":";
    WriteSession(stream, report.session_after_apply);
    stream << ",\"session_final\":";
    WriteSession(stream, report.session_final);

    stream << ",\"latency\":{\"read_samples_ms\":[";
    for (std::size_t index = 0;
         index < report.read_latency_samples_ms.size(); ++index) {
        if (index != 0) stream << ',';
        stream << report.read_latency_samples_ms[index];
    }
    stream << "],\"read_median_ms\":" << report.read_latency_median_ms
           << ",\"read_p95_ms\":" << report.read_latency_p95_ms << '}';

    stream << ",\"operations\":[";
    for (std::size_t index = 0; index < report.operations.size(); ++index) {
        if (index != 0) stream << ',';
        const auto& operation = report.operations[index];
        stream << "{\"name\":"; WriteString(stream, operation.name);
        stream << ",\"requested_bytes\":" << operation.requested_bytes
               << ",\"completed_bytes\":" << operation.completed_bytes
               << ",\"latency_ms\":" << operation.latency_ms
               << ",\"passed\":"
               << (operation.passed ? "true" : "false") << '}';
    }
    stream << ']';

    stream << ",\"comparisons\":[";
    for (std::size_t index = 0; index < report.comparisons.size(); ++index) {
        if (index != 0) stream << ',';
        const auto& comparison = report.comparisons[index];
        stream << "{\"name\":"; WriteString(stream, comparison.name);
        stream << ",\"byte_count\":" << comparison.byte_count
               << ",\"mismatch_count\":" << comparison.mismatch_count
               << ",\"expected_crc32\":" << comparison.expected_crc32
               << ",\"actual_crc32\":" << comparison.actual_crc32
               << ",\"match\":"
               << (comparison.match ? "true" : "false") << '}';
    }
    stream << ']';

    stream << ",\"write_cleanup\":{\"edit_offset\":"
           << report.edit_offset
           << ",\"edit_length\":" << report.edit_length
           << ",\"apply_requested_bytes\":" << report.apply_requested_bytes
           << ((report.schema == "kdbg.live-verify.v2" ||
                report.schema == "kdbg.live-verify.raw-pfn.v1")
                   ? ",\"user_dirty_bytes\":" : "")
           << ((report.schema == "kdbg.live-verify.v2" ||
                report.schema == "kdbg.live-verify.raw-pfn.v1")
                   ? std::to_string(report.apply_requested_bytes) : "")
           << ((report.schema == "kdbg.live-verify.v2" ||
                report.schema == "kdbg.live-verify.raw-pfn.v1")
                   ? ",\"apply_driver_transferred_bytes\":" : "")
           << ((report.schema == "kdbg.live-verify.v2" ||
                report.schema == "kdbg.live-verify.raw-pfn.v1")
                   ? std::to_string(report.apply_driver_transferred_bytes)
                   : "")
           << ",\"rollback_requested_bytes\":"
           << report.rollback_requested_bytes
           << ((report.schema == "kdbg.live-verify.v2" ||
                report.schema == "kdbg.live-verify.raw-pfn.v1")
                   ? ",\"rollback_driver_transferred_bytes\":" : "")
           << ((report.schema == "kdbg.live-verify.v2" ||
                report.schema == "kdbg.live-verify.raw-pfn.v1")
                   ? std::to_string(report.rollback_driver_transferred_bytes)
                   : "")
           << ",\"rollback_attempted\":"
           << (report.rollback_attempted ? "true" : "false")
           << ",\"rollback_verified\":"
           << (report.rollback_verified ? "true" : "false")
           << ",\"final_relock_attempted\":"
           << (report.final_relock_attempted ? "true" : "false")
           << ",\"final_gate_locked\":"
           << (report.final_gate_locked ? "true" : "false") << '}';

    stream << ",\"errors\":[";
    for (std::size_t index = 0; index < report.errors.size(); ++index) {
        if (index != 0) stream << ',';
        const auto& error = report.errors[index];
        stream << "{\"code\":"; WriteString(stream, error.code);
        stream << ",\"operation\":"; WriteString(stream, error.operation);
        stream << ",\"message\":"; WriteString(stream, error.message);
        stream << ",\"native_code\":" << error.native_code
               << ",\"requested\":" << error.requested
               << ",\"completed\":" << error.completed << '}';
    }
    stream << "]}";
    return stream.str();
}

}  // namespace kdbg::live_verify

#include "core/pfn/MemProcFsProvider.h"

#include <array>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace kdbg {
namespace {

#ifdef _WIN32
constexpr std::size_t kMaxBridgeOutput = 8U * 1024U * 1024U;
constexpr std::size_t kMaxWindowsCommandCharacters = 32767U;
constexpr DWORD kBridgePipeBytes = 64U * 1024U;
constexpr DWORD kBridgePollMilliseconds = 5;
constexpr DWORD kBridgeShutdownMilliseconds = 1000;

class ScopedHandle {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~ScopedHandle() { Reset(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            Reset(std::exchange(other.handle_, nullptr));
        }
        return *this;
    }

    [[nodiscard]] HANDLE Get() const noexcept { return handle_; }

    void Reset(HANDLE handle = nullptr) noexcept {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_{nullptr};
};

std::wstring Utf8ToWide(std::string_view value) {
    if (value.empty()) return {};
    const int count = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    if (count <= 0) return {};
    std::wstring output(static_cast<std::size_t>(count), L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        output.data(),
        count);
    return output;
}

std::wstring QuoteWindowsArgument(std::wstring_view value) {
    if (value.empty()) return L"\"\"";
    if (value.find_first_of(L" \t\"") == std::wstring_view::npos) {
        return std::wstring(value);
    }
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (const wchar_t c : value) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'\"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(L'\"');
            slashes = 0;
            continue;
        }
        result.append(slashes, L'\\');
        slashes = 0;
        result.push_back(c);
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}
#endif

[[nodiscard]] bool IsAllowedPageSize(std::uint64_t page_size) noexcept {
    return page_size == 0x1000ULL ||
           page_size == 0x200000ULL ||
           page_size == 0x40000000ULL;
}

template <typename UInt>
bool ReadDecimal(std::istringstream& stream, UInt* value) {
    std::string token;
    if (value == nullptr || !(stream >> token) || token.empty() ||
        token.front() == '+' || token.front() == '-') {
        return false;
    }
    const auto parsed = std::from_chars(
        token.data(), token.data() + token.size(), *value, 10);
    return parsed.ec == std::errc{} &&
           parsed.ptr == token.data() + token.size();
}

[[nodiscard]] bool IsValidUtf8(std::string_view value) noexcept {
    std::size_t index = 0;
    while (index < value.size()) {
        const auto first = static_cast<unsigned char>(value[index]);
        std::size_t continuation_count = 0;
        std::uint32_t code_point = 0;
        if (first <= 0x7FU) {
            ++index;
            continue;
        }
        if (first >= 0xC2U && first <= 0xDFU) {
            continuation_count = 1;
            code_point = first & 0x1FU;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            continuation_count = 2;
            code_point = first & 0x0FU;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            continuation_count = 3;
            code_point = first & 0x07U;
        } else {
            return false;
        }
        if (continuation_count > value.size() - index - 1U) return false;
        for (std::size_t offset = 1; offset <= continuation_count; ++offset) {
            const auto continuation =
                static_cast<unsigned char>(value[index + offset]);
            if ((continuation & 0xC0U) != 0x80U) return false;
            code_point = (code_point << 6U) | (continuation & 0x3FU);
        }
        if ((continuation_count == 2U && code_point < 0x800U) ||
            (continuation_count == 3U && code_point < 0x10000U) ||
            (code_point >= 0xD800U && code_point <= 0xDFFFU) ||
            code_point > 0x10FFFFU) {
            return false;
        }
        index += continuation_count + 1U;
    }
    return true;
}

[[nodiscard]] bool AsciiEqualInsensitive(
    std::string_view left,
    std::string_view right) noexcept {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        unsigned char lhs = static_cast<unsigned char>(left[index]);
        unsigned char rhs = static_cast<unsigned char>(right[index]);
        if (lhs >= 'A' && lhs <= 'Z') lhs = static_cast<unsigned char>(lhs + 0x20U);
        if (rhs >= 'A' && rhs <= 'Z') rhs = static_cast<unsigned char>(rhs + 0x20U);
        if (lhs != rhs) return false;
    }
    return true;
}

Result<void> ValidateUtf8Value(
    std::string_view value,
    std::string_view label,
    bool allow_empty) {
    if ((!allow_empty && value.empty()) || value.find('\0') != std::string_view::npos) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            std::string(label) + " is empty or contains an embedded NUL",
            "MemProcFsProvider::ValidateConfiguration"));
    }
    if (value.size() > MemProcFsProvider::kMaxBridgeArgumentBytes) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            std::string(label) + " exceeds the product cap",
            "MemProcFsProvider::ValidateConfiguration",
            0,
            MemProcFsProvider::kMaxBridgeArgumentBytes,
            value.size()));
    }
    if (!IsValidUtf8(value)) {
        return Result<void>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            std::string(label) + " is not valid UTF-8",
            "MemProcFsProvider::ValidateConfiguration"));
    }
    return Result<void>::Success();
}

Result<void> ValidateConfiguration(
    const MemProcFsConfiguration& configuration) {
    if (configuration.vmm_arguments.size() >
        MemProcFsProvider::kMaxVmmArguments) {
        return Result<void>::Failure(MakeError(
            ErrorCode::LimitReached,
            "MemProcFS --vmm-arg count exceeds the product cap",
            "MemProcFsProvider::ValidateConfiguration",
            0,
            MemProcFsProvider::kMaxVmmArguments,
            configuration.vmm_arguments.size()));
    }

    if (configuration.device.has_value()) {
        auto valid = ValidateUtf8Value(
            *configuration.device, "MemProcFS device", false);
        if (!valid) return valid;
        if (configuration.device->front() == '-') {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "MemProcFS device must not be option-like",
                "MemProcFsProvider::ValidateConfiguration"));
        }
    }

    if (configuration.vmm_path.has_value()) {
        if (configuration.vmm_path->empty()) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "MemProcFS vmm.dll path is empty",
                "MemProcFsProvider::ValidateConfiguration"));
        }
#ifdef _WIN32
        const auto& native = configuration.vmm_path->native();
        if (native.find(L'\0') != std::wstring::npos) {
#else
        const auto& native = configuration.vmm_path->native();
        if (native.find('\0') != std::string::npos) {
#endif
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "MemProcFS vmm.dll path contains an embedded NUL",
                "MemProcFsProvider::ValidateConfiguration"));
        }
    }

    for (const auto& argument : configuration.vmm_arguments) {
        auto valid = ValidateUtf8Value(
            argument, "MemProcFS additional VMMDLL argument", true);
        if (!valid) return valid;
        if (AsciiEqualInsensitive(argument, "-device") ||
            AsciiEqualInsensitive(argument, "--device") ||
            AsciiEqualInsensitive(argument, "-waitinitialize") ||
            AsciiEqualInsensitive(argument, "--waitinitialize") ||
            AsciiEqualInsensitive(argument, "-disable-python") ||
            AsciiEqualInsensitive(argument, "--disable-python")) {
            return Result<void>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "MemProcFS additional arguments must not override provider-controlled options",
                "MemProcFsProvider::ValidateConfiguration"));
        }
    }
    return Result<void>::Success();
}

}  // namespace

MemProcFsProvider::MemProcFsProvider(
    std::filesystem::path bridge_path,
    MemProcFsConfiguration configuration,
    std::chrono::milliseconds timeout)
    : bridge_path_(std::move(bridge_path)),
      configuration_(std::move(configuration)),
      timeout_(timeout) {}

std::filesystem::path MemProcFsProvider::PackagedBridgePath() {
#ifdef _WIN32
    std::vector<wchar_t> executable(32768U, L'\0');
    SetLastError(ERROR_SUCCESS);
    const DWORD length = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (length == 0 ||
        static_cast<std::size_t>(length) >= executable.size()) {
        return {};
    }
    return std::filesystem::path(
        std::wstring(executable.data(), length)).parent_path() /
        L"plugins" / L"memprocfs_bridge" / L"kdbg_memprocfs_bridge.exe";
#else
    return std::filesystem::current_path() / "plugins" /
        "memprocfs_bridge" / "kdbg_memprocfs_bridge";
#endif
}

const char* MemProcFsProvider::Name() const noexcept {
    return "memprocfs-bridge";
}

Result<PfnUsageResult> MemProcFsProvider::Query(
    std::uint64_t pfn,
    std::stop_token stop_token) {
    if (pfn > std::numeric_limits<std::uint32_t>::max()) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::InvalidPfn,
            "MemProcFS accepts PFNs up to 32 bits",
            "MemProcFsProvider::Query"));
    }
    if (stop_token.stop_requested()) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::Cancelled,
            "MemProcFS query was cancelled before launch",
            "MemProcFsProvider::Query"));
    }
    auto configuration = ValidateConfiguration(configuration_);
    if (!configuration) {
        return Result<PfnUsageResult>::Failure(configuration.GetError());
    }
    auto output = Execute(static_cast<std::uint32_t>(pfn), stop_token);
    if (!output) return Result<PfnUsageResult>::Failure(output.GetError());
    return ParseOutput(pfn, output.Value());
}

Result<std::string> MemProcFsProvider::Execute(
    std::uint32_t pfn,
    std::stop_token stop_token) const {
    if (timeout_ <= std::chrono::milliseconds::zero()) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "MemProcFS bridge timeout must be positive",
            "MemProcFsProvider::Execute"));
    }
#ifdef _WIN32
    std::error_code bridge_error;
    const auto bridge_status = std::filesystem::status(
        bridge_path_, bridge_error);
    if (bridge_path_.empty() || bridge_error ||
        !std::filesystem::is_regular_file(bridge_status)) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::BridgeUnavailable,
            "MemProcFS bridge path is unavailable or is not a regular file",
            "MemProcFsProvider::Execute",
            static_cast<std::uint64_t>(bridge_error.value())));
    }
    const auto resolved_bridge = std::filesystem::absolute(
        bridge_path_, bridge_error);
    if (bridge_error) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::BridgeUnavailable,
            "Unable to resolve the MemProcFS bridge path",
            "MemProcFsProvider::Execute",
            static_cast<std::uint64_t>(bridge_error.value())));
    }

    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE raw_read_pipe = nullptr;
    HANDLE raw_write_pipe = nullptr;
    if (!CreatePipe(
            &raw_read_pipe,
            &raw_write_pipe,
            &security,
            kBridgePipeBytes)) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "CreatePipe failed for MemProcFS bridge",
            "MemProcFsProvider::Execute",
            GetLastError()));
    }
    ScopedHandle read_pipe(raw_read_pipe);
    ScopedHandle write_pipe(raw_write_pipe);
    if (!SetHandleInformation(read_pipe.Get(), HANDLE_FLAG_INHERIT, 0)) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to restrict MemProcFS bridge pipe inheritance",
            "MemProcFsProvider::Execute",
            GetLastError()));
    }

    ScopedHandle job(CreateJobObjectW(nullptr, nullptr));
    if (job.Get() == nullptr) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "CreateJobObject failed for MemProcFS bridge",
            "MemProcFsProvider::Execute",
            GetLastError()));
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{};
    job_limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(
            job.Get(),
            JobObjectExtendedLimitInformation,
            &job_limits,
            sizeof(job_limits))) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to configure MemProcFS bridge job object",
            "MemProcFsProvider::Execute",
            GetLastError()));
    }

    std::vector<std::wstring> arguments;
    arguments.reserve(
        (configuration_.vmm_arguments.size() * 2U) + 6U);
    if (configuration_.device.has_value()) {
        const auto device = Utf8ToWide(*configuration_.device);
        if (device.empty()) {
            return Result<std::string>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "MemProcFS device could not be converted to UTF-16",
                "MemProcFsProvider::Execute"));
        }
        arguments.emplace_back(L"--device");
        arguments.push_back(device);
    }
    if (configuration_.vmm_path.has_value()) {
        arguments.emplace_back(L"--vmm");
        arguments.push_back(configuration_.vmm_path->native());
    }
    for (const auto& argument : configuration_.vmm_arguments) {
        const auto wide = Utf8ToWide(argument);
        if (!argument.empty() && wide.empty()) {
            return Result<std::string>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "MemProcFS additional argument could not be converted to UTF-16",
                "MemProcFsProvider::Execute"));
        }
        arguments.emplace_back(L"--vmm-arg");
        arguments.push_back(wide);
    }
    arguments.emplace_back(L"--pfn");
    arguments.push_back(std::to_wstring(pfn));
    if (arguments.size() > kMaxBridgeArguments) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::LimitReached,
            "MemProcFS bridge argument count exceeds the product cap",
            "MemProcFsProvider::Execute",
            0,
            kMaxBridgeArguments,
            arguments.size()));
    }

    std::wstring command = QuoteWindowsArgument(resolved_bridge.native());
    for (const auto& argument : arguments) {
        command.push_back(L' ');
        command += QuoteWindowsArgument(argument);
        if (command.size() >= kMaxWindowsCommandCharacters) {
            return Result<std::string>::Failure(MakeError(
                ErrorCode::LimitReached,
                "MemProcFS bridge command line exceeds the Windows limit",
                "MemProcFsProvider::Execute",
                0,
                kMaxWindowsCommandCharacters - 1U,
                command.size()));
        }
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_pipe.Get();
    startup.hStdError = write_pipe.Get();
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION raw_process{};

    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    const BOOL created = CreateProcessW(
        resolved_bridge.c_str(),
        mutable_command.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr,
        resolved_bridge.parent_path().empty()
            ? nullptr
            : resolved_bridge.parent_path().c_str(),
        &startup,
        &raw_process);
    const DWORD create_error = created ? ERROR_SUCCESS : GetLastError();
    ScopedHandle process(raw_process.hProcess);
    ScopedHandle process_thread(raw_process.hThread);
    write_pipe.Reset();
    if (!created) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::BridgeUnavailable,
            "Unable to start the MemProcFS bridge",
            "MemProcFsProvider::Execute",
            create_error));
    }

    if (!AssignProcessToJobObject(job.Get(), process.Get())) {
        const DWORD native_error = GetLastError();
        TerminateProcess(process.Get(), native_error);
        WaitForSingleObject(process.Get(), kBridgeShutdownMilliseconds);
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to assign MemProcFS bridge to its job object",
            "MemProcFsProvider::Execute",
            native_error));
    }
    if (ResumeThread(process_thread.Get()) == static_cast<DWORD>(-1)) {
        const DWORD native_error = GetLastError();
        TerminateJobObject(job.Get(), native_error);
        WaitForSingleObject(process.Get(), kBridgeShutdownMilliseconds);
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to resume the MemProcFS bridge process",
            "MemProcFsProvider::Execute",
            native_error));
    }

    std::string output;
    std::array<char, 4096> buffer{};
    auto drain_available = [&]() -> Result<bool> {
        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(
                    read_pipe.Get(), nullptr, 0, nullptr, &available, nullptr)) {
                const DWORD native_error = GetLastError();
                if (native_error == ERROR_BROKEN_PIPE) {
                    return Result<bool>::Success(true);
                }
                return Result<bool>::Failure(MakeError(
                    ErrorCode::IoFailure,
                    "Unable to inspect MemProcFS bridge output",
                    "MemProcFsProvider::Execute",
                    native_error));
            }
            if (available == 0) {
                return Result<bool>::Success(false);
            }
            if (static_cast<std::size_t>(available) >
                kMaxBridgeOutput - output.size()) {
                return Result<bool>::Failure(MakeError(
                    ErrorCode::LimitReached,
                    "MemProcFS bridge output exceeded 8 MiB",
                    "MemProcFsProvider::Execute",
                    0,
                    kMaxBridgeOutput,
                    output.size() + static_cast<std::size_t>(available)));
            }
            const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
                buffer.size(), static_cast<std::size_t>(available)));
            DWORD completed = 0;
            if (!ReadFile(
                    read_pipe.Get(),
                    buffer.data(),
                    requested,
                    &completed,
                    nullptr)) {
                const DWORD native_error = GetLastError();
                if (native_error == ERROR_BROKEN_PIPE) {
                    return Result<bool>::Success(true);
                }
                return Result<bool>::Failure(MakeError(
                    ErrorCode::IoFailure,
                    "Unable to read MemProcFS bridge output",
                    "MemProcFsProvider::Execute",
                    native_error,
                    requested,
                    completed));
            }
            if (completed == 0) {
                return Result<bool>::Failure(MakeError(
                    ErrorCode::ShortRead,
                    "MemProcFS bridge pipe returned an empty read",
                    "MemProcFsProvider::Execute",
                    0,
                    requested,
                    0));
            }
            output.append(buffer.data(), completed);
        }
    };

    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    std::optional<Error> supervision_error;
    for (;;) {
        auto drained = drain_available();
        if (!drained) {
            supervision_error = drained.GetError();
            break;
        }
        const DWORD completed_wait = WaitForSingleObject(process.Get(), 0);
        if (completed_wait == WAIT_OBJECT_0) {
            break;
        }
        if (completed_wait == WAIT_FAILED) {
            supervision_error = MakeError(
                ErrorCode::IoFailure,
                "Waiting for the MemProcFS bridge failed",
                "MemProcFsProvider::Execute",
                GetLastError());
            break;
        }
        if (stop_token.stop_requested()) {
            supervision_error = MakeError(
                ErrorCode::Cancelled,
                "MemProcFS query was cancelled",
                "MemProcFsProvider::Execute");
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            supervision_error = MakeError(
                ErrorCode::IoFailure,
                "MemProcFS bridge timed out",
                "MemProcFsProvider::Execute");
            break;
        }

        const DWORD wait = WaitForSingleObject(
            process.Get(), kBridgePollMilliseconds);
        if (wait == WAIT_OBJECT_0) {
            break;
        }
        if (wait == WAIT_FAILED) {
            supervision_error = MakeError(
                ErrorCode::IoFailure,
                "Waiting for the MemProcFS bridge failed",
                "MemProcFsProvider::Execute",
                GetLastError());
            break;
        }
        if (wait != WAIT_TIMEOUT) {
            supervision_error = MakeError(
                ErrorCode::IoFailure,
                "MemProcFS bridge wait returned an unexpected status",
                "MemProcFsProvider::Execute",
                wait);
            break;
        }
    }

    if (supervision_error.has_value()) {
        if (!TerminateJobObject(job.Get(), ERROR_CANCELLED)) {
            TerminateProcess(process.Get(), ERROR_CANCELLED);
        }
        WaitForSingleObject(process.Get(), kBridgeShutdownMilliseconds);
        job.Reset();
        static_cast<void>(drain_available());
        return Result<std::string>::Failure(std::move(*supervision_error));
    }

    DWORD exit_code = 0;
    if (!GetExitCodeProcess(process.Get(), &exit_code)) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to obtain the MemProcFS bridge exit code",
            "MemProcFsProvider::Execute",
            GetLastError()));
    }

    job.Reset();
    const auto pipe_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds{kBridgeShutdownMilliseconds};
    for (;;) {
        auto drained = drain_available();
        if (!drained) {
            return Result<std::string>::Failure(drained.GetError());
        }
        if (drained.Value()) break;
        if (std::chrono::steady_clock::now() >= pipe_deadline) {
            return Result<std::string>::Failure(MakeError(
                ErrorCode::IoFailure,
                "MemProcFS bridge output pipe did not close",
                "MemProcFsProvider::Execute"));
        }
        Sleep(1);
    }

    if (exit_code != 0) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::BridgeUnavailable,
            output.empty() ? "MemProcFS bridge returned an error" : output,
            "MemProcFsProvider::Execute",
            exit_code));
    }
    return Result<std::string>::Success(std::move(output));
#else
    (void)bridge_path_;
    (void)timeout_;
    (void)pfn;
    (void)stop_token;
    return Result<std::string>::Failure(MakeError(
        ErrorCode::Unsupported,
        "MemProcFS bridge process integration is Windows-only",
        "MemProcFsProvider::Execute"));
#endif
}

Result<PfnUsageResult> MemProcFsProvider::ParseOutput(
    std::uint64_t expected_pfn,
    std::string_view output,
    std::size_t max_mappings) {
    if (max_mappings == 0) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "MemProcFS protocol mapping limit must be non-zero",
            "MemProcFsProvider::ParseOutput"));
    }

    std::istringstream stream{std::string(output)};
    std::string line;
    if (!std::getline(stream, line)) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::ParseError,
            "MemProcFS bridge response is empty",
            "MemProcFsProvider::ParseOutput"));
    }

    std::istringstream header(line);
    std::string record;
    std::uint32_t protocol = 0;
    std::uint64_t pfn = 0;
    if (!(header >> record) ||
        !ReadDecimal(header, &protocol) ||
        !ReadDecimal(header, &pfn) ||
        record != "KDBG_PFN_RESULT" || protocol != 1 || pfn != expected_pfn) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::ParseError,
            "MemProcFS bridge returned an invalid protocol header",
            "MemProcFsProvider::ParseOutput"));
    }
    header >> std::ws;
    if (!header.eof()) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::ParseError,
            "MemProcFS bridge protocol header has trailing fields",
            "MemProcFsProvider::ParseOutput"));
    }

    PfnUsageResult result{};
    result.pfn = pfn;
    result.provider = "memprocfs-bridge";
    bool saw_end = false;
    while (std::getline(stream, line)) {
        std::istringstream row(line);
        std::string kind;
        if (!(row >> kind)) continue;
        if (kind == "END") {
            row >> std::ws;
            if (!row.eof()) {
                return Result<PfnUsageResult>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "MemProcFS END record has trailing fields",
                    "MemProcFsProvider::ParseOutput"));
            }
            saw_end = true;
            break;
        }
        if (kind == "ERROR") {
            std::string message;
            row >> std::ws;
            if (row.peek() != '"' || !(row >> std::quoted(message))) {
                return Result<PfnUsageResult>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "MemProcFS ERROR record is malformed",
                    "MemProcFsProvider::ParseOutput"));
            }
            row >> std::ws;
            if (!row.eof()) {
                return Result<PfnUsageResult>::Failure(MakeError(
                    ErrorCode::ParseError,
                    "MemProcFS ERROR record has trailing fields",
                    "MemProcFsProvider::ParseOutput"));
            }
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::BridgeUnavailable,
                message.empty() ? "MemProcFS bridge reported an error" : message,
                "MemProcFsProvider::ParseOutput"));
        }
        if (kind != "MAP") {
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::ParseError,
                "MemProcFS bridge returned an unknown record",
                "MemProcFsProvider::ParseOutput"));
        }
        if (result.mappings.size() >= max_mappings) {
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::LimitReached,
                "MemProcFS bridge returned too many mapping records",
                "MemProcFsProvider::ParseOutput",
                0,
                max_mappings,
                result.mappings.size() + 1U));
        }

        ProcessUsage usage{};
        std::uint32_t confidence = 0;
        std::uint32_t shared = 0;
        std::uint32_t writable = 0;
        std::uint32_t user = 0;
        std::uint32_t nx = 0;
        if (!ReadDecimal(row, &usage.pid) ||
            !ReadDecimal(row, &usage.virtual_address) ||
            !ReadDecimal(row, &usage.pte_address) ||
            !ReadDecimal(row, &usage.page_size) ||
            !ReadDecimal(row, &confidence) ||
            !ReadDecimal(row, &shared) ||
            !ReadDecimal(row, &writable) ||
            !ReadDecimal(row, &user) ||
            !ReadDecimal(row, &nx)) {
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::ParseError,
                "MemProcFS MAP record is malformed",
                "MemProcFsProvider::ParseOutput"));
        }
        row >> std::ws;
        if (row.peek() != '"' ||
            !(row >> std::quoted(usage.mapping_type))) {
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::ParseError,
                "MemProcFS MAP record has an invalid mapping type",
                "MemProcFsProvider::ParseOutput"));
        }
        row >> std::ws;
        if (row.peek() != '"' ||
            !(row >> std::quoted(usage.process_name))) {
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::ParseError,
                "MemProcFS MAP record has an invalid process name",
                "MemProcFsProvider::ParseOutput"));
        }
        row >> std::ws;
        if (!row.eof() || confidence > 3 ||
            (shared != 0 && shared != 1) ||
            (writable != 0 && writable != 1) ||
            (user != 0 && user != 1) ||
            (nx != 0 && nx != 1) ||
            !IsAllowedPageSize(usage.page_size)) {
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::ParseError,
                "MemProcFS MAP record contains an invalid field value",
                "MemProcFsProvider::ParseOutput"));
        }
        switch (confidence) {
        case 0: usage.confidence = MappingConfidence::Unknown; break;
        case 1: usage.confidence = MappingConfidence::Low; break;
        case 2: usage.confidence = MappingConfidence::Medium; break;
        case 3: usage.confidence = MappingConfidence::High; break;
        default: break;
        }
        usage.shared = shared == 1;
        usage.writable = writable == 1;
        usage.user_accessible = user == 1;
        usage.no_execute = nx == 1;
        usage.source = "memprocfs-bridge";
        result.mappings.push_back(std::move(usage));
    }

    if (!saw_end) {
        return Result<PfnUsageResult>::Failure(MakeError(
            ErrorCode::ParseError,
            "MemProcFS bridge response is missing END",
            "MemProcFsProvider::ParseOutput"));
    }
    while (std::getline(stream, line)) {
        std::istringstream trailing(line);
        trailing >> std::ws;
        if (!trailing.eof()) {
            return Result<PfnUsageResult>::Failure(MakeError(
                ErrorCode::ParseError,
                "MemProcFS bridge response has records after END",
                "MemProcFsProvider::ParseOutput"));
        }
    }
    return Result<PfnUsageResult>::Success(std::move(result));
}

}  // namespace kdbg

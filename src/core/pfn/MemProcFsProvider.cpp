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
constexpr DWORD kBridgePollMilliseconds = 25;
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

}  // namespace

MemProcFsProvider::MemProcFsProvider(
    std::filesystem::path bridge_path,
    std::vector<std::string> bridge_arguments,
    std::chrono::milliseconds timeout)
    : bridge_path_(std::move(bridge_path)),
      bridge_arguments_(std::move(bridge_arguments)),
      timeout_(timeout) {}

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
    std::vector<std::string> arguments = bridge_arguments_;
    arguments.emplace_back("--pfn");
    arguments.push_back(std::to_string(pfn));
    auto output = Execute(arguments, stop_token);
    if (!output) return Result<PfnUsageResult>::Failure(output.GetError());
    return ParseOutput(pfn, output.Value());
}

Result<std::string> MemProcFsProvider::Execute(
    const std::vector<std::string>& arguments,
    std::stop_token stop_token) const {
#ifdef _WIN32
    if (bridge_path_.empty() || !std::filesystem::exists(bridge_path_)) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::BridgeUnavailable,
            "MemProcFS bridge executable does not exist",
            "MemProcFsProvider::Execute"));
    }
    if (timeout_ <= std::chrono::milliseconds::zero()) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "MemProcFS bridge timeout must be positive",
            "MemProcFsProvider::Execute"));
    }

    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE raw_read_pipe = nullptr;
    HANDLE raw_write_pipe = nullptr;
    if (!CreatePipe(&raw_read_pipe, &raw_write_pipe, &security, 0)) {
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

    std::wstring command = QuoteWindowsArgument(bridge_path_.wstring());
    for (const auto& argument : arguments) {
        const auto wide = Utf8ToWide(argument);
        if (!argument.empty() && wide.empty()) {
            return Result<std::string>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "MemProcFS bridge argument is not valid UTF-8",
                "MemProcFsProvider::Execute"));
        }
        command.push_back(L' ');
        command += QuoteWindowsArgument(wide);
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
        bridge_path_.c_str(),
        mutable_command.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr,
        bridge_path_.parent_path().empty()
            ? nullptr
            : bridge_path_.parent_path().c_str(),
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
    (void)arguments;
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

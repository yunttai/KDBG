#include "TestHarness.h"

#include "core/address/AddressList.h"
#include "core/address/PointerResolver.h"
#include "core/memory/MockMemoryBackend.h"
#include "core/memory/KDbgBackend.h"
#include "core/memory/VerifiedWriter.h"
#include "core/pfn/MemProcFsProvider.h"
#include "core/pfn/PageTableReverseMapper.h"
#include "core/snapshot/MemorySnapshot.h"

#ifdef _WIN32
#include <Windows.h>
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

bool WriteBytes(
    kdbg::MockMemoryBackend& backend,
    std::uint64_t address,
    std::span<const std::uint8_t> bytes) {
    const auto armed = backend.SetWriteEnabled(true);
    if (!armed) return false;
    const auto written = backend.WritePhysical(address, bytes);
    const auto locked = backend.SetWriteEnabled(false);
    return written && locked && written.Value() == bytes.size();
}

template <typename T>
bool WriteScalar(
    kdbg::MockMemoryBackend& backend,
    std::uint64_t address,
    const T& value) {
    const auto* begin = reinterpret_cast<const std::uint8_t*>(&value);
    return WriteBytes(
        backend,
        address,
        std::span<const std::uint8_t>(begin, sizeof(value)));
}

template <typename T>
bool PatchFileScalar(
    const std::filesystem::path& path,
    std::streamoff offset,
    const T& value) {
    std::fstream file(
        path,
        std::ios::binary | std::ios::in | std::ios::out);
    if (!file) return false;
    file.seekp(offset);
    file.write(reinterpret_cast<const char*>(&value), sizeof(value));
    return static_cast<bool>(file);
}

#ifdef _WIN32
class ScopedEnvironment {
public:
    ScopedEnvironment(std::string name, std::string value)
        : name_(std::move(name)) {
        char* previous = nullptr;
        std::size_t length = 0;
        if (_dupenv_s(&previous, &length, name_.c_str()) == 0 &&
            previous != nullptr) {
            previous_ = previous;
        }
        std::free(previous);
        configured_ = _putenv_s(name_.c_str(), value.c_str()) == 0;
    }

    ~ScopedEnvironment() {
        if (!configured_) return;
        const char* value = previous_.has_value() ? previous_->c_str() : "";
        static_cast<void>(_putenv_s(name_.c_str(), value));
    }

    ScopedEnvironment(const ScopedEnvironment&) = delete;
    ScopedEnvironment& operator=(const ScopedEnvironment&) = delete;

    [[nodiscard]] bool Configured() const noexcept { return configured_; }

private:
    std::string name_;
    std::optional<std::string> previous_;
    bool configured_{false};
};

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int bytes = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (bytes <= 0) return {};
    std::string result(static_cast<std::size_t>(bytes), '\0');
    return WideCharToMultiByte(
               CP_UTF8,
               WC_ERR_INVALID_CHARS,
               value.data(),
               static_cast<int>(value.size()),
               result.data(),
               bytes,
               nullptr,
               nullptr) == bytes
        ? result
        : std::string{};
}

std::vector<std::string> VmmArguments(
    std::size_t count,
    const std::string& quoted_value = {}) {
    std::vector<std::string> arguments;
    arguments.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        if (index == 0 && !quoted_value.empty()) {
            arguments.push_back(quoted_value);
        } else if (index == 1) {
            arguments.emplace_back("--pfn");
        } else if (index == 2) {
            arguments.emplace_back();
        } else {
            arguments.push_back("value-" + std::to_string(index));
        }
    }
    return arguments;
}
#endif

}  // namespace

void RunAdvancedCoreTests(kdbg::test::TestRunner& runner) {
    using namespace kdbg;

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const std::array<std::uint8_t, 2> physical_bytes{0xA5U, 0x5AU};
        KDBG_CHECK(runner, backend.SetWriteEnabled(true).Ok());
        KDBG_CHECK(runner, backend.WritePhysical(
            MockMemoryBackend::kBaseAddress + 0x40U,
            physical_bytes).Ok());
        KDBG_CHECK(runner, !backend.Info().write_enabled);
        const auto repeated_physical = backend.WritePhysical(
            MockMemoryBackend::kBaseAddress + 0x42U,
            physical_bytes);
        KDBG_CHECK(runner, !repeated_physical.Ok());
        if (!repeated_physical) {
            KDBG_CHECK(
                runner,
                repeated_physical.GetError().code == ErrorCode::WriteLocked);
        }

        const std::array<std::uint8_t, 1> process_byte{0x3CU};
        KDBG_CHECK(runner, backend.SetWriteEnabled(true).Ok());
        KDBG_CHECK(runner, backend.WriteProcessVirtual(
            MockMemoryBackend::kMockPid,
            MockMemoryBackend::kVirtualBase + 0x50U,
            process_byte).Ok());
        KDBG_CHECK(runner, !backend.Info().write_enabled);
        const auto repeated_process = backend.WriteProcessVirtual(
            MockMemoryBackend::kMockPid,
            MockMemoryBackend::kVirtualBase + 0x51U,
            process_byte);
        KDBG_CHECK(runner, !repeated_process.Ok());
        if (!repeated_process) {
            KDBG_CHECK(
                runner,
                repeated_process.GetError().code == ErrorCode::WriteLocked);
        }
        backend.Close();
    }

    const auto run_provider_tests = [&runner]() {
        using namespace kdbg;

    {
        MemProcFsProvider invalid_timeout(
            {}, {}, std::chrono::milliseconds::zero());
        const auto timeout_result = invalid_timeout.Query(1, {});
        KDBG_CHECK(runner, !timeout_result.Ok());
        if (!timeout_result) {
            KDBG_CHECK(runner,
                timeout_result.GetError().code == ErrorCode::InvalidArgument);
        }

        std::stop_source stopped;
        stopped.request_stop();
        MemProcFsProvider cancelled({});
        const auto cancelled_result = cancelled.Query(1, stopped.get_token());
        KDBG_CHECK(runner, !cancelled_result.Ok());
        if (!cancelled_result) {
            KDBG_CHECK(runner,
                cancelled_result.GetError().code == ErrorCode::Cancelled);
        }

        MemProcFsProvider reserved(
            {},
            MemProcFsConfiguration{
                .device = "--help",
                .vmm_path = std::nullopt,
                .vmm_arguments = {}});
        const auto reserved_result = reserved.Query(1, {});
        KDBG_CHECK(runner, !reserved_result.Ok());
        if (!reserved_result) {
            KDBG_CHECK(runner,
                reserved_result.GetError().code == ErrorCode::InvalidArgument);
        }

        MemProcFsProvider oversized(
            {},
            MemProcFsConfiguration{
                .device = std::string(
                    MemProcFsProvider::kMaxBridgeArgumentBytes + 1U,
                    'A'),
                .vmm_path = std::nullopt,
                .vmm_arguments = {}});
        const auto oversized_result = oversized.Query(1, {});
        KDBG_CHECK(runner, !oversized_result.Ok());
        if (!oversized_result) {
            KDBG_CHECK(runner,
                oversized_result.GetError().code == ErrorCode::LimitReached);
        }

        MemProcFsProvider too_many(
            {},
            MemProcFsConfiguration{
                .device = std::nullopt,
                .vmm_path = std::nullopt,
                .vmm_arguments = std::vector<std::string>(
                    MemProcFsProvider::kMaxVmmArguments + 1U,
                    "value")});
        const auto too_many_result = too_many.Query(1, {});
        KDBG_CHECK(runner, !too_many_result.Ok());
        if (!too_many_result) {
            KDBG_CHECK(runner,
                too_many_result.GetError().code == ErrorCode::LimitReached);
        }

        MemProcFsProvider embedded_nul(
            {},
            MemProcFsConfiguration{
                .device = std::string("a\0b", 3),
                .vmm_path = std::nullopt,
                .vmm_arguments = {}});
        const auto nul_result = embedded_nul.Query(1, {});
        KDBG_CHECK(runner, !nul_result.Ok());
        if (!nul_result) {
            KDBG_CHECK(runner,
                nul_result.GetError().code == ErrorCode::InvalidArgument);
        }

        MemProcFsProvider invalid_pfn({});
        const auto invalid_pfn_result = invalid_pfn.Query(
            static_cast<std::uint64_t>(
                std::numeric_limits<std::uint32_t>::max()) + 1U,
            {});
        KDBG_CHECK(runner, !invalid_pfn_result.Ok());
        if (!invalid_pfn_result) {
            KDBG_CHECK(runner,
                invalid_pfn_result.GetError().code == ErrorCode::InvalidPfn);
        }

        MemProcFsProvider too_many_vmm(
            {},
            MemProcFsConfiguration{
                .device = std::nullopt,
                .vmm_path = std::nullopt,
                .vmm_arguments = VmmArguments(
                    MemProcFsProvider::kMaxVmmArguments + 1U)});
        const auto too_many_vmm_result = too_many_vmm.Query(1, {});
        KDBG_CHECK(runner, !too_many_vmm_result.Ok());
        if (!too_many_vmm_result) {
            KDBG_CHECK(runner,
                too_many_vmm_result.GetError().code == ErrorCode::LimitReached);
            KDBG_CHECK(runner,
                too_many_vmm_result.GetError().requested ==
                    MemProcFsProvider::kMaxVmmArguments);
            KDBG_CHECK(runner,
                too_many_vmm_result.GetError().completed ==
                    MemProcFsProvider::kMaxVmmArguments + 1U);
        }

        MemProcFsProvider controlled_override(
            {},
            MemProcFsConfiguration{
                .device = std::nullopt,
                .vmm_path = std::nullopt,
                .vmm_arguments = {"-DeViCe", "untrusted"}});
        const auto controlled_override_result =
            controlled_override.Query(1, {});
        KDBG_CHECK(runner, !controlled_override_result.Ok());
        if (!controlled_override_result) {
            KDBG_CHECK(runner,
                controlled_override_result.GetError().code ==
                    ErrorCode::InvalidArgument);
        }

        MemProcFsProvider invalid_utf8(
            {},
            MemProcFsConfiguration{
                .device = std::nullopt,
                .vmm_path = std::nullopt,
                .vmm_arguments = {std::string("\xC0\xAF", 2)}});
        const auto invalid_utf8_result = invalid_utf8.Query(1, {});
        KDBG_CHECK(runner, !invalid_utf8_result.Ok());
        if (!invalid_utf8_result) {
            KDBG_CHECK(runner,
                invalid_utf8_result.GetError().code ==
                    ErrorCode::InvalidArgument);
        }
    }

#ifdef _WIN32
    {
        const std::filesystem::path helper =
            KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH;
        KDBG_CHECK(runner, std::filesystem::is_regular_file(helper));

        const std::string quoted =
            "value with spaces \"quoted\" and trailing\\\\";
        ScopedEnvironment success_mode("KDBG_MEMPROCFS_TEST_MODE", "success");
        ScopedEnvironment expected_count(
            "KDBG_MEMPROCFS_TEST_EXPECTED_COUNT",
            std::to_string(MemProcFsProvider::kMaxVmmArguments));
        ScopedEnvironment expected_argument(
            "KDBG_MEMPROCFS_TEST_EXPECTED_ARGUMENT", quoted);
        KDBG_CHECK(runner, success_mode.Configured());
        KDBG_CHECK(runner, expected_count.Configured());
        KDBG_CHECK(runner, expected_argument.Configured());

        auto maximum_arguments =
            VmmArguments(MemProcFsProvider::kMaxVmmArguments, quoted);
        KDBG_CHECK(runner, maximum_arguments.size() ==
            MemProcFsProvider::kMaxVmmArguments);
        MemProcFsProvider provider(
            helper,
            MemProcFsConfiguration{
                .device = "pmem",
                .vmm_path = std::filesystem::path(
                    L"C:\\runtime with spaces\\vmm.dll"),
                .vmm_arguments = std::move(maximum_arguments)},
            std::chrono::seconds{3});
        const auto result = provider.Query(291, {});
        KDBG_CHECK(runner, result.Ok());
        if (result) {
            KDBG_CHECK(runner, result.Value().pfn == 291U);
            KDBG_CHECK(runner, result.Value().mappings.empty());
        }
    }

    {
        const std::filesystem::path original_helper =
            KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH;
        const auto root = test::UniqueTempPath(
            "kdbg-memprocfs-wide-command");
        const auto unicode_directory = root /
            std::filesystem::path(
                L"\u914D\u7F6E-\uACBD\uB85C-\U0001F642-"
                L"long-install-directory-with-spaces");
        const auto unicode_helper = unicode_directory /
            std::filesystem::path(
                L"bridge-\u914D\u7F6E-\uACBD\uB85C-\U0001F642.exe");
        std::error_code file_error;
        std::filesystem::create_directories(unicode_directory, file_error);
        KDBG_CHECK(runner, !file_error);
        std::filesystem::copy_file(
            original_helper,
            unicode_helper,
            std::filesystem::copy_options::overwrite_existing,
            file_error);
        KDBG_CHECK(runner, !file_error);

        constexpr std::wstring_view device =
            L"dump-\u914D\u7F6E-\uACBD\uB85C-\U0001F642.raw";
        constexpr std::wstring_view vmm_path =
            L"C:\\runtime-\u914D\u7F6E-\uACBD\uB85C-\U0001F642\\vmm.dll";
        constexpr std::wstring_view argument =
            L"value-\u914D\u7F6E-\uACBD\uB85C-\U0001F642";
        ScopedEnvironment mode("KDBG_MEMPROCFS_TEST_MODE", "unicode");
        KDBG_CHECK(runner, mode.Configured());
        MemProcFsProvider provider(
            unicode_helper,
            MemProcFsConfiguration{
                .device = WideToUtf8(device),
                .vmm_path = std::filesystem::path(vmm_path),
                .vmm_arguments = {WideToUtf8(argument)}},
            std::chrono::seconds{3});
        const auto result = provider.Query(291, {});
        KDBG_CHECK(runner, result.Ok());
        if (!result) {
            std::cerr << "Unicode provider helper failed: "
                      << result.GetError().message << '\n';
        }

        std::filesystem::remove_all(root, file_error);
    }

    {
        const std::filesystem::path helper =
            KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH;
        ScopedEnvironment mode("KDBG_MEMPROCFS_TEST_MODE", "exit");
        KDBG_CHECK(runner, mode.Configured());
        MemProcFsProvider provider(helper, {}, std::chrono::seconds{3});
        const auto result = provider.Query(1, {});
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(runner,
                result.GetError().code == ErrorCode::BridgeUnavailable);
            KDBG_CHECK(runner, result.GetError().native_code == 7U);
            KDBG_CHECK(runner,
                result.GetError().message.find("deterministic helper exit") !=
                    std::string::npos);
        }
    }

    {
        const std::filesystem::path helper =
            KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH;
        ScopedEnvironment mode("KDBG_MEMPROCFS_TEST_MODE", "sleep");
        KDBG_CHECK(runner, mode.Configured());
        MemProcFsProvider provider(
            helper, {}, std::chrono::milliseconds{100});
        const auto result = provider.Query(1, {});
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(runner, result.GetError().code == ErrorCode::IoFailure);
            KDBG_CHECK(runner,
                result.GetError().message == "MemProcFS bridge timed out");
        }
    }

    {
        const std::filesystem::path helper =
            KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH;
        const auto marker = std::filesystem::temp_directory_path() /
            ("kdbg memprocfs cancellation " +
             std::to_string(GetCurrentProcessId()) + ".tmp");
        std::error_code ignored;
        std::filesystem::remove(marker, ignored);
        ScopedEnvironment mode("KDBG_MEMPROCFS_TEST_MODE", "sleep");
        ScopedEnvironment marker_environment(
            "KDBG_MEMPROCFS_TEST_MARKER", marker.string());
        KDBG_CHECK(runner, mode.Configured());
        KDBG_CHECK(runner, marker_environment.Configured());

        std::stop_source stop;
        std::atomic_bool saw_marker{false};
        std::jthread canceller([&]() {
            const auto deadline = std::chrono::steady_clock::now() +
                std::chrono::seconds{5};
            while (std::chrono::steady_clock::now() < deadline) {
                if (std::filesystem::exists(marker)) {
                    saw_marker.store(true);
                    stop.request_stop();
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
            stop.request_stop();
        });
        MemProcFsProvider provider(helper, {}, std::chrono::seconds{8});
        const auto result = provider.Query(1, stop.get_token());
        canceller.join();
        KDBG_CHECK(runner, saw_marker.load());
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            KDBG_CHECK(runner, result.GetError().code == ErrorCode::Cancelled);
        }
        std::filesystem::remove(marker, ignored);
    }

    {
        const std::filesystem::path helper =
            KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH;
        ScopedEnvironment mode("KDBG_MEMPROCFS_TEST_MODE", "flood");
        KDBG_CHECK(runner, mode.Configured());
        MemProcFsProvider provider(helper, {}, std::chrono::seconds{5});
        const auto result = provider.Query(1, {});
        KDBG_CHECK(runner, !result.Ok());
        if (!result) {
            if (result.GetError().code != ErrorCode::LimitReached) {
                std::cerr << "MemProcFS output-cap helper returned: "
                          << result.GetError().message << '\n';
            }
            KDBG_CHECK(runner,
                result.GetError().code == ErrorCode::LimitReached);
            KDBG_CHECK(runner,
                result.GetError().requested == 8U * 1024U * 1024U);
        }
    }

    {
        const std::filesystem::path helper =
            KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH;
        ScopedEnvironment mode("KDBG_MEMPROCFS_TEST_MODE", "descendant");
        KDBG_CHECK(runner, mode.Configured());
        MemProcFsProvider provider(helper, {}, std::chrono::seconds{3});
        const auto result = provider.Query(17, {});
        KDBG_CHECK(runner, result.Ok());
        if (result) {
            KDBG_CHECK(runner, result.Value().pfn == 17U);
        }
    }
#endif

    };
    run_provider_tests();

    const auto run_memory_tool_tests = [&runner]() {
        using namespace kdbg;

#ifdef _WIN32
    {
        KDbgBackend disconnected(L"\\\\.\\KDBG-test-unopened");
        const auto user_read = disconnected.ReadKernelVirtual(0x1000U, 16U);
        KDBG_CHECK(runner, !user_read.Ok());
        if (!user_read) {
            KDBG_CHECK(runner,
                user_read.GetError().code == ErrorCode::InvalidArgument);
        }
        const auto kernel_read = disconnected.ReadKernelVirtual(
            0xFFFF800000001000ULL, 16U);
        KDBG_CHECK(runner, !kernel_read.Ok());
        if (!kernel_read) {
            KDBG_CHECK(runner,
                kernel_read.GetError().code == ErrorCode::BackendDisconnected);
        }
    }
#endif

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        VerifiedWriter writer(backend);
        const auto arm = [&writer](std::uint32_t pid =
                                  MockMemoryBackend::kMockPid) {
            return writer.ArmProcessWrite(pid).TakeValue();
        };
        const std::uint64_t address = MockMemoryBackend::kVirtualBase + 0x80U;
        const auto before = backend.ReadProcessVirtual(
            MockMemoryBackend::kMockPid,
            address,
            4);
        KDBG_CHECK(runner, before.Ok());
        const std::array<std::uint8_t, 4> replacement{0x10, 0x20, 0x30, 0x40};
        const auto result = writer.Write(
            arm(),
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address,
            replacement,
            std::span<const std::uint8_t>(before.Value()));
        KDBG_CHECK(runner, result.Ok());
        if (result) {
            KDBG_CHECK(runner, result.Value().verified);
            KDBG_CHECK(runner, result.Value().readback ==
                std::vector<std::uint8_t>(replacement.begin(), replacement.end()));
        }
        KDBG_CHECK(runner, !backend.Info().write_enabled);

        const std::array<std::uint8_t, 4> wrong_expected{
            0xFF, 0x20, 0x30, 0x40};
        const auto mismatch = writer.Write(
            arm(),
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address,
            replacement,
            std::span<const std::uint8_t>(wrong_expected));
        KDBG_CHECK(runner, !mismatch.Ok());
        if (!mismatch) {
            KDBG_CHECK(runner, mismatch.GetError().code ==
                ErrorCode::ConcurrentModification);
        }

        const std::array<std::uint8_t, 2> wrong_length{0x10, 0x20};
        const auto length_mismatch = writer.Write(
            arm(),
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address,
            replacement,
            std::span<const std::uint8_t>(wrong_length));
        KDBG_CHECK(runner, !length_mismatch.Ok());
        if (!length_mismatch) {
            KDBG_CHECK(runner, length_mismatch.GetError().code ==
                ErrorCode::InvalidArgument);
        }

        const auto physical_rejected = writer.Write(
            arm(),
            MemorySpace::Physical(),
            MockMemoryBackend::kBaseAddress + 0x80U,
            replacement);
        KDBG_CHECK(runner, !physical_rejected.Ok());
        if (!physical_rejected) {
            KDBG_CHECK(runner, physical_rejected.GetError().code ==
                ErrorCode::Unsupported);
        }

        const auto writes_before_limits = backend.WriteCallCount();
        const std::vector<std::uint8_t> oversized(
            VerifiedWriter::kMaxWriteLength + 1U,
            0x5A);
        const auto oversized_result = writer.Write(
            arm(),
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address,
            oversized);
        KDBG_CHECK(runner, !oversized_result.Ok());
        if (!oversized_result) {
            KDBG_CHECK(runner, oversized_result.GetError().code ==
                ErrorCode::LimitReached);
        }
        const auto overflow_result = writer.Write(
            arm(),
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            std::numeric_limits<std::uint64_t>::max() - 1U,
            replacement);
        KDBG_CHECK(runner, !overflow_result.Ok());
        if (!overflow_result) {
            KDBG_CHECK(runner, overflow_result.GetError().code ==
                ErrorCode::AddressOverflow);
        }
        KDBG_CHECK(runner, backend.WriteCallCount() == writes_before_limits);

        const auto disables_before = backend.WriteDisableCallCount();
        MockFaults disable_fault{};
        disable_fault.fail_write_disable_count = 1;
        backend.SetFaults(disable_fault);
        const auto disable_failure = writer.Write(
            arm(),
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            address + 0x20U,
            replacement);
        KDBG_CHECK(runner, !disable_failure.Ok());
        if (!disable_failure) {
            KDBG_CHECK(runner, disable_failure.GetError().code ==
                ErrorCode::IoFailure);
        }
        KDBG_CHECK(runner, backend.WriteDisableCallCount() ==
            disables_before + 2U);
        KDBG_CHECK(runner, !backend.Info().write_enabled);
        backend.ClearFaults();
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        constexpr std::uint64_t kSize = 8192;
        const std::uint64_t address =
            MockMemoryBackend::kBaseAddress + 0x20000U;
        const auto baseline = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            kSize,
            4096);
        KDBG_CHECK(runner, baseline.Ok());
        if (baseline) {
            auto all_changed = baseline.Value().Bytes();
            for (auto& byte : all_changed) byte ^= 0xFFU;
            KDBG_CHECK(runner, WriteBytes(backend, address, all_changed));
            const auto all = MemorySnapshot::Capture(
                backend,
                MemorySpace::Physical(),
                address,
                kSize,
                4096);
            KDBG_CHECK(runner, all.Ok());
            if (all) {
                const auto diff = baseline.Value().Diff(all.Value());
                KDBG_CHECK(runner, diff.Ok());
                if (diff) {
                    KDBG_CHECK(runner, diff.Value().size() == 1U);
                    if (!diff.Value().empty()) {
                        KDBG_CHECK(runner, diff.Value().front().offset == 0);
                        KDBG_CHECK(runner, diff.Value().front().length == kSize);
                    }
                }
                const auto byte_limited = baseline.Value().Diff(
                    all.Value(),
                    MemorySnapshot::kMaxDiffRuns,
                    kSize - 1U);
                KDBG_CHECK(runner, !byte_limited.Ok());
                if (!byte_limited) {
                    KDBG_CHECK(runner, byte_limited.GetError().code ==
                        ErrorCode::LimitReached);
                }

                std::stop_source diff_stop;
                const auto cancelled_diff = baseline.Value().Diff(
                    all.Value(),
                    MemorySnapshot::kMaxDiffRuns,
                    MemorySnapshot::kMaxSnapshotBytes,
                    diff_stop.get_token(),
                    [&diff_stop](const SnapshotProgress&) {
                        diff_stop.request_stop();
                    });
                KDBG_CHECK(runner, !cancelled_diff.Ok());
                if (!cancelled_diff) {
                    KDBG_CHECK(runner, cancelled_diff.GetError().code ==
                        ErrorCode::Cancelled);
                }
            }

            KDBG_CHECK(
                runner,
                WriteBytes(backend, address, baseline.Value().Bytes()));
            auto alternating = baseline.Value().Bytes();
            for (std::size_t index = 0; index < alternating.size(); index += 2) {
                alternating[index] ^= 0xFFU;
            }
            KDBG_CHECK(runner, WriteBytes(backend, address, alternating));
            const auto alternating_snapshot = MemorySnapshot::Capture(
                backend,
                MemorySpace::Physical(),
                address,
                kSize,
                4096);
            KDBG_CHECK(runner, alternating_snapshot.Ok());
            if (alternating_snapshot) {
                const auto alternating_diff =
                    baseline.Value().Diff(alternating_snapshot.Value());
                KDBG_CHECK(runner, alternating_diff.Ok());
                if (alternating_diff) {
                    KDBG_CHECK(
                        runner,
                        alternating_diff.Value().size() == kSize / 2U);
                    KDBG_CHECK(runner, std::all_of(
                        alternating_diff.Value().begin(),
                        alternating_diff.Value().end(),
                        [](const SnapshotDiffRun& run) {
                            return run.length == 1U;
                        }));
                }
                const auto run_limited = baseline.Value().Diff(
                    alternating_snapshot.Value(),
                    static_cast<std::size_t>(kSize / 2U - 1U));
                KDBG_CHECK(runner, !run_limited.Ok());
                if (!run_limited) {
                    KDBG_CHECK(runner, run_limited.GetError().code ==
                        ErrorCode::LimitReached);
                }
            }

            const auto path = test::UniqueTempPath(
                "kdbg-snapshot-cancel-test.kdbgmem");
            constexpr std::string_view snapshot_sentinel =
                "existing-snapshot-must-survive";
            {
                std::ofstream existing(
                    path,
                    std::ios::binary | std::ios::trunc);
                existing.write(
                    snapshot_sentinel.data(),
                    static_cast<std::streamsize>(snapshot_sentinel.size()));
            }
            std::stop_source save_stop;
            const auto cancelled_save = baseline.Value().Save(
                path,
                save_stop.get_token(),
                [&save_stop](const SnapshotProgress&) {
                    save_stop.request_stop();
                });
            KDBG_CHECK(runner, !cancelled_save.Ok());
            if (!cancelled_save) {
                KDBG_CHECK(runner, cancelled_save.GetError().code ==
                        ErrorCode::Cancelled);
            }
            {
                std::ifstream existing(path, std::ios::binary);
                const std::string contents{
                    std::istreambuf_iterator<char>(existing),
                    std::istreambuf_iterator<char>()};
                KDBG_CHECK(runner, contents == snapshot_sentinel);
            }

            const auto faulted_save = baseline.Value().Save(
                path,
                {},
                {},
                SnapshotSaveFault::AfterFlushBeforeReplace);
            KDBG_CHECK(runner, !faulted_save.Ok());
            if (!faulted_save) {
                KDBG_CHECK(runner, faulted_save.GetError().code ==
                    ErrorCode::IoFailure);
            }
            {
                std::ifstream existing(path, std::ios::binary);
                const std::string contents{
                    std::istreambuf_iterator<char>(existing),
                    std::istreambuf_iterator<char>()};
                KDBG_CHECK(runner, contents == snapshot_sentinel);
            }

            SnapshotProgress save_progress{};
            KDBG_CHECK(runner, baseline.Value().Save(
                path,
                {},
                [&save_progress](const SnapshotProgress& update) {
                    save_progress = update;
                }).Ok());
            KDBG_CHECK(runner, save_progress.phase == SnapshotProgressPhase::Save);
            KDBG_CHECK(runner, save_progress.completed == save_progress.total);

            std::stop_source load_stop;
            const auto cancelled_load = MemorySnapshot::Load(
                path,
                load_stop.get_token(),
                [&load_stop](const SnapshotProgress&) {
                    load_stop.request_stop();
                });
            KDBG_CHECK(runner, !cancelled_load.Ok());
            if (!cancelled_load) {
                KDBG_CHECK(runner, cancelled_load.GetError().code ==
                    ErrorCode::Cancelled);
            }

            SnapshotProgress load_progress{};
            const auto loaded = MemorySnapshot::Load(
                path,
                {},
                [&load_progress](const SnapshotProgress& update) {
                    load_progress = update;
                });
            KDBG_CHECK(runner, loaded.Ok());
            if (loaded) {
                KDBG_CHECK(
                    runner,
                    loaded.Value().Bytes() == baseline.Value().Bytes());
            }
            KDBG_CHECK(
                runner,
                load_progress.phase == SnapshotProgressPhase::LoadChecksum);
            KDBG_CHECK(runner, load_progress.completed == load_progress.total);

            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const std::uint64_t pointer_storage =
            MockMemoryBackend::kBaseAddress + 0x200U;
        const std::uint64_t pointed =
            MockMemoryBackend::kBaseAddress + 0x500U;
        KDBG_CHECK(runner, WriteScalar(backend, pointer_storage, pointed));

        PointerResolver resolver(backend);
        AddressPointerPath path{};
        path.space = MemorySpace::Physical();
        path.base_address = pointer_storage;
        path.pointer_size = 8;
        path.offsets = {0x10, 0x20};
        const auto resolved = resolver.Resolve(path);
        KDBG_CHECK(runner, resolved.Ok());
        if (resolved) {
            KDBG_CHECK(runner, resolved.Value() == pointed + 0x30U);
        }

        AddressPointerPath too_deep = path;
        too_deep.offsets.assign(PointerResolver::kMaxDepth + 1U, 0);
        const auto depth_result = resolver.Resolve(too_deep);
        KDBG_CHECK(runner, !depth_result.Ok());
        if (!depth_result) {
            KDBG_CHECK(runner, depth_result.GetError().code ==
                ErrorCode::LimitReached);
        }

        AddressPointerPath zero_base = path;
        zero_base.base_address = 0;
        KDBG_CHECK(runner, !resolver.Resolve(zero_base).Ok());

        AddressPointerPath missing_pid = path;
        missing_pid.space = MemorySpace::Process(0);
        KDBG_CHECK(runner, !resolver.Resolve(missing_pid).Ok());

        AddressPointerPath stray_pid = path;
        stray_pid.space = MemorySpace::Physical();
        stray_pid.space.pid = MockMemoryBackend::kMockPid;
        KDBG_CHECK(runner, !resolver.Resolve(stray_pid).Ok());

        const std::uint64_t null_storage =
            MockMemoryBackend::kBaseAddress + 0x280U;
        KDBG_CHECK(runner, WriteScalar(
            backend,
            null_storage,
            std::uint64_t{0}));
        AddressPointerPath null_path{};
        null_path.space = MemorySpace::Physical();
        null_path.base_address = null_storage;
        null_path.pointer_size = 8;
        null_path.offsets = {0, 0};
        const auto null_result = resolver.Resolve(null_path);
        KDBG_CHECK(runner, !null_result.Ok());
        if (!null_result) {
            KDBG_CHECK(runner, null_result.GetError().code ==
                ErrorCode::NotFound);
        }

        AddressPointerPath narrow_overflow{};
        narrow_overflow.space = MemorySpace::Physical();
        narrow_overflow.base_address =
            std::numeric_limits<std::uint32_t>::max() - 0xFU;
        narrow_overflow.pointer_size = 4;
        narrow_overflow.offsets = {0x20};
        const auto narrow_result = resolver.Resolve(narrow_overflow);
        KDBG_CHECK(runner, !narrow_result.Ok());
        if (!narrow_result) {
            KDBG_CHECK(runner, narrow_result.GetError().code ==
                ErrorCode::AddressOverflow);
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const std::uint64_t pointer_storage =
            MockMemoryBackend::kVirtualBase + 0x600U;
        const std::uint64_t target =
            MockMemoryBackend::kVirtualBase + 0x700U;
        KDBG_CHECK(runner, WriteScalar(
            backend,
            MockMemoryBackend::kBaseAddress + 0x600U,
            target));

        AddressEntry valid{};
        valid.description = "matching process pointer";
        valid.space = MemorySpace::Process(MockMemoryBackend::kMockPid);
        valid.address = MockMemoryBackend::kVirtualBase + 0x500U;
        valid.type = ScanValueType::UInt32;
        valid.width = 4;
        valid.pointer_path = AddressPointerPath{
            MemorySpace::Process(MockMemoryBackend::kMockPid),
            pointer_storage,
            {0, 0},
            8};

        AddressList pointer_list(backend);
        const auto valid_id = pointer_list.Add(valid);
        KDBG_CHECK(runner, valid_id != 0);
        const auto refresh = pointer_list.Refresh();
        KDBG_CHECK(runner, refresh.Ok());
        if (refresh) {
            KDBG_CHECK(runner, refresh.Value().refreshed == 1U);
            KDBG_CHECK(runner, refresh.Value().failed == 0U);
        }
        if (!pointer_list.Entries().empty()) {
            KDBG_CHECK(runner,
                pointer_list.Entries().front().resolved_address == target);
            KDBG_CHECK(runner,
                pointer_list.Entries().front().current_value.size() == 4U);
        }

        AddressEntry overflowing = valid;
        overflowing.id = 0;
        overflowing.pointer_path.reset();
        overflowing.address = std::numeric_limits<std::uint64_t>::max() - 1U;
        KDBG_CHECK(runner, pointer_list.Add(std::move(overflowing)) == 0);

        AddressEntry mismatched_kind = valid;
        mismatched_kind.id = 0;
        mismatched_kind.pointer_path->space = MemorySpace::Physical();
        mismatched_kind.pointer_path->base_address =
            MockMemoryBackend::kBaseAddress + 0x600U;
        KDBG_CHECK(runner, pointer_list.Add(std::move(mismatched_kind)) == 0);

        AddressEntry mismatched_pid = valid;
        mismatched_pid.id = 0;
        mismatched_pid.pointer_path->space = MemorySpace::Process(
            MockMemoryBackend::kMockPid + 1U);
        KDBG_CHECK(runner, pointer_list.Add(std::move(mismatched_pid)) == 0);

        AddressEntry excessive_depth = valid;
        excessive_depth.id = 0;
        excessive_depth.pointer_path->offsets.assign(
            PointerResolver::kMaxDepth + 1U,
            0);
        KDBG_CHECK(runner, pointer_list.Add(std::move(excessive_depth)) == 0);

        AddressEntry zero_pointer_base = valid;
        zero_pointer_base.id = 0;
        zero_pointer_base.pointer_path->base_address = 0;
        KDBG_CHECK(runner, pointer_list.Add(std::move(zero_pointer_base)) == 0);
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        AddressList list(backend);
        AddressEntry entry{};
        entry.description = "process u32";
        entry.space = MemorySpace::Process(MockMemoryBackend::kMockPid);
        entry.address = MockMemoryBackend::kVirtualBase + 0x300U;
        entry.type = ScanValueType::UInt32;
        entry.width = 4;
        const auto id = list.Add(std::move(entry));
        KDBG_CHECK(runner, id != 0);
        const auto refreshed = list.Refresh();
        KDBG_CHECK(runner, refreshed.Ok());
        if (refreshed) {
            KDBG_CHECK(runner, refreshed.Value().refreshed == 1U);
            KDBG_CHECK(runner, refreshed.Value().failed == 0U);
        }

        const std::array<std::uint8_t, 4> desired{0xAA, 0xBB, 0xCC, 0xDD};
        auto wrong_arm = list.ArmProcessWrites(
            MockMemoryBackend::kMockPid + 1U);
        KDBG_CHECK(runner, wrong_arm.Ok());
        if (wrong_arm) {
            const auto rejected = list.Write(
                wrong_arm.TakeValue(), id, desired);
            KDBG_CHECK(runner, !rejected.Ok());
            if (!rejected) {
                KDBG_CHECK(runner, rejected.GetError().code ==
                    ErrorCode::WriteLocked);
            }
        }
        auto write_arm = list.ArmProcessWrites(MockMemoryBackend::kMockPid);
        KDBG_CHECK(runner, write_arm.Ok());
        if (write_arm) {
            KDBG_CHECK(runner,
                list.Write(write_arm.TakeValue(), id, desired).Ok());
        }
        KDBG_CHECK(runner, list.SetFrozen(
            id,
            true,
            std::vector<std::uint8_t>(desired.begin(), desired.end())).Ok());
        backend.Mutate(MockMemoryBackend::kBaseAddress + 0x300U, 0x11U);
        auto freeze_arm = list.ArmProcessWrites(MockMemoryBackend::kMockPid);
        KDBG_CHECK(runner, freeze_arm.Ok());
        const auto frozen = freeze_arm
            ? list.TickFreeze(freeze_arm.TakeValue())
            : Result<FreezeSummary>::Failure(freeze_arm.GetError());
        KDBG_CHECK(runner, frozen.Ok());
        if (frozen) {
            KDBG_CHECK(runner, frozen.Value().verified == 1U);
            KDBG_CHECK(runner, frozen.Value().failed == 0U);
        }
        const auto readback = backend.ReadPhysical(
            MockMemoryBackend::kBaseAddress + 0x300U,
            4);
        KDBG_CHECK(runner, readback.Ok());
        if (readback) {
            KDBG_CHECK(runner, readback.Value() ==
                std::vector<std::uint8_t>(desired.begin(), desired.end()));
        }

        const auto path = test::UniqueTempPath(
            "kdbg-address-list-test.txt");
        AddressEntry unfrozen_entry{};
        unfrozen_entry.description = "unfrozen";
        unfrozen_entry.space = MemorySpace::Process(
            MockMemoryBackend::kMockPid);
        unfrozen_entry.address = MockMemoryBackend::kVirtualBase + 0x380U;
        unfrozen_entry.type = ScanValueType::UInt32;
        unfrozen_entry.width = 4;
        KDBG_CHECK(runner, list.Add(std::move(unfrozen_entry)) != 0);
        KDBG_CHECK(runner, list.Save(path).Ok());
        AddressList loaded(backend);
        KDBG_CHECK(runner, loaded.Load(path).Ok());
        KDBG_CHECK(runner, loaded.Entries().size() == 2U);
        if (!loaded.Entries().empty()) {
            KDBG_CHECK(runner, loaded.Entries().front().description ==
                "process u32");
            KDBG_CHECK(runner, !loaded.Entries().front().frozen);
            KDBG_CHECK(runner, loaded.Entries().front().freeze_value.empty());
            KDBG_CHECK(runner, loaded.Entries().front().last_error.has_value());
        }
        if (loaded.Entries().size() == 2U) {
            KDBG_CHECK(runner, !loaded.Entries()[1].frozen);
            KDBG_CHECK(runner, loaded.Entries()[1].freeze_value.empty());
        }

        AddressEntry physical{};
        physical.description = "read only physical";
        physical.space = MemorySpace::Physical();
        physical.address = MockMemoryBackend::kBaseAddress + 0x500U;
        physical.type = ScanValueType::UInt32;
        physical.width = 4;
        const auto physical_id = loaded.Add(std::move(physical));
        KDBG_CHECK(runner, physical_id != 0);
        const auto writes_before = backend.WriteCallCount();
        auto physical_arm = loaded.ArmProcessWrites(
            MockMemoryBackend::kMockPid);
        KDBG_CHECK(runner, physical_arm.Ok());
        const auto physical_write = physical_arm
            ? loaded.Write(physical_arm.TakeValue(), physical_id, desired)
            : Result<VerifiedWriteResult>::Failure(physical_arm.GetError());
        KDBG_CHECK(runner, !physical_write.Ok());
        if (!physical_write) {
            KDBG_CHECK(runner, physical_write.GetError().code ==
                ErrorCode::Unsupported);
        }
        const auto physical_freeze = loaded.SetFrozen(
            physical_id,
            true,
            std::vector<std::uint8_t>(desired.begin(), desired.end()));
        KDBG_CHECK(runner, !physical_freeze.Ok());
        KDBG_CHECK(runner, backend.WriteCallCount() == writes_before);

        AddressEntry kernel{};
        kernel.description = "read only kernel";
        kernel.space = MemorySpace::Kernel();
        kernel.address = 0xFFFF800000000500ULL;
        kernel.type = ScanValueType::UInt32;
        kernel.width = 4;
        const auto kernel_id = loaded.Add(std::move(kernel));
        KDBG_CHECK(runner, kernel_id != 0);
        auto kernel_arm = loaded.ArmProcessWrites(MockMemoryBackend::kMockPid);
        KDBG_CHECK(runner, kernel_arm.Ok());
        const auto kernel_write = kernel_arm
            ? loaded.Write(kernel_arm.TakeValue(), kernel_id, desired)
            : Result<VerifiedWriteResult>::Failure(kernel_arm.GetError());
        KDBG_CHECK(runner, !kernel_write.Ok());
        if (!kernel_write) {
            KDBG_CHECK(runner, kernel_write.GetError().code ==
                ErrorCode::Unsupported);
        }
        KDBG_CHECK(runner, !loaded.SetFrozen(
            kernel_id,
            true,
            std::vector<std::uint8_t>(desired.begin(), desired.end())).Ok());
        KDBG_CHECK(runner, backend.WriteCallCount() == writes_before);

        const auto legacy_path = test::UniqueTempPath(
            "kdbg-address-list-unfrozen-legacy.txt");
        {
            std::ofstream legacy(legacy_path, std::ios::binary | std::ios::trunc);
            legacy << "KDBG_ADDRESS_LIST\t1\n"
                   << "1\t1\t1337\t5368709120\t5\t4\t0\t\"legacy\"\t\n";
        }
        AddressList legacy_loaded(backend);
        KDBG_CHECK(runner, legacy_loaded.Load(legacy_path).Ok());
        KDBG_CHECK(runner, legacy_loaded.Entries().size() == 1U);

        const auto invalid_path = test::UniqueTempPath(
            "kdbg-address-list-invalid.txt");
        {
            std::ofstream invalid(invalid_path, std::ios::binary | std::ios::trunc);
            invalid << "KDBG_ADDRESS_LIST\t1\n"
                    << "1\t1\t0\t4096\t5\t4\t0\t\"bad pid\"\t-\n";
        }
        AddressList invalid_loaded(backend);
        KDBG_CHECK(runner, !invalid_loaded.Load(invalid_path).Ok());

        const auto wide_path = test::UniqueTempPath(
            "kdbg-address-list-wide.txt");
        {
            std::ofstream wide(wide_path, std::ios::binary | std::ios::trunc);
            wide << "KDBG_ADDRESS_LIST\t1\n"
                 << "1\t1\t1337\t4096\t12\t"
                 << (AddressList::kMaxValueWidth + 1U)
                 << "\t0\t\"wide\"\t-\n";
        }
        AddressList wide_loaded(backend);
        KDBG_CHECK(runner, !wide_loaded.Load(wide_path).Ok());

        AddressEntry invalid_entry{};
        invalid_entry.space = MemorySpace::Process(0);
        invalid_entry.address = 0x1000;
        invalid_entry.type = ScanValueType::UInt32;
        invalid_entry.width = 4;
        KDBG_CHECK(runner, loaded.Add(std::move(invalid_entry)) == 0);

        const auto long_row_path = test::UniqueTempPath(
            "kdbg-address-list-long-row.txt");
        {
            std::ofstream long_row(
                long_row_path,
                std::ios::binary | std::ios::trunc);
            long_row << "KDBG_ADDRESS_LIST\t1\n"
                     << std::string(AddressList::kMaxRowBytes + 1U, 'X')
                     << '\n';
        }
        AddressList long_row_loaded(backend);
        KDBG_CHECK(runner, !long_row_loaded.Load(long_row_path).Ok());

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        std::filesystem::remove(legacy_path, ignored);
        std::filesystem::remove(invalid_path, ignored);
        std::filesystem::remove(wide_path, ignored);
        std::filesystem::remove(long_row_path, ignored);
    }

    };
    run_memory_tool_tests();

    const auto run_snapshot_and_reverse_map_tests = [&runner]() {
        using namespace kdbg;

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        const std::uint64_t address = MockMemoryBackend::kBaseAddress + 0x400U;
        const auto first = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            64,
            17);
        KDBG_CHECK(runner, first.Ok());
        const std::array<std::uint8_t, 3> change{0x31, 0x32, 0x33};
        KDBG_CHECK(runner, WriteBytes(backend, address + 10U, change));
        const auto second = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            64,
            13);
        KDBG_CHECK(runner, second.Ok());
        if (first && second) {
            const auto diff = first.Value().Diff(second.Value());
            KDBG_CHECK(runner, diff.Ok());
            if (diff) {
                KDBG_CHECK(runner, diff.Value().size() == 1U);
                if (!diff.Value().empty()) {
                    KDBG_CHECK(runner, diff.Value().front().offset == 10U);
                    KDBG_CHECK(runner, diff.Value().front().length == change.size());
                    const auto changed = std::span<const std::uint8_t>(
                        second.Value().Bytes()).subspan(
                            static_cast<std::size_t>(diff.Value().front().offset),
                            static_cast<std::size_t>(diff.Value().front().length));
                    KDBG_CHECK(runner, std::equal(
                        changed.begin(), changed.end(), change.begin(), change.end()));
                }
            }

            const auto path = test::UniqueTempPath(
                "kdbg-snapshot-test.kdbgmem");
            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const auto loaded = MemorySnapshot::Load(path);
            KDBG_CHECK(runner, loaded.Ok());
            if (loaded) {
                KDBG_CHECK(runner, loaded.Value().Bytes() == first.Value().Bytes());
                KDBG_CHECK(runner, loaded.Value().Checksum() == first.Value().Checksum());
            }

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const std::uint32_t nonzero_reserved = 1;
            KDBG_CHECK(runner, PatchFileScalar(path, 20, nonzero_reserved));
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const std::uint64_t huge_count =
                MemorySnapshot::kMaxSnapshotBytes + 1U;
            KDBG_CHECK(runner, PatchFileScalar(path, 40, huge_count));
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            {
                std::ofstream trailing(path, std::ios::binary | std::ios::app);
                trailing.put('X');
            }
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const std::uint64_t overflowing_address =
                std::numeric_limits<std::uint64_t>::max();
            KDBG_CHECK(runner, PatchFileScalar(path, 32, overflowing_address));
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());

            KDBG_CHECK(runner, first.Value().Save(path).Ok());
            const std::uint32_t process_kind =
                static_cast<std::uint32_t>(MemorySpaceKind::ProcessVirtual);
            KDBG_CHECK(runner, PatchFileScalar(path, 12, process_kind));
            KDBG_CHECK(runner, !MemorySnapshot::Load(path).Ok());
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        const auto too_large = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            MemorySnapshot::kMaxSnapshotBytes + 1U,
            4096);
        KDBG_CHECK(runner, !too_large.Ok());
        if (!too_large) {
            KDBG_CHECK(runner, too_large.GetError().code == ErrorCode::LimitReached);
        }
        const auto invalid_space = MemorySnapshot::Capture(
            backend,
            MemorySpace::Process(0),
            address,
            64,
            4096);
        KDBG_CHECK(runner, !invalid_space.Ok());
        const auto invalid_chunk = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            address,
            64,
            MemorySnapshot::kMaxChunkBytes + 1U);
        KDBG_CHECK(runner, !invalid_chunk.Ok());
        const auto overflow_capture = MemorySnapshot::Capture(
            backend,
            MemorySpace::Physical(),
            std::numeric_limits<std::uint64_t>::max(),
            2,
            4096);
        KDBG_CHECK(runner, !overflow_capture.Ok());
        if (!overflow_capture) {
            KDBG_CHECK(runner, overflow_capture.GetError().code ==
                ErrorCode::AddressOverflow);
        }
    }

    {
        MockMemoryBackend backend;
        KDBG_CHECK(runner, backend.Open().Ok());
        constexpr std::uint64_t root_pfn = 0x100U;
        constexpr std::uint64_t pdpt_pfn = 0x101U;
        constexpr std::uint64_t pd_pfn = 0x102U;
        constexpr std::uint64_t pt_pfn = 0x103U;
        constexpr std::uint64_t target_pfn = 0x104U;
        const std::vector<std::uint8_t> zero(0x1000U);
        KDBG_CHECK(runner, WriteBytes(backend, root_pfn << 12U, zero));
        KDBG_CHECK(runner, WriteBytes(backend, pdpt_pfn << 12U, zero));
        KDBG_CHECK(runner, WriteBytes(backend, pd_pfn << 12U, zero));
        KDBG_CHECK(runner, WriteBytes(backend, pt_pfn << 12U, zero));
        constexpr std::uint64_t flags = 0x7U;
        const std::uint64_t pml4e = (pdpt_pfn << 12U) | flags;
        const std::uint64_t pdpte = (pd_pfn << 12U) | flags;
        const std::uint64_t pde = (pt_pfn << 12U) | flags;
        const std::uint64_t pte = (target_pfn << 12U) | flags;
        KDBG_CHECK(runner, WriteScalar(backend, root_pfn << 12U, pml4e));
        KDBG_CHECK(runner, WriteScalar(backend, pdpt_pfn << 12U, pdpte));
        KDBG_CHECK(runner, WriteScalar(backend, pd_pfn << 12U, pde));
        KDBG_CHECK(runner, WriteScalar(
            backend,
            (pt_pfn << 12U) + 5U * sizeof(std::uint64_t),
            pte));

        PageTableReverseMapper mapper(backend);
        mapper.SetLimits(ReverseMapLimits{
            .max_table_pages = 16,
            .max_results = 16,
            .include_page_table_pages = true,
            .continue_on_read_error = false});
        mapper.SetTargets({ProcessScanTarget{
            MockMemoryBackend::kMockPid,
            "mock.exe",
            root_pfn << 12U,
            false}});
        const auto result = mapper.Query(target_pfn, {});
        KDBG_CHECK(runner, result.Ok());
        if (result) {
            KDBG_CHECK(runner, result.Value().mappings.size() == 1U);
            if (!result.Value().mappings.empty()) {
                const auto& mapping = result.Value().mappings.front();
                KDBG_CHECK(runner, mapping.pid == MockMemoryBackend::kMockPid);
                KDBG_CHECK(runner, mapping.virtual_address == 0x5000U);
                KDBG_CHECK(runner, mapping.pte_address ==
                    (pt_pfn << 12U) + 5U * sizeof(std::uint64_t));
                KDBG_CHECK(runner, mapping.page_size == 0x1000U);
                KDBG_CHECK(runner, mapping.writable);
                KDBG_CHECK(runner, mapping.user_accessible);
            }
        }
    }

    };
    run_snapshot_and_reverse_map_tests();
}

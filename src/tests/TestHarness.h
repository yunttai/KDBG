#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace kdbg::test {

inline std::filesystem::path UniqueTempPath(std::string_view filename) {
    static std::atomic<std::uint64_t> sequence{0};
#if defined(_WIN32)
    const auto process_id = static_cast<std::uint64_t>(_getpid());
#else
    const auto process_id = static_cast<std::uint64_t>(getpid());
#endif
    const auto ordinal = sequence.fetch_add(1, std::memory_order_relaxed);
    const std::filesystem::path requested{filename};
    const auto unique_name = requested.stem().string() + '-' +
        std::to_string(process_id) + '-' + std::to_string(ordinal) +
        requested.extension().string();
    return std::filesystem::temp_directory_path() / unique_name;
}

class TestRunner {
public:
    void Check(
        bool condition,
        std::string_view expression,
        std::string_view file,
        int line) {
        ++checks_;
        if (!condition) {
            ++failures_;
            std::cerr << file << ':' << line
                      << " CHECK failed: " << expression << '\n';
        }
    }

    [[nodiscard]] int Failures() const noexcept {
        return failures_;
    }

    [[nodiscard]] int Checks() const noexcept {
        return checks_;
    }

private:
    int checks_{0};
    int failures_{0};
};

}  // namespace kdbg::test

#define KDBG_CHECK(runner, expression) \
    (runner).Check(                   \
        static_cast<bool>(expression), \
        #expression,                  \
        __FILE__,                     \
        __LINE__)

#pragma once

#include <iostream>
#include <string_view>

namespace kdbg::test {

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

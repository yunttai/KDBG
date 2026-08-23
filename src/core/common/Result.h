#pragma once

#include "core/common/Error.h"

#include <stdexcept>
#include <utility>
#include <variant>

namespace kdbg {

template <typename T>
class Result {
public:
    static Result Success(T value) {
        return Result(std::move(value));
    }

    static Result Failure(Error error) {
        return Result(std::move(error));
    }

    [[nodiscard]] bool Ok() const noexcept {
        return std::holds_alternative<T>(data_);
    }

    explicit operator bool() const noexcept {
        return Ok();
    }

    [[nodiscard]] const T& Value() const {
        if (!Ok()) {
            throw std::logic_error("Result does not contain a value");
        }
        return std::get<T>(data_);
    }

    [[nodiscard]] T& Value() {
        if (!Ok()) {
            throw std::logic_error("Result does not contain a value");
        }
        return std::get<T>(data_);
    }

    [[nodiscard]] T TakeValue() {
        if (!Ok()) {
            throw std::logic_error("Result does not contain a value");
        }
        return std::move(std::get<T>(data_));
    }

    [[nodiscard]] const Error& GetError() const {
        if (Ok()) {
            throw std::logic_error("Result does not contain an error");
        }
        return std::get<Error>(data_);
    }

private:
    explicit Result(T value) : data_(std::move(value)) {}
    explicit Result(Error error) : data_(std::move(error)) {}

    std::variant<T, Error> data_;
};

template <>
class Result<void> {
public:
    static Result Success() {
        return Result(true, {});
    }

    static Result Failure(Error error) {
        return Result(false, std::move(error));
    }

    [[nodiscard]] bool Ok() const noexcept {
        return ok_;
    }

    explicit operator bool() const noexcept {
        return ok_;
    }

    [[nodiscard]] const Error& GetError() const {
        if (ok_) {
            throw std::logic_error("Result does not contain an error");
        }
        return error_;
    }

private:
    Result(bool ok, Error error) : ok_(ok), error_(std::move(error)) {}

    bool ok_{false};
    Error error_{};
};

}  // namespace kdbg

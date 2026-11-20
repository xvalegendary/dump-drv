#pragma once

#ifndef _KERNEL_MODE
#include <optional>
#include <utility>
#endif

namespace dump {

enum class Status : unsigned int {
    success = 0,
    invalid_argument,
    invalid_magic,
    version_mismatch,
    size_mismatch,
    nonce_mismatch,
    sequence_replay,
    range_overflow,
    noncanonical_address,
    kernel_identity_mismatch,
    invalid_symbol_packet,
    access_denied,
    process_not_found,
    process_exited,
    io_error,
    partial_copy,
    invalid_state,
    mapper_failure,
    driver_failure,
    validation_failure
};

#ifndef _KERNEL_MODE
template <typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)), status_(Status::success) {}
    Result(Status status) : status_(status) {}

    explicit operator bool() const noexcept { return value_.has_value(); }
    [[nodiscard]] Status status() const noexcept { return status_; }
    [[nodiscard]] T& value() & { return value_.value(); }
    [[nodiscard]] const T& value() const& { return value_.value(); }
    [[nodiscard]] T&& value() && { return std::move(value_.value()); }

private:
    std::optional<T> value_;
    Status status_;
};
#endif

}

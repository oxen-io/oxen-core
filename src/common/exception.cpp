#include "exception.h"

#include <fmt/core.h>
#include <sstream>
#include <iostream>

namespace oxen {

void on_terminate_handler()
{
    // TODO: Support std::nested_exception?
    try {
        auto ptr = std::current_exception();
        if (ptr) {
            std::rethrow_exception(ptr);
        } else {
            fmt::println(stderr, "Terminate called without an active exception");
        }
    } catch (cpptrace::exception& e) {
        fmt::println(stderr, "Terminate called after throwing an instance of {}: {}\n", cpptrace::demangle(typeid(e).name()), e.what());
    } catch (std::exception& e) {
        fmt::println(stderr, "Terminate called after throwing an instance of {}: {}\n", cpptrace::demangle(typeid(e).name()), e.what());
    }
    std::flush(std::cerr);
    abort();
}

exception::exception(std::string&& msg, cpptrace::raw_trace&& trace) :
        raw_trace(trace), user_msg(msg) {}

const char* exception::what() const noexcept {
    if (what_msg.empty()) {
        std::ostringstream oss;
        raw_trace.resolve().print_with_snippets(oss, /*colour*/ false);
        what_msg = user_msg + std::string(":\n") + oss.str();
    }
    return what_msg.c_str();
}

const cpptrace::raw_trace& exception::trace() const noexcept {
    return raw_trace;
}

logic_error::logic_error(std::string msg, cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

domain_error::domain_error(std::string msg, cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

invalid_argument::invalid_argument(std::string msg, cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

length_error::length_error(
        std::string msg,
        cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

out_of_range::out_of_range(
        std::string msg,
        cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

runtime_error::runtime_error(
        std::string msg,
        cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

range_error::range_error(
        std::string msg,
        cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

overflow_error::overflow_error(
        std::string msg,
        cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

underflow_error::underflow_error(
        std::string msg,
        cpptrace::raw_trace&& trace) noexcept :
        exception(std::move(msg), std::move(trace)) {}

system_error::system_error(int error_code, std::string msg, cpptrace::raw_trace&& trace) noexcept :
        exception(
                msg + ": " + std::error_code(error_code, std::generic_category()).message(),
                std::move(trace)),
        ec(std::error_code(error_code, std::generic_category())) {}

const std::error_code& system_error::code() const noexcept {
    return ec;
}
};  // namespace oxen

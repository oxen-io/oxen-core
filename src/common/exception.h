#pragma once

#include <cpptrace/cpptrace.hpp>
#include <exception>
#include <string>
#include <system_error>

// Custom exception implementations that store the stacktrace of the exception
// at the call-site that it was thrown at. This implementation is based off
// cpptrace's implementation and we also use cpptrace as a library for
// generating cross-platform stack traces.
//
// Our implementatin is the same as cpptrace with the added feature that we dump
// the stack trace with inline code-snippets for the call-site that threw the
// exception instead of just the stack trace itself.

namespace oxen {

// Catches application termination and dumps a stack-trace where possible.
// It must be registered as the handler on startup, preferrably in main() e.g.
//
//   std::set_terminate(oxen::on_terminate_handler)
//
// This implementation is mostly copied from cpptrace's
// `register_terminate_handler` except that we look for `oxen::` exceptions
// thrown from one of the types in this file.
void on_terminate_handler();

struct exception : public std::exception {
    exception(std::string&& msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256));

    const char* what() const noexcept override;

    const cpptrace::raw_trace& trace() const noexcept;

    cpptrace::raw_trace raw_trace;

    // Cache of the string to be printed when 'what' is called because we store
    // the stack trace as a list of U64 addresses.
    mutable std::string what_msg;

    // The message created when the exception was thrown.
    std::string user_msg;
};

struct logic_error : public exception {
    logic_error(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct domain_error : public exception {
    domain_error(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct invalid_argument : public exception {
    invalid_argument(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct length_error : public exception {
    length_error(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct out_of_range : public exception {
    out_of_range(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct runtime_error : public exception {
    runtime_error(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct range_error : public exception {
    range_error(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct overflow_error : public exception {
    overflow_error(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct underflow_error : public exception {
    underflow_error(
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;
};

struct system_error : public exception {
    system_error(
            int error_code,
            std::string msg,
            cpptrace::raw_trace&& trace =
                    cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)) noexcept;

    const std::error_code& code() const noexcept;

    std::error_code ec;
};
}  // namespace oxen

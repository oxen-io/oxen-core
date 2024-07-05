#include "exception.h"

#include <fmt/core.h>
#include <sstream>
#include <iostream>

namespace oxen {

std::string make_traced_msg(std::string_view what, const cpptrace::raw_trace& trace) {
    std::ostringstream oss;
    #if defined(NDEBUG)
    trace.resolve().print(oss, /*colour*/ false);
    #else
    trace.resolve().print_with_snippets(oss, /*colour*/ false);
    #endif
    std::string result = std::string(what) + std::string(":\n") + oss.str();
    return result;
}

void on_terminate_handler() {
    // TODO: Support std::nested_exception?
    try {
        auto ptr = std::current_exception();
        if (ptr) {
            std::rethrow_exception(ptr);
        } else {
            fmt::println(stderr, "Terminate called without an active exception");
        }
    } catch (cpptrace::exception& e) {
        fmt::println(
                stderr,
                "Terminate called after throwing an instance of {}: {}\n",
                cpptrace::demangle(typeid(e).name()),
                e.what());
    } catch (std::exception& e) {
        fmt::println(
                stderr,
                "Terminate called after throwing an instance of {}: {}\n",
                cpptrace::demangle(typeid(e).name()),
                e.what());
    }
    std::flush(std::cerr);
    abort();
}
};  // namespace oxen

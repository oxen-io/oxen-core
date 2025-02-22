#include "exception.h"

#include <fmt/core.h>

#include <cstdio>
#include <exception>
#include <sstream>

namespace oxen {

std::string make_traced_msg(std::string_view what, const cpptrace::raw_trace& trace) {
    std::ostringstream oss;
    trace.resolve().print_with_snippets(oss, /*colour*/ false);
    std::string result = std::string(what) + std::string(":\n") + oss.str();
    return result;
}

void set_terminate_handler() {
    std::set_terminate([] {
        // TODO: Support std::nested_exception?
        try {
            auto ptr = std::current_exception();
            if (ptr) {
                std::rethrow_exception(ptr);
            } else {
                fmt::print(stderr, "Terminate called without an active exception\n");
            }
        } catch (cpptrace::exception& e) {
            fmt::print(
                    stderr,
                    "Terminate called after throwing an instance of {}: {}\n",
                    cpptrace::demangle(typeid(e).name()),
                    e.what());
        } catch (std::exception& e) {
            fmt::print(
                    stderr,
                    "Terminate called after throwing an instance of {}: {}\n",
                    cpptrace::demangle(typeid(e).name()),
                    e.what());
        }
        std::fflush(stderr);
        abort();
    });
}
};  // namespace oxen

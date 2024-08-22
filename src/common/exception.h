#pragma once

#include <concepts>
#include <exception>

#ifdef NDEBUG

namespace oxen {

// For a release build `traced<E>` is just a typedef for `E`:
template <std::derived_from<std::exception> StdExcept>
using traced = StdExcept;

// Release build: set_terminate_handler() is a no-op
inline void set_terminate_handler() {}

}  // namespace oxen

#else

#include <cpptrace/cpptrace.hpp>
#include <string>
#include <string_view>

namespace oxen {

std::string make_traced_msg(std::string_view what, const cpptrace::raw_trace& trace);

// Sets a termination handler that dumps a stack-trace where possible.  It should be called on
// startup, main() e.g.:
//
//   oxen::set_terminate_handler()
//
// This implementation is mostly copied from cpptrace's `register_terminate_handler` except that we
// look for `oxen::` exceptions thrown from one of the types in this file.
//
// This call does nothing (i.e. leaves the current terminate handler intact) on a release build.
void set_terminate_handler();

// oxen::exception extends a standard exception object adding stack trace
// information to it, when in a debug build.
template <std::derived_from<std::exception> StdExcept>
class exception : public StdExcept {
  public:
    template <typename... Args>
    explicit exception(Args&&... args) :
            StdExcept{std::forward<Args>(args)...},
            raw_trace{cpptrace::generate_raw_trace(/*skip*/ 0, /*max_depth*/ 256)} {}

    const char* what() const noexcept override {
        if (what_msg.empty())
            what_msg = make_traced_msg(StdExcept::what(), raw_trace);
        return what_msg.c_str();
    }

    const cpptrace::raw_trace& trace() const noexcept { return raw_trace; }

  private:
    // Cache of the string to be printed when 'what' is called because we store
    // the stack trace as a list of U64 addresses and only construct the full
    // trace string on demand.
    mutable std::string what_msg;

    cpptrace::raw_trace raw_trace;
};

template <std::derived_from<std::exception> StdExcept>
using traced = exception<StdExcept>;

}  // namespace oxen

#endif

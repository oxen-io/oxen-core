// So that std::span checks that it's constructed with its own size (only this file's spans; the
// assertions don't change libstdc++'s ABI).
#define _GLIBCXX_ASSERTIONS 1

#include "common/guts.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>

TEST(guts, span_guts_wider_elements) {
    // The default ("fast") style forks this process, which other tests leave with threads running
    // (deadlocking the child); this one runs the death tests in a fresh process instead.
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(
            {
                uint64_t x = 0;
                auto s = tools::span_guts<uint16_t>(x);
                std::exit(s.size() == 4 && static_cast<void*>(s.data()) == &x ? 0 : 1);
            },
            ::testing::ExitedWithCode(0),
            "");
    EXPECT_EXIT(
            {
                const uint64_t x = 0;
                auto s = tools::span_guts<uint16_t>(x);
                std::exit(s.size() == 4 && static_cast<const void*>(s.data()) == &x ? 0 : 1);
            },
            ::testing::ExitedWithCode(0),
            "");
}

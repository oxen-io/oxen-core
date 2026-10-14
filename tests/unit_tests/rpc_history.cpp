#include <gtest/gtest.h>

#include "rpc/core_rpc_server_history.h"

using namespace cryptonote::rpc;

TEST(rpc_history, not_kept_error) {
    const auto e = history_not_kept(2'119'862);
    EXPECT_EQ(e.code, ERROR_HISTORY_NOT_KEPT);
    EXPECT_EQ(
            e.message,
            "Not available on this node: it keeps block history from height 2119862 (--history)");
}

TEST(rpc_history, ranges) {
    // A node keeping all of its history has everything
    EXPECT_FALSE(before_history(0, 0));
    EXPECT_FALSE(before_history(123, 0));

    constexpr uint64_t start = 1'000;
    EXPECT_FALSE(before_history(start, start));
    EXPECT_FALSE(before_history(start + 1, start));
    EXPECT_TRUE(before_history(start - 1, start));
    EXPECT_TRUE(before_history(0, start));
}

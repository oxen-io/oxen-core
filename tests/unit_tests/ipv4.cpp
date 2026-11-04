#include "common/ipv4.h"

#include "gtest/gtest.h"

using oxen::quic::ipv4;

TEST(ipv4, legacy_int) {
    EXPECT_EQ(tools::ipv4_to_legacy_int(ipv4{1, 2, 3, 4}), 0x04030201u);
    EXPECT_EQ(tools::ipv4_to_legacy_int(ipv4{200, 1, 2, 3}), 0x030201c8u);
    EXPECT_EQ(tools::ipv4_from_legacy_int(0x04030201u), (ipv4{1, 2, 3, 4}));
    EXPECT_EQ(tools::ipv4_from_legacy_int(0x030201c8u), (ipv4{200, 1, 2, 3}));
    EXPECT_EQ(tools::ipv4_from_legacy_int(tools::ipv4_to_legacy_int(ipv4{})), ipv4{});
}

TEST(ipv4, parse_range) {
    auto r = tools::parse_ipv4_range("1.2.3.4/23", false);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->ip, (ipv4{1, 2, 2, 0}));
    EXPECT_EQ(r->mask, 23);
    EXPECT_TRUE(r->contains(ipv4{1, 2, 3, 255}));
    EXPECT_FALSE(r->contains(ipv4{1, 2, 4, 0}));

    EXPECT_FALSE(tools::parse_ipv4_range("5.6.7.8", false));
    r = tools::parse_ipv4_range("5.6.7.8", true);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->ip, (ipv4{5, 6, 7, 8}));
    EXPECT_EQ(r->mask, 32);

    r = tools::parse_ipv4_range("5.6.7.8/0", false);
    ASSERT_TRUE(r);
    EXPECT_TRUE(r->contains(ipv4{255, 255, 255, 255}));

    r = tools::parse_ipv4_range("10.20.30.40/1", false);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->to_string(), "0.0.0.0/1");
    EXPECT_TRUE(r->contains(ipv4{127, 255, 255, 255}));
    EXPECT_FALSE(r->contains(ipv4{128, 0, 0, 0}));

    r = tools::parse_ipv4_range("12.34.56.78/16", false);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->to_string(), "12.34.0.0/16");

    EXPECT_FALSE(tools::parse_ipv4_range("5.6.7.8/33", true));
    EXPECT_FALSE(tools::parse_ipv4_range("5.6.7.8/", true));
    EXPECT_FALSE(tools::parse_ipv4_range("5.6.7/24", true));
    EXPECT_FALSE(tools::parse_ipv4_range("foo", true));
}

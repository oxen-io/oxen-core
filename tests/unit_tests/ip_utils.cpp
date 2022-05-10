#include "gtest/gtest.h"

#include "common/net_utils.h"

TEST(IPv4, TestIPv4Netmask)
{
  ASSERT_TRUE(tools::net_utils::netmask_ipv4_bits(8) == uint32_t{0xFF000000});
  ASSERT_TRUE(tools::net_utils::netmask_ipv4_bits(24) == uint32_t{0xFFFFFF00});
}

TEST(IPv4, TestBogon_10_8)
{
  ASSERT_FALSE(tools::net_utils::is_ip_public(tools::net_utils::ip_address(10, 40, 11, 6)));
}

TEST(IPv4, TestBogon_192_168_16)
{
  ASSERT_FALSE(tools::net_utils::is_ip_public(tools::net_utils::ip_address(192, 168, 1, 111)));
}

TEST(IPv4, TestBogon_127_8)
{
  ASSERT_FALSE(tools::net_utils::is_ip_public(tools::net_utils::ip_address(127, 0, 0, 1)));
}

TEST(IPv4, TestBogon_0_8)
{
  ASSERT_FALSE(tools::net_utils::is_ip_public(tools::net_utils::ip_address(0, 0, 0, 0)));
}

TEST(IPv4, TestBogon_NonBogon)
{
  ASSERT_TRUE(tools::net_utils::is_ip_public(tools::net_utils::ip_address(1, 1, 1, 1)));
  ASSERT_TRUE(tools::net_utils::is_ip_public(tools::net_utils::ip_address(8, 8, 6, 6)));
  ASSERT_TRUE(tools::net_utils::is_ip_public(tools::net_utils::ip_address(141, 55, 12, 99)));
  ASSERT_TRUE(tools::net_utils::is_ip_public(tools::net_utils::ip_address(79, 12, 3, 4)));
}

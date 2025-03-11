// Copyright (c) 2022, The Oxen Project
//

#include "common/median.h"

#include <vector>

#include "gtest/gtest.h"

TEST(median, median) {
    using tools::median;

    std::vector<int> data;
    data = {1, 4, 24};
    ASSERT_EQ(median(data.begin(), data.end()), 4);
    data = {4, 1, 24};
    ASSERT_EQ(median(data.begin(), data.end()), 4);
    data = {24, 1, 4};
    ASSERT_EQ(median(data.begin(), data.end()), 4);
    ASSERT_EQ(data[1], 4);
    data = {24, 1, 4, 7};
    ASSERT_EQ(median(data.begin(), data.end()), 5);
    ASSERT_EQ(median(data.begin(), data.end(), true), 4);
    ASSERT_EQ(data[1], 4);
    data = {1, 24, 8, 4};
    ASSERT_EQ(median(data.begin(), data.end()), 6);
    ASSERT_EQ(median(data.begin(), data.end(), true), 4);
    data = {};
    ASSERT_EQ(median(data.begin(), data.end()), 0);
    data = {42};
    ASSERT_EQ(median(data.begin(), data.end()), 42);

    data = {5, -10, 12};
    ASSERT_EQ(median(data), 5);
    ASSERT_EQ(data[1], -10);  // The version above copies
}

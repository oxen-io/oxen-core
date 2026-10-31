#include "wallet/kv_json.h"

#include <list>
#include <nlohmann/json.hpp>
#include <optional>

#include "gtest/gtest.h"

using namespace std::literals;
using tools::kv_json::from_json;
using tools::kv_json::to_json;

namespace {

struct inner {
    std::string name;
    std::vector<uint32_t> nums;
    void serialize(levin_kv::archive& ar) {
        ar.value("name", name);
        ar.value("nums", nums);
    }
};

struct kv_test {
    uint32_t small = 0;
    int64_t neg = 0;
    uint64_t big = 0;
    std::string str;
    std::vector<uint64_t> list;
    std::vector<int32_t> signed_list;
    std::vector<bool> bools;
    std::vector<std::string> strs;
    inner in;
    std::list<inner> ins;
    std::optional<uint16_t> opt;
    bool flag = false;

    void serialize(levin_kv::archive& ar) {
        ar.value("small", small);
        ar.value("neg", neg);
        ar.value("big", big);
        ar.value("str", str);
        ar.value("list", list);
        ar.value("signed_list", signed_list);
        ar.value("bools", bools);
        ar.value("strs", strs);
        ar.value("in", in);
        ar.value("ins", ins);
        ar.value("opt", opt);
        ar.value_or("flag", flag, false);
    }
};

}  // namespace

TEST(kv_json, round_trip) {
    auto j = R"({
        "small": 7,
        "neg": -3,
        "big": 18446744073709551615,
        "str": "hello \"world\"\n",
        "list": [1, 2, 18446744073709551615],
        "signed_list": [5, -6],
        "bools": [true, false],
        "strs": ["a", "b"],
        "in": {"name": "x", "nums": [1]},
        "ins": [{"name": "y", "nums": [2, 3]}, {"name": "z"}],
        "opt": 9,
        "flag": true
    })"_json;
    kv_test t{};
    ASSERT_TRUE(from_json(j, t));
    EXPECT_EQ(t.small, 7);
    EXPECT_EQ(t.neg, -3);
    EXPECT_EQ(t.big, 18446744073709551615ULL);
    EXPECT_EQ(t.list, (std::vector<uint64_t>{1, 2, 18446744073709551615ULL}));
    EXPECT_EQ(t.signed_list, (std::vector<int32_t>{5, -6}));
    ASSERT_EQ(t.ins.size(), 2u);
    EXPECT_EQ(t.ins.back().name, "z");
    EXPECT_EQ(t.opt, 9);
    EXPECT_EQ(to_json(t), j);
}

TEST(kv_json, omitted) {
    // Empty containers, unset optionals and defaults aren't written
    EXPECT_EQ(to_json(kv_test{}), R"({
        "small": 0, "neg": 0, "big": 0, "str": "", "in": {"name": ""}
    })"_json);

    // Nulls and empty arrays are as good as missing
    kv_test t{};
    t.small = 5;
    t.list = {1};
    ASSERT_TRUE(from_json(R"({"small": null, "list": [], "str": "x"})"_json, t));
    EXPECT_EQ(t.small, 5);
    EXPECT_EQ(t.list, (std::vector<uint64_t>{1}));
    EXPECT_EQ(t.str, "x");
}

TEST(kv_json, conversions) {
    kv_test t{};
    t.small = 1;
    t.neg = 2;
    // Out of range, a float, or a negative for an unsigned field: left as it was
    ASSERT_TRUE(from_json(R"({"small": 4294967296, "neg": 1.5})"_json, t));
    EXPECT_EQ(t.small, 1u);
    EXPECT_EQ(t.neg, 2);
    ASSERT_TRUE(from_json(R"({"small": -1})"_json, t));
    EXPECT_EQ(t.small, 1u);
    // ... as is an array with any element that doesn't convert
    t.signed_list = {9};
    ASSERT_TRUE(from_json(R"({"signed_list": [1, 4294967296]})"_json, t));
    EXPECT_EQ(t.signed_list, (std::vector<int32_t>{9}));

    // Strings of digits convert into uint64_ts, and nothing else
    ASSERT_TRUE(from_json(R"({"big": "12345", "list": ["1", "2"], "small": "7"})"_json, t));
    EXPECT_EQ(t.big, 12345u);
    EXPECT_EQ(t.list, (std::vector<uint64_t>{1, 2}));
    EXPECT_EQ(t.small, 1u);
    ASSERT_TRUE(from_json(R"({"big": "12x"})"_json, t));
    EXPECT_EQ(t.big, 12345u);

    // Bools and integers don't convert into each other
    ASSERT_TRUE(from_json(R"({"flag": 1, "small": true})"_json, t));
    EXPECT_FALSE(t.flag);
    EXPECT_EQ(t.small, 1u);
}

TEST(kv_json, unsupported) {
    kv_test t{};
    EXPECT_THROW(from_json("[1]"_json, t), std::invalid_argument);
    EXPECT_THROW(from_json("123"_json, t), std::invalid_argument);
    EXPECT_THROW(from_json(R"({"a": [[1]]})"_json, t), std::invalid_argument);
    EXPECT_THROW(from_json(R"({"a": [1, "2"]})"_json, t), std::invalid_argument);
    EXPECT_THROW(from_json(R"({"a": [true, 1]})"_json, t), std::invalid_argument);
    EXPECT_THROW(from_json(R"({"a": [null]})"_json, t), std::invalid_argument);
    EXPECT_THROW(from_json(R"({"a": {"b": [1, "2"]}})"_json, t), std::invalid_argument);
    EXPECT_THROW(from_json(R"({"a": [-1, 9223372036854775808]})"_json, t), std::invalid_argument);
    EXPECT_NO_THROW(from_json(R"({"a": [-1, 9223372036854775807]})"_json, t));
    EXPECT_NO_THROW(from_json(R"({"a": [1.5, 2]})"_json, t));
}

TEST(kv_json, serialize_throws) {
    struct checked {
        uint32_t v = 0;
        void serialize(levin_kv::archive& ar) {
            ar.value("v", v);
            if (ar.loading() && v > 10)
                throw std::runtime_error{"too big"};
        }
    };
    checked c;
    EXPECT_TRUE(from_json(R"({"v": 10})"_json, c));
    EXPECT_FALSE(from_json(R"({"v": 11})"_json, c));
}

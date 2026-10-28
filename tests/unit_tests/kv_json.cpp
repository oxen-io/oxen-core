#include "wallet/kv_json.h"

#include <nlohmann/json.hpp>

#include "epee/serialization/keyvalue_serialization.h"
#include "epee/storages/portable_storage.h"
#include "gtest/gtest.h"

namespace ser = epee::serialization;

namespace {

struct kv_test {
    uint32_t small;
    int64_t neg;
    std::string str;
    std::vector<uint64_t> list;
    std::vector<int32_t> signed_list;
    bool flag;

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(small)
    KV_SERIALIZE(neg)
    KV_SERIALIZE(str)
    KV_SERIALIZE(list)
    KV_SERIALIZE(signed_list)
    KV_SERIALIZE_OPT(flag, false)
    END_KV_SERIALIZE_MAP()
};

}  // namespace

TEST(kv_json, round_trip) {
    auto j = R"({
        "u": 18446744073709551615,
        "i": -42,
        "d": 1.25,
        "b": true,
        "s": "hello \"world\"\n",
        "obj": {"x": 1, "y": {"z": "deep"}},
        "us": [1, 2, 3],
        "is": [-1, 2, -3],
        "ds": [1.5, 2],
        "bs": [true, false],
        "ss": ["a", "b"],
        "os": [{"a": 1}, {"b": [2]}]
    })"_json;

    auto sec = tools::kv_json::to_section(j);
    EXPECT_TRUE(std::holds_alternative<uint64_t>(sec.m_entries.at("u")));
    EXPECT_TRUE(std::holds_alternative<int64_t>(sec.m_entries.at("i")));
    auto& is = std::get<ser::array_entry>(sec.m_entries.at("is"));
    EXPECT_TRUE(std::holds_alternative<ser::array_t<int64_t>>(is));
    auto& ds = std::get<ser::array_entry>(sec.m_entries.at("ds"));
    EXPECT_TRUE(std::holds_alternative<ser::array_t<double>>(ds));

    auto expected = j;
    expected["ds"] = {1.5, 2.0};
    EXPECT_EQ(tools::kv_json::to_json(sec), expected);
}

TEST(kv_json, omitted) {
    auto sec = tools::kv_json::to_section(R"({"a": null, "b": [], "c": 1})"_json);
    EXPECT_EQ(sec.m_entries.size(), 1u);
    EXPECT_EQ(tools::kv_json::to_json(sec), R"({"c": 1})"_json);
}

TEST(kv_json, unsupported) {
    using tools::kv_json::to_section;
    EXPECT_THROW(to_section("[1]"_json), std::invalid_argument);
    EXPECT_THROW(to_section("123"_json), std::invalid_argument);
    EXPECT_THROW(to_section(R"({"a": [[1]]})"_json), std::invalid_argument);
    EXPECT_THROW(to_section(R"({"a": [1, "2"]})"_json), std::invalid_argument);
    EXPECT_THROW(to_section(R"({"a": [true, 1]})"_json), std::invalid_argument);
    EXPECT_THROW(to_section(R"({"a": [null]})"_json), std::invalid_argument);
    EXPECT_THROW(to_section(R"({"a": [-1, 9223372036854775808]})"_json), std::invalid_argument);
    EXPECT_NO_THROW(to_section(R"({"a": [-1, 9223372036854775807]})"_json));
}

TEST(kv_json, kv_serializable) {
    ser::portable_storage ps;
    ps.root() = tools::kv_json::to_section(R"({
        "small": 7,
        "neg": -3,
        "str": "abc",
        "list": [1, 2, 18446744073709551615],
        "signed_list": [5, -6]
    })"_json);
    kv_test t{};
    ASSERT_TRUE(t.load(ps));
    EXPECT_EQ(t.small, 7);
    EXPECT_EQ(t.neg, -3);
    EXPECT_EQ(t.str, "abc");
    EXPECT_EQ(t.list, (std::vector<uint64_t>{1, 2, 18446744073709551615ULL}));
    EXPECT_EQ(t.signed_list, (std::vector<int32_t>{5, -6}));
    EXPECT_FALSE(t.flag);

    ser::portable_storage out;
    t.flag = true;
    t.store(out);
    EXPECT_EQ(tools::kv_json::to_json(out.root()), R"({
        "small": 7,
        "neg": -3,
        "str": "abc",
        "list": [1, 2, 18446744073709551615],
        "signed_list": [5, -6],
        "flag": true
    })"_json);

    // An out-of-range value is not truncated: epee logs it and leaves the field as it was.
    ser::portable_storage too_big;
    too_big.root() = tools::kv_json::to_section(R"({"small": 4294967296})"_json);
    kv_test t2{};
    t2.load(too_big);
    EXPECT_EQ(t2.small, 0u);
}

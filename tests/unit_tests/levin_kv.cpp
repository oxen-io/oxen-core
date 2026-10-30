#include "serialization/levin_kv/levin_kv.h"

#include <gtest/gtest.h>
#include <oxenc/hex.h>

#include <array>
#include <deque>
#include <limits>
#include <list>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/guts.h"
#include "levin_kv_dump.h"

using namespace std::literals;

namespace {

enum class colour : uint8_t { red = 1, green = 2 };

struct inner {
    uint32_t a = 0;
    std::string s;

    void serialize(levin_kv::archive& ar) {
        ar.value("a", a);
        ar.value("s", s);
    }

    bool operator==(const inner&) const = default;
};

// Everything the archive can do, checked (as sample()) against epee's encoding of it.
struct everything {
    int64_t i64 = 0;
    int32_t i32 = 0;
    int16_t i16 = 0;
    int8_t i8 = 0;
    uint64_t u64 = 0;
    uint32_t u32 = 0;
    uint16_t u16 = 0;
    uint8_t u8 = 0;
    bool b = false;
    std::string str;
    std::vector<uint64_t> u64s;
    std::vector<int16_t> i16s;
    std::vector<std::string> strs;
    inner in;
    std::vector<inner> ins;
    std::array<uint8_t, 32> hash{};
    std::vector<std::array<uint8_t, 4>> blobs;
    std::vector<uint64_t> packed;
    colour col = colour::red;
    uint64_t opt = 7;

    void serialize(levin_kv::archive& ar) {
        ar.value("i64", i64);
        ar.value("i32", i32);
        ar.value("i16", i16);
        ar.value("i8", i8);
        ar.value("u64", u64);
        ar.value("u32", u32);
        ar.value("u16", u16);
        ar.value("u8", u8);
        ar.value("b", b);
        ar.value("str", str);
        ar.value("u64s", u64s);
        ar.value("i16s", i16s);
        ar.value("strs", strs);
        ar.value("in", in);
        ar.value("ins", ins);
        ar.value("hash", tools::byte_span(hash));
        ar.value("blobs", blobs);
        ar.packed("packed", packed);
        ar.value("col", col);
        ar.value_or("opt", opt, uint64_t{7});
    }

    bool operator==(const everything&) const = default;
};

everything sample() {
    everything e;
    e.i64 = -1234567890123;
    e.i32 = -123456;
    e.i16 = -1234;
    e.i8 = -12;
    e.u64 = 12345678901234567890ULL;
    e.u32 = 4000000000;
    e.u16 = 60000;
    e.u8 = 250;
    e.b = true;
    e.str = "hello\0world"s;
    e.u64s = {1, 300, 70000, 1ULL << 40};
    e.i16s = {-1, 2, -3};
    e.strs = {"", "a", std::string(300, 'x')};
    e.in = {42, "inner"};
    e.ins = {{1, "one"}, {2, "two"}};
    for (size_t i = 0; i < e.hash.size(); i++)
        e.hash[i] = static_cast<uint8_t>(i);
    e.blobs = {{1, 2, 3, 4}, {5, 6, 7, 8}};
    e.packed = {1, 1ULL << 63, 0x0102030405060708};
    e.col = colour::green;
    e.opt = 99;
    return e;
}

template <typename T>
T round_trip(const T& v) {
    T out{};
    EXPECT_TRUE(levin_kv::decode(levin_kv::encode(v), out));
    return out;
}

template <typename T>
struct one {
    T v{};
    void serialize(levin_kv::archive& ar) { ar.value("v", v); }
};
template <typename T>
struct one_packed {
    std::vector<T> v;
    void serialize(levin_kv::archive& ar) { ar.packed("v", v); }
};
struct one_blob {
    std::array<uint8_t, 4> v{};
    void serialize(levin_kv::archive& ar) { ar.value("v", tools::byte_span(v)); }
};
struct one_default {
    uint32_t v = 0;
    void serialize(levin_kv::archive& ar) { ar.value_or("v", v, 5u); }
};

// Concatenates pieces of hex, kept apart in the tests to show the parts of a message
template <typename... S>
std::string cat(const S&... hex) {
    return (std::string{} + ... + hex);
}

constexpr auto HEADER = "011101010101020101";

// The header, then a map of one field, named "v", with the type and value given
template <typename... S>
std::string header_and_v(const S&... type_and_value) {
    return cat(HEADER, "04", "0176", type_and_value...);
}

}  // namespace

TEST(levin_kv, round_trip_everything) {
    auto e = sample();
    EXPECT_EQ(round_trip(e), e);
}

TEST(levin_kv, exact_bytes) {
    // 300 as a uint16 (type 7)
    EXPECT_EQ(oxenc::to_hex(levin_kv::encode(one<uint64_t>{300})), header_and_v("07", "2c01"));
    // a string of 3 bytes: type 10, varint 3 (3 << 2 = 0x0c), bytes
    EXPECT_EQ(
            oxenc::to_hex(levin_kv::encode(one<std::string>{"abc"})),
            header_and_v("0a", "0c", "616263"));
    EXPECT_EQ(oxenc::to_hex(levin_kv::encode(one<bool>{true})), header_and_v("0b", "01"));
    // an array (0x80) of uint16 (7), varint 2 (0x08), 1 and 300
    EXPECT_EQ(
            oxenc::to_hex(levin_kv::encode(one<std::vector<uint32_t>>{{1, 300}})),
            header_and_v("87", "08", "0100", "2c01"));
    // packed: a string (type 10) of 2 little-endian uint32s, varint 8 (0x20)
    EXPECT_EQ(
            oxenc::to_hex(levin_kv::encode(one_packed<uint32_t>{{1, 0x01020304}})),
            header_and_v("0a", "20", "01000000", "04030201"));
}

TEST(levin_kv, narrowest_integer_types) {
    auto type_of = [](auto v) {
        auto enc = levin_kv::encode(one<decltype(v)>{v});
        return static_cast<int>(enc[12]);
    };
    EXPECT_EQ(type_of(uint64_t{0}), 8);
    EXPECT_EQ(type_of(uint64_t{255}), 8);
    EXPECT_EQ(type_of(uint64_t{256}), 7);
    EXPECT_EQ(type_of(uint64_t{65535}), 7);
    EXPECT_EQ(type_of(uint64_t{65536}), 6);
    EXPECT_EQ(type_of(uint64_t{0xffffffff}), 6);
    EXPECT_EQ(type_of(uint64_t{0x100000000}), 5);
    EXPECT_EQ(type_of(int8_t{1}), 8) << "non-negative values of signed types are sent unsigned";
    EXPECT_EQ(type_of(int64_t{-1}), 4);
    EXPECT_EQ(type_of(int64_t{-128}), 4);
    EXPECT_EQ(type_of(int64_t{-129}), 3);
    EXPECT_EQ(type_of(int64_t{-32768}), 3);
    EXPECT_EQ(type_of(int64_t{-32769}), 2);
    EXPECT_EQ(type_of(int64_t{std::numeric_limits<int32_t>::min()}), 2);
    EXPECT_EQ(type_of(int64_t{std::numeric_limits<int32_t>::min()} - 1), 1);

    // An array's type holds its lowest and highest values
    auto array_type = [](auto v) {
        auto enc = levin_kv::encode(one<decltype(v)>{v});
        return static_cast<int>(enc[12]) & 0x7f;
    };
    EXPECT_EQ(array_type(std::vector<uint64_t>{1, 2, 3}), 8);
    EXPECT_EQ(array_type(std::vector<uint64_t>{1, 300}), 7);
    EXPECT_EQ(array_type(std::vector<int32_t>{-1, 1}), 4);
    EXPECT_EQ(array_type(std::vector<int32_t>{-1, 200}), 3);
    EXPECT_EQ(array_type(std::vector<int64_t>{-1, std::numeric_limits<int64_t>::max()}), 1);
}

TEST(levin_kv, varint_widths) {
    // String lengths around each varint size boundary
    for (size_t len : {0, 1, 63, 64, 16383, 16384, 100000}) {
        one<std::string> s{std::string(len, 'z')};
        EXPECT_EQ(round_trip(s).v, s.v) << len;
        auto enc = levin_kv::encode(s);
        const size_t varint_size = len < 64 ? 1 : len < 16384 ? 2 : 4;
        EXPECT_EQ(enc.size(), 9 + 1 + 2 + 1 + varint_size + len) << len;
    }
}

TEST(levin_kv, map_counts) {
    // More fields than a one-byte count holds, in nested and root maps
    struct many {
        std::vector<uint8_t> vals = std::vector<uint8_t>(100);
        std::vector<std::string> names;
        many() {
            for (size_t i = 0; i < vals.size(); i++) {
                vals[i] = static_cast<uint8_t>(i);
                names.push_back("f" + std::to_string(i));
            }
        }
        void serialize(levin_kv::archive& ar) {
            for (size_t i = 0; i < vals.size(); i++)
                ar.value(names[i], vals[i]);
        }
        bool operator==(const many& o) const { return vals == o.vals; }
    };
    struct outer {
        many m;
        uint8_t after = 9;
        void serialize(levin_kv::archive& ar) {
            ar.value("m", m);
            ar.value("after", after);
        }
    };
    outer o;
    o.m.vals[50] = 200;
    auto got = round_trip(o);
    EXPECT_TRUE(got.m == o.m);
    EXPECT_EQ(got.after, 9);
    EXPECT_TRUE(round_trip(o.m) == o.m);
}

TEST(levin_kv, other_integer_types) {
    // Types the same as but distinct from the fixed-width ones (int64_t is long, on most platforms)
    EXPECT_EQ(round_trip(one<long long>{-5'000'000'000}).v, -5'000'000'000);
    EXPECT_EQ(round_trip(one<unsigned long long>{1ULL << 63}).v, 1ULL << 63);
    EXPECT_EQ(round_trip(one<unsigned long>{1UL << 31}).v, 1UL << 31);
}

TEST(levin_kv, other_containers) {
    // Sent as vectors are, so read as each other
    one<std::list<std::string>> strs{{"a", "b", "c"}};
    EXPECT_EQ(round_trip(strs).v, strs.v);
    one<std::vector<std::string>> vec;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(strs), vec));
    EXPECT_EQ(vec.v, (std::vector<std::string>{"a", "b", "c"}));

    one<std::deque<uint64_t>> nums{{1, 300, 1ULL << 40}};
    EXPECT_EQ(round_trip(nums).v, nums.v);
    EXPECT_EQ(round_trip(one<std::list<inner>>{{{1, "one"}, {2, "two"}}}).v.size(), 2u);

    // A set keeps the first of repeated elements
    one<std::set<uint32_t>> set;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::vector<uint32_t>>{{3, 1, 3, 2}}), set));
    EXPECT_EQ(set.v, (std::set<uint32_t>{1, 2, 3}));

    // Empty isn't written; when read, a container is replaced, not appended to
    EXPECT_EQ(levin_kv::encode(one<std::list<std::string>>{}).size(), 10u);
    one<std::list<std::string>> existing{{"x"}};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(strs), existing));
    EXPECT_EQ(existing.v, strs.v);

    one<std::optional<std::list<uint16_t>>> opt{std::list<uint16_t>{7}};
    EXPECT_EQ(round_trip(opt).v, opt.v);
}

TEST(levin_kv, bool_arrays) {
    // (Which epee can't write, so they aren't in `everything`)
    one<std::vector<bool>> bools{{true, false, true}};
    EXPECT_EQ(round_trip(bools).v, bools.v);
    EXPECT_EQ(oxenc::to_hex(levin_kv::encode(bools)), header_and_v("8b", "0c", "010001"));
}

TEST(levin_kv, enums) {
    EXPECT_EQ(round_trip(one<colour>{colour::green}).v, colour::green);
}

namespace adl {
struct free_serialized {
    uint16_t x = 0;
};
void serialize(levin_kv::archive& ar, free_serialized& v) {
    ar.value("x", v.x);
}
}  // namespace adl

TEST(levin_kv, free_serialize) {
    EXPECT_EQ(round_trip(adl::free_serialized{1234}).x, 1234);
    EXPECT_EQ(round_trip(one<adl::free_serialized>{{4321}}).v.x, 4321);
}

// A type whose namespace we don't add to (such as a library's), serialized by an overload in
// levin_kv's, declared after the archive.
namespace foreign {
struct thing {
    uint16_t x = 0;
};
}  // namespace foreign
namespace levin_kv {
void serialize(archive& ar, foreign::thing& v) {
    ar.value("x", v.x);
}
}  // namespace levin_kv

TEST(levin_kv, serialize_in_levin_kv_namespace) {
    EXPECT_EQ(round_trip(one<foreign::thing>{{4321}}).v.x, 4321);
    EXPECT_EQ(round_trip(one<std::vector<foreign::thing>>{{{1}, {2}}}).v.size(), 2u);
}

TEST(levin_kv, blob_defaults) {
    struct checksum {
        std::array<uint8_t, 4> v{};
        void serialize(levin_kv::archive& ar) {
            static constexpr std::array<uint8_t, 4> none{};
            ar.value_or("v", tools::byte_span(v), tools::byte_span(none));
        }
    };
    EXPECT_EQ(levin_kv::encode(checksum{}).size(), 10u) << "header and an empty map";
    checksum c{{1, 2, 3, 4}};
    EXPECT_EQ(round_trip(c).v, c.v);

    // Not read (missing, or the wrong size): the default
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(checksum{}), c));
    EXPECT_EQ(c.v, (std::array<uint8_t, 4>{}));
    c.v = {1, 2, 3, 4};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::string>{"abc"}), c));
    EXPECT_EQ(c.v, (std::array<uint8_t, 4>{}));
}

TEST(levin_kv, empty_containers_and_defaults_not_written) {
    everything e;  // all empty, and opt at its default
    auto enc = levin_kv::encode(e);
    for (auto name : {"u64s", "i16s", "strs", "ins", "blobs", "packed", "opt"})
        EXPECT_EQ(enc.find(name), std::string::npos) << name;

    everything got;
    got.opt = 123;
    ASSERT_TRUE(levin_kv::decode(enc, got));
    EXPECT_EQ(got.opt, 7) << "a missing field with a default takes the default";
}

TEST(levin_kv, defaults) {
    one_default d;
    d.v = 5;
    EXPECT_EQ(levin_kv::encode(d).size(), 10u) << "header and an empty map";
    d.v = 6;
    EXPECT_EQ(round_trip(d).v, 6u);

    // A field that doesn't convert takes the default too, as epee did
    d.v = 1;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::string>{"x"}), d));
    EXPECT_EQ(d.v, 5u);
}

TEST(levin_kv, optionals) {
    one<std::optional<uint32_t>> unset;
    EXPECT_EQ(levin_kv::encode(unset).size(), 10u) << "header and an empty map";
    EXPECT_FALSE(round_trip(unset).v);
    EXPECT_EQ(round_trip(one<std::optional<uint32_t>>{5}).v, 5u);

    // Reset when not sent, or not convertible
    one<std::optional<uint32_t>> set{5};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(unset), set));
    EXPECT_FALSE(set.v);
    set.v = 5;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::string>{"x"}), set));
    EXPECT_FALSE(set.v);

    one<std::optional<inner>> o{inner{3, "three"}};
    EXPECT_EQ(round_trip(o).v, o.v);
    one<std::optional<std::vector<std::string>>> strs{std::vector{"a"s, "b"s}};
    EXPECT_EQ(round_trip(strs).v, strs.v);
}

TEST(levin_kv, integer_conversions) {
    one<uint32_t> small;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<uint64_t>{4000000000}), small));
    EXPECT_EQ(small.v, 4000000000u);

    // Out of range for the field's type: the field is left as it was
    small.v = 9;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<uint64_t>{1ULL << 32}), small));
    EXPECT_EQ(small.v, 9u);
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<int64_t>{-1}), small));
    EXPECT_EQ(small.v, 9u);

    one<int8_t> tiny;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<uint64_t>{200}), tiny));
    EXPECT_EQ(tiny.v, 0);
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<uint64_t>{100}), tiny));
    EXPECT_EQ(tiny.v, 100);

    // Integers and bools don't convert into each other
    one<bool> b;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<uint64_t>{1}), b));
    EXPECT_FALSE(b.v);
    one<uint64_t> big{1};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<bool>{true}), big));
    EXPECT_EQ(big.v, 1u);

    // Nor do strings and integers, even strings of digits
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::string>{"12345"}), big));
    EXPECT_EQ(big.v, 1u);
}

TEST(levin_kv, array_conversions) {
    using u8s = one<std::vector<uint8_t>>;
    using i64s = one<std::vector<int64_t>>;
    EXPECT_EQ(
            round_trip(one<std::vector<int64_t>>{{-5, 0, 5}}).v, (std::vector<int64_t>{-5, 0, 5}));

    u8s got;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(i64s{{1, 2, 255}}), got));
    EXPECT_EQ(got.v, (std::vector<uint8_t>{1, 2, 255}));

    // An element out of range leaves the whole array as it was
    got.v = {9};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(i64s{{1, 2, 256}}), got));
    EXPECT_EQ(got.v, (std::vector<uint8_t>{9}));
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(i64s{{-1, 2}}), got));
    EXPECT_EQ(got.v, (std::vector<uint8_t>{9}));

    // A scalar isn't an array, nor an array a scalar
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<uint8_t>{1}), got));
    EXPECT_EQ(got.v, (std::vector<uint8_t>{9}));
    one<uint8_t> scalar{7};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(u8s{{1}}), scalar));
    EXPECT_EQ(scalar.v, 7);
}

TEST(levin_kv, packed) {
    using packed = one_packed<uint64_t>;
    packed p{{1, 1ULL << 63}};
    EXPECT_EQ(round_trip(p).v, p.v);

    // Reads an array too
    packed got;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::vector<int32_t>>{{3, 4}}), got));
    EXPECT_EQ(got.v, (std::vector<uint64_t>{3, 4}));
    // ... but not one with a negative value
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::vector<int32_t>>{{3, -4}}), got));
    EXPECT_EQ(got.v, (std::vector<uint64_t>{3, 4}));

    // And an unsigned array field reads a packed one
    one<std::vector<uint64_t>> arr;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(p), arr));
    EXPECT_EQ(arr.v, p.v);
    one<std::vector<uint16_t>> arr16;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one_packed<uint16_t>{{7, 65535}}), arr16));
    EXPECT_EQ(arr16.v, (std::vector<uint16_t>{7, 65535}));

    // ... when it's a whole number of them
    arr.v = {9};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::string>{"1234567"}), arr));
    EXPECT_EQ(arr.v, (std::vector<uint64_t>{9}));

    // A signed array doesn't
    one<std::vector<int64_t>> signed_arr;
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(p), signed_arr));
    EXPECT_TRUE(signed_arr.v.empty());
}

TEST(levin_kv, blob_sizes) {
    EXPECT_EQ(round_trip(one_blob{{1, 2, 3, 4}}).v, (std::array<uint8_t, 4>{1, 2, 3, 4}));

    // A blob of the wrong size is left alone
    one_blob b{{9, 9, 9, 9}};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(one<std::string>{"abc"}), b));
    EXPECT_EQ(b.v, (std::array<uint8_t, 4>{9, 9, 9, 9}));

    // A vector blob that isn't a whole number of elements is too
    everything e;
    e.blobs = {{7, 7, 7, 7}};
    struct bad_blobs {
        std::string blobs = "12345";
        void serialize(levin_kv::archive& ar) { ar.value("blobs", blobs); }
    };
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(bad_blobs{}), e));
    ASSERT_EQ(e.blobs.size(), 1u);
}

TEST(levin_kv, decode_fails_if_serialize_throws) {
    // As a type that checks what it reads does, by throwing
    struct checked {
        uint64_t v = 0;
        void serialize(levin_kv::archive& ar) {
            ar.value("v", v);
            if (ar.loading() && v > 10)
                throw std::runtime_error{"too big"};
        }
    };
    checked c;
    EXPECT_TRUE(levin_kv::decode(levin_kv::encode(one<uint64_t>{10}), c));
    EXPECT_FALSE(levin_kv::decode(levin_kv::encode(one<uint64_t>{11}), c));
}

TEST(levin_kv, first_duplicate_wins) {
    // header, 2 entries, both "v" (uint8): 1, then 2
    auto msg = oxenc::from_hex(cat(HEADER, "08", "017608", "01", "017608", "02"));
    one<uint64_t> v;
    ASSERT_TRUE(levin_kv::decode(msg, v));
    EXPECT_EQ(v.v, 1u);
}

TEST(levin_kv, malformed) {
    one<uint64_t> v;
    auto good = levin_kv::encode(one<uint64_t>{300});
    EXPECT_TRUE(levin_kv::decode(good, v));

    // Every truncation of a message is refused
    for (size_t len = 0; len < good.size(); len++)
        EXPECT_FALSE(levin_kv::decode(std::string_view{good}.substr(0, len), v)) << len;

    // A wrong signature or version
    for (size_t i = 0; i < 9; i++) {
        auto bad = good;
        bad[i] ^= 0x40;
        EXPECT_FALSE(levin_kv::decode(bad, v)) << i;
    }

    // An unknown type; a double (9), which epee never read; and a nested array (13, which epee
    // doesn't support either)
    for (uint8_t type : {0, 9, 0x80 | 9, 13, 14, 0x80 | 13}) {
        auto bad = good;
        bad[12] = static_cast<char>(type);
        EXPECT_FALSE(levin_kv::decode(bad, v)) << +type;
    }

    // Counts larger than what's left: of fields, array elements, and string bytes
    EXPECT_FALSE(levin_kv::decode(oxenc::from_hex(cat(HEADER, "fc")), v));
    EXPECT_FALSE(
            levin_kv::decode(oxenc::from_hex(header_and_v("85", "08", "0100000000000000")), v));
    EXPECT_FALSE(levin_kv::decode(oxenc::from_hex(header_and_v("8a", "08", "00")), v));
    EXPECT_FALSE(levin_kv::decode(oxenc::from_hex(header_and_v("0a", "0c", "6162")), v));

    // Anything after the message is ignored
    EXPECT_TRUE(levin_kv::decode(good + "trailing", v));
}

TEST(levin_kv, nesting_limit) {
    // Maps nested n deep, each with one field "m" holding the next
    auto nested = [](int n) {
        std::string msg = oxenc::from_hex(HEADER);
        for (int i = 0; i < n; i++)
            msg += oxenc::from_hex(cat("04", "016d", "0c"));
        msg += oxenc::from_hex("00");
        return msg;
    };
    one<uint64_t> v;
    EXPECT_TRUE(levin_kv::decode(nested(49), v));
    EXPECT_FALSE(levin_kv::decode(nested(51), v));
}

namespace {
// clang-format off
// epee's encodings of sample() and sorted{}, recorded before epee went
constexpr auto epee_everything = "0111010101010201015001620b0105626c6f62730a20010203040506070803636f6c080204686173680a80000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f03693136032efb0469313673830cffff0200fdff0369333202c01dfeff036936340135fb048ee0feffff02693804f402696e0c080161062a00000001730a14696e6e657203696e738c08080161060100000001730a0c6f6e65080161060200000001730a0c74776f036f7074056300000000000000067061636b65640a60010000000000000000000000000000800807060504030201037374720a2c68656c6c6f00776f726c6404737472738a0c000461b104787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878037531360760ea037533320600286bee0375363405d20a1feb8ca954ab0475363473851001000000000000002c010000000000007011010000000000000000000001000002753808fa";
constexpr auto epee_sorted = "0111010101010201012001610a047801620805016304fb01648a080479047a01650c0401730a046501660a0c01020301670a20010000000200000001680b01";
// clang-format on
}  // namespace

TEST(levin_kv, ours_says_what_epees_did) {
    EXPECT_EQ(
            levin_kv_test::dump(levin_kv::encode(sample())),
            levin_kv_test::dump(oxenc::from_hex(epee_everything)));
}

TEST(levin_kv, we_read_epees) {
    everything got;
    ASSERT_TRUE(levin_kv::decode(oxenc::from_hex(epee_everything), got));
    EXPECT_EQ(got, sample());
}

namespace {
// epee writes a map's fields sorted by name, and integers as their declared types; with the
// fields serialized in that order, and declared as the narrowest types their values fit, we write
// exactly the same bytes.
struct label {
    std::string s = "e";
    void serialize(levin_kv::archive& ar) { ar.value("s", s); }
};
struct sorted {
    std::string a = "x";
    uint8_t b = 5;
    int8_t c = -5;
    std::vector<std::string> d{"y", "z"};
    label e;
    std::array<uint8_t, 3> f{1, 2, 3};
    std::vector<uint32_t> g{1, 2};
    bool h = true;
    void serialize(levin_kv::archive& ar) {
        ar.value("a", a);
        ar.value("b", b);
        ar.value("c", c);
        ar.value("d", d);
        ar.value("e", e);
        ar.value("f", tools::byte_span(f));
        ar.packed("g", g);
        ar.value("h", h);
    }
};
}  // namespace

TEST(levin_kv, same_bytes_as_epee) {
    EXPECT_EQ(oxenc::to_hex(levin_kv::encode(sorted{})), epee_sorted);
}

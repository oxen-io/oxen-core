#include <gtest/gtest.h>
#include <oxenc/hex.h>

#include <cstring>

#include "epee/net/levin_base.h"
#include "p2p/levin/frame.h"

using namespace nodetool;

static std::span<const unsigned char> bytes(std::string_view s) {
    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

TEST(levin_frame, header_bytes) {
    // signature, body size, expect response, command, return code, flags, protocol version
    EXPECT_EQ(
            oxenc::to_hex(levin::make_request(1001, bytes("hello"), true)),
            "0121010101010101"
            "0500000000000000"
            "01"
            "e9030000"
            "00000000"
            "01000000"
            "01000000"
            "68656c6c6f");
    EXPECT_EQ(
            oxenc::to_hex(levin::make_response(2002, -4, {})),
            "0121010101010101"
            "0000000000000000"
            "00"
            "d2070000"
            "fcffffff"
            "02000000"
            "01000000");
}

// The epee header is a packed struct written to the wire with memcpy; ours must produce exactly
// the same bytes, so that the two can talk to each other.
TEST(levin_frame, matches_epee_header) {
    for (auto [command, size, flags, expect] : {
                 std::tuple<uint32_t, uint64_t, uint32_t, bool>{
                         1001, 0, LEVIN_PACKET_REQUEST, true},
                 {2002, 123456789012, LEVIN_PACKET_REQUEST, false},
                 {3, 33, LEVIN_PACKET_RESPONSE, false},
                 {0xffffffff, 1, LEVIN_PACKET_RESPONSE, false},
         }) {
        auto epee_head = epee::levin::make_header(command, size, flags, expect);
        epee_head.m_return_code = -7;

        levin::header head;
        head.body_size = size;
        head.expect_response = expect;
        head.command = command;
        head.return_code = -7;
        head.flags = flags;

        static_assert(sizeof(epee_head) == levin::header::SIZE);
        auto encoded = head.encode();
        EXPECT_EQ(0, std::memcmp(encoded.data(), &epee_head, sizeof(epee_head)));

        auto decoded = levin::header::decode(encoded);
        ASSERT_TRUE(decoded);
        EXPECT_EQ(decoded->body_size, size);
        EXPECT_EQ(decoded->expect_response, expect);
        EXPECT_EQ(decoded->command, command);
        EXPECT_EQ(decoded->return_code, -7);
        EXPECT_EQ(decoded->flags, flags);
        EXPECT_EQ(decoded->protocol_version, levin::PROTOCOL_VERSION);
    }
}

TEST(levin_frame, decode_rejects_bad_signature) {
    auto encoded = levin::header{}.encode();
    encoded[3] ^= 0x10;
    EXPECT_FALSE(levin::header::decode(encoded));
}

TEST(levin_frame, response_needs_version_1) {
    levin::header head;
    head.flags = levin::FLAG_RESPONSE;
    EXPECT_TRUE(head.is_response());
    head.protocol_version = 0;
    EXPECT_FALSE(head.is_response());
    head.flags = levin::FLAG_REQUEST;
    EXPECT_FALSE(head.is_response());
    EXPECT_TRUE(head.is_request());
}

TEST(levin_frame, parser_splits_stream) {
    const std::string body2(70'000, 'b');
    const std::string stream = levin::make_request(1, bytes("first"), true) +
                               levin::make_response(1, 1, bytes(body2)) +
                               levin::make_request(9, {}, false);

    // Every way of splitting the stream in two gives the same frames
    for (size_t split = 0; split <= stream.size(); split += split < 200 ? 1 : 997) {
        levin::frame_parser parser{1'000'000};
        auto frames = parser.feed(bytes(std::string_view{stream}.substr(0, split)));
        auto rest = parser.feed(bytes(std::string_view{stream}.substr(split)));
        frames.insert(frames.end(), rest.begin(), rest.end());
        ASSERT_EQ(frames.size(), 3u) << "split at " << split;
        EXPECT_EQ(frames[0].head.command, 1u);
        EXPECT_TRUE(frames[0].head.expect_response);
        EXPECT_EQ(frames[0].body, "first");
        EXPECT_TRUE(frames[1].head.is_response());
        EXPECT_EQ(frames[1].head.return_code, 1);
        EXPECT_EQ(frames[1].body, body2);
        EXPECT_EQ(frames[2].head.command, 9u);
        EXPECT_TRUE(frames[2].body.empty());
        EXPECT_FALSE(parser.in_body());
    }

    // ... as does feeding it a byte at a time
    levin::frame_parser parser{1'000'000};
    size_t count = 0;
    for (size_t i = 0; i < stream.size(); i++) {
        count += parser.feed(bytes(std::string_view{stream}.substr(i, 1))).size();
        if (i == levin::header::SIZE + 2)
            EXPECT_TRUE(parser.in_body());
    }
    EXPECT_EQ(count, 3u);
}

TEST(levin_frame, parser_rejects_bad_signature_early) {
    std::string frame = levin::make_request(1, bytes("x"), false);
    frame[0] = 0x02;
    levin::frame_parser parser{1000};
    EXPECT_NO_THROW(parser.feed(bytes(std::string_view{frame}.substr(0, 7))));
    EXPECT_THROW(parser.feed(bytes(std::string_view{frame}.substr(7, 1))), levin::parse_error);
}

TEST(levin_frame, parser_rejects_oversized_body) {
    const std::string frame = levin::make_request(1, bytes(std::string(101, 'x')), false);
    levin::frame_parser ok{101};
    EXPECT_EQ(ok.feed(bytes(frame)).size(), 1u);

    // Rejected as soon as the header is in, without waiting for the body
    levin::frame_parser parser{100};
    EXPECT_THROW(
            parser.feed(bytes(std::string_view{frame}.substr(0, levin::header::SIZE))),
            levin::parse_error);
}

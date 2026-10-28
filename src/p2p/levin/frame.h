#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

// The levin framing: the wire format of the p2p protocol.  Every message is a fixed 33-byte header
// followed by a body (a portable-storage blob); the layout here must stay byte-for-byte what
// current nodes send and expect.
namespace nodetool::levin {

inline constexpr uint64_t SIGNATURE = 0x0101010101012101;

inline constexpr uint32_t FLAG_REQUEST = 0x01;
inline constexpr uint32_t FLAG_RESPONSE = 0x02;

inline constexpr uint32_t PROTOCOL_VERSION = 1;

struct header {
    // On the wire, in this order and every field little-endian: signature (u64), body size (u64),
    // expect response (u8), command (u32), return code (i32), flags (u32), protocol version (u32).
    static constexpr size_t SIZE = 33;

    uint64_t body_size = 0;
    bool expect_response = false;
    uint32_t command = 0;
    int32_t return_code = 0;
    uint32_t flags = 0;
    uint32_t protocol_version = PROTOCOL_VERSION;

    // A response answers the oldest invoke still waiting for one: levin has no request ids, so
    // peers answer in the order requests arrive.  Only a version 1 frame can be a response; to the
    // reference implementation everything from an older peer is a request.
    bool is_response() const {
        return protocol_version == PROTOCOL_VERSION && (flags & FLAG_RESPONSE);
    }
    bool is_request() const { return flags & FLAG_REQUEST; }

    std::array<unsigned char, SIZE> encode() const;

    // Decodes a header from its wire bytes; nullopt if they don't start with the signature.
    static std::optional<header> decode(std::span<const unsigned char, SIZE> data);
};

// A whole frame (header and body), ready to send.  An invoke is a request that expects a
// response; a notify is one that doesn't.
std::string make_request(
        uint32_t command, std::span<const unsigned char> body, bool expect_response);
std::string make_response(
        uint32_t command, int32_t return_code, std::span<const unsigned char> body);

struct parse_error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct frame {
    header head;
    std::string body;
};

// Splits a byte stream into frames: feed it whatever arrives and it returns each frame as soon as
// the last of it is in.
class frame_parser {
  public:
    explicit frame_parser(uint64_t max_body_size) : max_body_size_{max_body_size} {}

    // Throws parse_error on a stream that isn't levin: a bad signature (caught as soon as its first
    // 8 bytes are in) or a body over the size limit (as soon as the header is).
    std::vector<frame> feed(std::span<const unsigned char> data);

    // Whether we are partway through a frame's body, and so whether the sender is still making
    // progress on a large frame.
    bool in_body() const { return head_.has_value(); }

  private:
    uint64_t max_body_size_;
    std::string buf_;
    std::optional<header> head_;
};

}  // namespace nodetool::levin

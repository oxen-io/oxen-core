#pragma once

#include <cstdint>
#include <string_view>

#include "common/formattable.h"
#include "crypto/crypto.h"                      // crypto::hash ...
#include "cryptonote_basic/cryptonote_basic.h"  // pulse_random_value
#include "cryptonote_config.h"                  // cryptonote::network_type ...

namespace cryptonote {
class core;
class Blockchain;
};  // namespace cryptonote

namespace pulse {
using clock = std::chrono::system_clock;
using time_point = std::chrono::time_point<clock>;

enum struct message_type : uint8_t {
    invalid,
    handshake,
    handshake_bitset,
    block_template,
    random_value_hash,
    random_value,
    signed_block,
};

constexpr std::string_view to_string(message_type type) {
    using namespace std::literals;
    switch (type) {
        case message_type::invalid: return "Invalid"sv;
        case message_type::handshake: return "Handshake"sv;
        case message_type::handshake_bitset: return "Handshake Bitset"sv;
        case message_type::block_template: return "Block Template"sv;
        case message_type::random_value_hash: return "Random Value Hash"sv;
        case message_type::random_value: return "Random Value"sv;
        case message_type::signed_block: return "Signed Block"sv;
    }
    return "Invalid2"sv;
}

struct message {
    message_type type;
    uint16_t quorum_position;
    uint8_t round;
    crypto::signature signature;  // Signs the contents of the message, proving it came from the
                                  // node at quorum_position

    struct {
        uint16_t validator_bitset;  // Set if type is handshake_bitset, otherwise 0.
    } handshakes;

    struct {
        std::string blob;
    } block_template;

    struct {
        crypto::hash hash;
    } random_value_hash;

    struct {
        cryptonote::pulse_random_value value;
    } random_value;

    struct {
        crypto::signature signature_of_final_block_hash;
    } signed_block;
};

struct timings {
    time_point genesis_timestamp;
    time_point prev_timestamp;

    time_point ideal_timestamp;
    time_point r0_timestamp;
    time_point miner_fallback_timestamp;
};

void main(void* quorumnet_state, cryptonote::core& core);
void handle_message(void* quorumnet_state, message const& msg);

// Calculate the current Pulse round active depending on the 'time' elapsed since round 0 started
// for a block. r0_timestamp: The timestamp that round 0 starts at for the desired block (this
// timestamp can be calculated via 'pulse::get_round_timings'). round: (Optional) Set to the round
// that is currently active when the function returns true. return: False when enough 'time' has
// elapsed such that Pulse round has overflowed 255 and Pulse blocks are no longer possible to
// generate.
bool convert_time_to_round(
        cryptonote::network_type nettype,
        const time_point& time,
        const time_point& r0_timestamp,
        uint8_t* round);
bool get_round_timings(
        const cryptonote::Blockchain& blockchain,
        uint64_t height,
        uint64_t prev_timestamp,
        timings& times);

}  // namespace pulse

template <>
inline constexpr bool formattable::via_to_string<pulse::message_type> = true;

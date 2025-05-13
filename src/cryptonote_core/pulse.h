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
    block_signature,
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
        case message_type::block_signature: return "Block Signature"sv;
    }
    return "Invalid2"sv;
}

struct message {
    message_type type;
    uint16_t quorum_position;
    uint8_t round;
    crypto::signature signature;  // Signs the contents of the message, proving it came from the
                                  // node at quorum_position

    using block_and_txes = std::pair<std::string, std::vector<std::string>>;
    std::variant<
            std::monostate,
            uint16_t,
            block_and_txes,
            crypto::hash,
            cryptonote::pulse_random_value,
            crypto::signature>
            payload;  // Contained type dependent on `type`

    // clang-format off
    template <message_type Type>
    using payload_t =
        std::conditional_t<Type == message_type::handshake_bitset, uint16_t,
        std::conditional_t<Type == message_type::block_template, block_and_txes,
        std::conditional_t<Type == message_type::random_value_hash, crypto::hash,
        std::conditional_t<Type == message_type::random_value, cryptonote::pulse_random_value,
        std::conditional_t<Type == message_type::block_signature, crypto::signature, void>>>>>;
    // clang-format on

    template <message_type Type>
        requires(!std::is_void_v<payload_t<Type>>)
    auto& get() const {
        return std::get<payload_t<Type>>(payload);
    }
    template <message_type Type>
        requires(!std::is_void_v<payload_t<Type>>)
    auto& get() {
        return std::get<payload_t<Type>>(payload);
    }
};

struct timings {
    time_point genesis_timestamp;
    time_point prev_timestamp;

    time_point ideal_timestamp;
    time_point r0_timestamp;
    time_point miner_fallback_timestamp;
};

// Opaque holder class for the private internal implementation; an external pulse caller constructs
// this, then calls it like a function (i.e. `operator()`) to deliver new messages, and periodically
// to trigger stage/round advancement.  The holder is essentially a shared_ptr and so can be copied
// without duplicating the underlying pulse state.
class pulse {
  private:
    std::shared_ptr<void> impl;

  public:
    pulse() = default;
    explicit pulse(cryptonote::core& core);

    // Finishes initialization, taking the quorumnet_state pointer (because quorumnet itself depends
    // on a pulse object).
    void init(void* quorumnet_state);

    // The pulse object should be called periodically to check for pulse state advancement (i.e.
    // from timeouts, next rounds etc.).  It can also be invoked to deliver a message when incoming,
    // external messages arrive: if `msg` is not nullptr, then the message will be processed before
    // the state is rechecked (so that incoming messages can immediately trigger state changes).
    void operator()(const message* msg = nullptr) const;
};

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
std::optional<timings> get_round_timings(
        const cryptonote::Blockchain& blockchain, uint64_t height, uint64_t prev_timestamp);

}  // namespace pulse

template <>
inline constexpr bool formattable::via_to_string<pulse::message_type> = true;

#include <array>
#include <chrono>
#include <iterator>
#include <memory>

#include "common/formattable.h"
#include "common/random.h"
#include "common/tracy_shim.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_core.h"
#include "ethereum_transactions.h"
#include "network_config/mocknet.h"
#include "service_node_list.h"
#include "service_node_quorum_cop.h"
#include "service_node_rules.h"

extern "C" {
#include <sodium/crypto_generichash.h>
};

namespace pulse {

namespace log = oxen::log;

namespace {

    auto logcat = log::Cat("pulse");

    // Deliberately makes pulse communications flakey for testing purposes:
    // #define PULSE_TEST_CODE

    enum struct round_state {
        null_state,
        wait_for_next_block,

        prepare_for_round,
        wait_for_round,

        send_and_wait_for_handshakes,

        send_handshake_bitsets,
        wait_for_handshake_bitsets,

        send_block_template,
        wait_for_block_template,

        send_and_wait_for_random_value_hashes,
        send_and_wait_for_random_value,
        send_and_wait_for_block_signatures,
    };

    constexpr std::string_view round_state_string(round_state state) {
        switch (state) {
            case round_state::null_state: return "XX Null State"sv;
            case round_state::wait_for_next_block: return "Wait For Next Block"sv;

            case round_state::prepare_for_round: return "Prepare For Round"sv;
            case round_state::wait_for_round: return "Wait For Round"sv;

            case round_state::send_and_wait_for_handshakes: return "Send & Wait For Handshakes"sv;

            case round_state::send_handshake_bitsets: return "Send Validator Handshake Bitsets"sv;
            case round_state::wait_for_handshake_bitsets:
                return "Wait For Validator Handshake Bitsets"sv;

            case round_state::send_block_template: return "Send Block Template"sv;
            case round_state::wait_for_block_template: return "Wait For Block Template"sv;

            case round_state::send_and_wait_for_random_value_hashes:
                return "Send & Wait For Random Value Hash"sv;
            case round_state::send_and_wait_for_random_value:
                return "Send & Wait For Random Value"sv;
            case round_state::send_and_wait_for_block_signatures:
                return "Send & Wait For Block Signatures"sv;
        }

        return "Invalid2"sv;
    }

    enum struct sn_type {
        none,
        producer,
        validator,
    };

    enum struct queueing_state {
        empty,
        received,
        processed,
    };

    struct quorum_printer {
        const service_nodes::quorum& quorum;
        const crypto::public_key& me;
        std::string to_string() const {
            assert(!quorum.workers.empty());
            std::string result = "P: {:8.0x}{}; V: "_format(
                    quorum.workers[0], quorum.workers[0] == me ? "[THIS NODE]" : "");
            auto append = std::back_inserter(result);
            for (size_t i = 0; i < quorum.validators.size(); i++)
                fmt::format_to(
                        append,
                        "{}{}:{:8.0x}{}",
                        i > 0 ? ", " : "",
                        i,
                        quorum.validators[i],
                        quorum.validators[i] == me ? "[THIS NODE]" : "");
            return result;
        }
        static constexpr bool to_string_formattable = true;
    };

    template <typename T>
    using quorum_array = std::array<T, service_nodes::PULSE_QUORUM_NUM_VALIDATORS>;

    // Stores message for quorumnet per stage. Some validators may reach later
    // stages before we arrive at that stage. To properly validate messages we also
    // need to wait until we arrive at the same stage such that we have received all
    // the necessary information to do so on Quorumnet.
    struct message_queue {
        quorum_array<std::pair<message, queueing_state>> buffer;
        size_t count;
    };

    struct pulse_wait_stage {
        message_queue queue;  // messages from later stages that arrived ahead of schedule
        uint16_t bitset;      // Bitset of validators that we received a message from for this stage
        uint16_t msgs_received;  // Number of unique messages received in the stage
        time_point end_time;     // Time at which the stage ends, determined when the stage begins
    };

    crypto::hash blake2b_hash(void const* data, size_t size) {
        crypto::hash result;
        static_assert(sizeof(result) == crypto_generichash_BYTES);
        crypto_generichash(
                result.data(),
                result.size(),
                reinterpret_cast<unsigned char const*>(data),
                size,
                nullptr /*key*/,
                0 /*key length*/);
        return result;
    }

    class pulse_impl {
      public:
        explicit pulse_impl(cryptonote::core& core);

        // Sets the quorumnet_state pointer and finishes initialization.  Must be called before
        // check_state or handle_message.
        void init(void* qnet_state);

        // Called periodically on a timer, via the public pulse::operator()
        void check_state();

        // Called externally when a message is received, and internally to process a new message and
        // to handle previously received messages that arrived early.
        void handle_message(const message& msg);

      private:
        cryptonote::core& core;
        void* quorumnet_state = nullptr;
        std::optional<uint64_t> hf16, hf21;

        struct {
            uint64_t height;  // Current blockchain height that Pulse wants to generate a block for
            crypto::hash top_hash;  // Latest block hash included in signatures for rejecting out of
                                    // date nodes
            time_point round_0_start_time;  // When round 0 should start and subsequent round
                                            // timings are derived from.
        } curr_block;

        struct {
            bool queue_for_next_round;  // When set to true, invoking prepare_for_round(...) will
                                        // wait for (round + 1)
            uint8_t number;  // The next round number the Pulse ceremony will generate a block for
            service_nodes::quorum
                    quorum;       // The block producer/validator participating in the next round
            sn_type participant;  // Is this daemon a block producer, validator or non participant.
            size_t my_quorum_position;  // Position in the quorum, 0 if producer or neither, or [0,
                                        // PULSE_QUORUM_NUM_VALIDATORS) if a validator
            std::string node_name;  // Short-hand string for describing the node in logs, i.e. V[0]
                                    // for validator 0 or P for the producer.
            time_point start_time;  // When the round starts
            time_point end_time;    // When the round times out (i.e. when the next round begins)
        } round;

        struct transient_t {
            struct {
                bool sent;  // When true, handshake sent and waiting for other handshakes
                quorum_array<bool> data;  // Received data from messages from Quorumnet
                pulse_wait_stage stage;
            } send_and_wait_for_handshakes;

            struct {
                quorum_array<std::optional<uint16_t>> data;
                pulse_wait_stage stage;

                uint16_t best_bitset;  // The most agreed upon validators for participating in
                                       // rounds. Value is set when all handshake bitsets are
                                       // received.
                uint16_t best_count;   // How many validators agreed upon the best bitset.
            } wait_for_handshake_bitsets;

            struct {
                pulse_wait_stage stage;
            } wait_for_block_template;

            // The block, send by the producer after all determining all (initial) participating
            // validators.  The producer also (starting with Oxen 11.3) also sends any included
            // state change txes alongside the block template because those can easily have
            // equivalent but different local txes on the validators if they received quorum
            // signatures in a different order, and the validators will fail to add the block to the
            // chain if they don't have the same version of those txes.  (We don't send or allow
            // other types of txes because we should received those separately).
            cryptonote::block block;
            std::unordered_map<crypto::hash, std::string> state_change_txs;

            template <typename T, round_state RoundState>
            struct send_and_wait {
                inline static constexpr auto round_state = RoundState;

                // Data to be sent once to other nodes; cleared when sending, so that data is sent
                // only once.
                std::optional<T> to_send;

                // Data from other nodes that we are waiting for:
                struct {
                    quorum_array<std::optional<T>> data;
                    pulse_wait_stage stage;
                } wait;

                void clear() {
                    to_send.reset();
                    wait.data.fill(std::nullopt);
                    wait.stage = {};
                }
            };

            send_and_wait<crypto::hash, round_state::send_and_wait_for_random_value_hashes>
                    random_value_hashes;

            send_and_wait<
                    cryptonote::pulse_random_value,
                    round_state::send_and_wait_for_random_value>
                    random_value;

            send_and_wait<crypto::signature, round_state::send_and_wait_for_block_signatures>
                    block_signatures;

        } transient;

        round_state state = round_state::null_state;

      public:
        static constexpr bool to_string_formattable = true;
        std::string to_string() const;

      private:
        template <message_type mtype, typename... Value>
        message msg_init(Value&&... val) const;

        std::string msg_source_string(const message& msg) const;
        bool msg_signature_check(
                const message& msg,
                const crypto::hash& top_block_hash,
                const service_nodes::quorum& quorum) const;

        void handle_messages_received_early_for(pulse_wait_stage& stage);
        void relay_validator_handshake_bit_or_bitset(bool sending_bitset);

        void generate_random_value();

        void clear_round_data();

        round_state begin_stage_timer(round_state new_state);

        std::optional<bool> reset_for_missing_validators(
                const pulse_wait_stage& stage, bool timed_out);

        round_state goto_preparing_for_next_round();
        round_state goto_wait_for_next_block_and_clear_round_data();

        crypto::hash last_wait_log_hash = {}, last_timing_log_hash = {};
        round_state wait_for_next_block();

        round_state prepare_for_round();
        round_state wait_for_round();

        round_state send_and_wait_for_handshakes();

        round_state send_handshake_bitsets();
        round_state wait_for_handshake_bitsets();

        round_state send_block_template();
        round_state wait_for_block_template();

        // "Late stage": starts after the block template, and can be restarted
        // with a reduced validator set if one or more don't complete:
        void reset_late_stages();
        template <message_type mtype, typename SendAndWait>
        void start_send(SendAndWait& saw);
        round_state send_and_wait_for_random_value_hashes();
        round_state send_and_wait_for_random_value();
        round_state send_and_wait_for_block_signatures();
    };

    std::string pulse_impl::to_string() const {
        return "Pulse B{} R{}: {}'{}' "_format(
                curr_block.height,
                state >= round_state::prepare_for_round ? round.number : 0,
                round.node_name.empty() ? "" : "{} "_format(round.node_name),
                round_state_string(state));
    }

    //
    // NOTE: pulse::message Utiliities
    //

    // msg_init takes the message type as template parameter, and, for message types requiring a
    // payload, requires exactly 1 argument to be perfect-forward-assigned into the message
    // `payload` member.
    template <message_type mtype, typename... Value>
    message pulse_impl::msg_init(Value&&... val) const {
        using ValType = message::payload_t<mtype>;
        static_assert(
                !std::is_void_v<ValType> || sizeof...(Value) == 0,
                "msg_init with this message_type requires no argument");
        static_assert(
                std::is_void_v<ValType> ||
                        (sizeof...(Value) == 1 &&
                         (... && std::same_as<std::remove_cvref_t<Value>, ValType>)),
                "msg_init with this message_type requires exactly one argument of the appropriate "
                "payload type");

        message result = {};
        result.quorum_position = round.my_quorum_position;
        result.round = round.number;
        result.type = mtype;
        if constexpr (!std::is_void_v<ValType>)
            ((result.payload = std::forward<Value>(val)), ...);
        return result;
    }

    // Generate the hash necessary for signing a message. All fields of the 'msg'
    // must have been set for the type of the message except the signature for the
    // hash to be generated correctly.
    crypto::hash msg_signature_hash(crypto::hash const& top_block_hash, message const& msg) {
        crypto::hash result = {};
        switch (msg.type) {
            case message_type::invalid: assert("Invalid Code Path" == nullptr); break;

            case message_type::handshake: {
                auto buf = tools::memcpy_le(top_block_hash, msg.quorum_position, msg.round);
                result = blake2b_hash(buf.data(), buf.size());
            } break;

            case message_type::handshake_bitset: {
                auto buf = tools::memcpy_le(
                        msg.get<message_type::handshake_bitset>(),
                        top_block_hash,
                        msg.quorum_position,
                        msg.round);
                result = blake2b_hash(buf.data(), buf.size());
            } break;

            case message_type::block_template: {
                const auto& [blob, state_changes] = msg.get<message_type::block_template>();
                crypto::hash block_hash = blake2b_hash(blob.data(), blob.size());
                auto buf = tools::memcpy_le(msg.round, block_hash);
                result = blake2b_hash(buf.data(), buf.size());
                // blobs in state_changes aren't directly signed, but we parse them and only accept
                // them if they match txes referenced in the signed block.
            } break;

            case message_type::random_value_hash: {
                auto buf = tools::memcpy_le(
                        top_block_hash,
                        msg.quorum_position,
                        msg.round,
                        msg.get<message_type::random_value_hash>());
                result = blake2b_hash(buf.data(), buf.size());
            } break;

            case message_type::random_value: {
                auto buf = tools::memcpy_le(
                        top_block_hash,
                        msg.quorum_position,
                        msg.round,
                        msg.get<message_type::random_value>());
                result = blake2b_hash(buf.data(), buf.size());
            } break;

            case message_type::block_signature: {
                const auto& final_signature = msg.get<message_type::block_signature>();
                auto buf = tools::memcpy_le(
                        top_block_hash, msg.quorum_position, msg.round, final_signature);
                result = blake2b_hash(buf.data(), buf.size());
            } break;
        }

        return result;
    }

    // Generate a helper string that describes the origin of the message, i.e.
    // 'Signed Block' at round 2 from
    // 6:f9337ffc8bc30baf3fca92a13fa5a3a7ab7c93e69acb7136906e7feae9d3e769
    //   or
    // <Message Type> at round <Round> from <Validator Index>:<Validator Public Key>
    std::string pulse_impl::msg_source_string(const message& msg) const {
        if (msg.quorum_position >= round.quorum.validators.size())
            return "XX";

        return "'{}' at round {:d} from {:d}{}"_format(
                msg.type,
                msg.round,
                msg.quorum_position,
                state >= round_state::prepare_for_round &&
                                msg.quorum_position < round.quorum.validators.size()
                        ? ":{}"_format(round.quorum.validators[msg.quorum_position])
                        : "");
    }

    bool pulse_impl::msg_signature_check(
            message const& msg,
            crypto::hash const& top_block_hash,
            service_nodes::quorum const& quorum) const {
        // Get Service Node Key
        crypto::public_key const* key = nullptr;
        switch (msg.type) {
            case message_type::invalid:
                assert("Invalid Code Path" == nullptr);
                log::debug(
                        logcat,
                        "{}Unhandled message type '{}' can not verify signature.",
                        *this,
                        msg.type);
                return false;

            case message_type::handshake: [[fallthrough]];
            case message_type::handshake_bitset: [[fallthrough]];
            case message_type::random_value_hash: [[fallthrough]];
            case message_type::random_value: [[fallthrough]];
            case message_type::block_signature: {
                if (msg.quorum_position >= quorum.validators.size()) {
                    log::debug(
                            logcat,
                            "{}Invalid quorum position {} in {} message",
                            *this,
                            msg.type,
                            msg.quorum_position);
                    return false;
                }

                key = &quorum.validators[msg.quorum_position];
            } break;

            case message_type::block_template: {
                if (msg.quorum_position != 0) {
                    log::debug(
                            logcat,
                            "{}Invalid {} message quorum position {} (expected 0)",
                            *this,
                            msg.type,
                            msg.quorum_position);
                    return false;
                }

                key = &round.quorum.workers[0];
            } break;
        }

        if (crypto::check_signature(msg_signature_hash(top_block_hash, msg), *key, msg.signature))
            return true;

        log::debug(
                logcat,
                "{}Signature for {} is invalid for block {}",
                *this,
                msg_source_string(msg),
                curr_block.height);
        return false;
    }

    //
    // NOTE: pulse_impl Utilities
    //

    // Construct a pulse::message for sending the handshake bit or bitset.
    void pulse_impl::relay_validator_handshake_bit_or_bitset(bool sending_bitset) {
        assert(round.participant == sn_type::validator);

        // Message
        message msg;
        if (sending_bitset) {
            // Generate the bitset from our received handshakes.
            auto const& quorum = transient.send_and_wait_for_handshakes.data;
            uint16_t validator_bitset = 0;
            for (size_t quorum_index = 0; quorum_index < quorum.size(); quorum_index++)
                if (quorum[quorum_index])
                    validator_bitset |= (1 << quorum_index);
            msg = msg_init<message_type::handshake_bitset>(validator_bitset);
        } else {
            msg = msg_init<message_type::handshake>();
        }
        auto& key = core.get_service_keys();
        crypto::generate_signature(
                msg_signature_hash(curr_block.top_hash, msg), key.pub, key.key, msg.signature);
        handle_message(msg);  // Add our own. We receive our own msg for the first
                              // time which also triggers us to relay.
    }

    // Check the stage's queue for any messages that we received early and process
    // them if any. Any messages in the queue that we haven't received yet will also
    // be relayed to the quorum.
    void pulse_impl::handle_messages_received_early_for(pulse_wait_stage& stage) {
        if (!stage.queue.count)
            return;

        for (auto& [msg, queued] : stage.queue.buffer) {
            if (queued == queueing_state::received) {
                handle_message(msg);
                queued = queueing_state::processed;
            }
        }
    }

    // Called when a stage should be considered to begin, to update the stage end_time to current
    // time + stage timeout.  Does nothing before HF21 (i.e. we keep the initially assigned stage
    // end_time values).
    //
    // Returns `st` for convenience.
    round_state pulse_impl::begin_stage_timer(round_state st) {
        pulse_wait_stage* pws = st == round_state::wait_for_handshake_bitsets
                                      ? &transient.wait_for_handshake_bitsets.stage
                              : st == round_state::wait_for_block_template
                                      ? &transient.wait_for_block_template.stage
                              : st == round_state::send_and_wait_for_random_value_hashes
                                      ? &transient.random_value_hashes.wait.stage
                              : st == round_state::send_and_wait_for_random_value
                                      ? &transient.random_value.wait.stage
                              : st == round_state::send_and_wait_for_block_signatures
                                      ? &transient.block_signatures.wait.stage
                                      : nullptr;
        assert(pws);
        if (!pws) {
            log::error(logcat, "Internal error: begin_stage_timer called with invalid new state!");
            return st;
        }

        if (core.blockchain.get_network_version(curr_block.height) < cryptonote::hf::hf21_eth)
            return st;

        auto& conf = core.get_net_config();
        auto now = clock::now();
        pws->end_time = std::min(
                now + conf.PULSE_STAGE_TIMEOUT, round.start_time + conf.PULSE_ROUND_TIMEOUT);
        using fseconds = std::chrono::duration<float>;
        log::debug(
                logcat,
                "Beginning stage: {}; stage timeout in {:.1f}s",
                round_state_string(st),
                fseconds{pws->end_time - now}.count());

        return st;
    }

    // Check to see that all expected validators provided a response.  Returns:
    // - std::nullopt if all responses are present (and so we can proceed to the next stage)
    // - true if missing validators have been removed from the bitset but we still have enough
    //   remaining validators and time to restart from 'Send & Wait for Value Hash'.  The "best
    //   bitset" and the block template will have been updated when this is returned, and previous
    //   state for the hash-value-signature stages will have been cleared.
    // - false if we can neither continue nor retry, and thus need to revert to waiting for the next
    //   round.
    std::optional<bool> pulse_impl::reset_for_missing_validators(
            const pulse_wait_stage& stage, bool timed_out) {
        assert(state >= round_state::send_and_wait_for_random_value_hashes);

        auto& participants = transient.block.pulse.validator_bitset;
        if (stage.bitset == participants)
            return std::nullopt;

        // NOTE: This is not technically meant to hit, internal invariant checking
        // that should have been triggered earlier. (This function is only called
        // after the stage has ended/timed out.)
        bool unexpected_items = (stage.bitset | participants) != participants;
        if (unexpected_items) {
            log::error(
                    logcat,
                    "{}Internal error: expected bitset {:011b}, but accepted and received {:011b}",
                    *this,
                    participants,
                    stage.bitset);
            return false;
        }

        if (timed_out && participants != stage.bitset) {
            log::debug(
                    logcat,
                    "{}Stage timed out: missing responses. Expected ({}) {:011b} "
                    "received ({}) {:011b}",
                    *this,
                    std::popcount(participants),
                    participants,
                    std::popcount(stage.bitset),
                    stage.bitset);
        }

        // TODO: delete the last condition (HF21+) once HF21 has happened, along with the HF21 gate
        // in begin_stage_timer
        if (std::popcount(stage.bitset) >= service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES &&
            clock::now() < round.end_time &&
            core.blockchain.get_network_version() >= cryptonote::hf::hf21_eth) {

            uint16_t new_participants = stage.bitset;
            log::debug(
                    logcat,
                    "{}Attempting to retry hash/value/signing stages with {} validators: {:011b}",
                    *this,
                    std::popcount(new_participants),
                    new_participants);

            // mutate the block bitset to drop the validators that didn't respond:
            participants = new_participants;

            reset_late_stages();
            return true;  // We can continue!
        }
        // else we don't have enough potential validators left to retry or we're out of time, so we
        // have to give up on the round:
        return false;
    }

    void pulse_impl::handle_message(const message& msg) {
        if (state < round_state::wait_for_round) {
            // TODO(doyle): Handle this better.
            // We are not ready for any messages because we haven't prepared for a round
            // yet (don't have the necessary information yet to validate the message).
            return;
        }

        // TODO(oxen): We don't support messages from future rounds. A round
        // mismatch will be detected in the signature as the round is included in the
        // signature hash.

        if (!msg_signature_check(msg, curr_block.top_hash, round.quorum)) {
            log::debug(
                    logcat,
                    "{}Dropping message with invalid signature: probably a stale message from a "
                    "previous block/round",
                    *this);
            return;
        }

        pulse_wait_stage* stage = nullptr;
        switch (msg.type) {
            case message_type::invalid: {
                log::debug(logcat, "{}Received invalid message type, dropped", *this);
                return;
            }

            case message_type::handshake:
                stage = &transient.send_and_wait_for_handshakes.stage;
                break;
            case message_type::handshake_bitset:
                stage = &transient.wait_for_handshake_bitsets.stage;
                break;
            case message_type::block_template:
                stage = &transient.wait_for_block_template.stage;
                break;
            case message_type::random_value_hash:
                stage = &transient.random_value_hashes.wait.stage;
                break;
            case message_type::random_value: stage = &transient.random_value.wait.stage; break;
            case message_type::block_signature:
                stage = &transient.block_signatures.wait.stage;
                break;
        }

        bool msg_received_early = false;
        switch (msg.type) {
            case message_type::invalid: assert("Invalid Code Path" != nullptr); return;
            case message_type::handshake:
                msg_received_early = state < round_state::send_and_wait_for_handshakes;
                break;
            case message_type::handshake_bitset:
                msg_received_early = state < round_state::wait_for_handshake_bitsets;
                break;
            case message_type::block_template:
                msg_received_early = state < round_state::wait_for_block_template;
                break;
            case message_type::random_value_hash:
                msg_received_early = state < round_state::send_and_wait_for_random_value_hashes;
                break;
            case message_type::random_value:
                msg_received_early = state < round_state::send_and_wait_for_random_value;
                break;
            case message_type::block_signature:
                msg_received_early = state < round_state::send_and_wait_for_block_signatures;
                break;
        }

        if (msg.quorum_position >= service_nodes::PULSE_QUORUM_NUM_VALIDATORS) {
            log::debug(
                    logcat,
                    "{}Dropping {}: invalid message quorum position",
                    *this,
                    msg_source_string(msg));
            return;
        }

        if (msg_received_early)  // Enqueue the message until we're ready to process it
        {
            auto& [entry, queued] = stage->queue.buffer[msg.quorum_position];
            if (queued == queueing_state::empty) {
                if (state <= round_state::wait_for_round &&
                    msg.type == message_type::block_signature) {
                    // Because we advance the the next stage immediately upon achieving a full set
                    // of signatures, we very often end up with a few more copies of signatures
                    // coming in shortly after we start waiting for the next block, so if we're
                    // waiting then just drop them: even if we are slow and they are valid for the
                    // upcoming round, in order to produce a signature, the quorum must have already
                    // gone ahead without us and so there isn't anything we can do with it.
                    log::debug(
                            logcat, "{}Ignoring block sig from last round; probably a dupe", *this);
                } else {
                    log::debug(
                            logcat,
                            "{}Message received early {}, queueing until we're ready.",
                            *this,
                            msg_source_string(msg));
                    stage->queue.count++;
                    entry = std::move(msg);
                    queued = queueing_state::received;
                }
            }

            return;
        }

        uint16_t const validator_bit = (1 << msg.quorum_position);
        if (state > round_state::wait_for_block_template &&
            msg.type > message_type::block_template) {
            // Receiving the block template locks in the validator superset: validators can still be
            // removed, but never added, and so we can discard anything we receive that isn't in
            // that validator set anymore.
            const auto participants = transient.block.pulse.validator_bitset;
            if (!(participants & validator_bit)) {
                log::debug(
                        logcat,
                        "{}Dropping {}: validator has been dropped from the round; "
                        "current bitset is {:011b}",
                        *this,
                        msg_source_string(msg),
                        participants);
                return;
            }
        }

        //
        // Add Message Data to Pulse Stage
        //
        switch (msg.type) {
            case message_type::invalid: assert("Invalid Code Path" != nullptr); return;

            case message_type::handshake: {
                auto& quorum = transient.send_and_wait_for_handshakes.data;
                if (quorum[msg.quorum_position])
                    return;
                quorum[msg.quorum_position] = true;
                log::debug(
                        logcat,
                        "{}Received handshake with quorum position bit ({}) {:011b} adding to "
                        "bitset {:011b}",
                        *this,
                        msg.quorum_position,
                        validator_bit,
                        stage->bitset);
            } break;

            case message_type::handshake_bitset: {
                auto& quorum = transient.wait_for_handshake_bitsets.data;
                auto& bitset = quorum[msg.quorum_position];
                if (bitset)
                    return;  // This message is a duplicate, nothing to do.
                bitset = msg.get<message_type::handshake_bitset>();

                log::debug(
                        logcat,
                        "{}Received proposed bitset {:011b} from V[{}]",
                        *this,
                        *bitset,
                        msg.quorum_position);
            } break;

            case message_type::block_template: {
                if (stage->msgs_received == 1)
                    return;  // Duplicate copy; nothing to do.

                cryptonote::block block = {};
                auto& [block_blob, state_change_blobs] = msg.get<message_type::block_template>();
                if (!cryptonote::t_serializable_object_from_blob(block, block_blob)) {
                    log::warning(logcat, "{}Received unparsable pulse block template blob", *this);
                    return;
                }

                if (block.pulse.round != round.number) {
                    log::debug(
                            logcat,
                            "{}Received pulse block template specifying different round {}, "
                            "expected {}",
                            *this,
                            block.pulse.round,
                            round.number);
                    return;
                }

                if (block.pulse.validator_bitset !=
                    transient.wait_for_handshake_bitsets.best_bitset) {
                    log::debug(
                            logcat,
                            "{}Received pulse block template specifying different validator "
                            "handshake bitsets {:011b}, expected {:011b}",
                            *this,
                            block.pulse.validator_bitset,
                            transient.wait_for_handshake_bitsets.best_bitset);
                    return;
                }

                std::unordered_map<crypto::hash, std::string> supp_tx;
                for (auto& tx_blob : state_change_blobs) {
                    cryptonote::transaction tx;
                    if (!parse_and_validate_tx_from_blob(tx_blob, tx)) {
                        log::warning(logcat, "{}Received unparsable supplemental tx", *this);
                        return;
                    }

                    if (tx.type != cryptonote::txtype::state_change) {
                        log::warning(
                                logcat,
                                "{}Received invalid non-state change supplemental tx type: {}",
                                *this,
                                tx.type);
                        return;
                    }

                    auto hash = get_transaction_hash(tx);
                    if (std::find(block.tx_hashes.begin(), block.tx_hashes.end(), hash) ==
                        block.tx_hashes.end()) {
                        log::warning(
                                logcat,
                                "{}Received invalid state change tx {} not referenced by the block "
                                "template",
                                *this,
                                hash);
                        return;
                    }

                    supp_tx.emplace(hash, std::move(tx_blob));
                }

                log::debug(
                        logcat,
                        "{}Accepted {}B block template with {} state change txes",
                        *this,
                        block_blob.size(),
                        supp_tx.size());

                transient.block = std::move(block);
                transient.state_change_txs = std::move(supp_tx);
            } break;

            case message_type::random_value_hash: {
                auto& quorum = transient.random_value_hashes.wait.data;
                auto& value = quorum[msg.quorum_position];
                if (value)
                    return;  // Duplicate message, nothing to do
                value = msg.get<message_type::random_value_hash>();
            } break;

            case message_type::random_value: {
                auto& quorum = transient.random_value.wait.data;
                auto& value = quorum[msg.quorum_position];
                if (value)
                    return;  // Duplicate message, nothing to do

                const auto& msg_rv = msg.get<message_type::random_value>();
                if (const auto& hash =
                            transient.random_value_hashes.wait.data[msg.quorum_position]) {
                    if (auto derived = blake2b_hash(msg_rv.data, sizeof(msg_rv.data));
                        derived != *hash) {
                        log::debug(
                                logcat,
                                "{}Dropping {}. Rederived random value hash {} does not match "
                                "original hash {}",
                                *this,
                                msg_source_string(msg),
                                derived,
                                *hash);
                        return;
                    }
                }

                value = msg_rv;
            } break;

            case message_type::block_signature: {
                auto& quorum = transient.block_signatures.wait.data;
                auto& signature = quorum[msg.quorum_position];
                if (signature)
                    return;  // Duplicate message, ignore it.

                // NOTE: The block template with the final random value inserted but no
                // Service Node signatures. (Service Node signatures are added in one shot
                // after this stage has ended with all signatures are collected).
                const auto final_block_hash = cryptonote::get_block_hash(transient.block);

                assert(msg.quorum_position < round.quorum.validators.size());
                const auto& validator_key = round.quorum.validators[msg.quorum_position];
                if (auto& sig = msg.get<message_type::block_signature>();
                    crypto::check_signature(final_block_hash, validator_key, sig))
                    signature = sig;
                else {
                    log::debug(
                            logcat,
                            "{}Dropping {}. Signature signing final block hash {} does not "
                            "validate with the Service Node",
                            *this,
                            msg_source_string(msg),
                            sig);
                    return;
                }
            } break;
        }

        stage->bitset |= validator_bit;
        stage->msgs_received++;

        if (quorumnet_state)
            cryptonote::quorumnet_pulse_relay_message_to_quorum(
                    quorumnet_state, msg, round.quorum, round.participant == sn_type::producer);
    }

}  // anonymous namespace

// TODO(doyle): Update pulse::perpare_for_round with this function after the hard fork and sanity
// check it on testnet.
bool convert_time_to_round(
        cryptonote::network_type nettype,
        time_point const& time,
        time_point const& r0_timestamp,
        uint8_t* round) {
    const auto time_since_round_started = time <= r0_timestamp ? 0s : (time - r0_timestamp);
    size_t result_usize = time_since_round_started / get_config(nettype).PULSE_ROUND_TIMEOUT;
    if (round)
        *round = static_cast<uint8_t>(result_usize);
    return result_usize <= 255;
}

std::optional<timings> get_round_timings(
        cryptonote::Blockchain const& blockchain, uint64_t block_height, uint64_t prev_timestamp) {
    auto& conf = get_config(blockchain.nettype());
    auto hf16 = hard_fork_begins(conf.NETWORK_TYPE, cryptonote::hf::hf16_pulse);
    if (!hf16 || blockchain.get_current_blockchain_height() < *hf16)
        return std::nullopt;

    cryptonote::block genesis_block;
    if (!blockchain.get_block_by_height(*hf16 - 1, genesis_block))
        return std::nullopt;

    auto times = std::make_optional<timings>();
    uint64_t const delta_height = block_height - genesis_block.get_height();
    times->genesis_timestamp = clock::from_time_t(genesis_block.timestamp);

    times->prev_timestamp = clock::from_time_t(prev_timestamp);
    times->ideal_timestamp = times->genesis_timestamp + conf.TARGET_BLOCK_TIME * delta_height;

    times->r0_timestamp = std::clamp(
            times->ideal_timestamp,
            times->prev_timestamp + conf.TARGET_BLOCK_TIME - conf.PULSE_MAX_START_ADJUSTMENT,
            times->prev_timestamp + conf.TARGET_BLOCK_TIME + conf.PULSE_MAX_START_ADJUSTMENT);

    times->miner_fallback_timestamp = times->r0_timestamp + (conf.PULSE_ROUND_TIMEOUT * 255);
    return times;
}

namespace {

    /*
      Pulse progresses via a state-machine that is iterated through job submissions
      to 1 dedicated Pulse thread, started by OMQ.

      Iterating the state-machine is done by a periodic invocation of
      operator() on the pulse wrapper and messages received via Quorumnet for Pulse, which are
      queued in the thread's job queue.

      Using 1 dedicated thread via OMQ avoids any synchronization required in the
      user code when implementing Pulse.

      Skip control flow graph for textual description of stages.

              +---------------------+
              | Wait For Next Block |<--------<-------<
              +---------------------+         |       |
               |                              |       |
              [Blocks for round acquired]-----^ No    |
               |                              |       |
               | Yes                          |       |
               v                              |       |
              +---------------------+         |       |
        >---->| Prepare For Round   |         |       |
        |     +---------------------+         |       |
        |      |                              |       |
        |     [Enough SNs for Pulse? ]--------^ No    |
        |      |                                      |
        |      | Yes                                  |
        |      v                                      |
        |     +---------------------+                 |
        |     | Wait For Round      |                 |
        |     +---------------------+                 |
        |      |                                      |
        |     [Block Height Changed?]-----------------^ Yes
        |      |
        |      | No
        |      v
     No ^-----[Participating in Quorum?]
        |      |
        |      | Yes
        |      v
        |     [Validator?]------------------------------------v No (We are Block Producer)
        |      |                                              |
        |      | Yes                                          |
        |      v                                              |
        |     +------------------------------+                |
        |     | Send And Wait For Handshakes |                |
        |     +------------------------------+                |
        |      |                                              |
    Yes ^-----[Quorumnet Comm Failure?]                       |
        |      |                                              |
        |      | No                                           |
        |      v                                              |
        |     +-----------------------+                       |
        |     | Send Handshake Bitset |                       |
        |     +-----------------------+                       |
        |      |                                              |
    Yes ^-----[Quorumnet Comm Failure?]                       |
        |      |                                              |
        |      | No                                           |
        |      v                                              |
        |     +----------------------------+                  |
        |     | Wait For Handshake Bitsets |<-----------------<
        |     +----------------------------+
        |      |
     No ^-----[Bitset reached consensus?]
        |      |
        |      | Yes
        |      v
        |     [Block Producer?]-------------------------------v No (We are a Validator)
        |      |                                              |
        |      | Yes                                          |
        |      v                                              |
        |     +---------------------+                         |
        |     | Send Block Template |                         |
        |     +---------------------+                         |
        |      |                                              |
        ^------< (Block Producer's role is finished)          |
        |                                                     |
        |     +-------------------------+                     |
        |     | Wait For Block Template |<--------------------<
        |     +-------------------------+
        |      |
    Yes ^-----[Timed Out Waiting for Template?]
        |      |
        |      | No
        |      v
        |     +---------------------------------------+
        |     | Send And Wait For Random Value Hashes |<------<
        |     +---------------------------------------+       |
        |      |                                              |
        |      |                    +-----------------------------------------------+
        |      |                    | update bitset to exclude missing value nodes; |
        |      |                    | make new random value                         |
        |      |                    +-----------------------------------------------+
        |      |                                                               ^
        ^----- | -----------------------------------------------------<        |
        |      v                                                      | Yes    | No
     No ^-----[Received sufficient Hashes?]                           |        |
        |      |            |                               [Overall pulse round timed out?]
        |      |            |                                               |
        |      | All        |      (7 <= NumHashes < All) && HF21+          |
        |      |            >-----------------------------------------------^
        |      v                                                            |
        |     +---------------------------------+                           |
        |     | Send And Wait For Random Values |                           |
        |     +---------------------------------+                           |
        |      |                                                            |
     No ^-----[Received sufficient Values?]                                 |
        |      |            |                                               |
        |      | All        |      (7 <= NumValues < All) && HF21+          |
        |      |            >-----------------------------------------------^
        |      v                                                            |
        |     +--------------------------------------------+                |
        |     | - update block template with random values |                |
        |     | Send And Wait For Block Signatures         |                |
        |     +--------------------------------------------+                |
        |      |                                                            |
     No ^-----[Received and verified sufficient Signatures?]                |
        |      |            |                                               |
        |      | All        |      (7 <= NumSigs < All) && HF21+            |
        |      |            >-----------------------------------------------^
        |      v
        |     +---------------------------------------------------------+
        |     | - add first 7 Signatures (by validator index) to Block; |
        |     | - add completed Block to blockchain                     |
        |     +---------------------------------------------------------+
        |      |
     No ^-----[Block added successfully to blockchain?]
               |
               | Yes
               |
               + (Finished, state machine resets)

      Wait For Next Block:
        - Waits for the next block in the blockchain to arrive

        - Retrieves the blockchain metadata for starting a Pulse Round including the
          Genesis Pulse Block for the base timestamp and the top block hash and
          height for signatures.

        - // TODO(oxen): After the Genesis Pulse Block is checkpointed, we can
          // remove it from the event loop. Right now we recheck every block incase
          // of (the very unlikely event) reorgs that might change the block at the
          // hardfork.

        - The ideal next block timestamp is determined by

          G.Timestamp + (height * TARGET_BLOCK_TIME)

          Where 'G' is the base Pulse genesis block, i.e. the hardforking block
          activating Pulse (HF16).

          The actual next block timestamp is determined by

          P.Timestamp + (TARGET_BLOCK_TIME ±15s)

          Where 'P' is the previous block. The block time is adjusted ±15s depending
          on how close/far away the ideal block time is.

      Prepare For Round:
        - Generate data for executing the round such as the Quorum and stage
          durations depending on the round Pulse is at by comparing the clock with
          the ideal block timestamp.

        - The state machine *always* reverts to 'Prepare For Round' when any
          subsequent stage fails, except in the cases where Pulse can not proceed
          because of an insufficient Service Node network.

        - If the next round to prepare for is >255, we disable Pulse and re-allow
          PoW blocks to be added to the chain, the Pulse state machine resets and
          waits for the next block to arrive and re-evaluates if Pulse is possible
          again.

      Wait For Round (Block Producer & Validator)
        - Checks clock against the next expected Pulse timestamps has arrived,
          otherwise continues sleeping.

        - If we are a validator we 'Submit Handshakes' with other Validators
          If we are a block producer we skip to 'Wait For Handshake Bitset' and
          await the final handshake bitsets from all the Validators
          Otherwise we return to 'Prepare For Round' and sleep.

      Send And Wait For Handshakes (Validator)
        - On first invocation, we send the handshakes to Validator peers, then waits
          for handshakes. Validators handshake to confirm participation in the round
          and collect other handshakes.

      Send Handshake Bitset (Validator)
        - Send our collected participation bitset to the validators

      Wait For Handshake Bitsets (Block Producer & Validator)
        - Upon receipt, the most common agreed upon bitset is used to lock in
          participation for the round. The round proceeds if at least 7 of the
          11 validators are participating, the round fails otherwise and reverts to
          'Prepare For Round'.

        - If we are a validator      we go to 'Wait For Block Template'
        - If we are a block producer we go to 'Submit Block Template'

      Submit Block Template (Block Producer)
        - Block producer signs the block template with the validator bitset and
          pulse round applied to the block and sends it to the round validators

        - The block producer is finished for the round and awaits the next
          round (if any subsequent stage fails) or block.

      Wait For Block Template (Validator)
        - Await the block template and ensure it's signed by the block producer, if
          not we revert to 'Prepare For Round'

        - We generate our part of the random value and prepare the hash of the
          random value and proceed to the next stage.

      Send And Wait For Random Value Hashes (Validator)
        - On first invocation, send the hash of our random value prepared in the
          'Wait For Block Template' stage, followed by waiting for the other random
          value hashes from validators.

        - If not all hashes are received according to the validator bitset in the
          block, but a retry is possible, then we retry (see Late Stages Retry
          below).

        - If we couldn't retry and didn't receive all value hashes then we revert to
          'Prepare For Round'.

      Send And Wait For Random Values (Validator)
        - On first invcation, send the random value prepared in the 'Wait For Block
          Template' stage, followed by waiting for the other random values from
          validators.

        - If not all values are received according to the validator bitset in the
          block, but a retry is possible, then we retry (see Late Stages Retry
          below).

        - If we couldn't retry and didn't receive all values then we revert to
          'Prepare For Round'.

      Send And Wait For Block Signatures (Validator)
        - On first invcation, send our signature, signing the block template with
          all the random values combined into 1 to other validators and await for
          the other signatures to arrive.

        - Ensure the signature signs the same block template we have on hand, which
          might the original one we received from the Block Producer, or might have
          bitset modifications (see below).

        - If not all values are received according to the validator bitset
          in the block, but a retry is possible, then we retry (see Late Stages
          Retry below).

        - If we couldn't retry and didn't receive all (valid) signatures then we
          revert to 'Prepare For Round'.

        - Add the first 7 signatures (ordered by validator index) to the block, and
          add the block to the blockchain.  This will automatically begin
          propagation of the block via P2P.

        - If block addition fails, revert to 'Prepare For Round'

      Late Stages Retry

        If any of the "Send And Wait" stages for Random Value Hashes, Random Values,
        or Block Signatures fails to accumulate all required values then a retry is
        considered where we adjust the bitset to exclude nodes that failed to
        contribute a value and restart the hash-value-signature sequence.

        Specifically it must be the case that:
        - we are on HF21+
        - there is still time left in the overall pulse round
        - after clearing the bits of the validators that did not send a valid value
          we still have at least 7 validators in the bitset that did.

        There is no guarantee that a retry will succeed, but it catches a common
        case where some validator timed out or dropped out in the middle of the
        pulse quorum by allowing the remaining validators to nevertheless recover
        and push out a block without that faulty node.

        (Before the introduction of this retry, such failures would simply result in
        no block being produced at all, which could not lead to network penalties
        against the faulty node because the pulse quorum consensus is only ever
        published via the blocks themselves, which would simply fail to be
        produced).

        If the retry conditions are met, then each node:
        - updates the bitset to clear the bits of nodes that failed to respond
        - chooses a new random value
        - returns to Send And Wait For Random Value Hashes

        Multiple retries are possible, so long as there is sufficient time remaining
        in the pulse round.
    */

    round_state pulse_impl::goto_preparing_for_next_round() {
        round.queue_for_next_round = true;
        return round_state::prepare_for_round;
    }

    void pulse_impl::clear_round_data() {
        transient = {};
        round = {};
    }

    round_state pulse_impl::goto_wait_for_next_block_and_clear_round_data() {
        clear_round_data();
        return round_state::wait_for_next_block;
    }

    round_state pulse_impl::wait_for_next_block() {
        ZoneScoped;
        //
        // NOTE: If the top hash we have stored is the same as the top block's hash then we've
        // already attempted Pulse with the current state of the blockchain and encountered a
        // failure.
        //
        cryptonote::block top_block = core.blockchain.db().get_top_block();
        const auto top_hash = cryptonote::get_block_hash(top_block);
        uint64_t chain_height = top_block.get_height() + 1;
        if (curr_block.top_hash == top_hash) {
            if (last_wait_log_hash != top_hash) {
                last_wait_log_hash = top_hash;
                log::debug(
                        logcat,
                        "{}Network is currently producing block {} (w/ parent {}), "
                        "waiting until next block",
                        *this,
                        chain_height,
                        top_hash);
            }
            return round_state::wait_for_next_block;
        }

        auto times = get_round_timings(core.blockchain, chain_height, top_block.timestamp);
        if (!times) {
            if (last_timing_log_hash != top_hash) {
                last_timing_log_hash = top_hash;
                log::error(logcat, "{}Failed to query the block data for Pulse timings", *this);
            }
            return round_state::wait_for_next_block;
        }

        curr_block.round_0_start_time = times->r0_timestamp;
        curr_block.height = chain_height;
        curr_block.top_hash = top_hash;
        round = {};

        return round_state::prepare_for_round;
    }

    round_state pulse_impl::prepare_for_round() {
        auto& blockchain = core.blockchain;
        auto& conf = core.get_net_config();
        //
        // NOTE: Clear Round Data
        //
        {
            // Store values
            uint8_t round_no = round.number;
            bool queue_for_next_round = round.queue_for_next_round;

            clear_round_data();

            // Restore values
            round.number = round_no;
            round.queue_for_next_round = queue_for_next_round;
        }

        if (round.queue_for_next_round) {
            if (round.number >= 255) {
                // If the next round overflows, we consider the network stalled. Wait for
                // the next block and allow PoW to return.
                return goto_wait_for_next_block_and_clear_round_data();
            }

            // Also check if the blockchain has changed, in which case we stop and
            // restart Pulse stages.
            std::pair<uint64_t, crypto::hash> tail = blockchain.get_tail_id();
            const crypto::hash& top_hash = tail.second;
            if (curr_block.top_hash != top_hash)
                return goto_wait_for_next_block_and_clear_round_data();

            // 'queue_for_next_round' is set when an intermediate Pulse stage has failed
            // and the caller requests us to wait until the next round to occur.
            round.queue_for_next_round = false;
            round.number++;
        }

        //
        // NOTE: Check Current Round
        //
        {
            auto now = clock::now();
            auto const time_since_block =
                    now <= curr_block.round_0_start_time ? 0s : now - curr_block.round_0_start_time;
            size_t round_usize = time_since_block / conf.PULSE_ROUND_TIMEOUT;

            if (round_usize > 255) {  // Network stalled
                log::info(
                        logcat,
                        "{}Pulse has timed out, reverting to accepting miner blocks only.",
                        *this);
                return goto_wait_for_next_block_and_clear_round_data();
            }

            auto curr_round = static_cast<uint8_t>(round_usize);
            if (curr_round > round.number)
                round.number = curr_round;
        }

        round.start_time =
                curr_block.round_0_start_time + (round.number * conf.PULSE_ROUND_TIMEOUT);
        round.end_time = round.start_time + conf.PULSE_ROUND_TIMEOUT;

        // We initially set all these timeouts to fixed increments from the round start, which is
        // how everything worked in HF20 and earlier, but starting in HF21 we will update these end
        // times when we begin each stage from wait_for_bitsets onwards to the current time +
        // PULSE_STAGE_TIMEOUT, thus ensuring that each stage only gets PULSE_STAGE_TIMEOUT, rather
        // than each stage getting PULSE_STAGE_TIMEOUT + all unused time from previous stages; that,
        // in turn, gives us more opportunity to retry late stages in the case of a dropped
        // validator.
        {
            auto t = round.start_time;
            for (auto* stage :
                 {&transient.send_and_wait_for_handshakes.stage,
                  &transient.wait_for_handshake_bitsets.stage,
                  &transient.wait_for_block_template.stage,
                  &transient.random_value_hashes.wait.stage,
                  &transient.random_value.wait.stage,
                  &transient.block_signatures.wait.stage}) {
                stage->end_time = (t += conf.PULSE_STAGE_TIMEOUT);
            }
        }

        std::vector<crypto::hash> const entropy = service_nodes::get_pulse_entropy_for_next_block(
                blockchain.db(), curr_block.top_hash, round.number);
        auto const active_node_list = blockchain.service_node_list.active_service_nodes_infos();
        crypto::public_key const& block_leader =
                blockchain.service_node_list.get_next_block_leader().key;

        auto hf_version = blockchain.get_network_version();
        round.quorum = service_nodes::generate_pulse_quorum(
                blockchain.nettype(),
                block_leader,
                hf_version,
                active_node_list,
                entropy,
                round.number,
                curr_block.height);

        if (!service_nodes::verify_pulse_quorum_sizes(round.quorum)) {
            log::info(
                    logcat,
                    "{}There are not enough nodes to execute Pulse for height {}. PoW block is "
                    "required. Sleeping until next block.\n"
                    "  Producers: {} (required 1), Validators: {} (required {})",
                    *this,
                    curr_block.height,
                    round.quorum.workers.size(),
                    round.quorum.validators.size(),
                    service_nodes::PULSE_QUORUM_NUM_VALIDATORS);
            return goto_wait_for_next_block_and_clear_round_data();
        }

        auto& key = core.get_service_keys();

        log::debug(
                logcat,
                "{}Generate Pulse quorum:\n    {}",
                *this,
                quorum_printer{round.quorum, key.pub});

        //
        // NOTE: Quorum participation
        //
        if (key.pub == round.quorum.workers[0]) {
            // NOTE: Producer doesn't send handshakes, they only collect the
            // handshake bitsets from the other validators to determine who to
            // lock in for this round in the block template.
            round.participant = sn_type::producer;
            round.node_name = "Prod";
        } else {
            for (size_t index = 0; index < round.quorum.validators.size(); index++) {
                auto const& validator_key = round.quorum.validators[index];
                if (validator_key == key.pub) {
                    round.participant = sn_type::validator;
                    round.my_quorum_position = index;
                    round.node_name = "V[{}]"_format(round.my_quorum_position);
                    break;
                }
            }
        }

        return round_state::wait_for_round;
    }

    round_state pulse_impl::wait_for_round() {
        const auto [height, top_hash] = core.blockchain.get_tail_id();
        if (curr_block.top_hash != top_hash) {
            log::debug(
                    logcat,
                    "{}Top block changed (from {} to {}) whilst waiting for round {}, "
                    "restarting Pulse stages",
                    *this,
                    curr_block.top_hash,
                    top_hash,
                    round.number);
            return goto_wait_for_next_block_and_clear_round_data();
        }

        auto start_time = round.start_time;
        if (auto now = clock::now(); now < start_time) {
            for (static uint64_t last_height = 0; last_height != curr_block.height;
                 last_height = curr_block.height)
                log::info(
                        logcat,
                        "{}Waiting for round {} to start in {}",
                        *this,
                        round.number,
                        tools::friendly_duration(start_time - now));
            return round_state::wait_for_round;
        }

#ifdef PULSE_TEST_CODE
        // For testing purposes: we apply possible random non-response and random delays to half of
        // all blocks; we go in batches of 10: 10 maybe-faulty blocks followed by 10 well-behaved
        // blocks. (Faulty blocks have an odd second-last height digit).
        if (curr_height % 20 >= 10) {
            size_t faulty_chance = tools::uniform_distribution_portable(tools::rng, 100);
            if (faulty_chance < 10) {
                log::debug(logcat, "{}FAULTY NODE ACTIVATED", *this);
                return goto_preparing_for_next_round();
            }

            size_t sleep_chance = tools::uniform_distribution_portable(tools::rng, 100);
            if (sleep_chance < 10) {
                auto sleep_time =
                        std::chrono::seconds(tools::uniform_distribution_portable(tools::rng, 20));
                std::this_thread::sleep_for(sleep_time);
                log::debug(
                        logcat, "{}SLEEP TIME ACTIVATED {}s", *this, tools::to_seconds(sleep_time));
            }
        }
#endif

        if (round.participant == sn_type::validator) {
            log::info(
                    logcat,
                    "{}We are a pulse validator, sending handshake bit and collecting other "
                    "handshakes.",
                    *this);
            return round_state::send_and_wait_for_handshakes;
        } else if (round.participant == sn_type::producer) {
            log::info(
                    logcat,
                    "{}We are the block producer for height {} in round {}, awaiting handshake "
                    "bitsets.",
                    *this,
                    curr_block.height,
                    round.number);
            return round_state::wait_for_handshake_bitsets;
        } else {
            log::debug(
                    logcat, "{}Non-participant for round, waiting on next round or block.", *this);
            return goto_preparing_for_next_round();
        }
    }

    round_state pulse_impl::send_and_wait_for_handshakes() {
        ZoneScoped;
        //
        // NOTE: Send
        //
        assert(round.participant == sn_type::validator);
        if (!transient.send_and_wait_for_handshakes.sent) {
            transient.send_and_wait_for_handshakes.sent = true;
            try {
                relay_validator_handshake_bit_or_bitset(false /*sending_bitset*/);
            } catch (std::exception const& e) {
                log::error(
                        logcat,
                        "{}Attempting to invoke and send a Pulse participation handshake "
                        "unexpectedly failed. {}",
                        *this,
                        e.what());
                return goto_preparing_for_next_round();
            }
        }

        //
        // NOTE: Wait
        //
        handle_messages_received_early_for(transient.send_and_wait_for_handshakes.stage);
        pulse_wait_stage const& stage = transient.send_and_wait_for_handshakes.stage;

        auto const& quorum = transient.send_and_wait_for_handshakes.data;
        bool const timed_out = clock::now() >= stage.end_time;
        bool const all_handshakes = stage.msgs_received == quorum.size();

        assert(round.participant == sn_type::validator);
        assert(round.my_quorum_position < quorum.size());

        if (all_handshakes || timed_out) {
            bool missing_handshakes = timed_out && !all_handshakes;
            log::info(
                    logcat,
                    "{}Collected validator handshakes {:011b}{} Sending handshake bitset and "
                    "collecting other validator bitsets.",
                    *this,
                    stage.bitset,
                    missing_handshakes ? ", we timed out and some handshakes were not seen!" : ".");
            return round_state::send_handshake_bitsets;
        } else {
            return round_state::send_and_wait_for_handshakes;
        }
    }

    round_state pulse_impl::send_handshake_bitsets() {
        try {
            relay_validator_handshake_bit_or_bitset(true /*sending_bitset*/);
            return begin_stage_timer(round_state::wait_for_handshake_bitsets);
        } catch (std::exception const& e) {
            log::error(
                    logcat,
                    "{}Attempting to invoke and send a Pulse validator bitset unexpectedly failed. "
                    "{}",
                    *this,
                    e.what());
            return goto_preparing_for_next_round();
        }
    }

    round_state pulse_impl::wait_for_handshake_bitsets() {
        ZoneScoped;
        handle_messages_received_early_for(transient.wait_for_handshake_bitsets.stage);
        pulse_wait_stage const& stage = transient.wait_for_handshake_bitsets.stage;

        auto const& quorum = transient.wait_for_handshake_bitsets.data;
        bool const timed_out = clock::now() >= stage.end_time;
        bool const all_bitsets = stage.msgs_received == quorum.size();

        if (timed_out || all_bitsets) {
            std::map<uint16_t, int> bitset_count;
            uint16_t best_bitset = 0;
            size_t count = 0;
            for (size_t quorum_index = 0; quorum_index < quorum.size(); quorum_index++) {
                auto& bitset = quorum[quorum_index];
                if (bitset) {
                    uint16_t num = ++bitset_count[*bitset];
                    if (num > count) {
                        best_bitset = *bitset;
                        count = num;
                    }
                }
            }
            if (log::get_level(logcat) <= log::Level::debug) {
                std::vector<std::string> received;
                for (const auto& [bitset, count] : bitset_count)
                    received.push_back("{:011b} (x{})"_format(bitset, count));
                log::debug(
                        logcat,
                        "{}Most common bitset {:011b}, from received bitsets: {}",
                        *this,
                        best_bitset,
                        fmt::join(received, ", "));
            }

            bool i_am_not_participating = false;
            if (best_bitset != 0 && round.participant == sn_type::validator)
                i_am_not_participating = ((best_bitset & (1 << round.my_quorum_position)) == 0);

            if (count < service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES || best_bitset == 0 ||
                i_am_not_participating) {
                if (best_bitset == 0) {
                    // Less than the threshold of the validators can come to agreement about
                    // which validators are online, we wait until the next round.
                    log::debug(
                            logcat,
                            "{}{}/{} validators did not send any handshake bitset or sent an empty "
                            "handshake bitset and have failed to come to agreement. Waiting until "
                            "next round.",
                            *this,
                            count,
                            quorum.size());
                } else if (i_am_not_participating) {
                    log::debug(
                            logcat,
                            "{}The participating validator bitset {:011b} does not include us "
                            "(quorum index {}). Waiting until next round.",
                            *this,
                            best_bitset,
                            round.my_quorum_position);
                } else {
                    // Can't come to agreement, see threshold comment above
                    log::debug(
                            logcat,
                            "{}We heard back from less than {} of the validators ({}/{}). Waiting "
                            "until next round.",
                            *this,
                            service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES,
                            count,
                            quorum.size());
                }

                return goto_preparing_for_next_round();
            }

            transient.wait_for_handshake_bitsets.best_bitset = best_bitset;
            transient.wait_for_handshake_bitsets.best_count = count;
            log::info(
                    logcat,
                    "{}{}/{} validators agreed on the participating nodes in the quorum {:011b}{}",
                    *this,
                    count,
                    quorum.size(),
                    best_bitset,
                    round.participant == sn_type::producer  //
                            ? ""
                            : ". Awaiting block template from block producer");

            if (round.participant == sn_type::producer)
                return round_state::send_block_template;
            else
                return begin_stage_timer(round_state::wait_for_block_template);
        }

        return round_state::wait_for_handshake_bitsets;
    }

    round_state pulse_impl::send_block_template() {
        ZoneScoped;
        assert(round.participant == sn_type::producer);
        auto& key = core.get_service_keys();
        std::vector<service_nodes::service_node_pubkey_info> list_state =
                core.blockchain.service_node_list.get_service_node_list_state({key.pub});

        // Invariants
        if (list_state.empty()) {
            log::warning(
                    logcat,
                    "{}Block producer (us) is not available on the service node list, waiting "
                    "until next round",
                    *this);
            return goto_preparing_for_next_round();
        }

        std::shared_ptr<const service_nodes::service_node_info> info = list_state[0].info;
        if (!info->is_active()) {
            log::warning(
                    logcat,
                    "{}Block producer (us) is not an active service node, waiting until next round",
                    *this);
            return goto_preparing_for_next_round();
        }

        // Block
        cryptonote::block new_block{};
        std::vector<std::string> state_change_txes;
        {
            uint64_t height = 0;
            service_nodes::payout block_producer_payouts =
                    service_nodes::service_node_payout_portions(key.pub, *info);

            try {
                if (!core.blockchain.create_next_pulse_block_template(
                            new_block,
                            block_producer_payouts,
                            round.number,
                            transient.wait_for_handshake_bitsets.best_bitset,
                            height,
                            &state_change_txes)) {
                    log::error(
                            logcat,
                            "{}Failed to generate a block template, waiting until next round",
                            *this);
                    return goto_preparing_for_next_round();
                }
            } catch (const std::exception& e) {
                log::error(
                        logcat,
                        "{}Failed to generate a block template, waiting until next round: {}",
                        *this,
                        e.what());
                return goto_preparing_for_next_round();
            }

            if (curr_block.height != height) {
                log::debug(
                        logcat,
                        "{}Block height changed whilst preparing block template for round {}, "
                        "restarting Pulse stages",
                        *this,
                        round.number);
                return goto_wait_for_next_block_and_clear_round_data();
            }
        }

        // Message
        message msg = msg_init<message_type::block_template>(message::block_and_txes{
                cryptonote::t_serializable_object_to_blob(new_block),
                std::move(state_change_txes)});
        crypto::generate_signature(
                msg_signature_hash(curr_block.top_hash, msg), key.pub, key.key, msg.signature);

        // Send
        log::info(
                logcat,
                "{}Validators are handshaken and ready, sending block template from producer (us) "
                "to validators.\n{}",
                *this,
                cryptonote::obj_to_json_str(new_block));
        cryptonote::quorumnet_pulse_relay_message_to_quorum(
                quorumnet_state, msg, round.quorum, true /*block_producer*/);
        return goto_preparing_for_next_round();
    }

    round_state pulse_impl::wait_for_block_template() {
        ZoneScoped;
        handle_messages_received_early_for(transient.wait_for_block_template.stage);
        const auto& stage = transient.wait_for_block_template.stage;

        assert(round.participant == sn_type::validator);
        bool timed_out = clock::now() >= stage.end_time;
        bool received = stage.msgs_received == 1;
        if (timed_out || received) {
            if (received) {
                auto& block = transient.block;

                // Before we sign off on the block make sure that we support the inclusion of any
                // eth state change transactions by making sure we have them in our pool *and* that
                // we have the indicated state change in our L2 tracker.
                if (block.major_version >= cryptonote::feature::ETH_BLS) {
                    if (block.tx_eth_count > block.tx_hashes.size()) {
                        log::warning(
                                logcat,
                                "{}Invalid block from producer: block claims eth L2 state change "
                                "txs {} > tx count {}",
                                *this,
                                block.tx_eth_count,
                                block.tx_hashes.size());
                        return goto_preparing_for_next_round();
                    }
                    auto mempool_txs = core.blockchain.tx_pool.load_transactions(block.tx_hashes);
                    for (size_t i = 0; i < block.tx_eth_count; i++) {
                        if (!mempool_txs[i]) {
                            log::warning(
                                    logcat,
                                    "{}Rejecting block: eth state change tx {} is not in our "
                                    "mempool",
                                    *this,
                                    block.tx_hashes[i]);
                            return goto_preparing_for_next_round();
                        }
                        auto& tx = *mempool_txs[i];
                        if (!is_l2_event_tx(tx.type)) {
                            log::warning(
                                    logcat,
                                    "{}Rejecting block: claimed state change tx {} is not a state "
                                    "change tx",
                                    *this,
                                    block.tx_hashes[i]);
                            return goto_preparing_for_next_round();
                        }
                        std::string fail;
                        auto event = eth::extract_event(tx, &fail);
                        if (std::holds_alternative<std::monostate>(event)) {
                            log::warning(
                                    logcat,
                                    "{}Rejecting block: failed to extract event from {}: {}",
                                    *this,
                                    tx,
                                    fail);
                            return goto_preparing_for_next_round();
                        }
                        if (!std::visit(
                                    [&l2 = core.blockchain.l2_tracker()](const auto& e) {
                                        return l2.get_vote_for(e);
                                    },
                                    event)) {
                            log::warning(
                                    logcat,
                                    "{}Rejecting block: event not found in L2Tracker for tx {}",
                                    *this,
                                    tx);
                            return goto_preparing_for_next_round();
                        }
                    }
                    // NOTE: We only concern ourselves with the claimed [0, tx_eth_count)
                    // transactions because signing a block containing *those* means we are casting
                    // a vote in favour of them.  Later state changes in the list aren't valid and
                    // get rejected during blockchain handling so don't need to be checked here.
                    log::debug(
                            logcat,
                            "{}Block passed L2 event validation ({} L2 events of {} txs)",
                            *this,
                            block.tx_eth_count,
                            block.tx_hashes.size());

                    // Confirm that votes for recent state changes match our vote:
                    if (auto my_l2_votes = core.service_node_list.l2_pending_state_votes();
                        block.l2_votes != my_l2_votes) {
                        log::warning(
                                logcat,
                                "{}Rejecting block: L2 event vote mismatch: [{}] (block) != [{}] "
                                "(this node)",
                                *this,
                                fmt::join(block.l2_votes, ","),
                                fmt::join(block.l2_votes, ","));
                        return goto_preparing_for_next_round();
                    }
                }

                if (!block.signatures.empty()) {
                    log::warning(
                            logcat,
                            "{}Rejecting block: block template has {} pre-filled signatures",
                            *this,
                            block.signatures.size());
                    return goto_preparing_for_next_round();
                }

                log::info(logcat, "{}Valid block received", *this);
#ifndef NDEBUG
                log::trace(logcat, "{}Block data: {}", *this, cryptonote::obj_to_json_str(block));
#endif

                // Generate my random value and its hash
                generate_random_value();

                return round_state::send_and_wait_for_random_value_hashes;
            } else {
                log::info(logcat, "{}Timed out, block template was not received", *this);
                return goto_preparing_for_next_round();
            }
        }

        return round_state::wait_for_block_template;
    }

    // (Re-)Generate my random value and its hash
    void pulse_impl::generate_random_value() {
        auto& rv = transient.random_value.to_send.emplace().data;
        crypto::generate_random_bytes_thread_safe(sizeof(rv), rv);
        transient.random_value_hashes.to_send = blake2b_hash(rv, sizeof(rv));
    }

    // Resets the "late stage" states, that is, everything after wait_for_block_template.  This is
    // used when a validator fails to complete one of the late stages, which ejects the failing
    // validator and attempts to restart from random_value_hashes.  (We restart to there, regardless
    // of where the failure is, so that a validator cannot influence the block random value by
    // observing all the actual random values and then being able to pick the final random value
    // between the two alternatives or staying in or sitting out).
    void pulse_impl::reset_late_stages() {
        transient.random_value_hashes.clear();
        transient.random_value.clear();
        transient.block_signatures.clear();
        generate_random_value();
    }

    // Common code for late stage send-and-wait functions: if the type's value is not yet sent, this
    // builds a message, loads it, signs it, and starts distributing it, and starts the stage timer
    // (defining when we time out the stage).  If the value is already sent, this method does
    // nothing.
    template <message_type mtype, typename SendAndWait>
    void pulse_impl::start_send(SendAndWait& saw) {
        if (!saw.to_send)
            return;  // already sent
        begin_stage_timer(SendAndWait::round_state);
        // Message
        message msg = msg_init<mtype>(*saw.to_send);
        saw.to_send.reset();  // Send only once
        auto& key = core.get_service_keys();
        crypto::generate_signature(
                msg_signature_hash(curr_block.top_hash, msg), key.pub, key.key, msg.signature);
        handle_message(msg);  // Add our own. We receive our own msg for the
                              // first time which also triggers us to relay.
    }

    round_state pulse_impl::send_and_wait_for_random_value_hashes() {
        ZoneScoped;
        assert(round.participant == sn_type::validator);

        //
        // NOTE: Send, and kick off the stage timer
        //
        start_send<message_type::random_value_hash>(transient.random_value_hashes);

        //
        // NOTE: Wait
        //
        handle_messages_received_early_for(transient.random_value_hashes.wait.stage);
        pulse_wait_stage const& stage = transient.random_value_hashes.wait.stage;

        bool const timed_out = clock::now() >= stage.end_time;
        bool const all_hashes = stage.bitset == transient.block.pulse.validator_bitset;

        if (timed_out || all_hashes) {
            log::info(
                    logcat,
                    "{}Received {} random value hashes from {:011b}{}",
                    *this,
                    std::popcount(stage.bitset),
                    stage.bitset,
                    timed_out ? ". We timed out and some hashes are missing" : "");

            if (!all_hashes && (!hf21 || core.blockchain.get_current_blockchain_height() < *hf21)) {
                // HF20 workaround to allow pulse to proceed even if a validator fails to send a
                // random value hash in type.  This can be deleted once we are on HF21 (when the
                // more robust version via reset_for_missing_validators takes over).
                if (std::popcount(stage.bitset) < service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES)
                    return goto_preparing_for_next_round();
                log::info(logcat, "{}Attempting to continue with HF20 workaround handling", *this);
            } else if (auto missing = reset_for_missing_validators(stage, timed_out)) {
                bool retry = *missing;
                if (retry)
                    // Missing validators have been removed, but there are enough left to retry
                    return round_state::send_and_wait_for_random_value_hashes;
                else
                    // Missing too many (or took to long) to be able to make a block
                    return goto_preparing_for_next_round();
            }

            return round_state::send_and_wait_for_random_value;
        }

        return round_state::send_and_wait_for_random_value_hashes;
    }

    round_state pulse_impl::send_and_wait_for_random_value() {
        ZoneScoped;
        //
        // NOTE: Send, and kick off the stage timer
        //
        assert(round.participant == sn_type::validator);
        start_send<message_type::random_value>(transient.random_value);

        //
        // NOTE: Wait
        //
        handle_messages_received_early_for(transient.random_value.wait.stage);
        pulse_wait_stage const& stage = transient.random_value.wait.stage;

        auto const& quorum = transient.random_value.wait.data;
        bool const timed_out = clock::now() >= stage.end_time;
        bool all_values;
        // HF20 "maybe keep going" workaround code:
        const bool hf20_compat_mode =
                !hf21 || core.blockchain.get_current_blockchain_height() < *hf21;
        if (hf20_compat_mode)
            all_values = stage.bitset == transient.random_value_hashes.wait.stage.bitset;
        else
            all_values = stage.bitset == transient.block.pulse.validator_bitset;

        if (timed_out || all_values) {
            if (!all_values && hf20_compat_mode) {
                auto num_validators = std::popcount(stage.bitset);
                if (num_validators < service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES)
                    return goto_preparing_for_next_round();
                log::debug(
                        logcat,
                        "{}Attempting to continue with HF20 workaround handling with {}/{} "
                        "validators",
                        *this,
                        num_validators,
                        std::popcount(transient.random_value_hashes.wait.stage.bitset));
            } else if (auto missing = reset_for_missing_validators(stage, timed_out)) {
                bool retry = *missing;
                if (retry)
                    // Missing validators have been removed, but there are enough left to restart
                    // from just after the block template was received.
                    return round_state::send_and_wait_for_random_value_hashes;
                else
                    // Missing too many (or took to long) to be able to make a block
                    return goto_preparing_for_next_round();
            }

            // Generate Final Random Value
            crypto::hash final_hash = {};
            {
                unsigned char constexpr key[crypto_generichash_KEYBYTES] = {};
                crypto_generichash_state state = {};
                crypto_generichash_init(&state, key, sizeof(key), sizeof(final_hash));

                for (size_t index = 0; index < quorum.size(); index++) {
                    if (auto& random_value = quorum[index]) {
                        crypto_generichash_update(
                                &state, random_value->data, sizeof(random_value->data));

                        log::debug(
                                logcat,
                                "{}Final random value seeding with V[{}] value: {:02x}...{:02x}",
                                *this,
                                index,
                                *std::begin(random_value->data),
                                *std::rbegin(random_value->data));
                    }
                }

                crypto_generichash_final(&state, final_hash.data(), final_hash.size());
            }

            // Add final random value to the block
            auto& block_rv = transient.block.pulse.random_value.data;
            static_assert(sizeof(final_hash) >= sizeof(block_rv));
            std::memcpy(block_rv, final_hash.data(), sizeof(block_rv));
            transient.block.invalidate_hashes();

            if (hf20_compat_mode) {
                const auto& rv_validators = transient.random_value_hashes.wait.stage.bitset;
                // We mutate the bitset in the block with the random_value_hashes stage bitset
                // (rather than this random_value bitset) because 11.2.0 nodes without this
                // workaround will drop out after the random_value_hashes stage because they didn't
                // get all the rv hashes, and don't have this "keep trying" workaround, but we don't
                // want to penalize them, so if someone provided rv hashes we give them
                // participation credit in the final block even if they didn't make it to the end.
                //
                // Observed problematic (apparently massively overloaded) nodes during the 11.2.0
                // release generally failed to make it to the random value hash phase, so this
                // effectively pruned them out with pulse participation failures properly assigned.
                if (transient.block.pulse.validator_bitset != rv_validators) {
                    transient.block.pulse.validator_bitset = rv_validators;
                    log::info(
                            logcat,
                            "{}Using subset of ideal bitset as some validators dropped out of the "
                            "process; updating block validator bitset.",
                            *this);
                }
            }

            // Generate the signature of the final block (without any of the other
            // Service Node signatures because we allow the first
            // 'PULSE_BLOCK_REQUIRED_SIGNATURES' that arrive to be added. These can be
            // inconsistent between syncing clients, as long as the signature itself is
            // valid against the quorum Service Nodes).
            auto& key = core.get_service_keys();
            crypto::generate_signature(
                    cryptonote::get_block_hash(transient.block),
                    key.pub,
                    key.key,
                    transient.block_signatures.to_send.emplace());

            log::info(
                    logcat,
                    "{}Block final random value {} generated from validators {:011b}",
                    *this,
                    tools::hex_guts(block_rv),
                    stage.bitset);
            return round_state::send_and_wait_for_block_signatures;
        }

        return round_state::send_and_wait_for_random_value;
    }

    round_state pulse_impl::send_and_wait_for_block_signatures() {
        ZoneScoped;
        assert(round.participant == sn_type::validator);

        //
        // NOTE: Send, and kick off the stage timer
        //
        start_send<message_type::block_signature>(transient.block_signatures);

        //
        // NOTE: Wait
        //
        auto& wait = transient.block_signatures.wait;
        handle_messages_received_early_for(wait.stage);
        pulse_wait_stage const& stage = wait.stage;

        auto const& quorum = wait.data;
        bool const timed_out = clock::now() >= stage.end_time;

        // HF20 "maybe keep going" workaround code:
        const bool hf20_compat_mode =
                !hf21 || core.blockchain.get_current_blockchain_height() < *hf21;
        auto& block = transient.block;
        const bool all_sigs =
                stage.bitset == (hf20_compat_mode ? transient.random_value.wait.stage.bitset
                                                  : block.pulse.validator_bitset);

        if (timed_out || all_sigs) {
            if (auto missing = reset_for_missing_validators(stage, timed_out)) {
                bool retry = *missing;
                if (retry)
                    // Missing validators have been removed, but there are enough left to restarting
                    // from just after the block template was received.
                    return round_state::send_and_wait_for_random_value_hashes;
                else
                    // Missing too many (or took to long) to be able to make a block
                    return goto_preparing_for_next_round();
            }

            assert(std::popcount(stage.bitset) >= service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES);

            // Add first PULSE_BLOCK_REQUIRED_SIGNATURES signatures
            for (uint16_t validator_index = 0; validator_index < quorum.size(); validator_index++) {
                const auto& signature = quorum[validator_index];
                if (!signature)
                    continue;
                log::debug(
                        logcat,
                        "{}Signature added: {}:{}, {}",
                        *this,
                        validator_index,
                        round.quorum.validators[validator_index],
                        *signature);
                block.signatures.emplace_back(validator_index, *signature);
                if (block.signatures.size() == service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES)
                    break;
            }
            assert(block.signatures.size() == service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES);
            block.invalidate_hashes();

            // Propagate Final Block
            if (log::get_level(logcat) <= log::Level::debug)
                log::debug(
                        logcat,
                        "{}Final signed block constructed:\n{}",
                        *this,
                        cryptonote::obj_to_json_str(block));

            // Insert any state change txes into the mempool, because we quite possibly have
            // *equivalent* ones but those do not have the same hash and will not be found, and we
            // need to ensure we have the exact one the block producer sent in order for the block
            // to get admitted to the chain.
            for (auto& [hash, blob] : transient.state_change_txs) {
                cryptonote::tx_verification_context tvc{};
                if (!core.handle_incoming_tx(
                            blob, tvc, cryptonote::tx_pool_options::from_block()) ||
                    tvc.m_verifivation_failed) {
                    log::error(logcat, "Failed to add state change tx {} to mempool", hash);
                    return goto_preparing_for_next_round();
                }
            }

            cryptonote::block_verification_context bvc = {};
            if (!core.handle_block_found(block, bvc))
                return goto_preparing_for_next_round();

            return goto_wait_for_next_block_and_clear_round_data();
        }

        return round_state::send_and_wait_for_block_signatures;
    }

    pulse_impl::pulse_impl(cryptonote::core& core) : core{core} {}

    void pulse_impl::init(void* qnet_state) {
        assert(!quorumnet_state);
        quorumnet_state = qnet_state;
        hf16 = hard_fork_begins(core.get_nettype(), cryptonote::hf::hf16_pulse);
        hf21 = hard_fork_begins(core.get_nettype(), cryptonote::hf::hf21_eth);

        if (!hf16)
            log::error(logcat, "Pulse: HF16 is not defined; pulse disabled");
        else if (uint64_t height = core.blockchain.get_current_blockchain_height();
                 height < *hf16) {
            log::debug(
                    logcat,
                    "Pulse: Network at block {} is not ready for Pulse until block {}, waiting",
                    height,
                    *hf16);
        }
    }

    void pulse_impl::check_state() {
        //
        // NOTE: Early exit if too early
        //
        if (!hf16)
            return;

        if (state <= round_state::wait_for_next_block &&
            core.blockchain.get_current_blockchain_height() < *hf16)
            return;

        auto last_state = round_state::null_state;
        do {
            ZoneScoped;
            last_state = state;
            switch (state) {
                case round_state::null_state: state = round_state::wait_for_next_block; break;

                case round_state::wait_for_next_block: state = wait_for_next_block(); break;

                case round_state::prepare_for_round: state = prepare_for_round(); break;

                case round_state::wait_for_round: state = wait_for_round(); break;

                case round_state::send_and_wait_for_handshakes:
                    state = send_and_wait_for_handshakes();
                    break;

                case round_state::send_handshake_bitsets: state = send_handshake_bitsets(); break;

                case round_state::wait_for_handshake_bitsets:
                    state = wait_for_handshake_bitsets();
                    break;

                case round_state::wait_for_block_template: state = wait_for_block_template(); break;

                case round_state::send_block_template: state = send_block_template(); break;

                case round_state::send_and_wait_for_random_value_hashes:
                    state = send_and_wait_for_random_value_hashes();
                    break;

                case round_state::send_and_wait_for_random_value:
                    state = send_and_wait_for_random_value();
                    break;

                case round_state::send_and_wait_for_block_signatures:
                    state = send_and_wait_for_block_signatures();
                    break;
            }

            mocknet_push_mock_pulse_block(core);
        } while (last_state != state);
    }

}  // anonymous namespace

pulse::pulse(cryptonote::core& core) : impl{std::make_shared<pulse_impl>(core)} {}

void pulse::init(void* quorumnet_state) {
    static_cast<pulse_impl*>(impl.get())->init(quorumnet_state);
}

void pulse::operator()(const message* msg) const {
    auto* pimpl = static_cast<pulse_impl*>(impl.get());
    if (!pimpl) {
        log::error(logcat, "Pulse state update attempted without initialized pulse state!");
        return;
    }
    if (msg)
        pimpl->handle_message(*msg);
    pimpl->check_state();
}

}  // namespace pulse

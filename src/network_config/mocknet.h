#pragma once

#include <crypto/crypto.h>

#if defined(WITH_MOCKNET)
#include <stdint.h>
namespace service_nodes {
struct quorum;
};

namespace oxen::sent {
struct transition_context;
};

namespace cryptonote {
class core;
};

namespace boost::program_options {
class options_description;
class variables_map;
};  // namespace boost::program_options

void mocknet_add_cli_arg(boost::program_options::options_description& desc);
bool mocknet_read_cli_for_mocknet_arg(
        const boost::program_options::variables_map& vm, bool is_service_node);
bool mocknet_is_forking(uint64_t top_block_height);
bool mocknet_has_forked(uint64_t top_block_height);
crypto::public_key mocknet_get_deterministic_block_leader();
void mocknet_replace_quorum_with_mock_nodes(
        service_nodes::quorum& quorum, uint64_t top_block_height);
void mocknet_inject_nodes(uint8_t nettype, void* snl_state_ptr, uint8_t hf_version);
void mocknet_push_mock_pulse_block(cryptonote::core& core);
void mocknet_get_transition_context(oxen::sent::transition_context& context);
#else
#define mocknet_add_cli_arg(...)
#define mocknet_read_cli_for_mocknet_arg(...) true
#define mocknet_is_forking(...) false
#define mocknet_has_forked(...) false
#define mocknet_get_deterministic_block_leader(...) crypto::null<crypto::public_key>
#define mocknet_replace_quorum_with_mock_nodes(...)
#define mocknet_inject_nodes(...)
#define mocknet_push_mock_pulse_block(...)
#define mocknet_get_transition_context(...)
#endif

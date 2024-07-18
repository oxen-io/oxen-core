#pragma once

#include <oxenc/bt_value.h>

#include <nlohmann/json.hpp>

#include "core_rpc_server_commands_defs.h"

namespace cryptonote::rpc {

using rpc_input = std::variant<std::monostate, nlohmann::json, oxenc::bt_dict_consumer>;

inline void parse_request(NO_ARGS&, rpc_input) {}

void parse_request(BANNED& banned, rpc_input in);
void parse_request(FLUSH_CACHE& flush_cache, rpc_input in);
void parse_request(FLUSH_TRANSACTION_POOL& flush_transaction_pool, rpc_input in);
void parse_request(GET_ACCRUED_REWARDS& rpc, rpc_input in);
void parse_request(GET_FEE_ESTIMATE& get_fee_estimate, rpc_input in);
void parse_request(GET_BLOCK& get_block, rpc_input in);
void parse_request(GET_BLOCK_HASH& bh, rpc_input in);
void parse_request(GET_BLOCK_HEADERS_RANGE& get_block_headers_range, rpc_input in);
void parse_request(GET_BLOCK_HEADER_BY_HASH& get_block_header_by_hash, rpc_input in);
void parse_request(GET_BLOCK_HEADER_BY_HEIGHT& get_block_header_by_height, rpc_input in);
void parse_request(GET_CHECKPOINTS& getcp, rpc_input in);
void parse_request(GET_COINBASE_TX_SUM& get_coinbase_tx_sum, rpc_input in);
void parse_request(GET_QUORUM_STATE& get_quorum_state, rpc_input in);
void parse_request(GET_LAST_BLOCK_HEADER& get_last_block_header, rpc_input in);
void parse_request(GET_OUTPUTS& get_outputs, rpc_input in);
void parse_request(GET_OUTPUT_HISTOGRAM& get_output_histogram, rpc_input in);
void parse_request(GET_PEER_LIST& bh, rpc_input in);
void parse_request(GET_SERVICE_NODES& sns, rpc_input in);
void parse_request(GET_SERVICE_NODE_REGISTRATION_CMD& cmd, rpc_input in);
void parse_request(GET_SERVICE_NODE_REGISTRATION_CMD_RAW& cmd, rpc_input in);
void parse_request(GET_SN_STATE_CHANGES& get_sn_state_changes, rpc_input in);
void parse_request(GET_STAKING_REQUIREMENT& get_staking_requirement, rpc_input in);
void parse_request(GET_TRANSACTIONS& get, rpc_input in);
void parse_request(GET_TRANSACTION_POOL& get, rpc_input in);
void parse_request(GET_TRANSACTION_POOL_STATS& pstats, rpc_input in);
void parse_request(HARD_FORK_INFO& hfinfo, rpc_input in);
void parse_request(IN_PEERS& in_peers, rpc_input in);
void parse_request(IS_KEY_IMAGE_SPENT& spent, rpc_input in);
void parse_request(LOKINET_PING& lokinet_ping, rpc_input in);
void parse_request(ONS_OWNERS_TO_NAMES& ons_owners_to_names, rpc_input in);
void parse_request(ONS_NAMES_TO_OWNERS& ons_names_to_owners, rpc_input in);
void parse_request(ONS_RESOLVE& ons, rpc_input in);
void parse_request(OUT_PEERS& out_peers, rpc_input in);
void parse_request(POP_BLOCKS& pop_blocks, rpc_input in);
void parse_request(PRUNE_BLOCKCHAIN& prune_blockchain, rpc_input in);
void parse_request(REPORT_PEER_STATUS& report_peer_status, rpc_input in);
void parse_request(SET_BANS& set_bans, rpc_input in);
void parse_request(SET_LIMIT& limit, rpc_input in);
void parse_request(SET_LOG_LEVEL& set_log_level, rpc_input in);
void parse_request(START_MINING& start_mining, rpc_input in);
void parse_request(STORAGE_SERVER_PING& storage_server_ping, rpc_input in);
void parse_request(SUBMIT_TRANSACTION& tx, rpc_input in);
void parse_request(BLS_REWARDS_REQUEST& cmd, rpc_input in);
void parse_request(BLS_EXIT_REQUEST& cmd, rpc_input in);
void parse_request(BLS_LIQUIDATION_REQUEST& cmd, rpc_input in);
void parse_request(BLS_REGISTRATION& cmd, rpc_input in);
}  // namespace cryptonote::rpc

#include "core_rpc_server_commands_defs.h"

namespace cryptonote::rpc {

KV_SERIALIZE_MAP_CODE_BEGIN(STATUS)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(EMPTY)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_HEIGHT::response)
  KV_SERIALIZE(height)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
  KV_SERIALIZE(hash)
  KV_SERIALIZE(immutable_height)
  KV_SERIALIZE(immutable_hash)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_FAST::request)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(prune)
  KV_SERIALIZE_OPT(no_miner_tx, false)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_FAST::tx_output_indices)
  KV_SERIALIZE(indices)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_FAST::block_output_indices)
  KV_SERIALIZE(indices)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_FAST::response)
  KV_SERIALIZE(blocks)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(current_height)
  KV_SERIALIZE(status)
  KV_SERIALIZE(output_indices)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_BY_HEIGHT::request)
  KV_SERIALIZE(heights)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCKS_BY_HEIGHT::response)
  KV_SERIALIZE(blocks)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_ALT_BLOCKS_HASHES::response)
  KV_SERIALIZE(blks_hashes)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_HASHES_FAST::request)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
  KV_SERIALIZE(start_height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_HASHES_FAST::response)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(m_block_ids)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(current_height)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTIONS::request)
  KV_SERIALIZE(txs_hashes)
  KV_SERIALIZE(decode_as_json)
  KV_SERIALIZE(tx_extra)
  KV_SERIALIZE_OPT(prune, false)
  KV_SERIALIZE_OPT(split, false)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTIONS::extra_entry::sn_reg_info::contribution)
  KV_SERIALIZE(wallet)
  KV_SERIALIZE(portion)
KV_SERIALIZE_MAP_CODE_END()
KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTIONS::extra_entry::sn_reg_info)
  KV_SERIALIZE(contributors)
  KV_SERIALIZE(fee)
  KV_SERIALIZE(expiry)
KV_SERIALIZE_MAP_CODE_END()
KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTIONS::extra_entry::state_change)
  KV_SERIALIZE(old_dereg)
  KV_SERIALIZE(type)
  KV_SERIALIZE(height)
  KV_SERIALIZE(index)
  KV_SERIALIZE(voters)
KV_SERIALIZE_MAP_CODE_END()
KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTIONS::extra_entry::lns_details)
  KV_SERIALIZE(buy)
  KV_SERIALIZE(update)
  KV_SERIALIZE(type)
  KV_SERIALIZE(blocks)
  KV_SERIALIZE_VAL_POD_AS_BLOB(name)
  KV_SERIALIZE(prev_txid)
  KV_SERIALIZE(value)
  KV_SERIALIZE(owner)
  KV_SERIALIZE(backup_owner)
KV_SERIALIZE_MAP_CODE_END()
KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTIONS::extra_entry)
  KV_SERIALIZE(pubkey)
  KV_SERIALIZE(burn_amount)
  KV_SERIALIZE(extra_nonce)
  KV_SERIALIZE(mm_depth)
  KV_SERIALIZE(mm_root)
  KV_SERIALIZE(additional_pubkeys)
  KV_SERIALIZE(sn_winner)
  KV_SERIALIZE(sn_pubkey)
  KV_SERIALIZE(sn_registration)
  KV_SERIALIZE(sn_contributor)
  KV_SERIALIZE(sn_state_change)
  KV_SERIALIZE(tx_secret_key)
  KV_SERIALIZE(locked_key_images)
  KV_SERIALIZE(key_image_unlock)
  KV_SERIALIZE(lns)
KV_SERIALIZE_MAP_CODE_END()
KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTIONS::entry)
  KV_SERIALIZE(tx_hash)
  KV_SERIALIZE(as_hex)
  KV_SERIALIZE(as_json)
  KV_SERIALIZE(pruned_as_hex)
  KV_SERIALIZE(prunable_as_hex)
  KV_SERIALIZE(prunable_hash)
  KV_SERIALIZE(size)
  KV_SERIALIZE(in_pool)
  KV_SERIALIZE(double_spend_seen)
  if (!in_pool)
  {
    KV_SERIALIZE(block_height)
    KV_SERIALIZE(block_timestamp)
    KV_SERIALIZE(output_indices)
  }
  else
  {
    KV_SERIALIZE(relayed)
    KV_SERIALIZE(received_timestamp)
  }
  KV_SERIALIZE(blink)
  KV_SERIALIZE(extra)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTIONS::response)
  KV_SERIALIZE(txs)
  KV_SERIALIZE(missed_tx)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(IS_KEY_IMAGE_SPENT::request)
  KV_SERIALIZE(key_images)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(IS_KEY_IMAGE_SPENT::response)
  KV_SERIALIZE(spent_status)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TX_GLOBAL_OUTPUTS_INDEXES::request)
  KV_SERIALIZE_VAL_POD_AS_BLOB(txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TX_GLOBAL_OUTPUTS_INDEXES::response)
  KV_SERIALIZE(o_indexes)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(get_outputs_out)
  KV_SERIALIZE(amount)
  KV_SERIALIZE(index)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS_BIN::request)
  KV_SERIALIZE(outputs)
  KV_SERIALIZE_OPT(get_txid, true)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS_BIN::outkey)
  KV_SERIALIZE_VAL_POD_AS_BLOB(key)
  KV_SERIALIZE_VAL_POD_AS_BLOB(mask)
  KV_SERIALIZE(unlocked)
  KV_SERIALIZE(height)
  KV_SERIALIZE_VAL_POD_AS_BLOB(txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS_BIN::response)
  KV_SERIALIZE(outs)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS::request)
  KV_SERIALIZE(outputs)
  KV_SERIALIZE(get_txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS::outkey)
  KV_SERIALIZE(key)
  KV_SERIALIZE(mask)
  KV_SERIALIZE(unlocked)
  KV_SERIALIZE(height)
  KV_SERIALIZE(txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUTS::response)
  KV_SERIALIZE(outs)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SEND_RAW_TX::request)
  KV_SERIALIZE(tx_as_hex)
  KV_SERIALIZE_OPT(do_not_relay, false)
  KV_SERIALIZE_OPT(do_sanity_checks, true)
  KV_SERIALIZE_OPT(blink, false)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SEND_RAW_TX::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(reason)
  KV_SERIALIZE(not_relayed)
  KV_SERIALIZE(sanity_check_failed)
  KV_SERIALIZE(untrusted)
  KV_SERIALIZE(tvc)
  KV_SERIALIZE_ENUM(blink_status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(START_MINING::request)
  KV_SERIALIZE(miner_address)
  KV_SERIALIZE(threads_count)
  KV_SERIALIZE_OPT(num_blocks, uint64_t{0})
  KV_SERIALIZE_OPT(slow_mining, false)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(MINING_STATUS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(active)
  KV_SERIALIZE(speed)
  KV_SERIALIZE(threads_count)
  KV_SERIALIZE(address)
  KV_SERIALIZE(pow_algorithm)
  KV_SERIALIZE(block_target)
  KV_SERIALIZE(block_reward)
  KV_SERIALIZE(difficulty)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_INFO::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(height)
  KV_SERIALIZE(target_height)
  KV_SERIALIZE(immutable_height)
  KV_SERIALIZE(difficulty)
  KV_SERIALIZE(target)
  KV_SERIALIZE(tx_count)
  KV_SERIALIZE(tx_pool_size)
  KV_SERIALIZE(alt_blocks_count)
  KV_SERIALIZE(outgoing_connections_count)
  KV_SERIALIZE(incoming_connections_count)
  KV_SERIALIZE(rpc_connections_count)
  KV_SERIALIZE(white_peerlist_size)
  KV_SERIALIZE(grey_peerlist_size)
  KV_SERIALIZE(mainnet)
  KV_SERIALIZE(testnet)
  KV_SERIALIZE(devnet)
  KV_SERIALIZE(nettype)
  KV_SERIALIZE(top_block_hash)
  KV_SERIALIZE(immutable_block_hash)
  KV_SERIALIZE(cumulative_difficulty)
  KV_SERIALIZE(block_size_limit)
  KV_SERIALIZE_OPT(block_weight_limit, (uint64_t)0)
  KV_SERIALIZE(block_size_median)
  KV_SERIALIZE_OPT(block_weight_median, (uint64_t)0)
  KV_SERIALIZE(start_time)
  KV_SERIALIZE(service_node)
  KV_SERIALIZE(last_storage_server_ping)
  KV_SERIALIZE(last_lokinet_ping)
  KV_SERIALIZE(free_space)
  KV_SERIALIZE(offline)
  KV_SERIALIZE(untrusted)
  KV_SERIALIZE(bootstrap_daemon_address)
  KV_SERIALIZE(height_without_bootstrap)
  KV_SERIALIZE(was_bootstrap_ever_used)
  KV_SERIALIZE(database_size)
  KV_SERIALIZE(version)
  KV_SERIALIZE(status_line)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_NET_STATS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(start_time)
  KV_SERIALIZE(total_packets_in)
  KV_SERIALIZE(total_bytes_in)
  KV_SERIALIZE(total_packets_out)
  KV_SERIALIZE(total_bytes_out)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GETBLOCKCOUNT::response)
  KV_SERIALIZE(count)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


bool GETBLOCKHASH::request::load(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section)
{
  return epee::serialization::perform_serialize<false>(height, ps, hparent_section, "height");
}
bool GETBLOCKHASH::request::store(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section)
{
  return epee::serialization::perform_serialize<true>(height, ps, hparent_section, "height");
}


KV_SERIALIZE_MAP_CODE_BEGIN(GETBLOCKTEMPLATE::request)
  KV_SERIALIZE(reserve_size)
  KV_SERIALIZE(wallet_address)
  KV_SERIALIZE(prev_block)
  KV_SERIALIZE(extra_nonce)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GETBLOCKTEMPLATE::response)
  KV_SERIALIZE(difficulty)
  KV_SERIALIZE(height)
  KV_SERIALIZE(reserved_offset)
  KV_SERIALIZE(expected_reward)
  KV_SERIALIZE(prev_hash)
  KV_SERIALIZE(blocktemplate_blob)
  KV_SERIALIZE(blockhashing_blob)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
  KV_SERIALIZE(seed_hash)
  KV_SERIALIZE(next_seed_hash)
KV_SERIALIZE_MAP_CODE_END()


bool SUBMITBLOCK::request::load(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section)
{
  return epee::serialization::perform_serialize<false>(blob, ps, hparent_section, "blob");
}
bool SUBMITBLOCK::request::store(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section)
{
  return epee::serialization::perform_serialize<true>(blob, ps, hparent_section, "blob");
}


KV_SERIALIZE_MAP_CODE_BEGIN(GENERATEBLOCKS::request)
  KV_SERIALIZE(amount_of_blocks)
  KV_SERIALIZE(wallet_address)
  KV_SERIALIZE(prev_block)
  KV_SERIALIZE_OPT(starting_nonce, (uint32_t)0)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GENERATEBLOCKS::response)
  KV_SERIALIZE(height)
  KV_SERIALIZE(blocks)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(block_header_response)
  KV_SERIALIZE(major_version)
  KV_SERIALIZE(minor_version)
  KV_SERIALIZE(timestamp)
  KV_SERIALIZE(prev_hash)
  KV_SERIALIZE(nonce)
  KV_SERIALIZE(orphan_status)
  KV_SERIALIZE(height)
  KV_SERIALIZE(depth)
  KV_SERIALIZE(hash)
  KV_SERIALIZE(difficulty)
  KV_SERIALIZE(cumulative_difficulty)
  KV_SERIALIZE(reward)
  KV_SERIALIZE(miner_reward)
  KV_SERIALIZE(block_size)
  KV_SERIALIZE_OPT(block_weight, (uint64_t)0)
  KV_SERIALIZE(num_txes)
  KV_SERIALIZE(pow_hash)
  KV_SERIALIZE_OPT(long_term_weight, (uint64_t)0)
  KV_SERIALIZE(miner_tx_hash)
  KV_SERIALIZE(tx_hashes)
  KV_SERIALIZE(service_node_winner)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_LAST_BLOCK_HEADER::request)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
  KV_SERIALIZE_OPT(get_tx_hashes, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_LAST_BLOCK_HEADER::response)
  KV_SERIALIZE(block_header)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADER_BY_HASH::request)
  KV_SERIALIZE(hash)
  KV_SERIALIZE(hashes)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
  KV_SERIALIZE_OPT(get_tx_hashes, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADER_BY_HASH::response)
  KV_SERIALIZE(block_header)
  KV_SERIALIZE(block_headers)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADER_BY_HEIGHT::request)
  KV_SERIALIZE(height)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
  KV_SERIALIZE_OPT(get_tx_hashes, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADER_BY_HEIGHT::response)
  KV_SERIALIZE(block_header)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK::request)
  KV_SERIALIZE(hash)
  KV_SERIALIZE(height)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK::response)
  KV_SERIALIZE(block_header)
  KV_SERIALIZE(tx_hashes)
  KV_SERIALIZE(status)
  KV_SERIALIZE(blob)
  KV_SERIALIZE(json)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_PEER_LIST::peer)
  KV_SERIALIZE(id)
  KV_SERIALIZE(host)
  KV_SERIALIZE(ip)
  KV_SERIALIZE(port)
  KV_SERIALIZE_OPT(rpc_port, (uint16_t)0)
  KV_SERIALIZE(last_seen)
  KV_SERIALIZE_OPT(pruning_seed, (uint32_t)0)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_PEER_LIST::request)
  KV_SERIALIZE_OPT(public_only, true)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_PEER_LIST::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(white_list)
  KV_SERIALIZE(gray_list)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(public_node)
  KV_SERIALIZE(host)
  KV_SERIALIZE(last_seen)
  KV_SERIALIZE(rpc_port)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_PUBLIC_NODES::request)
  KV_SERIALIZE_OPT(gray, false)
  KV_SERIALIZE_OPT(white, true)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_PUBLIC_NODES::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(gray)
  KV_SERIALIZE(white)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LOG_HASH_RATE::request)
  KV_SERIALIZE(visible)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LOG_LEVEL::request)
  KV_SERIALIZE(level)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LOG_CATEGORIES::request)
  KV_SERIALIZE(categories)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LOG_CATEGORIES::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(categories)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(tx_info)
  KV_SERIALIZE(id_hash)
  KV_SERIALIZE(tx_json)
  KV_SERIALIZE(blob_size)
  KV_SERIALIZE_OPT(weight, (uint64_t)0)
  KV_SERIALIZE(fee)
  KV_SERIALIZE(max_used_block_id_hash)
  KV_SERIALIZE(max_used_block_height)
  KV_SERIALIZE(kept_by_block)
  KV_SERIALIZE(last_failed_height)
  KV_SERIALIZE(last_failed_id_hash)
  KV_SERIALIZE(receive_time)
  KV_SERIALIZE(relayed)
  KV_SERIALIZE(last_relayed_time)
  KV_SERIALIZE(do_not_relay)
  KV_SERIALIZE(double_spend_seen)
  KV_SERIALIZE(tx_blob)
  KV_SERIALIZE(extra)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(spent_key_image_info)
  KV_SERIALIZE(id_hash)
  KV_SERIALIZE(txs_hashes)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL::request)
  KV_SERIALIZE(tx_extra)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(transactions)
  KV_SERIALIZE(spent_key_images)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL_HASHES_BIN::request)
  KV_SERIALIZE_OPT(long_poll, false)
  KV_SERIALIZE_VAL_POD_AS_BLOB_OPT(tx_pool_checksum, crypto::hash{})
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL_HASHES_BIN::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(tx_hashes)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL_HASHES::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(tx_hashes)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL_BACKLOG::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE_CONTAINER_POD_AS_BLOB(backlog)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(txpool_histo)
  KV_SERIALIZE(txs)
  KV_SERIALIZE(bytes)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(txpool_stats)
  KV_SERIALIZE(bytes_total)
  KV_SERIALIZE(bytes_min)
  KV_SERIALIZE(bytes_max)
  KV_SERIALIZE(bytes_med)
  KV_SERIALIZE(fee_total)
  KV_SERIALIZE(oldest)
  KV_SERIALIZE(txs_total)
  KV_SERIALIZE(num_failing)
  KV_SERIALIZE(num_10m)
  KV_SERIALIZE(num_not_relayed)
  KV_SERIALIZE(histo_98pc)
  KV_SERIALIZE(histo)
  KV_SERIALIZE(num_double_spends)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_TRANSACTION_POOL_STATS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(pool_stats)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CONNECTIONS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(connections)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADERS_RANGE::request)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(end_height)
  KV_SERIALIZE_OPT(fill_pow_hash, false);
  KV_SERIALIZE_OPT(get_tx_hashes, false);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BLOCK_HEADERS_RANGE::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(headers)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(SET_BOOTSTRAP_DAEMON::request)
  KV_SERIALIZE(address)
  KV_SERIALIZE(username)
  KV_SERIALIZE(password)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_LIMIT::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(limit_up)
  KV_SERIALIZE(limit_down)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LIMIT::request)
  KV_SERIALIZE(limit_down)
  KV_SERIALIZE(limit_up)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SET_LIMIT::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(limit_up)
  KV_SERIALIZE(limit_down)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(OUT_PEERS::request)
  KV_SERIALIZE_OPT(set, true)
  KV_SERIALIZE(out_peers)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(OUT_PEERS::response)
  KV_SERIALIZE(out_peers)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(IN_PEERS::request)
  KV_SERIALIZE_OPT(set, true)
  KV_SERIALIZE(in_peers)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(IN_PEERS::response)
  KV_SERIALIZE(in_peers)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(HARD_FORK_INFO::request)
  KV_SERIALIZE(version)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(HARD_FORK_INFO::response)
  KV_SERIALIZE(version)
  KV_SERIALIZE(enabled)
  KV_SERIALIZE(window)
  KV_SERIALIZE(votes)
  KV_SERIALIZE(threshold)
  KV_SERIALIZE(voting)
  KV_SERIALIZE(state)
  KV_SERIALIZE(earliest_height)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GETBANS::ban)
  KV_SERIALIZE(host)
  KV_SERIALIZE(ip)
  KV_SERIALIZE(seconds)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GETBANS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(bans)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SETBANS::ban)
  KV_SERIALIZE(host)
  KV_SERIALIZE(ip)
  KV_SERIALIZE(ban)
  KV_SERIALIZE(seconds)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SETBANS::request)
  KV_SERIALIZE(bans)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(BANNED::request)
  KV_SERIALIZE(address)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(BANNED::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(banned)
  KV_SERIALIZE(seconds)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(FLUSH_TRANSACTION_POOL::request)
  KV_SERIALIZE(txids)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_HISTOGRAM::request)
  KV_SERIALIZE(amounts);
  KV_SERIALIZE(min_count);
  KV_SERIALIZE(max_count);
  KV_SERIALIZE(unlocked);
  KV_SERIALIZE(recent_cutoff);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_HISTOGRAM::entry)
  KV_SERIALIZE(amount);
  KV_SERIALIZE(total_instances);
  KV_SERIALIZE(unlocked_instances);
  KV_SERIALIZE(recent_instances);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_HISTOGRAM::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(histogram)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_VERSION::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(version)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_COINBASE_TX_SUM::request)
  KV_SERIALIZE(height);
  KV_SERIALIZE(count);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_COINBASE_TX_SUM::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(emission_amount)
  KV_SERIALIZE(fee_amount)
  KV_SERIALIZE(burn_amount)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BASE_FEE_ESTIMATE::request)
  KV_SERIALIZE(grace_blocks)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_BASE_FEE_ESTIMATE::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(fee_per_byte)
  KV_SERIALIZE(fee_per_output)
  KV_SERIALIZE(blink_fee_per_byte)
  KV_SERIALIZE(blink_fee_per_output)
  KV_SERIALIZE(blink_fee_fixed)
  KV_SERIALIZE_OPT(quantization_mask, (uint64_t)1)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_ALTERNATE_CHAINS::chain_info)
  KV_SERIALIZE(block_hash)
  KV_SERIALIZE(height)
  KV_SERIALIZE(length)
  KV_SERIALIZE(difficulty)
  KV_SERIALIZE(block_hashes)
  KV_SERIALIZE(main_chain_parent_block)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_ALTERNATE_CHAINS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(chains)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(RELAY_TX::request)
  KV_SERIALIZE(txids)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SYNC_INFO::peer)
  KV_SERIALIZE(info)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SYNC_INFO::span)
  KV_SERIALIZE(start_block_height)
  KV_SERIALIZE(nblocks)
  KV_SERIALIZE(connection_id)
  KV_SERIALIZE(rate)
  KV_SERIALIZE(speed)
  KV_SERIALIZE(size)
  KV_SERIALIZE(remote_address)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(SYNC_INFO::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(height)
  KV_SERIALIZE(target_height)
  KV_SERIALIZE(next_needed_pruning_seed)
  KV_SERIALIZE(peers)
  KV_SERIALIZE(spans)
  KV_SERIALIZE(overview)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::request)
  KV_SERIALIZE(amounts)
  KV_SERIALIZE_OPT(from_height, (uint64_t)0)
  KV_SERIALIZE_OPT(to_height, (uint64_t)0)
  KV_SERIALIZE_OPT(cumulative, false)
  KV_SERIALIZE_OPT(binary, true)
  KV_SERIALIZE_OPT(compress, false)
KV_SERIALIZE_MAP_CODE_END()


namespace
{
  template<typename T>
  std::string compress_integer_array(const std::vector<T> &v)
  {
    std::string s;
    s.reserve(tools::VARINT_MAX_LENGTH<T>);
    auto ins = std::back_inserter(s);
    for (const T &t: v)
      tools::write_varint(ins, t);
    return s;
  }

  template<typename T>
  std::vector<T> decompress_integer_array(const std::string &s)
  {
    std::vector<T> v;
    for (auto it = s.begin(); it < s.end(); )
    {
      int read = tools::read_varint(it, s.end(), v.emplace_back());
      CHECK_AND_ASSERT_THROW_MES(read > 0, "Error decompressing data");
    }
    return v;
  }
}

KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::distribution)
  KV_SERIALIZE(amount)
  KV_SERIALIZE_N(data.start_height, "start_height")
  KV_SERIALIZE(binary)
  KV_SERIALIZE(compress)
  if (binary)
  {
    if (is_store)
    {
      if (compress)
      {
        const_cast<std::string&>(compressed_data) = compress_integer_array(data.distribution);
        KV_SERIALIZE(compressed_data)
      }
      else
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
    }
    else
    {
      if (compress)
      {
        KV_SERIALIZE(compressed_data)
        const_cast<std::vector<uint64_t>&>(data.distribution) = decompress_integer_array<uint64_t>(compressed_data);
      }
      else
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
    }
  }
  else
    KV_SERIALIZE_N(data.distribution, "distribution")
  KV_SERIALIZE_N(data.base, "base")
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(distributions)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(POP_BLOCKS::request)
  KV_SERIALIZE(nblocks);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(POP_BLOCKS::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(PRUNE_BLOCKCHAIN::request)
  KV_SERIALIZE_OPT(check, false)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(PRUNE_BLOCKCHAIN::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(pruned)
  KV_SERIALIZE(pruning_seed)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_QUORUM_STATE::request)
  KV_SERIALIZE_OPT(start_height, HEIGHT_SENTINEL_VALUE)
  KV_SERIALIZE_OPT(end_height, HEIGHT_SENTINEL_VALUE)
  KV_SERIALIZE_OPT(quorum_type, ALL_QUORUMS_SENTINEL_VALUE)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_QUORUM_STATE::quorum_t)
  KV_SERIALIZE(validators)
  KV_SERIALIZE(workers)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_QUORUM_STATE::quorum_for_height)
  KV_SERIALIZE(height)
  KV_SERIALIZE(quorum_type)
  KV_SERIALIZE(quorum)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_QUORUM_STATE::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(quorums)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_REGISTRATION_CMD_RAW::request)
  KV_SERIALIZE(args)
  KV_SERIALIZE(make_friendly)
  KV_SERIALIZE(staking_requirement)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_REGISTRATION_CMD_RAW::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(registration_cmd)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_REGISTRATION_CMD::contribution_t)
  KV_SERIALIZE(address)
  KV_SERIALIZE(amount)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_REGISTRATION_CMD::request)
  KV_SERIALIZE(operator_cut)
  KV_SERIALIZE(contributions)
  KV_SERIALIZE(staking_requirement)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_KEYS::response)
  KV_SERIALIZE(service_node_pubkey)
  KV_SERIALIZE(service_node_ed25519_pubkey)
  KV_SERIALIZE(service_node_x25519_pubkey)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_PRIVKEYS::response)
  KV_SERIALIZE(service_node_privkey)
  KV_SERIALIZE(service_node_ed25519_privkey)
  KV_SERIALIZE(service_node_x25519_privkey)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(PERFORM_BLOCKCHAIN_TEST::request)
  KV_SERIALIZE(max_height)
  KV_SERIALIZE(seed)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(PERFORM_BLOCKCHAIN_TEST::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(res_height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(service_node_contribution)
  KV_SERIALIZE(key_image)
  KV_SERIALIZE(key_image_pub_key)
  KV_SERIALIZE(amount)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(service_node_contributor)
  KV_SERIALIZE(amount)
  KV_SERIALIZE(reserved)
  KV_SERIALIZE(address)
  KV_SERIALIZE(locked_contributions)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODES::requested_fields_t)
  KV_SERIALIZE(all)
  if (!this_ref.all)
  {
    KV_SERIALIZE(service_node_pubkey)
    KV_SERIALIZE(registration_height)
    KV_SERIALIZE(registration_hf_version)
    KV_SERIALIZE(requested_unlock_height)
    KV_SERIALIZE(last_reward_block_height)
    KV_SERIALIZE(last_reward_transaction_index)
    KV_SERIALIZE(active)
    KV_SERIALIZE(funded)
    KV_SERIALIZE(state_height)
    KV_SERIALIZE(decommission_count)
    KV_SERIALIZE(earned_downtime_blocks)
    KV_SERIALIZE(service_node_version)
    KV_SERIALIZE(contributors)
    KV_SERIALIZE(total_contributed)
    KV_SERIALIZE(total_reserved)
    KV_SERIALIZE(staking_requirement)
    KV_SERIALIZE(portions_for_operator)
    KV_SERIALIZE(swarm_id)
    KV_SERIALIZE(operator_address)
    KV_SERIALIZE(public_ip)
    KV_SERIALIZE(storage_port)
    KV_SERIALIZE(storage_lmq_port)
    KV_SERIALIZE(quorumnet_port)
    KV_SERIALIZE(pubkey_ed25519)
    KV_SERIALIZE(pubkey_x25519)
    KV_SERIALIZE(block_hash)
    KV_SERIALIZE(height)
    KV_SERIALIZE(target_height)
    KV_SERIALIZE(hardfork)

    KV_SERIALIZE(last_uptime_proof)
    KV_SERIALIZE(storage_server_reachable)
    KV_SERIALIZE(storage_server_reachable_timestamp)
    KV_SERIALIZE(votes)
  }
KV_SERIALIZE_MAP_CODE_END()


static constexpr GET_SERVICE_NODES::requested_fields_t all_fields{true};
KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODES::request)
  KV_SERIALIZE(service_node_pubkeys);
  KV_SERIALIZE(include_json);
  KV_SERIALIZE(limit)
  KV_SERIALIZE(active_only)
  KV_SERIALIZE_OPT(fields, all_fields)
  KV_SERIALIZE(poll_block_hash)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODES::response::entry)
  const auto* res = stg.template get_context<response>();
  const bool all = !res || res->fields.all;

  #define KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(var) if (all || res->fields.var) KV_SERIALIZE(var)

  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(service_node_pubkey);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(registration_height);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(registration_hf_version);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(requested_unlock_height);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(last_reward_block_height);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(last_reward_transaction_index);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(active);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(funded);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(state_height);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(decommission_count);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(earned_downtime_blocks);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(service_node_version);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(contributors);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(total_contributed);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(total_reserved);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(staking_requirement);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(portions_for_operator);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(swarm_id);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(operator_address);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(public_ip);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(storage_port);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(storage_lmq_port);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(quorumnet_port);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(pubkey_ed25519);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(pubkey_x25519);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(last_uptime_proof);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(storage_server_reachable);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(storage_server_reachable_timestamp);
  KV_SERIALIZE_ENTRY_FIELD_IF_REQUESTED(votes);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODES::response)
  if (!unchanged) KV_SERIALIZE_DEPENDENT(service_node_states)
  KV_SERIALIZE(status)
  if (fields.height || fields.all) KV_SERIALIZE(height)
  if (fields.target_height || fields.all) KV_SERIALIZE(target_height)
  if (fields.block_hash || fields.all || (polling_mode && !unchanged)) KV_SERIALIZE(block_hash)
  if (fields.hardfork || fields.all) KV_SERIALIZE(hardfork)
  if (!as_json.empty()) KV_SERIALIZE(as_json)
  if (polling_mode) KV_SERIALIZE(unchanged);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_STATUS::request)
  KV_SERIALIZE(include_json);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_STATUS::response)
  KV_SERIALIZE(service_node_state)
  KV_SERIALIZE(height)
  KV_SERIALIZE(block_hash)
  KV_SERIALIZE(status)
  KV_SERIALIZE(as_json)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(STORAGE_SERVER_PING::request)
  KV_SERIALIZE(version_major);
  KV_SERIALIZE(version_minor);
  KV_SERIALIZE(version_patch);
  KV_SERIALIZE(storage_lmq_port);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LOKINET_PING::request)
  KV_SERIALIZE(version);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_STAKING_REQUIREMENT::request)
  KV_SERIALIZE(height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_STAKING_REQUIREMENT::response)
  KV_SERIALIZE(staking_requirement)
  KV_SERIALIZE(height)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::entry)
  KV_SERIALIZE(key_image)
  KV_SERIALIZE(unlock_height)
  KV_SERIALIZE(amount)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::response)
  KV_SERIALIZE(blacklist)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_BLACKLIST::response)
  KV_SERIALIZE(blacklist)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CHECKPOINTS::request)
  KV_SERIALIZE_OPT(start_height, HEIGHT_SENTINEL_VALUE)
  KV_SERIALIZE_OPT(end_height, HEIGHT_SENTINEL_VALUE)
  KV_SERIALIZE_OPT(count, NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CHECKPOINTS::voter_to_signature_serialized)
  KV_SERIALIZE(voter_index);
  KV_SERIALIZE(signature);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CHECKPOINTS::checkpoint_serialized)
  KV_SERIALIZE(version);
  KV_SERIALIZE(type);
  KV_SERIALIZE(height);
  KV_SERIALIZE(block_hash);
  KV_SERIALIZE(signatures);
  KV_SERIALIZE(prev_height);
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_CHECKPOINTS::response)
  KV_SERIALIZE(checkpoints)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SN_STATE_CHANGES::request)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE_OPT(end_height, HEIGHT_SENTINEL_VALUE)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(GET_SN_STATE_CHANGES::response)
  KV_SERIALIZE(status)
  KV_SERIALIZE(untrusted)
  KV_SERIALIZE(total_deregister)
  KV_SERIALIZE(total_ip_change_penalty)
  KV_SERIALIZE(total_decommission)
  KV_SERIALIZE(total_recommission)
  KV_SERIALIZE(start_height)
  KV_SERIALIZE(end_height)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(REPORT_PEER_SS_STATUS::request)
  KV_SERIALIZE(type)
  KV_SERIALIZE(pubkey)
  KV_SERIALIZE(passed)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LNS_NAMES_TO_OWNERS::request_entry)
  KV_SERIALIZE(name_hash)
  KV_SERIALIZE(types)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LNS_NAMES_TO_OWNERS::request)
  KV_SERIALIZE(entries)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LNS_NAMES_TO_OWNERS::response_entry)
  KV_SERIALIZE(entry_index)
  KV_SERIALIZE(type)
  KV_SERIALIZE(name_hash)
  KV_SERIALIZE(owner)
  KV_SERIALIZE(backup_owner)
  KV_SERIALIZE(encrypted_value)
  KV_SERIALIZE(register_height)
  KV_SERIALIZE(update_height)
  KV_SERIALIZE(txid)
  KV_SERIALIZE(prev_txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LNS_NAMES_TO_OWNERS::response)
  KV_SERIALIZE(entries)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LNS_OWNERS_TO_NAMES::request)
  KV_SERIALIZE(entries)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LNS_OWNERS_TO_NAMES::response_entry)
  KV_SERIALIZE(request_index)
  KV_SERIALIZE(type)
  KV_SERIALIZE(name_hash)
  KV_SERIALIZE(owner)
  KV_SERIALIZE(backup_owner)
  KV_SERIALIZE(encrypted_value)
  KV_SERIALIZE(register_height)
  KV_SERIALIZE(update_height)
  KV_SERIALIZE(txid)
  KV_SERIALIZE(prev_txid)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(LNS_OWNERS_TO_NAMES::response)
  KV_SERIALIZE(entries)
  KV_SERIALIZE(status)
KV_SERIALIZE_MAP_CODE_END()


KV_SERIALIZE_MAP_CODE_BEGIN(FLUSH_CACHE::request)
  KV_SERIALIZE_OPT(bad_txs, false)
  KV_SERIALIZE_OPT(bad_blocks, false)
KV_SERIALIZE_MAP_CODE_END()

}

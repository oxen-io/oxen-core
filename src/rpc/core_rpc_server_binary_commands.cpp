#include "core_rpc_server_binary_commands.h"

#include "common/guts.h"
#include "serialization/levin_kv/archive.h"

namespace cryptonote::rpc {

void EMPTY::serialize(levin_kv::archive&) {}

void to_json(nlohmann::json& j, const GET_BLOCKS_BIN::tx_output_indices& toi) {
    j = nlohmann::json{{"indices", toi.indices}};
}

void to_json(nlohmann::json& j, const GET_BLOCKS_BIN::block_output_indices& boi) {
    j = nlohmann::json{{"indices", boi.indices}};
}

void GET_BLOCKS_BIN::request::serialize(levin_kv::archive& ar) {
    ar.value("block_ids", block_ids);
    ar.value("start_height", start_height);
    ar.value("prune", prune);
    ar.value_or("no_miner_tx", no_miner_tx, false);
}

void GET_BLOCKS_BIN::tx_output_indices::serialize(levin_kv::archive& ar) {
    ar.value("indices", indices);
}

void GET_BLOCKS_BIN::block_output_indices::serialize(levin_kv::archive& ar) {
    ar.value("indices", indices);
}

void GET_BLOCKS_BIN::response::serialize(levin_kv::archive& ar) {
    ar.value("blocks", blocks);
    ar.value("start_height", start_height);
    ar.value("current_height", current_height);
    ar.value("status", status);
    ar.value("output_indices", output_indices);
    ar.value("untrusted", untrusted);
}

void GET_BLOCKS_BY_HEIGHT_BIN::request::serialize(levin_kv::archive& ar) {
    ar.value("heights", heights);
}

void GET_BLOCKS_BY_HEIGHT_BIN::response::serialize(levin_kv::archive& ar) {
    ar.value("blocks", blocks);
    ar.value("status", status);
    ar.value("untrusted", untrusted);
}

void GET_HASHES_BIN::request::serialize(levin_kv::archive& ar) {
    ar.value("block_ids", block_ids);
    ar.value("start_height", start_height);
}

void GET_HASHES_BIN::response::serialize(levin_kv::archive& ar) {
    ar.value("m_block_ids", m_block_ids);
    ar.value("start_height", start_height);
    ar.value("current_height", current_height);
    ar.value("status", status);
    ar.value("untrusted", untrusted);
}

void get_outputs_out::serialize(levin_kv::archive& ar) {
    ar.value("amount", amount);
    ar.value("index", index);
}

void GET_OUTPUTS_BIN::request::serialize(levin_kv::archive& ar) {
    ar.value("outputs", outputs);
    ar.value_or("get_txid", get_txid, true);
}

void GET_OUTPUTS_BIN::outkey::serialize(levin_kv::archive& ar) {
    ar.value("key", tools::byte_span(key));
    ar.value("mask", tools::byte_span(mask));
    ar.value("unlocked", unlocked);
    ar.value("height", height);
    ar.value("txid", tools::byte_span(txid));
}

void GET_OUTPUTS_BIN::response::serialize(levin_kv::archive& ar) {
    ar.value("outs", outs);
    ar.value("status", status);
    ar.value("untrusted", untrusted);
}

void GET_TRANSACTION_POOL_HASHES_BIN::request::serialize(levin_kv::archive& ar) {
    ar.value_or("blinked_txs_only", blinked_txs_only, false);
    ar.value_or("long_poll", long_poll, false);
    ar.value_or(
            "tx_pool_checksum",
            tools::byte_span(tx_pool_checksum),
            tools::byte_span(crypto::null<crypto::hash>));
}

void GET_TRANSACTION_POOL_HASHES_BIN::response::serialize(levin_kv::archive& ar) {
    ar.value("status", status);
    ar.value("tx_hashes", tx_hashes);
    ar.value("untrusted", untrusted);
}

void GET_OUTPUT_BLACKLIST_BIN::response::serialize(levin_kv::archive& ar) {
    ar.value("blacklist", blacklist);
    ar.value("status", status);
    ar.value("untrusted", untrusted);
}

}  // namespace cryptonote::rpc

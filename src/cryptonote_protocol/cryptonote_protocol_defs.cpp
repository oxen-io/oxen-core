#include "cryptonote_protocol_defs.h"

#include "common/guts.h"
#include "common/varint.h"
#include "serialization/levin_kv/levin_kv.h"

namespace cryptonote {

void serializable_blink_metadata::serialize(levin_kv::archive& ar) {
    ar.value("#", tools::byte_span(tx_hash));
    ar.value("h", height);
    ar.packed("q", quorum);
    ar.packed("p", position);
    ar.value("s", signature);
}

void block_complete_entry::serialize(levin_kv::archive& ar) {
    ar.value("block", block);
    ar.value("txs", txs);
    ar.value("checkpoint", checkpoint);
    ar.value("blinks", blinks);
}

void NOTIFY_NEW_TRANSACTIONS::request::serialize(levin_kv::archive& ar) {
    ar.value("txs", txs);
    ar.value("blinks", blinks);
    ar.value_or("requested", requested, false);
    ar.value("_", _);
}

std::string serialize_tx_notify(std::vector<std::string> txs, const bool pad) {
    NOTIFY_NEW_TRANSACTIONS::request request{};
    request.txs = std::move(txs);

    if (pad) {
        size_t bytes = 9 /* header */ + 4 /* 1 + 'txs' */ +
                       tools::get_varint_data(request.txs.size()).size();
        for (const auto& tx : request.txs)
            bytes += tools::get_varint_data(tx.size()).size() + tx.size();

        static constexpr size_t granularity = 1024;
        size_t padding = granularity - bytes % granularity;
        const size_t overhead = 2 /* 1 + '_' */ + tools::get_varint_data(padding).size();
        if (overhead > padding)
            padding = 0;
        else
            padding -= overhead;
        request._ = std::string(padding, ' ');

        // The estimate above can come in a little low, padding a little too much; trim the
        // excess.  If that shrinks the varint encoding the padding's length, the result is a byte
        // or so short of the boundary, which is fine.
        size_t remove = levin_kv::encode(request).size() % granularity;
        if (remove > request._.size())
            request._.clear();
        else
            request._.resize(request._.size() - remove);
    }

    return levin_kv::encode(request);
}

void NOTIFY_REQUEST_GET_BLOCKS::request::serialize(levin_kv::archive& ar) {
    ar.value("blocks", blocks);
}

void NOTIFY_RESPONSE_GET_BLOCKS::request::serialize(levin_kv::archive& ar) {
    ar.value("blocks", blocks);
    ar.value("missed_ids", missed_ids);
    ar.value("current_blockchain_height", current_blockchain_height);
}

void CORE_SYNC_DATA::serialize(levin_kv::archive& ar) {
    ar.value("current_height", current_height);
    ar.value("cumulative_difficulty", cumulative_difficulty);
    ar.value("top_id", tools::byte_span(top_id));
    ar.value("top_version", top_version);
    ar.value("blink_blocks", blink_blocks);
    ar.value("blink_hash", blink_hash);
    ar.value("history", history);
}

void NOTIFY_REQUEST_CHAIN::request::serialize(levin_kv::archive& ar) {
    ar.value("block_ids", block_ids);
}

void NOTIFY_RESPONSE_CHAIN_ENTRY::request::serialize(levin_kv::archive& ar) {
    ar.value("start_height", start_height);
    ar.value("total_height", total_height);
    ar.value("cumulative_difficulty", cumulative_difficulty);
    ar.value("m_block_ids", m_block_ids);
}

void NOTIFY_NEW_FLUFFY_BLOCK::request::serialize(levin_kv::archive& ar) {
    ar.value("b", b);
    ar.value("current_blockchain_height", current_blockchain_height);
}

void NOTIFY_REQUEST_FLUFFY_MISSING_TX::request::serialize(levin_kv::archive& ar) {
    ar.value("block_hash", tools::byte_span(block_hash));
    ar.value("current_blockchain_height", current_blockchain_height);
    ar.packed("missing_tx_indices", missing_tx_indices);
}

void NOTIFY_BTENCODED_UPTIME_PROOF::request::serialize(levin_kv::archive& ar) {
    ar.value("proof", proof);
    ar.value("sig", sig);
    ar.value("ed_sig", ed_sig);
}

void NOTIFY_REQUEST_BLOCK_BLINKS::request::serialize(levin_kv::archive& ar) {
    ar.value("heights", heights);
}

void NOTIFY_RESPONSE_BLOCK_BLINKS::request::serialize(levin_kv::archive& ar) {
    ar.value("txs", txs);
}

void NOTIFY_REQUEST_GET_TXS::request::serialize(levin_kv::archive& ar) {
    ar.value("txs", txs);
}

// NOTIFY_NEW_SERVICE_NODE_VOTE::request's serialize() is in service_node_voting.cpp

}  // namespace cryptonote

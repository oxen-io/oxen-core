#include "cryptonote_protocol_defs.h"

#include "common/varint.h"
#include "epee/storages/portable_storage_template_helper.h"

namespace cryptonote {

KV_SERIALIZE_MAP_CODE_BEGIN(serializable_blink_metadata)
KV_SERIALIZE_VAL_POD_AS_BLOB_N(tx_hash, "#")
KV_SERIALIZE_N(height, "h")
KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(quorum, "q")
KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(position, "p")
KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(signature, "s")
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(block_complete_entry)
KV_SERIALIZE(block)
KV_SERIALIZE(txs)
KV_SERIALIZE(checkpoint)
KV_SERIALIZE(blinks)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_NEW_TRANSACTIONS::request)
KV_SERIALIZE(txs)
KV_SERIALIZE(blinks)
KV_SERIALIZE_OPT(requested, false)
KV_SERIALIZE(_)
KV_SERIALIZE_MAP_CODE_END()

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
        std::string arg_buff;
        epee::serialization::store_t_to_binary(request, arg_buff);
        size_t remove = arg_buff.size() % granularity;
        if (remove > request._.size())
            request._.clear();
        else
            request._.resize(request._.size() - remove);
    }

    std::string blob;
    if (!epee::serialization::store_t_to_binary(request, blob))
        throw std::runtime_error{"Failed to serialize to epee binary format"};
    return blob;
}

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_GET_BLOCKS::request)
KV_SERIALIZE_CONTAINER_POD_AS_BLOB(blocks)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_RESPONSE_GET_BLOCKS::request)
KV_SERIALIZE(blocks)
KV_SERIALIZE_CONTAINER_POD_AS_BLOB(missed_ids)
KV_SERIALIZE(current_blockchain_height)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(CORE_SYNC_DATA)
KV_SERIALIZE(current_height)
KV_SERIALIZE(cumulative_difficulty)
KV_SERIALIZE_VAL_POD_AS_BLOB(top_id)
KV_SERIALIZE_ENUM(top_version)
KV_SERIALIZE(blink_blocks)
KV_SERIALIZE_CONTAINER_POD_AS_BLOB(blink_hash)
KV_SERIALIZE(history)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_CHAIN::request)
KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_RESPONSE_CHAIN_ENTRY::request)
KV_SERIALIZE(start_height)
KV_SERIALIZE(total_height)
KV_SERIALIZE(cumulative_difficulty)
KV_SERIALIZE_CONTAINER_POD_AS_BLOB(m_block_ids)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_NEW_FLUFFY_BLOCK::request)
KV_SERIALIZE(b)
KV_SERIALIZE(current_blockchain_height)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_FLUFFY_MISSING_TX::request)
KV_SERIALIZE_VAL_POD_AS_BLOB(block_hash)
KV_SERIALIZE(current_blockchain_height)
KV_SERIALIZE_CONTAINER_POD_AS_BLOB(missing_tx_indices)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_BTENCODED_UPTIME_PROOF::request)
KV_SERIALIZE(proof)
KV_SERIALIZE(sig)
KV_SERIALIZE(ed_sig)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_BLOCK_BLINKS::request)
KV_SERIALIZE(heights)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_RESPONSE_BLOCK_BLINKS::request)
KV_SERIALIZE_CONTAINER_POD_AS_BLOB(txs)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(NOTIFY_REQUEST_GET_TXS::request)
KV_SERIALIZE_CONTAINER_POD_AS_BLOB(txs)
KV_SERIALIZE_MAP_CODE_END()

// NOTIFY_NEW_SERVICE_NODE_VOTE::request implementation is in service_node_voting.cpp

}  // namespace cryptonote

#include "core_rpc_server_commands_defs.h"

#include <nlohmann/json.hpp>

static auto logcat = oxen::log::Cat("rpc");

namespace nlohmann {

template <class T>
void to_json(nlohmann::json& j, const std::optional<T>& v) {
    if (v.has_value())
        j = *v;
    else
        j = nullptr;
}

template <class T>
void from_json(const nlohmann::json& j, std::optional<T>& v) {
    if (j.is_null())
        v = std::nullopt;
    else
        v = j.get<T>();
}

}  // namespace nlohmann

namespace cryptonote {
void to_json(nlohmann::json& j, const checkpoint_t& c) {
    j = nlohmann::json{
            {"version", c.version},
            {"type", c.type},
            {"height", c.height},
            {"block_hash", tools::type_to_hex(c.block_hash)},
            {"signatures", c.signatures},
            {"prev_height", c.prev_height},
    };
};
}  // namespace cryptonote

namespace service_nodes {
void to_json(nlohmann::json& j, const key_image_blacklist_entry& b) {
    j = nlohmann::json{
            {"key_image", tools::type_to_hex(b.key_image)},
            {"unlock_height", b.unlock_height},
            {"amount", b.amount}};
};

void to_json(nlohmann::json& j, const quorum_signature& s) {
    j = nlohmann::json{
            {"voter_index", s.voter_index},
            {"signature", tools::type_to_hex(s.signature)},
    };
};
}  // namespace service_nodes

namespace cryptonote::rpc {

void RPC_COMMAND::set_bt() {
    bt = true;
    response_b64.format = tools::json_binary_proxy::fmt::bt;
    response_hex.format = tools::json_binary_proxy::fmt::bt;
}

void to_json(nlohmann::json& j, const block_header_response& h) {
    j = nlohmann::json{
            {"major_version", h.major_version},
            {"minor_version", h.minor_version},
            {"timestamp", h.timestamp},
            {"prev_hash", h.prev_hash},
            {"nonce", h.nonce},
            {"orphan_status", h.orphan_status},
            {"height", h.height},
            {"depth", h.depth},
            {"hash", h.hash},
            {"difficulty", h.difficulty},
            {"cumulative_difficulty", h.cumulative_difficulty},
            {"reward", h.reward},
            {"coinbase_payouts", h.coinbase_payouts},
            {"block_size", h.block_size},
            {"block_weight", h.block_weight},
            {"num_txes", h.num_txes},
            {"long_term_weight", h.long_term_weight},
            {"miner_tx_hash", h.miner_tx_hash},
            {"miner_tx_hash", h.miner_tx_hash},
            {"tx_hashes", h.tx_hashes},
            {"service_node_winner", h.service_node_winner},
            {"l2_height", h.l2_height},
            {"l2_state", h.l2_state},
    };
    if (h.pow_hash)
        j["pow_hash"] = *h.pow_hash;
};

void from_json(const nlohmann::json& j, block_header_response& h) {
    j.at("major_version").get_to(h.major_version);
    j.at("minor_version").get_to(h.minor_version);
    j.at("timestamp").get_to(h.timestamp);
    j.at("prev_hash").get_to(h.prev_hash);
    j.at("nonce").get_to(h.nonce);
    j.at("orphan_status").get_to(h.orphan_status);
    j.at("height").get_to(h.height);
    j.at("depth").get_to(h.depth);
    j.at("hash").get_to(h.hash);
    j.at("difficulty").get_to(h.difficulty);
    j.at("cumulative_difficulty").get_to(h.cumulative_difficulty);
    j.at("reward").get_to(h.reward);
    j.at("coinbase_payouts").get_to(h.coinbase_payouts);
    j.at("block_size").get_to(h.block_size);
    j.at("block_weight").get_to(h.block_weight);
    j.at("num_txes").get_to(h.num_txes);
    if (auto it = j.find("pow_hash"); it == j.end() || it->is_null())
        h.pow_hash = std::nullopt;
    else
        h.pow_hash = it->get<std::string>();
    j.at("long_term_weight").get_to(h.long_term_weight);
    j.at("miner_tx_hash").get_to(h.miner_tx_hash);
    j.at("miner_tx_hash").get_to(h.miner_tx_hash);
    j.at("tx_hashes").get_to(h.tx_hashes);
    j.at("service_node_winner").get_to(h.service_node_winner);
    j.at("l2_height").get_to(h.l2_height);
    j.at("l2_state").get_to(h.l2_state);
};

void to_json(nlohmann::json& j, const GET_QUORUM_STATE::quorum_t& q) {
    j = nlohmann::json{{"validators", q.validators}, {"workers", q.workers}};
};
void to_json(nlohmann::json& j, const GET_QUORUM_STATE::quorum_for_height& q) {
    j = nlohmann::json{{"height", q.height}, {"quorum_type", q.quorum_type}, {"quorum", q.quorum}};
};

void to_json(nlohmann::json& j, const GET_ALTERNATE_CHAINS::chain_info& c) {
    j = nlohmann::json{
            {"block_hash", c.block_hash},
            {"height", c.height},
            {"length", c.length},
            {"difficulty", c.difficulty},
            {"block_hashes", c.block_hashes},
            {"main_chain_parent_block", c.main_chain_parent_block},
    };
}
void from_json(const nlohmann::json& j, GET_ALTERNATE_CHAINS::chain_info& c) {
    j.at("block_hash").get_to(c.block_hash);
    j.at("height").get_to(c.height);
    j.at("length").get_to(c.length);
    j.at("difficulty").get_to(c.difficulty);
    j.at("block_hashes").get_to(c.block_hashes);
    j.at("main_chain_parent_block").get_to(c.main_chain_parent_block);
}

void to_json(nlohmann::json& j, const GET_OUTPUT_HISTOGRAM::entry& e) {
    j = nlohmann::json{
            {"amount", e.amount},
            {"total_instances", e.total_instances},
            {"unlocked_instances", e.unlocked_instances},
            {"recent_instances", e.recent_instances},
    };
}

void from_json(const nlohmann::json& j, GET_OUTPUT_HISTOGRAM::entry& e) {
    j.at("amount").get_to(e.amount);
    j.at("total_instances").get_to(e.total_instances);
    j.at("unlocked_instances").get_to(e.unlocked_instances);
    j.at("recent_instances").get_to(e.recent_instances);
};

void to_json(nlohmann::json& j, const ONS_OWNERS_TO_NAMES::response_entry& r) {
    j = nlohmann::json{
            {"request_index", r.request_index},
            {"type", r.type},
            {"name_hash", r.name_hash},
            {"owner", r.owner},
            {"backup_owner", r.backup_owner},
            {"encrypted_value", r.encrypted_value},
            {"update_height", r.update_height},
            {"expiration_height", r.expiration_height},
            {"txid", r.txid},
    };
}

KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::request)
KV_SERIALIZE(amounts)
KV_SERIALIZE_OPT(from_height, (uint64_t)0)
KV_SERIALIZE_OPT(to_height, (uint64_t)0)
KV_SERIALIZE_OPT(cumulative, false)
KV_SERIALIZE_OPT(binary, true)
KV_SERIALIZE_OPT(compress, false)
KV_SERIALIZE_MAP_CODE_END()

namespace {
    template <typename T>
    std::string compress_integer_array(const std::vector<T>& v) {
        std::string s;
        s.reserve(tools::VARINT_MAX_LENGTH<T>);
        auto ins = std::back_inserter(s);
        for (const T& t : v)
            tools::write_varint(ins, t);
        return s;
    }

    template <typename T>
    std::vector<T> decompress_integer_array(const std::string& s) {
        std::vector<T> v;
        for (auto it = s.begin(); it < s.end();) {
            int read = tools::read_varint(it, s.end(), v.emplace_back());
            CHECK_AND_ASSERT_THROW_MES(read > 0, "Error decompressing data");
        }
        return v;
    }
}  // namespace

KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::distribution)
KV_SERIALIZE(amount)
KV_SERIALIZE_N(data.start_height, "start_height")
KV_SERIALIZE(binary)
KV_SERIALIZE(compress)
if (binary) {
    if (is_store) {
        if (compress) {
            const_cast<std::string&>(compressed_data) = compress_integer_array(data.distribution);
            KV_SERIALIZE(compressed_data)
        } else
            KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
    } else {
        if (compress) {
            KV_SERIALIZE(compressed_data)
            const_cast<std::vector<uint64_t>&>(data.distribution) =
                    decompress_integer_array<uint64_t>(compressed_data);
        } else
            KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(data.distribution, "distribution")
    }
} else
    KV_SERIALIZE_N(data.distribution, "distribution")
KV_SERIALIZE_N(data.base, "base")
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(GET_OUTPUT_DISTRIBUTION::response)
KV_SERIALIZE(status)
KV_SERIALIZE(distributions)
KV_SERIALIZE_MAP_CODE_END()
}  // namespace cryptonote::rpc

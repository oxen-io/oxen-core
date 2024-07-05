#include "cryptonote_basic.h"

#include "cryptonote_format_utils.h"

#include <oxenc/endian.h>
#include <common/exception.h>

namespace cryptonote {

void transaction_prefix::set_null() {
    version = txversion::v1;
    unlock_time = 0;
    vin.clear();
    vout.clear();
    extra.clear();
    output_unlock_times.clear();
    type = txtype::standard;
}

std::vector<crypto::public_key> transaction_prefix::get_public_keys() const {
    std::vector<cryptonote::tx_extra_field> fields;

    if (!parse_tx_extra(extra, fields)) {
        throw oxen::traced<std::invalid_argument>("Failed to parse tx_extra of a transaction.");
    }

    std::vector<crypto::public_key> keys;
    tx_extra_pub_key pk_field;
    size_t i = 0;
    while (find_tx_extra_field_by_type(fields, pk_field, i++)) {
        keys.push_back(pk_field.pub_key);
    }

    return keys;
}

transaction::transaction(const transaction& t) :
        transaction_prefix(t),
        hash_valid(false),
        blob_size_valid(false),
        signatures(t.signatures),
        rct_signatures(t.rct_signatures),
        pruned(t.pruned),
        unprunable_size(t.unprunable_size.load()),
        prefix_size(t.prefix_size.load()) {
    if (t.is_hash_valid()) {
        hash = t.hash;
        set_hash_valid(true);
    }
    if (t.is_blob_size_valid()) {
        blob_size = t.blob_size;
        set_blob_size_valid(true);
    }
}

transaction& transaction::operator=(const transaction& t) {
    transaction_prefix::operator=(t);
    set_hash_valid(false);
    set_blob_size_valid(false);
    signatures = t.signatures;
    rct_signatures = t.rct_signatures;
    if (t.is_hash_valid()) {
        hash = t.hash;
        set_hash_valid(true);
    }
    if (t.is_blob_size_valid()) {
        blob_size = t.blob_size;
        set_blob_size_valid(true);
    }
    pruned = t.pruned;
    unprunable_size = t.unprunable_size.load();
    prefix_size = t.prefix_size.load();
    return *this;
}

void transaction::set_null() {
    transaction_prefix::set_null();
    signatures.clear();
    rct_signatures = {};
    rct_signatures.type = rct::RCTType::Null;
    set_hash_valid(false);
    set_blob_size_valid(false);
    pruned = false;
    unprunable_size = 0;
    prefix_size = 0;
}

void transaction::invalidate_hashes() {
    set_hash_valid(false);
    set_blob_size_valid(false);
}

size_t transaction::get_signature_size(const txin_v& tx_in) {
    if (std::holds_alternative<txin_to_key>(tx_in))
        return var::get<txin_to_key>(tx_in).key_offsets.size();
    return 0;
}

block::block(const block& b) :
        block_header(b),
        miner_tx{b.miner_tx},
        tx_hashes{b.tx_hashes},
        signatures{b.signatures},
        height{b.height},
        service_node_winner_key{b.service_node_winner_key},
        reward{b.reward},
        l2_height{b.l2_height},
        l2_state{b.l2_state} {
    copy_hash(b);
}

block::block(block&& b) :
        block_header(std::move(b)),
        miner_tx{std::move(b.miner_tx)},
        tx_hashes{std::move(b.tx_hashes)},
        signatures{std::move(b.signatures)},
        height{std::move(b.height)},
        service_node_winner_key{std::move(b.service_node_winner_key)},
        reward{std::move(b.reward)},
        l2_height{std::move(b.l2_height)},
        l2_state{std::move(b.l2_state)} {
    copy_hash(b);
}

block& block::operator=(const block& b) {
    block_header::operator=(b);
    miner_tx = b.miner_tx;
    tx_hashes = b.tx_hashes;
    signatures = b.signatures;
    height = b.height;
    service_node_winner_key = b.service_node_winner_key;
    reward = b.reward;
    l2_height = b.l2_height;
    l2_state = b.l2_state;
    copy_hash(b);
    return *this;
}
block& block::operator=(block&& b) {
    block_header::operator=(std::move(b));
    miner_tx = std::move(b.miner_tx);
    tx_hashes = std::move(b.tx_hashes);
    signatures = std::move(b.signatures);
    height = std::move(b.height);
    service_node_winner_key = std::move(b.service_node_winner_key);
    reward = std::move(b.reward);
    l2_height = std::move(b.l2_height);
    l2_state = std::move(b.l2_state);
    copy_hash(b);
    return *this;
}

bool block::is_hash_valid() const {
    return hash_valid.load(std::memory_order_acquire);
}
void block::set_hash_valid(bool v) const {
    hash_valid.store(v, std::memory_order_release);
}

// Convert the address to an integer and then performs (address % interval)
// it does this by taking the first 64 bits of the public_view_key and converting to an integer
// This is used to determine when an address gets paid their batching reward.
uint64_t account_public_address::modulus(uint64_t interval) const {
    uint64_t address_as_integer = 0;
    std::memcpy(&address_as_integer, m_view_public_key.data(), sizeof(address_as_integer));
    oxenc::host_to_little_inplace(address_as_integer);
    return address_as_integer % interval;
}

uint64_t account_public_address::next_payout_height(
        uint64_t current_height, uint64_t interval) const {
    auto pay_offset = modulus(interval);
    auto curr_offset = current_height % interval;
    if (pay_offset < curr_offset)
        pay_offset += interval;
    return current_height + pay_offset - curr_offset;
}

}  // namespace cryptonote

#include "tx_extra.h"

#include "common/guts.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

namespace cryptonote {

tx_extra_oxen_name_system tx_extra_oxen_name_system::make_buy(
        ons::generic_owner const& owner,
        ons::generic_owner const* backup_owner,
        ons::mapping_type type,
        const crypto::hash& name_hash,
        const std::string& encrypted_value,
        const crypto::hash& prev_txid) {
    tx_extra_oxen_name_system result{};
    result.fields = ons::extra_field::buy;
    result.owner = owner;

    if (backup_owner)
        result.backup_owner = *backup_owner;
    else
        result.fields = ons::extra_field::buy_no_backup;

    result.type = type;
    result.name_hash = name_hash;
    result.encrypted_value = encrypted_value;
    result.prev_txid = prev_txid;
    return result;
}

tx_extra_oxen_name_system tx_extra_oxen_name_system::make_renew(
        ons::mapping_type type, crypto::hash const& name_hash, crypto::hash const& prev_txid) {
    assert(is_lokinet_type(type) && prev_txid);

    tx_extra_oxen_name_system result{};
    result.fields = ons::extra_field::none;
    result.type = type;
    result.name_hash = name_hash;
    result.prev_txid = prev_txid;
    return result;
}

tx_extra_oxen_name_system tx_extra_oxen_name_system::make_update(
        const ons::generic_signature& signature,
        ons::mapping_type type,
        const crypto::hash& name_hash,
        std::string_view encrypted_value,
        const ons::generic_owner* owner,
        const ons::generic_owner* backup_owner,
        const crypto::hash& prev_txid) {
    tx_extra_oxen_name_system result{};
    result.signature = signature;
    result.type = type;
    result.name_hash = name_hash;
    result.fields |= ons::extra_field::signature;

    if (encrypted_value.size()) {
        result.fields |= ons::extra_field::encrypted_value;
        result.encrypted_value = std::string{encrypted_value};
    }

    if (owner) {
        result.fields |= ons::extra_field::owner;
        result.owner = *owner;
    }

    if (backup_owner) {
        result.fields |= ons::extra_field::backup_owner;
        result.backup_owner = *backup_owner;
    }

    result.prev_txid = prev_txid;
    return result;
}

std::vector<std::string> readable_reasons(uint16_t decomm_reason) {
    std::vector<std::string> results;
    if (decomm_reason & missed_uptime_proof)
        results.push_back("Missed Uptime Proofs");
    if (decomm_reason & missed_checkpoints)
        results.push_back("Missed Checkpoints");
    if (decomm_reason & missed_pulse_participations)
        results.push_back("Missed Pulse Participation");
    if (decomm_reason & storage_server_unreachable)
        results.push_back("Storage Server Unreachable");
    if (decomm_reason & timestamp_response_unreachable)
        results.push_back("Unreachable for Timestamp Check");
    if (decomm_reason & timesync_status_out_of_sync)
        results.push_back("Time out of sync");
    if (decomm_reason & lokinet_unreachable)
        results.push_back("Lokinet Unreachable");
    if (decomm_reason & l2_height_out_of_sync)
        results.push_back("L2 Out of Sync");
    return results;
}

std::vector<std::string> coded_reasons(uint16_t decomm_reason) {
    std::vector<std::string> results;
    if (decomm_reason & missed_uptime_proof)
        results.push_back("uptime");
    if (decomm_reason & missed_checkpoints)
        results.push_back("checkpoints");
    if (decomm_reason & missed_pulse_participations)
        results.push_back("pulse");
    if (decomm_reason & storage_server_unreachable)
        results.push_back("storage");
    if (decomm_reason & timestamp_response_unreachable)
        results.push_back("timecheck");
    if (decomm_reason & timesync_status_out_of_sync)
        results.push_back("timesync");
    if (decomm_reason & lokinet_unreachable)
        results.push_back("lokinet");
    if (decomm_reason & l2_height_out_of_sync)
        results.push_back("l2");
    return results;
}

}  // namespace cryptonote

namespace ons {

std::string generic_owner::to_string(cryptonote::network_type nettype) const {
    if (type == generic_owner_sig_type::monero)
        return cryptonote::get_account_address_as_str(
                nettype, wallet.is_subaddress, wallet.address);
    else
        return tools::hex_guts(ed25519);
}

bool generic_owner::operator==(const generic_owner& other) const {
    if (type != other.type)
        return false;

    if (type == generic_owner_sig_type::monero)
        return wallet.is_subaddress == other.wallet.is_subaddress &&
               wallet.address == other.wallet.address;
    else
        return ed25519 == other.ed25519;
}

}  // namespace ons

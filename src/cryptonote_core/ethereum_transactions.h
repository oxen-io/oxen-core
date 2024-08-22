#pragma once

#include <concepts>
#include <string>

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "l2_tracker/events.h"

namespace cryptonote {
class Blockchain;
}

namespace eth {

template <std::derived_from<event::L2StateChange> Event>
bool extract_event(const cryptonote::transaction& tx, Event& evt, std::string* fail_reason) {
    if (cryptonote::get_field_from_tx_extra(tx.extra, evt))
        return true;
    if (fail_reason)
        *fail_reason =
                "{} didn't have ethereum {} data in the tx_extra"_format(tx, Event::description);
    return false;
}

template <std::derived_from<event::L2StateChange> Event>
bool validate_event_tx(
        cryptonote::hf hf_version, const cryptonote::transaction& tx, std::string* reason) {
    if (hf_version < cryptonote::feature::ETH_BLS) {
        if (reason)
            *reason = "{} is attempting to provide an L2 transactions before HF{}"_format(
                    tx, static_cast<int>(hf_version));
        return false;
    }
    if (tx.type != Event::txtype) {
        if (reason)
            *reason = "{} uses wrong tx type, expected={}"_format(tx, Event::txtype);
        return false;
    }
    Event evt;
    if (!extract_event(tx, evt, reason))
        return false;
    if (evt.l2_height == 0) {
        if (reason)
            *reason = "{} tx's L2 event is missing l2_height"_format(tx);
        return false;
    }
    return true;
}

/// Extract the state change event details from a transaction.  If no state change is present in the
/// transaction then `fail_reason` is set and std::monostate is returned.
event::StateChangeVariant extract_event(
        const cryptonote::transaction& tx, std::string* fail_reason = nullptr);

/// Extracts an event from the blockchain given a txid.
event::StateChangeVariant extract_event(
        cryptonote::Blockchain& chain,
        const crypto::hash& txid,
        std::string* fail_reason = nullptr);

/// Extracts the L2Height from an eth event.  Returns nullopt if not an eth event (or even
/// extraction fails).
std::optional<uint64_t> extract_event_l2_height(
        const cryptonote::transaction& tx, std::string* fail_reason = nullptr);

}  // namespace eth

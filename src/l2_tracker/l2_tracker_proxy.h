#pragma once

#include <oxenmq/oxenmq.h>

#include "crypto/crypto.h"
#include "l2_tracker.h"
#include "l2_tracker/events.h"
#include "serialization/crypto.h"
#include "serialization/map.h"
#include "serialization/serialization.h"
#include "serialization/set.h"
#include "serialization/string.h"
#include "serialization/vector.h"

namespace eth {

template <class Archive>
void serialize_object(Archive& ar, L2State& l2) {
    field(ar, "#", l2.version);
    if (Archive::is_deserializer && l2.version != 1)
        throw std::runtime_error{
                "Don't know how to deserialize v{} L2 state data"_format(l2.version)};

    field(ar, "chain_id", l2.chain_id);
    field(ar, "rewards_contract", l2.rewards_contract);

    field(ar, "latest_height", l2.latest_height);
    field(ar, "synced_height", l2.synced_height);
    // We do *not* include contract pubkeys in serialization, because it's enormous and this
    // serialization is sent frequently when proxying:
    // field(ar, "contract_bls_pubkeys", l2.in_contract);
    field(ar, "reward_rate", l2.reward_rate);
    {
        if constexpr (Archive::is_serializer)
            ar.tag("recent_events");
        auto recent = ar.begin_object();
        field(ar, "registrations", l2.recent_regs);
        field(ar, "unlocks", l2.recent_unlocks);
        field(ar, "exits", l2.recent_exits);
        field(ar, "req_changes", l2.recent_req_changes);
    }
}

template <class Archive>
void serialize_object(Archive& ar, L2PurgeState& l2p) {
    field(ar, "#", l2p.version);
    if (Archive::is_deserializer && l2p.version != 1)
        throw std::runtime_error{
                "Don't know how to deserialize v{} L2 purge state data"_format(l2p.version)};

    field(ar, "chain_id", l2p.chain_id);
    field(ar, "rewards_contract", l2p.rewards_contract);

    field(ar, "latest_height", l2p.latest_height);
    field(ar, "contract_bls_pubkeys", l2p.in_contract);
}

template <std::derived_from<event::L2StateChange> Event>
template <class Archive>
void RecentEvents<Event>::serialize_value(Archive& ar) {
    value(ar, events);
}

// The server side of proxied L2 state requests.
//
// Constructing this object (via L2Tracker::enable_proxy) sets up new OxenMQ endpoints that are
// reachable on any oxenmq interface: typically quorumnet for a service node, local unix socket for
// another machine on the same system, or a custom OMQ listener set up with --lmq-curve.  The
// available endpoints are:
//
//     l2_proxy.state -- takes one argument, the highest serialization version the requester
//                       supports (currently "1").  Returns two part message ["OK", DATA] where DATA
//                       is the serialized binary archive of the L2Tracker's current L2State.  If a
//                       failure occurs this will return ["ERROR", "reason"].  (All endpoints can
//                       also return ["FORBIDDEN"]; see below).  The serialization version allows
//                       for future changes, e.g. an upgraded server with new state fields should
//                       support both v1 and v2 serialized data so that it can communicate with pre-
//                       and post-upgraded proxying nodes.  Or an upgraded client could request v2,
//                       but the unupgraded server would respond with v1 data.
//     l2_proxy.state_json -- same, but returns json for the DATA part.  (Mainly for debugging).
//     l2_proxy.purge_state -- Just like l2_proxy.state, but returns L2PurgeState containing a
//                             vaguely recent contract pubkey list.  Return ["ERROR", "reason..."]
//                             on error, and returns ["FORBIDDEN"] if the requestor is not in the L2
//                             proxy whitelist.
//     l2_proxy.purge_state_json -- same, but return json DATA.  (Mainly for debugging).
//     l2_proxy.subscribe -- subscribes to L2State and L2PurgeState updates for the next minute.
//                           Clients are expected to use a long (>1min) connection timeout and
//                           re-subscribe to this more frequently (e.g. every 30s) to keep the
//                           subscription alive, especially across proxy restarts.  If this is a new
//                           subscription for the server (e.g. because the server restarted, or the
//                           client took too long to resubscribe) then this replies with a
//                           three-part message: ["SUBSCRIBED", "STATE_HEIGHT", "PURGE_HEIGHT"] that
//                           the client can use to decide if it wants to initiate a state or purge
//                           update.  If the request is renewing an already-active subscription then
//                           the reply is 1-part message ["RENEWED"].
//
//                           While subscribed, the server will send these messages (basic commands,
//                           not requests!) whenever the tracked state is updated:
//         l2_notify.state -- called when the state changes.  Data consists of one part: the new L2
//                            height (so that the remote can decide whether or not it wants to
//                            retrieve it via l2_proxy.state).
//         l2_notify.purge_state -- called when the purge state changes (typically around once an
//                                  hour).  Called with one data part, the new L2 purge state
//                                  height.
//
// Access to the endpoint is gated by a pubkey whitelist which contains the service node (Ed25519)
// pubkeys are are allowed to connect (note that local unix socket connections are treated as admin
// connections and always allowed regardless of the whitelist).  All of the above endpoints will
// return a single part reply ["FORBIDDEN"] if they are not on the whitelist.
//
class L2Proxy {
    // The whitelist file is periodically checked for modifications and, if modified, is reloaded.
    // The file itself contains Ed25519 pubkeys, one per line, with hex, b32, or b64 encoding.  We
    // take those pubkeys and convert them to X pubkeys (inside the `whitelist` set) for quick
    // authentication and looking when processing the OMQ request where pubkeys are always X25519.
    std::filesystem::path whitelist_file;
    std::unordered_set<crypto::ed25519_public_key> whitelist_ed;
    // The key here is the main point: the value is just here so that we can report Ed keys in
    // debugging:
    std::unordered_map<std::string, crypto::ed25519_public_key> whitelist_x;
    std::filesystem::file_time_type whitelist_mtime;
    std::unordered_map<oxenmq::ConnectionID, std::chrono::steady_clock::time_point> subscribers;
    std::shared_mutex mutex;

    static constexpr std::chrono::milliseconds SUBSCRIBE_TIMEOUT = 2min + 5s;

    uint64_t last_notify_height = 0, last_notify_purge_height = 0;

    // Called by the proxy's endpoints when a proxying node attempts to subscribe or obtain L2
    // state.  If the connection is allowed, return true; otherwise replies with ["FORBIDDEN"] and
    // returns false.
    bool authorize(std::string_view endpoint, oxenmq::Message& msg);

    // l2_proxy.state, .purge_state, and json variation handler
    void state(oxenmq::Message& msg, bool purge, bool json);

    // l2_proxy.subscribe handler
    void subscribe(oxenmq::Message& msg);

    // Called periodically to reload from disk (if needed) and to prune expired connections from the
    // subscription list.
    void refresh(bool initial = false);

    L2Tracker& l2_tracker;
    oxenmq::OxenMQ& omq;

  public:
    L2Proxy(oxenmq::OxenMQ& omq, L2Tracker& l2_tracker, std::filesystem::path whitelist);

    // Called by L2Tracker when an L2 update completes to trigger notifying subscribers of the
    // change.
    void notify(uint64_t state_height, uint64_t purge_state_height);
};

}  // namespace eth

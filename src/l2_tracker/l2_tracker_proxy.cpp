#include "l2_tracker_proxy.h"

#include <fmt/std.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <filesystem>
#include <oxen/log.hpp>

#include "common/lock.h"
#include "common/string_util.h"
#include "crypto/crypto.h"
#include "cryptonote_core/cryptonote_core.h"
#include "l2_tracker.h"
#include "logging/oxen_logger.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"

namespace eth {

namespace log = oxen::log;
auto logcat = log::Cat("l2_proxy");

L2Proxy::L2Proxy(oxenmq::OxenMQ& omq, L2Tracker& l2_tracker, std::filesystem::path whitelist) :
        whitelist_file{std::move(whitelist)}, l2_tracker{l2_tracker}, omq{omq} {

    refresh(true);  // true = throw if initial loading fails

    omq.add_category("l2_proxy", oxenmq::AuthLevel::none, /*reserved_threads=*/1)
            .add_request_command("state", [this](auto& msg) { state(msg, false, false); })
            .add_request_command("state_json", [this](auto& msg) { state(msg, false, true); })
            .add_request_command("purge_state", [this](auto& msg) { state(msg, true, false); })
            .add_request_command("purge_state_json", [this](auto& msg) { state(msg, true, true); })
            .add_request_command("subscribe", [this](auto& msg) { subscribe(msg); });

    omq.add_timer([this] { refresh(); }, 5s);
}

void L2Proxy::refresh(bool initial) {
    try {
        auto mtime = std::filesystem::last_write_time(whitelist_file);
        bool reload = initial || mtime != whitelist_mtime;

        if (reload) {
            log::debug(logcat, "Reloading L2 proxy whitelist from {}", whitelist_file);

            std::ifstream in;
            in.exceptions(std::ios::badbit);
            in.open(whitelist_file);

            std::unordered_set<crypto::ed25519_public_key> new_ed;

            std::string line_in;
            int lineno = 0;
            while (std::getline(in, line_in)) {
                ++lineno;
                std::string_view line{line_in};

                // Strip out comments, both whole line ("# comment") and suffix ("pubkey # comment")
                if (auto pos = line.find('#'); pos != std::string_view::npos)
                    line = line.substr(0, pos);

                // Strip out leading/trailing whitespace:
                while (line.starts_with(' ') || line.starts_with('\t') || line.starts_with('\r'))
                    line.remove_prefix(1);
                while (line.ends_with(' ') || line.ends_with('\t') || line.ends_with('\r'))
                    line.remove_suffix(1);

                if (line.empty())  // Empty, whitespace-only, or comment-only
                    continue;

                std::string ed_pk;
                bool bad = false;
                if (line.size() == 64 && oxenc::is_hex(line)) {
                    ed_pk = oxenc::from_hex(line);
                } else if ((line.size() == 43 || line.size() == 44) && oxenc::is_base64(line)) {
                    ed_pk = oxenc::from_base64(line);
                } else if (line.size() == 52 && oxenc::is_base32z(line)) {
                    ed_pk = oxenc::from_base32z(line);
                } else {
                    bad = true;
                }
                if (bad || ed_pk.size() != 32) {
                    log::error(
                            logcat,
                            "Invalid pubkey '{}' in L2 proxy allow file {}, line {}",
                            line,
                            whitelist_file,
                            lineno);
                    continue;
                }

                crypto::ed25519_public_key edpk;
                std::memcpy(edpk.data(), ed_pk.data(), 32);

                auto [it, ins] = new_ed.insert(edpk);
                if (!ins)
                    log::warning(
                            logcat,
                            "Duplicate pubkey {} in L2 proxy allow file {}, line {}",
                            oxenc::to_hex(ed_pk),
                            whitelist_file,
                            lineno);
                else
                    log::debug(
                            logcat,
                            "Parsed pubkey {} from L2 proxy allow file {}, line {}",
                            oxenc::to_hex(ed_pk),
                            whitelist_file,
                            lineno);
            }

            std::unordered_map<std::string, crypto::ed25519_public_key> new_x;
            for (auto it = new_ed.begin(); it != new_ed.end();) {
                std::string xpk;
                xpk.resize(32);
                if (0 == crypto_sign_ed25519_pk_to_curve25519(
                                 reinterpret_cast<unsigned char*>(xpk.data()),
                                 reinterpret_cast<const unsigned char*>(it->data()))) {
                    log::debug(
                            logcat,
                            "Ed25519 pubkey {} maps to X25519 pubkey {}",
                            oxenc::to_hex(it->begin(), it->end()),
                            oxenc::to_hex(xpk));
                    new_x.emplace(std::move(xpk), *it);
                    ++it;
                } else {
                    log::error(
                            logcat,
                            "{} is not a valid Ed25519 pubkey in L2 proxy allow file {}, line {}",
                            oxenc::to_hex(it->begin(), it->end()),
                            whitelist_file,
                            lineno);
                    it = new_ed.erase(it);
                }
            }

            std::shared_lock read_lock{mutex};

            bool changed = true;
            if (initial)
                log::info(
                        logcat,
                        fg(fmt::terminal_color::green) | fmt::emphasis::bold,
                        "L2 proxy whitelist intialized with {} pubkeys",
                        new_ed.size());
            else {
                std::vector<crypto::ed25519_public_key> added, removed;
                std::copy_if(
                        new_ed.begin(),
                        new_ed.end(),
                        std::back_inserter(added),
                        [this](const auto& edpk) { return !whitelist_ed.count(edpk); });
                std::copy_if(
                        whitelist_ed.begin(),
                        whitelist_ed.end(),
                        std::back_inserter(removed),
                        [&new_ed](const auto& edpk) { return !new_ed.count(edpk); });
                std::sort(added.begin(), added.end());
                std::sort(removed.begin(), removed.end());

                if (added.empty() && removed.empty()) {
                    changed = false;
                    log::debug(logcat, "Whitelist reloaded, but pubkeys are unchanged");
                } else {
                    log::info(
                            logcat,
                            "L2 proxy whitelist updated with {} additions, {} removals:",
                            added.size(),
                            removed.size());
                    for (auto& a : added)
                        log::info(
                                logcat,
                                fg(fmt::terminal_color::green) | fmt::emphasis::bold,
                                "{} added to L2 proxy whitelist",
                                a);
                    for (auto& r : removed)
                        log::info(
                                logcat,
                                fg(fmt::terminal_color::yellow) | fmt::emphasis::bold,
                                "{} removed from L2 proxy whitelist",
                                r);
                }
            }
            if (changed) {
                auto write_lock = tools::upgrade_lock(read_lock);

                whitelist_ed = std::move(new_ed);
                whitelist_x = std::move(new_x);
                whitelist_mtime = mtime;
            }
        }
    } catch (std::exception& e) {
        log::log(
                logcat,
                initial ? log::Level::critical : log::Level::err,
                fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                "Failed to load L2 proxy whitelist file {}: {}",
                whitelist_file,
                e.what());
        if (initial)
            throw;
    }

    {
        // Remove any connections that haven't resubscribed in the last couple minutes
        std::unique_lock lock{mutex};

        auto now = std::chrono::steady_clock::now();
        int count = 0;
        for (auto it = subscribers.begin(); it != subscribers.end();) {
            if (it->second <= now) {
                it = subscribers.erase(it);
                count++;
            } else
                ++it;
        }
        if (count)
            log::debug(logcat, "Removed {} stale subscriptions", count);
    }
}

bool L2Proxy::authorize(std::string_view endpoint, oxenmq::Message& msg) {
    if (msg.access.auth == oxenmq::AuthLevel::admin) {
        log::debug(
                logcat,
                "Allowing incoming admin-authenticated request from {} request to {}",
                msg.remote,
                endpoint);
        return true;
    }

    {
        std::shared_lock lock{mutex};
        const auto& pk = msg.conn.pubkey();
        if (auto it = whitelist_x.find(pk); it != whitelist_x.end()) {
            log::debug(
                    logcat,
                    "Allowing incoming whitelisted pubkey request from {} @ {} to {}",
                    it->second,
                    msg.remote,
                    endpoint);
            return true;
        }
    }

    log::warning(
            logcat,
            "Denied incoming request to {} from {}: requestor (with X25519 pubkey {}) is not in "
            "the L2 proxy whitelist",
            endpoint,
            msg.remote,
            oxenc::to_hex(msg.conn.pubkey()));
    msg.send_reply("FORBIDDEN");
    return false;
}

template <typename T>
static std::string serialize(T&& stuff, uint8_t max_version, bool json) {
    stuff.version = std::clamp(max_version, stuff.MIN_VERSION, stuff.MAX_VERSION);
    if (json) {
        serialization::json_archiver ar;
        serialization::serialize(ar, stuff);
        return ar.dump();
    }
    std::ostringstream s;
    serialization::binary_archiver ar{s};
    serialization::serialize(ar, stuff);
    return std::move(s).str();
}

void L2Proxy::state(oxenmq::Message& msg, bool purge, bool json) {
    if (!authorize("l2_proxy.{}state{}"_format(purge ? "purge_" : "", json ? "_json" : ""), msg))
        return;

    if (msg.data.empty()) {
        msg.send_reply("ERROR", "serialization version missing from request");
        return;
    }
    uint8_t version;
    if (!tools::parse_int(msg.data[0], version)) {
        msg.send_reply("ERROR", "requested serialization version is invalid");
        return;
    }

    std::string data;
    try {
        data = purge ? serialize(l2_tracker.get_purge_state(), version, json)
                     : serialize(l2_tracker.get_state(), version, json);
    } catch (const std::exception& e) {
        log::error(
                logcat,
                "Failed to serialize L2 {}state for incoming request from {}: {}",
                purge ? "purge " : "",
                msg.remote,
                e.what());
        msg.send_reply("ERROR", "serialization failed");
        return;
    }
    msg.send_reply("OK", std::move(data));
}

void L2Proxy::subscribe(oxenmq::Message& msg) {
    if (!authorize("l2_proxy.subscribe", msg))
        return;

    bool renewal = false;
    {
        std::unique_lock lock{mutex};
        auto expiry = std::chrono::steady_clock::now() + SUBSCRIBE_TIMEOUT;
        auto [it, ins] = subscribers.emplace(msg.conn, expiry);
        if (!ins) {
            it->second = expiry;
            renewal = true;
        }
    }

    log::debug(logcat, "{} L2 proxy subscription from {}", renewal ? "Renewed" : "New", msg.remote);

    if (renewal)
        msg.send_reply("RENEWED");
    else
        msg.send_reply(
                "SUBSCRIBED",
                "{}"_format(last_notify_height),
                "{}"_format(last_notify_purge_height));
}

void L2Proxy::notify(uint64_t state_height, uint64_t purge_state_height) {
    std::shared_lock lock{mutex};
    if (state_height > last_notify_height) {
        last_notify_height = state_height;
        if (!subscribers.empty()) {
            log::debug(
                    logcat,
                    "Sending l2_notify.state notifications to {} L2 proxy subscribers",
                    subscribers.size());
            for (const auto& [conn, expiry] : subscribers)
                omq.send(conn, "l2_notify.state", "{}"_format(state_height));
        }
    }
    if (purge_state_height > last_notify_purge_height) {
        last_notify_purge_height = purge_state_height;
        if (!subscribers.empty()) {
            log::debug(
                    logcat,
                    "Sending l2_notify.purge_state notifications to {} L2 proxy subscribers",
                    subscribers.size());
            for (const auto& [conn, expiry] : subscribers)
                omq.send(conn, "l2_notify.purge_state", "{}"_format(last_notify_purge_height));
        }
    }
}

void L2Tracker::proxy_request_generic(
        oxenmq::ConnectionID to,
        std::string_view endpoint,
        std::optional<std::string_view> body,
        std::string_view descr,
        std::string_view id,
        std::function<
                void(bool& success,
                     bool& log_error,
                     std::vector<std::string>& data,
                     const oxenmq::ConnectionID& conn,
                     std::string_view id)> handler) {
    // Generic request handler that deals with errors and, if necessary, disconnecting.  This call
    // `handler` only if the request was successful (at the OMQ level), is not empty, and does not
    // start with the "FORBIDDEN" msg part that all the l2_proxy endpoints returns.  The handler can
    // mark a further failure (e.g. for invalid "successful" response data) by setting success to
    // false and putting some message to be logged in data[0].  If it sets `log_error` to true then
    // we log it in bold red as a global error, otherwise an error just becomes a warning.

    core.omq().request(
            to,
            endpoint,
            [this, to, descr, id, handler = std::move(handler)](
                    bool success, std::vector<std::string> data) {
                bool log_error = false;

                if (success) {
                    if (data.empty()) {
                        success = false;
                        data.push_back("Received empty response");
                    } else if (data[0] == "FORBIDDEN"sv) {
                        success = false;
                        log_error = true;
                        data[0] = "Remote is not allowing L2 proxy requests from this node!";
                    }
                }

                if (success)
                    handler(success, log_error, data, to, id);

                if (!success) {
                    if (data.empty())
                        data.push_back("Unknown error");
                    else if (data[0] == "TIMEOUT"sv) {
                        data[0] = "request timed out; will attempt to reconnect";
                        // This is the only error that we can usefully disconnect for; everything
                        // else would just try reconnecting and then get the same error.
                        proxy_disconnect(to);
                    } else if (data[0] == "UNKNOWNCOMMAND"sv) {
                        log_error = true;
                        data[0] = "Remote oxend is not configured in l2-proxy mode!";
                    }

                    if (log_error)
                        log::error(
                                globallogcat,
                                fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                                "{} request to {} failed: {}",
                                descr,
                                id,
                                data[0]);
                    else
                        log::warning(logcat, "{} request to {} failed: {}", descr, id, data[0]);
                }
            },
            std::move(body),
            oxenmq::send_option::request_timeout{20s});
}

void L2Tracker::proxy_connect_and_subscribe() {
    using namespace oxenmq;
    std::unique_lock lock{mutex};

    auto& omq = core.omq();

    for (auto& oxend : l2_oxend_proxies) {
        if (!oxend.connid) {
            log::debug(logcat, "Establishing connection to oxend L2 proxy {}", oxend.id);
            oxend.pending_connect = true;
            oxend.connid = omq.connect_remote(
                    oxend.address,
                    [this, &oxend](ConnectionID cid) {
                        log::info(logcat, "Connected to remote oxend L2 proxy {}", oxend.id);
                        oxend.pending_connect = false;
                        proxy_send_subscribe(oxend);
                    },
                    [this, &oxend](ConnectionID cid, std::string_view reason) {
                        log::error(
                                logcat,
                                "Failed to connect to remote oxend L2 proxy {}: {}",
                                oxend.id,
                                reason);
                        // Clear it so that we retry at the next subscribe interval
                        proxy_disconnect(cid, true);
                    },
                    connect_option::ephemeral_routing_id{},
                    connect_option::timeout{20s});

            // We could queue the subscribe request immediately (by doing the below
            // proxy_send_subscribe even in this new connection case) but then we can't easily
            // distinguish between a request timeout, and a request failure due to connection
            // failure because both fire a TIMEOUT response, and then we get a warning for trying to
            // close a connection that doesn't exist anymore if it was the connection that timed
            // out.
        } else if (!oxend.pending_connect) {
            proxy_send_subscribe(oxend);
        }
    }
}

void L2Tracker::proxy_send_subscribe(const l2_oxend_proxy& oxend) {
    proxy_request_generic(
            oxend.connid,
            "l2_proxy.subscribe",
            std::nullopt,
            "L2 subscription"sv,
            oxend.id,
            [this](bool& success,
                   bool& log_error,
                   std::vector<std::string>& data,
                   const oxenmq::ConnectionID& conn,
                   std::string_view id) {
                if (data.empty()) {
                    success = false;
                    data.push_back("Received empty response");
                } else if (data[0] == "RENEWED"sv) {
                    log::debug(logcat, "Renewed L2 proxy subscription with {}", id);
                } else if (data[0] == "SUBSCRIBED"sv) {
                    uint64_t state_height, purge_state_height;
                    if (data.size() == 3 && tools::parse_int(data[1], state_height) &&
                        tools::parse_int(data[2], purge_state_height)) {
                        log::info(logcat, "Subscribed to L2 updates from {}", id);
                        proxy_request_if_newer(conn, state_height, purge_state_height);
                    } else {
                        success = false;
                        data[0] = "Failed to parse SUBSCRIBED state heights";
                    }
                } else {
                    success = false;
                    data[0] = "Unknown reply type '{}'"_format(data[0]);
                }
            });
}

void L2Tracker::proxy_disconnect(oxenmq::ConnectionID conn, bool clear_only) {
    if (!clear_only)
        core.omq().disconnect(conn, 0s);

    std::unique_lock lock{mutex};
    for (auto& oxend : l2_oxend_proxies) {
        if (conn == oxend.connid) {
            oxend.connid = oxenmq::ConnectionID{};
            oxend.pending_connect = false;
            break;
        }
    }
}

std::optional<std::string_view> L2Tracker::find_proxy(const oxenmq::ConnectionID& conn) const {
    std::shared_lock lock{mutex};

    for (auto& oxend : l2_oxend_proxies) {
        if (conn == oxend.connid)
            return oxend.id;
        // When both local and remote are SNs, the remote may fire the notification by SN pubkey
        // rather than the specific connection id, which means it is possible for it to arrive via
        // some other connection we have with that same SN (e.g. a connection that it established to
        // us), and so we also want to allow an incoming request with a remote pubkey that matches
        // even if it didn't arrive on the same connection that we use to subscribe.
        if (oxend.address.curve() && !conn.pubkey().empty() &&
            oxend.address.pubkey == conn.pubkey())
            return oxend.id;
    }

    return std::nullopt;
}

void L2Tracker::l2_notify_state(oxenmq::Message& msg, bool purge) {
    auto proxy_conn = find_proxy(msg.conn);
    if (!proxy_conn) {
        log::warning(
                logcat,
                "l2_notify.{}state notification received from unrecognized remote node {}; "
                "ignoring",
                purge ? "purge_" : "",
                msg.remote);
        return;
    }

    uint64_t l2_height;
    if (msg.data.empty() || !tools::parse_int(msg.data[0], l2_height)) {
        log::warning(
                logcat,
                "Invalid incoming {}state notification from {}: did not include a valid l2 height",
                purge ? "purge " : "",
                *proxy_conn);
        return;
    }

    std::optional<uint64_t> state_h, purge_h;
    (purge ? purge_h : state_h) = l2_height;
    proxy_request_if_newer(msg.conn, state_h, purge_h);
}

void L2Tracker::proxy_request_state(oxenmq::ConnectionID conn, bool purge_state) {
    std::string_view id = find_proxy(conn).value_or("(unknown remote)"sv);

    proxy_request_generic(
            conn,
            purge_state ? "l2_proxy.purge_state" : "l2_proxy.state",
            "{}"_format(L2PurgeState::MAX_VERSION),
            purge_state ? "L2 state"sv : "L2 purge state"sv,
            id,
            [this, purge_state](
                    bool& success,
                    bool& log_error,
                    std::vector<std::string>& data,
                    const oxenmq::ConnectionID& conn,
                    std::string_view id) {
                if (data[0] == "ERROR"sv) {
                    success = false;
                    log_error = true;
                    data[0] = data.size() > 1 ? std::move(data[1]) : "unknown error"s;
                } else if (data[0] != "OK"sv) {
                    success = false;
                    data[0] = "Unknown response status '{}'"_format(data[0]);
                } else if (data.size() < 2) {
                    success = false;
                    data[0] = "State data missing from response!";
                } else {
                    try {
                        std::istringstream iss{data[1]};
                        serialization::binary_unarchiver ar{iss};
                        if (purge_state) {
                            L2PurgeState state;
                            serialize(ar, state);
                            proxy_update_state(std::move(state), id);
                        } else {
                            L2State state;
                            serialize(ar, state);
                            proxy_update_state(std::move(state), id);
                        }
                    } catch (const std::exception& e) {
                        success = false;
                        log_error = true;
                        data[0] = "Failed to deserialize L2 {}state data from {}: {}"_format(
                                purge_state ? "purge " : "", id, e.what());
                    }
                }
            });
}

template <typename T>
static bool check_state_update(const T& new_state, const T& state, std::string_view from) {
    constexpr std::string_view type = std::same_as<T, L2State> ? "state" : "purge state";
    if (new_state.chain_id != state.chain_id ||
        new_state.rewards_contract != state.rewards_contract) {
        log::error(
                globallogcat,
                "Wrong L2 chain/contract ({}/{}, expected {}/{}) in L2 {} from L2 proxy {}",
                new_state.chain_id,
                new_state.rewards_contract,
                state.chain_id,
                state.rewards_contract,
                type,
                from);
        return false;
    }
    if (new_state.latest_height <= state.latest_height) {
        log::debug(
                logcat,
                "Ignoring new L2 {} from {}: l2 height {} <= current {}",
                type,
                from,
                new_state.latest_height,
                state.latest_height);
        return false;
    }
    log::debug(
            logcat,
            "Updating L2 {} ({} -> {}) from {}",
            type,
            state.latest_height,
            new_state.latest_height,
            from);

    return true;
}

void L2Tracker::proxy_update_state(L2State&& new_state, std::string_view from) {
    // Our add to mempool below takes a mempool lock, and inside itself takes the blockchain lock,
    // which means if we don't hold all three we can deadlock with our hook_block_post_add in the
    // L2Tracker constructor, which is called with the blockchain lock already held, so lock
    // everything at once:
    auto locks = tools::unique_locks(mutex, core.mempool, core.blockchain);

    if (!check_state_update(new_state, state, from))
        return;

    uint64_t old_synced = state.synced_height;
    state = std::move(new_state);

    auto add_to_pool = [this](const auto& event) { add_to_mempool(event); };
    state.recent_regs.for_each(add_to_pool);
    state.recent_exits.for_each(add_to_pool);
    state.recent_unlocks.for_each(add_to_pool);
    state.recent_req_changes.for_each(add_to_pool);

    latest_height_ts = std::chrono::steady_clock::now();
}

void L2Tracker::proxy_update_state(L2PurgeState&& new_state, std::string_view from) {
    auto locks = tools::unique_locks(mutex, core.mempool, core.blockchain);
    if (!check_state_update(new_state, purge_state, from))
        return;

    purge_state = std::move(new_state);

    generate_purge_transactions();
}

void L2Tracker::proxy_request_if_newer(
        oxenmq::ConnectionID to,
        std::optional<uint64_t> state_height,
        std::optional<uint64_t> state_purge_height) {

    // If already have same-or-newer data, or already have a pending request (perhaps to another
    // oxend) for same-or-newer data, then we don't want to initiate a request here because its
    // response is just going to be data we would throw away.
    bool make_state_req = false, make_purge_req = false;
    {
        std::unique_lock lock{mutex};
        if (state_height && *state_height > state.latest_height &&
            *state_height > l2_state_requested) {
            l2_state_requested = *state_height;
            make_state_req = true;
        }
        if (state_purge_height && *state_purge_height > purge_state.latest_height &&
            *state_purge_height > l2_purge_state_requested) {
            l2_purge_state_requested = *state_purge_height;
            make_purge_req = true;
        }
    }

    if (make_state_req)
        proxy_request_state(to, false);
    if (make_purge_req)
        proxy_request_state(to, true);
}

}  // namespace eth

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <oxen/quic/address.hpp>
#include <oxen/quic/loop.hpp>
#include <set>
#include <span>
#include <string>
#include <unordered_map>

#include "cryptonote_basic/connection_context.h"
#include "levin/connection.h"
#include "levin/messages.h"
#include "p2p_protocol_defs.h"

struct ev_token_bucket_cfg;

namespace nodetool {

using cryptonote::cryptonote_connection_context;
using epee::connection_id_t;

struct p2p_connection_context : cryptonote_connection_context {
    using cryptonote_connection_context::cryptonote_connection_context;

    peerid_type peer_id = 0;
    bool m_in_timedsync = false;
    std::set<oxen::quic::Address> sent_addresses;
};

class node_server;

// Runs the p2p node's connections.  Each is a levin connection on a libquic event loop, and what
// the connections deliver (connections opening and closing, requests, notifies and invoke
// responses) goes to the node on the loop thread, as it arrives.
class transport {
  public:
    explicit transport(node_server& node);
    ~transport();

    transport(const transport&) = delete;
    transport& operator=(const transport&) = delete;

    // Binds to the IPv4 address and, if given, the IPv6 one, without accepting connections until
    // start().  An IPv4 failure is fatal only if `require_ipv4`; IPv6 failing too always is.
    // Throws on failure.
    void listen(
            const oxen::quic::Address& ipv4,
            const std::optional<oxen::quic::Address>& ipv6,
            bool require_ipv4);
    uint16_t port() const { return port_; }
    uint16_t port_ipv6() const { return port_ipv6_; }

    void start();
    // Closes every connection and stops listening, and wakes wait().  Closes still reach the
    // node.
    void stop();
    bool stopping() const { return stopping_; }
    void wait();
    // Drops every connection and stops listening, without telling the node.
    void detach();

    // The event loop the connections run on, and everything that deals with them.
    oxen::quic::Loop& loop() { return loop_; }

    // The callbacks run inside the connections lock.  Returning false from foreach_connection's
    // stops it.
    bool foreach_connection(const std::function<bool(p2p_connection_context&)>& f);
    bool for_connection(
            const connection_id_t& id, const std::function<bool(p2p_connection_context&)>& f);
    size_t get_connections_count();
    size_t get_out_connections_count();
    size_t get_in_connections_count();
    void del_out_connections(size_t count);
    void del_in_connections(size_t count);

    bool close(const connection_id_t& id);
    // Returns 1 if the notify is queued, or a (negative) levin error code.
    int notify(int command, std::span<const uint8_t> body, const connection_id_t& id);
    // `cb` gets the response's return code and body, or a levin error code (and no body), along
    // with the connection's context, on the loop.  Returns 1 if the invoke is sent, or a (negative)
    // levin error code if not, in which case `cb` is never called.
    int invoke_async(
            int command,
            std::span<const uint8_t> body,
            const connection_id_t& id,
            std::function<void(int, std::span<const uint8_t>, p2p_connection_context&)> cb,
            std::chrono::nanoseconds timeout = {});
    // invoke_async() of COMMAND: `cb` gets the decoded response (default-constructed if the return
    // code isn't positive), and ERROR_FORMAT as the code if the response doesn't parse.
    template <typename COMMAND>
    int invoke(
            const connection_id_t& id,
            const typename COMMAND::request& req,
            std::function<void(int, typename COMMAND::response&&, p2p_connection_context&)> cb,
            std::chrono::nanoseconds timeout = {}) {
        const auto body = levin::encode(req);
        return invoke_async(
                COMMAND::ID,
                oxen::quic::reinterpret_span<const uint8_t>(std::span{body}),
                id,
                [cb = std::move(cb)](
                        int code, std::span<const uint8_t> in, p2p_connection_context& context) {
                    std::optional<typename COMMAND::response> rsp;
                    if (code > 0 && !(rsp = levin::decode<typename COMMAND::response>(in)))
                        code = levin::ERROR_FORMAT;
                    cb(code, rsp ? std::move(*rsp) : typename COMMAND::response{}, context);
                },
                timeout);
    }
    // Calls `f` with the connection's context on the loop, after what is running or already queued
    // there, unless it has closed by then.
    bool call_on(const connection_id_t& id, std::function<void(p2p_connection_context&)> f);

    // Connects to `remote` (from `local`, if given) and calls `done` on the loop with the new
    // connection's context, or with nullptr if the connection failed.
    void connect(
            const oxen::quic::Address& remote,
            std::chrono::milliseconds timeout,
            std::function<void(p2p_connection_context*)> done,
            const std::optional<oxen::quic::Address>& local = std::nullopt);

    // The limits all connections share, in kB/s.
    void set_rate_limits(uint64_t up_kbps, uint64_t down_kbps);
    uint64_t rate_up_limit() const { return up_kbps_; }
    uint64_t rate_down_limit() const { return down_kbps_; }

    // The IP type-of-service byte for new connections; -1 to leave it alone.
    void set_tos(int tos) { tos_ = tos; }

    // Totals over all connections since we started: frames, and their bytes (headers included).
    struct traffic {
        uint64_t frames_in, bytes_in, frames_out, bytes_out;
    };
    traffic totals() const { return {frames_in_, bytes_in_, frames_out_, bytes_out_}; }

    // The default timeout of an invoke
    std::chrono::milliseconds invoke_timeout{2min};

  private:
    struct peer {
        std::shared_ptr<levin::connection> conn;
        p2p_connection_context context;
        // For the receive speed: bytes received, as of when the current one-second sample began
        uint64_t sample_bytes = 0;
        std::chrono::steady_clock::time_point sample_start;
    };

    std::shared_ptr<peer> find(const connection_id_t& id);
    std::shared_ptr<peer> add(std::shared_ptr<levin::connection> conn, bool incoming);
    void received(peer& p, uint64_t bytes_received, std::chrono::steady_clock::time_point at);
    void count_in(size_t body_size);
    void count_out(size_t body_size);
    void update_rate_limits();

    node_server& node_;
    // Declared first so it is destroyed last: everything below lives on it.
    oxen::quic::Loop loop_;
    std::unique_ptr<levin::listener> listener_ipv4_, listener_ipv6_;
    uint16_t port_ = 0, port_ipv6_ = 0;

    std::recursive_mutex mutex_;
    std::unordered_map<connection_id_t, std::shared_ptr<peer>> peers_;

    std::atomic<bool> stopping_{false};
    std::mutex stop_mutex_;
    std::condition_variable stop_cv_;

    bufferevent_rate_limit_group* rate_group_ = nullptr;
    ev_token_bucket_cfg* rate_cfg_ = nullptr;
    std::atomic<uint64_t> up_kbps_{0}, down_kbps_{0};
    std::atomic<int> tos_{-1};

    std::atomic<uint64_t> frames_in_{0}, bytes_in_{0}, frames_out_{0}, bytes_out_{0};
};

}  // namespace nodetool

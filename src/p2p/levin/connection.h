#pragma once

#include <event2/util.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <oxen/quic/address.hpp>
#include <oxen/quic/loop.hpp>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "frame.h"

struct bufferevent;
struct bufferevent_rate_limit_group;
struct evconnlistener;

namespace nodetool::levin {

// The return codes an invoke's callback gets when no response arrived, and that an invoke is
// answered with when nothing handles it (the values the epee levin implementation uses).
inline constexpr int32_t ERROR_CONNECTION_NOT_FOUND = -2;
inline constexpr int32_t ERROR_CONNECTION_DESTROYED = -3;
inline constexpr int32_t ERROR_TIMEDOUT = -4;
inline constexpr int32_t ERROR_HANDLER_NOT_DEFINED = -6;
// A request or response whose body doesn't parse as the command's
inline constexpr int32_t ERROR_FORMAT = -7;

// Describes one of the above, for logging.
constexpr std::string_view error_description(int32_t code) {
    switch (code) {
        case ERROR_CONNECTION_NOT_FOUND: return "connection not found";
        case ERROR_CONNECTION_DESTROYED: return "connection closed";
        case ERROR_TIMEDOUT: return "timed out";
        case ERROR_HANDLER_NOT_DEFINED: return "command not handled";
        case ERROR_FORMAT: return "malformed message";
        default: return "unknown error";
    }
}

class connection;

struct handlers {
    // A request that expects a response: returns the response's return code and body, which is
    // sent at once, or nullopt to send it later with respond().  Responses must go out in the
    // order their requests arrived: it is all a peer has to match them up by.
    std::function<std::optional<std::pair<int32_t, std::string>>(
            connection&, uint32_t command, std::string body)>
            on_invoke;
    // A request that doesn't
    std::function<void(connection&, uint32_t command, std::string body)> on_notify;
    // The connection has closed, for whatever reason.  This is the last call the connection makes;
    // the owner may release it then, but must not destroy it from inside this (or any other) of
    // its callbacks: release it with the loop's call_soon instead.
    std::function<void(connection&)> on_close;
};

// Called with the response's return code and body, or with ERROR_TIMEDOUT or
// ERROR_CONNECTION_DESTROYED (and no body) when there was none.
using invoke_callback = std::function<void(int32_t return_code, std::string body)>;

// A TCP connection carrying levin frames, driven by a libquic event loop.  Everything to do with
// it, its construction and destruction included, happens on the loop thread.
class connection {
  public:
    // Takes ownership of `bev`, a connected socket's bufferevent.
    connection(
            oxen::quic::Loop& loop,
            bufferevent* bev,
            oxen::quic::Address remote,
            bool incoming,
            uint64_t max_body_size);
    // Destroying an open connection drops its pending invokes without calling them back:
    // close() it, and wait for on_close, for that.
    ~connection();

    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    void set_handlers(handlers h) { handlers_ = std::move(h); }

    // Closes the connection if nothing arrives from the peer, or nothing queued gets sent to it,
    // for `timeout`.
    void set_idle_timeout(std::chrono::milliseconds timeout);

    // Makes the connection share the given group's rate limits.
    void join_rate_limit_group(bufferevent_rate_limit_group* group);

    // Sets the IP type-of-service byte on the connection's packets.
    void set_tos(int tos);

    void notify(uint32_t command, std::span<const unsigned char> body);

    // Sends the response to a request whose on_invoke deferred it.
    void respond(uint32_t command, int32_t return_code, std::span<const unsigned char> body);

    // Sends a request expecting a response.  A timeout closes the connection, as a late response
    // would otherwise be taken for the answer to the next invoke; it restarts while a large
    // response is still arriving.
    void invoke(
            uint32_t command,
            std::span<const unsigned char> body,
            std::chrono::milliseconds timeout,
            invoke_callback cb);

    // Stops reading and closes the connection once everything queued has been sent.
    void close();

    bool closed() const { return !bev_; }
    const oxen::quic::Address& remote() const { return remote_; }
    bool incoming() const { return incoming_; }

    std::chrono::steady_clock::time_point started() const { return started_; }
    std::chrono::steady_clock::time_point last_recv() const { return last_recv_; }
    std::chrono::steady_clock::time_point last_send() const { return last_send_; }
    uint64_t bytes_received() const { return bytes_received_; }
    uint64_t bytes_sent() const { return bytes_sent_; }

  private:
    static void on_read(bufferevent* bev, void* self);
    static void on_write(bufferevent* bev, void* self);
    static void on_event(bufferevent* bev, short what, void* self);

    void handle_frame(frame&& f);
    void send(std::string frame);
    void invoke_timed_out(oxen::quic::TimerID timer);
    // Frees the socket, fails the pending invokes and calls on_close.
    void shut_down();

    struct pending_invoke {
        uint32_t command;
        std::chrono::milliseconds timeout;
        invoke_callback cb;
        oxen::quic::TimerID timer;
    };

    oxen::quic::Loop& loop_;
    bufferevent* bev_;
    oxen::quic::Address remote_;
    bool incoming_;
    frame_parser parser_;
    handlers handlers_;
    std::deque<pending_invoke> pending_;
    bool closing_ = false;

    std::chrono::steady_clock::time_point started_, last_recv_, last_send_;
    uint64_t bytes_received_ = 0, bytes_sent_ = 0;

    // Declared last, so that it is destroyed (cancelling its timers) before what they use.
    oxen::quic::JobQueue jobs_{loop_};
};

// Starts connecting to `remote` (from `local`, if given), and later calls `done` with the new
// connection, or with nullptr if the connection failed or `timeout` passed first.  Call it on the
// loop thread; `done` is called there too.
void connect(
        oxen::quic::Loop& loop,
        const oxen::quic::Address& remote,
        const std::optional<oxen::quic::Address>& local,
        std::chrono::milliseconds timeout,
        uint64_t max_body_size,
        std::function<void(std::shared_ptr<connection>)> done);

// Accepts connections on an address, handing each one to `on_accept` on the loop thread.
// Construct and destroy it on the loop thread.
class listener {
  public:
    // Throws if it can't listen on `bind`.  Without `accepting`, it binds but leaves connections
    // waiting in the socket's backlog until accept() is called.
    listener(
            oxen::quic::Loop& loop,
            const oxen::quic::Address& bind,
            uint64_t max_body_size,
            std::function<void(std::shared_ptr<connection>)> on_accept,
            bool accepting = true);
    ~listener();

    listener(const listener&) = delete;
    listener& operator=(const listener&) = delete;

    void accept();

    // The address bound to, with the actual port when bound to port 0.
    const oxen::quic::Address& address() const { return bound_; }

  private:
    static void on_accept(
            evconnlistener* l, evutil_socket_t fd, struct sockaddr* addr, int len, void* self);

    oxen::quic::Loop& loop_;
    uint64_t max_body_size_;
    std::function<void(std::shared_ptr<connection>)> on_accept_;
    evconnlistener* listener_ = nullptr;
    oxen::quic::Address bound_;
};

}  // namespace nodetool::levin

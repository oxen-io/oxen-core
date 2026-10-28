#include "transport.h"

#include <event2/bufferevent.h>

#include <oxen/quic/format.hpp>

#include "logging/oxen_logger.h"
#include "net_node.h"

namespace nodetool {

static auto logcat = oxen::log::Cat("net.p2p");

// The largest frame body we take, as the epee levin implementation did
constexpr uint64_t MAX_BODY_SIZE = 100'000'000;

// How long a connection may go without any traffic, either way, before it is closed (epee's
// defaults)
constexpr auto IDLE_TIMEOUT = 5min;
constexpr auto IDLE_TIMEOUT_LOCAL = 30min;

static std::span<const uint8_t> as_span(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

// Whether `command`'s requests, and the responses to our invokes of it, are handled on the loop as
// they arrive rather than on the handler thread: the p2p layer's own commands, which take no chain
// locks, so that answering a peer (these are the only commands ever invoked) never waits behind
// chain work; and the cryptonote commands whose handlers queue their own chain jobs.
static constexpr bool handled_on_loop(int command) {
    using namespace cryptonote;
    switch (command) {
        case COMMAND_HANDSHAKE::ID:
        case COMMAND_TIMED_SYNC::ID:
        case COMMAND_PING::ID:
        case COMMAND_REQUEST_SUPPORT_FLAGS::ID:
        case NOTIFY_REQUEST_GET_BLOCKS::ID:
        case NOTIFY_REQUEST_GET_TXS::ID:
        case NOTIFY_REQUEST_CHAIN::ID:
        case NOTIFY_REQUEST_FLUFFY_MISSING_TX::ID:
        case NOTIFY_REQUEST_BLOCK_BLINKS::ID: return true;
        default: return false;
    }
}

transport::transport(node_server& node) : node_{node} {}

transport::~transport() {
    detach();
    loop_.call_get([this] {
        if (rate_group_)
            bufferevent_rate_limit_group_free(rate_group_);
        if (rate_cfg_)
            ev_token_bucket_cfg_free(rate_cfg_);
    });
}

void transport::post(std::function<void()> f) {
    std::lock_guard lock{stop_mutex_};
    if (omq_)
        omq_->job(std::move(f), *thread_);
}

void transport::listen(
        const oxen::quic::Address& ipv4,
        const std::optional<oxen::quic::Address>& ipv6,
        bool require_ipv4) {
    loop_.call_get([&] {
        auto on_accept = [this](std::shared_ptr<levin::connection> conn) {
            if (stopping_ || !node_.is_remote_host_allowed(conn->remote()))
                return;  // Dropping it closes it
            add(std::move(conn), true);
        };
        try {
            listener_ipv4_ =
                    std::make_unique<levin::listener>(loop_, ipv4, MAX_BODY_SIZE, on_accept, false);
            port_ = listener_ipv4_->address().port();
        } catch (const std::exception& e) {
            if (require_ipv4)
                throw;
            log::warning(logcat, "{}", e.what());
        }
        if (ipv6) {
            try {
                listener_ipv6_ = std::make_unique<levin::listener>(
                        loop_, *ipv6, MAX_BODY_SIZE, on_accept, false);
                port_ipv6_ = listener_ipv6_->address().port();
            } catch (const std::exception& e) {
                if (!listener_ipv4_)
                    throw std::runtime_error{"Failed to bind IPv4 and IPv6"};
                log::warning(logcat, "{}", e.what());
            }
        }
    });
}

void transport::start(oxenmq::OxenMQ& omq, oxenmq::TaggedThreadID thread) {
    {
        std::lock_guard lock{stop_mutex_};
        omq_ = &omq;
        thread_ = thread;
    }
    loop_.call_get([this] {
        if (listener_ipv4_)
            listener_ipv4_->accept();
        if (listener_ipv6_)
            listener_ipv6_->accept();
    });
}

void transport::stop() {
    if (stopping_.exchange(true))
        return;
    loop_.call_get([this] {
        listener_ipv4_.reset();
        listener_ipv6_.reset();
        std::lock_guard lock{mutex_};
        for (auto& [id, p] : peers_)
            p->conn->close();
    });
    {
        std::lock_guard lock{stop_mutex_};
    }
    stop_cv_.notify_all();
}

void transport::wait() {
    std::unique_lock lock{stop_mutex_};
    stop_cv_.wait(lock, [this] { return stopping_.load(); });
}

void transport::detach() {
    {
        std::lock_guard lock{stop_mutex_};
        omq_ = nullptr;
    }
    loop_.call_get([this] {
        listener_ipv4_.reset();
        listener_ipv6_.reset();
        std::lock_guard lock{mutex_};
        peers_.clear();
    });
}

std::shared_ptr<transport::peer> transport::find(const connection_id_t& id) {
    std::lock_guard lock{mutex_};
    auto it = peers_.find(id);
    return it == peers_.end() ? nullptr : it->second;
}

std::shared_ptr<transport::peer> transport::add(
        std::shared_ptr<levin::connection> conn, bool incoming) {
    const auto id = connection_id_t::random();
    auto p = std::make_shared<peer>(
            conn,
            p2p_connection_context{id, conn->remote(), incoming},
            0,
            std::chrono::steady_clock::now());

    conn->set_idle_timeout(conn->remote().is_public_ip() ? IDLE_TIMEOUT : IDLE_TIMEOUT_LOCAL);
    if (rate_group_)
        conn->join_rate_limit_group(rate_group_);
    if (int tos = tos_; tos >= 0)
        conn->set_tos(tos);

    // Weak, as the connection's handlers are kept by the connection, which the peer keeps
    std::weak_ptr<peer> wp = p;
    conn->set_handlers(
            {.on_invoke = [this, wp](levin::connection& c, uint32_t command, std::string body)
                     -> std::optional<std::pair<int32_t, std::string>> {
                 count_in(body.size());
                 if (handled_on_loop(command)) {
                     auto p = wp.lock();
                     received(*p, c.bytes_received(), c.last_recv());
                     std::string out;
                     const int code = node_.invoke(command, as_span(body), out, p->context);
                     count_out(out.size());
                     return std::pair<int32_t, std::string>{code, std::move(out)};
                 }
                 post([this,
                       wp,
                       command,
                       body = std::move(body),
                       bytes = c.bytes_received(),
                       at = c.last_recv()] {
                     auto p = wp.lock();
                     if (!p)
                         return;
                     received(*p, bytes, at);
                     std::string out;
                     const int code = node_.invoke(command, as_span(body), out, p->context);
                     count_out(out.size());
                     loop_.call([p, command, code, out = std::move(out)] {
                         p->conn->respond(
                                 command,
                                 code,
                                 {reinterpret_cast<const unsigned char*>(out.data()), out.size()});
                     });
                 });
                 return std::nullopt;
             },
             .on_notify =
                     [this, wp](levin::connection& c, uint32_t command, std::string body) {
                         count_in(body.size());
                         if (handled_on_loop(command)) {
                             auto p = wp.lock();
                             received(*p, c.bytes_received(), c.last_recv());
                             node_.notify(command, as_span(body), p->context);
                             return;
                         }
                         post([this,
                               wp,
                               command,
                               body = std::move(body),
                               bytes = c.bytes_received(),
                               at = c.last_recv()] {
                             auto p = wp.lock();
                             if (!p)
                                 return;
                             received(*p, bytes, at);
                             node_.notify(command, as_span(body), p->context);
                         });
                     },
             .on_close =
                     [this, wp](levin::connection&) {
                         post([this, wp] {
                             auto p = wp.lock();
                             if (!p)
                                 return;
                             node_.on_connection_close(p->context);
                             std::lock_guard lock{mutex_};
                             peers_.erase(p->context.m_connection_id);
                         });
                     }});

    {
        std::lock_guard lock{mutex_};
        peers_.emplace(id, p);
    }
    post([this, p] { node_.on_connection_new(p->context); });
    return p;
}

void transport::received(
        peer& p, uint64_t bytes_received, std::chrono::steady_clock::time_point at) {
    auto& c = p.context;
    c.m_recv_cnt = bytes_received;
    c.m_last_recv = at;
    const std::chrono::duration<double> elapsed = at - p.sample_start;
    if (elapsed >= 1s) {
        c.m_current_speed_down = (bytes_received - p.sample_bytes) / elapsed.count();
        c.m_max_speed_down = std::max(c.m_max_speed_down, c.m_current_speed_down);
        p.sample_bytes = bytes_received;
        p.sample_start = at;
    }
}

void transport::count_in(size_t body_size) {
    ++frames_in_;
    bytes_in_ += levin::header::SIZE + body_size;
}

void transport::count_out(size_t body_size) {
    ++frames_out_;
    bytes_out_ += levin::header::SIZE + body_size;
}

bool transport::foreach_connection(const std::function<bool(p2p_connection_context&)>& f) {
    std::lock_guard lock{mutex_};
    for (auto& [id, p] : peers_)
        if (!f(p->context))
            return false;
    return true;
}

bool transport::for_connection(
        const connection_id_t& id, const std::function<bool(p2p_connection_context&)>& f) {
    std::lock_guard lock{mutex_};
    auto it = peers_.find(id);
    if (it == peers_.end())
        return false;
    f(it->second->context);
    return true;
}

size_t transport::get_connections_count() {
    std::lock_guard lock{mutex_};
    return peers_.size();
}

size_t transport::get_out_connections_count() {
    std::lock_guard lock{mutex_};
    size_t n = 0;
    for (auto& [id, p] : peers_)
        n += !p->context.m_is_income;
    return n;
}

size_t transport::get_in_connections_count() {
    std::lock_guard lock{mutex_};
    size_t n = 0;
    for (auto& [id, p] : peers_)
        n += p->context.m_is_income;
    return n;
}

void transport::del_out_connections(size_t count) {
    std::vector<connection_id_t> ids;
    foreach_connection([&](p2p_connection_context& c) {
        if (!c.m_is_income)
            ids.push_back(c.m_connection_id);
        return ids.size() < count;
    });
    for (const auto& id : ids)
        close(id);
}

void transport::del_in_connections(size_t count) {
    std::vector<connection_id_t> ids;
    foreach_connection([&](p2p_connection_context& c) {
        if (c.m_is_income)
            ids.push_back(c.m_connection_id);
        return ids.size() < count;
    });
    for (const auto& id : ids)
        close(id);
}

bool transport::close(const connection_id_t& id) {
    auto p = find(id);
    if (!p)
        return false;
    loop_.call([p] { p->conn->close(); });
    return true;
}

int transport::notify(int command, std::span<const uint8_t> body, const connection_id_t& id) {
    auto p = find(id);
    if (!p)
        return levin::ERROR_CONNECTION_NOT_FOUND;
    if (stopping_)
        return levin::ERROR_CONNECTION_DESTROYED;
    count_out(body.size());
    loop_.call(
            [p, command, b = std::string{reinterpret_cast<const char*>(body.data()), body.size()}] {
                p->context.m_send_cnt += b.size();
                p->context.m_last_send = std::chrono::steady_clock::now();
                p->conn->notify(
                        command, {reinterpret_cast<const unsigned char*>(b.data()), b.size()});
            });
    return 1;
}

int transport::invoke_async(
        int command,
        std::span<const uint8_t> body,
        const connection_id_t& id,
        std::function<void(int, std::span<const uint8_t>, p2p_connection_context&)> cb,
        std::chrono::nanoseconds timeout) {
    auto p = find(id);
    if (!p)
        return levin::ERROR_CONNECTION_NOT_FOUND;
    if (stopping_)
        return levin::ERROR_CONNECTION_DESTROYED;
    if (timeout == timeout.zero())
        timeout = invoke_timeout;
    count_out(body.size());
    loop_.call([this,
                p,
                command,
                b = std::string{reinterpret_cast<const char*>(body.data()), body.size()},
                timeout = std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
                cb = std::move(cb)] {
        p->context.m_send_cnt += b.size();
        p->context.m_last_send = std::chrono::steady_clock::now();
        p->conn->invoke(
                command,
                {reinterpret_cast<const unsigned char*>(b.data()), b.size()},
                timeout,
                [this, p, command, cb](int32_t code, std::string response) {
                    if (code >= 0)
                        count_in(response.size());
                    if (handled_on_loop(command)) {
                        cb(code, as_span(response), p->context);
                        return;
                    }
                    post([p, cb, code, response = std::move(response)] {
                        cb(code, as_span(response), p->context);
                    });
                });
    });
    return 1;
}

bool transport::call_on(const connection_id_t& id, std::function<void(p2p_connection_context&)> f) {
    auto p = find(id);
    if (!p)
        return false;
    post([this, p, f = std::move(f)] {
        if (find(p->context.m_connection_id))
            f(p->context);
    });
    return true;
}

void transport::connect(
        const oxen::quic::Address& remote,
        std::chrono::milliseconds timeout,
        std::function<void(p2p_connection_context*)> done,
        const std::optional<oxen::quic::Address>& local) {
    loop_.call([this, remote, timeout, done = std::move(done), local] {
        levin::connect(
                loop_,
                remote,
                local,
                timeout,
                MAX_BODY_SIZE,
                [this, done](std::shared_ptr<levin::connection> conn) {
                    if (!conn || stopping_) {
                        post([done] { done(nullptr); });
                        return;
                    }
                    auto p = add(std::move(conn), false);
                    post([p, done] { done(&p->context); });
                });
    });
}

void transport::set_rate_limits(uint64_t up_kbps, uint64_t down_kbps) {
    up_kbps_ = up_kbps;
    down_kbps_ = down_kbps;
    loop_.call([this] { update_rate_limits(); });
}

void transport::update_rate_limits() {
    // One-second ticks (libevent's default): the group refills every tick for as long as it
    // exists, so a shorter tick only means more wakeups.
    auto* cfg = ev_token_bucket_cfg_new(
            down_kbps_ * 1024, down_kbps_ * 1024, up_kbps_ * 1024, up_kbps_ * 1024, nullptr);
    if (!rate_group_) {
        rate_group_ = bufferevent_rate_limit_group_new(loop_.get_event_base(), cfg);
        std::lock_guard lock{mutex_};
        for (auto& [id, p] : peers_)
            p->conn->join_rate_limit_group(rate_group_);
    } else {
        bufferevent_rate_limit_group_set_cfg(rate_group_, cfg);
    }
    // libevent doesn't promise to copy the config, so the current one is kept for the group's
    // lifetime.
    if (rate_cfg_)
        ev_token_bucket_cfg_free(rate_cfg_);
    rate_cfg_ = cfg;
}

}  // namespace nodetool

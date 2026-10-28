#include "connection.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include <array>
#include <oxen/quic/format.hpp>
#include <stdexcept>

#include "common/format.h"
#include "logging/oxen_logger.h"

namespace nodetool::levin {

static auto logcat = oxen::log::Cat("net.levin");

// How much of a response has to arrive at once to count as progress, restarting the timeout of
// the invoke it answers (as in the epee implementation).
constexpr size_t RESPONSE_PROGRESS_BYTES = 512;

static timeval to_timeval(std::chrono::milliseconds t) {
    timeval tv;
    tv.tv_sec = t.count() / 1000;
    tv.tv_usec = t.count() % 1000 * 1000;
    return tv;
}

static std::span<const unsigned char> as_bytes(std::string_view s) {
    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

connection::connection(
        oxen::quic::Loop& loop,
        bufferevent* bev,
        oxen::quic::Address remote,
        bool incoming,
        uint64_t max_body_size) :
        loop_{loop},
        bev_{bev},
        remote_{std::move(remote)},
        incoming_{incoming},
        parser_{max_body_size},
        started_{std::chrono::steady_clock::now()},
        last_recv_{started_},
        last_send_{started_} {
    bufferevent_setcb(bev_, on_read, nullptr, on_event, this);
    bufferevent_enable(bev_, EV_READ | EV_WRITE);
}

connection::~connection() {
    jobs_.stop();
    if (bev_)
        bufferevent_free(bev_);
}

void connection::set_idle_timeout(std::chrono::milliseconds timeout) {
    if (!bev_)
        return;
    const auto tv = to_timeval(timeout);
    bufferevent_set_timeouts(bev_, &tv, &tv);
}

void connection::send(std::string frame) {
    if (!bev_ || closing_)
        return;
    bufferevent_write(bev_, frame.data(), frame.size());
    bytes_sent_ += frame.size();
    last_send_ = std::chrono::steady_clock::now();
}

void connection::notify(uint32_t command, std::span<const unsigned char> body) {
    send(make_request(command, body, false));
}

void connection::invoke(
        uint32_t command,
        std::span<const unsigned char> body,
        std::chrono::milliseconds timeout,
        invoke_callback cb) {
    if (!bev_ || closing_) {
        cb(ERROR_CONNECTION_DESTROYED, {});
        return;
    }
    send(make_request(command, body, true));
    // A repeating timer, removed when the response arrives or when it first fires, so that its
    // cycle can be restarted while a large response is coming in.  It is given its own id once
    // that exists, which is before it can fire, as we are on the loop thread.
    auto id = std::make_shared<oxen::quic::TimerID>();
    *id = jobs_.add_timer(timeout, [this, id] { invoke_timed_out(*id); });
    pending_.push_back({command, timeout, std::move(cb), *id});
}

void connection::invoke_timed_out(oxen::quic::TimerID timer) {
    jobs_.remove(timer);
    for (auto it = pending_.begin(); it != pending_.end(); ++it) {
        if (it->timer != timer)
            continue;
        auto cb = std::move(it->cb);
        pending_.erase(it);
        log::debug(logcat, "Invoke to {} timed out; closing the connection", remote_);
        cb(ERROR_TIMEDOUT, {});
        break;
    }
    shut_down();
}

void connection::close() {
    if (!bev_ || closing_)
        return;
    closing_ = true;
    bufferevent_disable(bev_, EV_READ);
    if (evbuffer_get_length(bufferevent_get_output(bev_)) == 0)
        shut_down();
    else
        // The write callback fires once the output has drained (to its default low watermark of
        // zero).
        bufferevent_setcb(bev_, nullptr, on_write, on_event, this);
}

void connection::shut_down() {
    if (!bev_)
        return;
    bufferevent_free(bev_);
    bev_ = nullptr;
    auto pending = std::move(pending_);
    pending_.clear();
    for (auto& p : pending) {
        jobs_.remove(p.timer);
        p.cb(ERROR_CONNECTION_DESTROYED, {});
    }
    if (handlers_.on_close)
        handlers_.on_close(*this);
}

void connection::on_read(bufferevent* bev, void* self_) {
    auto& self = *static_cast<connection*>(self_);
    auto* input = bufferevent_get_input(bev);
    std::array<unsigned char, 16384> buf;
    int n;
    while (self.bev_ && !self.closing_ &&
           (n = evbuffer_remove(input, buf.data(), buf.size())) > 0) {
        self.bytes_received_ += n;
        self.last_recv_ = std::chrono::steady_clock::now();

        std::vector<frame> frames;
        try {
            frames = self.parser_.feed({buf.data(), static_cast<size_t>(n)});
        } catch (const parse_error& e) {
            log::warning(
                    logcat,
                    "Invalid data from {}: {}; closing the connection",
                    self.remote_,
                    e.what());
            self.shut_down();
            return;
        }

        if (self.parser_.in_body() && static_cast<size_t>(n) >= RESPONSE_PROGRESS_BYTES &&
            !self.pending_.empty()) {
            auto& front = self.pending_.front();
            self.jobs_.repeat(front.timer, front.timeout);
        }

        for (auto& f : frames) {
            self.handle_frame(std::move(f));
            if (!self.bev_ || self.closing_)
                return;
        }
    }
}

void connection::handle_frame(frame&& f) {
    const auto& h = f.head;
    // Every frame is a request or a response; anything else (such as Monero's noise and fragment
    // messages, which no Oxen node sends) is skipped.
    if (!(h.flags & (FLAG_REQUEST | FLAG_RESPONSE)))
        return;

    if (h.is_response()) {
        if (pending_.empty() || pending_.front().command != h.command) {
            log::warning(
                    logcat,
                    "{} sent a response (command {}) we weren't waiting for; closing the "
                    "connection",
                    remote_,
                    h.command);
            shut_down();
            return;
        }
        auto p = std::move(pending_.front());
        pending_.pop_front();
        jobs_.remove(p.timer);
        p.cb(h.return_code, std::move(f.body));
        return;
    }

    if (h.expect_response) {
        auto [code, body] = handlers_.on_invoke
                                  ? handlers_.on_invoke(*this, h.command, std::move(f.body))
                                  : std::pair{ERROR_HANDLER_NOT_DEFINED, std::string{}};
        send(make_response(h.command, code, as_bytes(body)));
    } else if (handlers_.on_notify) {
        handlers_.on_notify(*this, h.command, std::move(f.body));
    }
}

void connection::on_write(bufferevent*, void* self_) {
    auto& self = *static_cast<connection*>(self_);
    if (self.closing_)
        self.shut_down();
}

void connection::on_event(bufferevent*, short what, void* self_) {
    auto& self = *static_cast<connection*>(self_);
    if (what & BEV_EVENT_TIMEOUT)
        log::debug(logcat, "Connection to {} timed out", self.remote_);
    else if (what & BEV_EVENT_EOF)
        log::debug(logcat, "Connection to {} closed by the peer", self.remote_);
    else if (what & BEV_EVENT_ERROR)
        log::debug(
                logcat,
                "Connection to {} failed: {}",
                self.remote_,
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    self.shut_down();
}

namespace {
    struct pending_connect {
        oxen::quic::Loop& loop;
        oxen::quic::Address remote;
        uint64_t max_body_size;
        std::function<void(std::shared_ptr<connection>)> done;
    };

    void on_connect_event(bufferevent* bev, short what, void* arg) {
        std::unique_ptr<pending_connect> pc{static_cast<pending_connect*>(arg)};
        if (!(what & BEV_EVENT_CONNECTED)) {
            log::debug(logcat, "Connecting to {} failed", pc->remote);
            bufferevent_free(bev);
            pc->done(nullptr);
            return;
        }
        bufferevent_set_timeouts(bev, nullptr, nullptr);
        pc->done(pc->loop.make_shared<connection>(
                pc->loop, bev, std::move(pc->remote), false, pc->max_body_size));
    }
}  // namespace

void connect(
        oxen::quic::Loop& loop,
        const oxen::quic::Address& remote,
        const std::optional<oxen::quic::Address>& local,
        std::chrono::milliseconds timeout,
        uint64_t max_body_size,
        std::function<void(std::shared_ptr<connection>)> done) {
    evutil_socket_t fd = -1;
    if (local) {
        fd = ::socket(remote.is_ipv6() ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        if (fd < 0 || evutil_make_socket_nonblocking(fd) < 0 ||
            ::bind(fd, static_cast<const sockaddr*>(*local), local->socklen()) < 0) {
            log::warning(
                    logcat,
                    "Unable to connect to {} from {}: {}",
                    remote,
                    *local,
                    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            if (fd >= 0)
                evutil_closesocket(fd);
            done(nullptr);
            return;
        }
    }

    auto* bev = bufferevent_socket_new(loop.get_event_base(), fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        if (fd >= 0)
            evutil_closesocket(fd);
        done(nullptr);
        return;
    }
    auto* pc = new pending_connect{loop, remote, max_body_size, std::move(done)};
    bufferevent_setcb(bev, nullptr, nullptr, on_connect_event, pc);
    // While connecting, the write timeout is the connect timeout
    const auto tv = to_timeval(timeout);
    bufferevent_set_timeouts(bev, nullptr, &tv);
    if (bufferevent_socket_connect(bev, static_cast<const sockaddr*>(remote), remote.socklen()) <
        0) {
        // A failure here may already have called the event callback, which owns `pc`
        return;
    }
}

listener::listener(
        oxen::quic::Loop& loop,
        const oxen::quic::Address& bind,
        uint64_t max_body_size,
        std::function<void(std::shared_ptr<connection>)> on_accept) :
        loop_{loop}, max_body_size_{max_body_size}, on_accept_{std::move(on_accept)} {
    unsigned flags = LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE;
    // An IPv6 listener takes only IPv6, so that an IPv4 one can share its port
    if (bind.is_ipv6())
        flags |= LEV_OPT_BIND_IPV6ONLY;
    listener_ = evconnlistener_new_bind(
            loop.get_event_base(),
            listener::on_accept,
            this,
            flags,
            -1,
            static_cast<const sockaddr*>(bind),
            bind.socklen());
    if (!listener_)
        throw std::runtime_error{"Unable to listen on {}: {}"_format(
                bind, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};

    bound_ = bind;
    ::getsockname(
            evconnlistener_get_fd(listener_), static_cast<sockaddr*>(bound_), bound_.socklen_ptr());
}

listener::~listener() {
    if (listener_)
        evconnlistener_free(listener_);
}

void listener::on_accept(
        evconnlistener*, evutil_socket_t fd, struct sockaddr* addr, int len, void* self_) {
    auto& self = *static_cast<listener*>(self_);
    auto* bev = bufferevent_socket_new(self.loop_.get_event_base(), fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        evutil_closesocket(fd);
        return;
    }
    self.on_accept_(self.loop_.make_shared<connection>(
            self.loop_,
            bev,
            oxen::quic::Address{addr, static_cast<socklen_t>(len)},
            true,
            self.max_body_size_));
}

}  // namespace nodetool::levin

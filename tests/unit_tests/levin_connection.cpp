#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <future>
#include <thread>

#include "p2p/levin/connection.h"

using namespace nodetool;
using namespace std::literals;

namespace {

constexpr uint64_t MAX_BODY = 50'000'000;

std::span<const unsigned char> bytes(std::string_view s) {
    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

template <typename T>
T get(std::future<T>& f) {
    if (f.wait_for(10s) != std::future_status::ready)
        throw std::runtime_error{"timed out waiting for the event loop"};
    return f.get();
}

class levin_connection : public ::testing::Test {
  protected:
    oxen::quic::Loop loop;
    std::unique_ptr<levin::listener> server;
    std::shared_ptr<levin::connection> server_conn, client_conn;

    void TearDown() override {
        loop.call_get([this] {
            server.reset();
            server_conn.reset();
            client_conn.reset();
        });
    }

    void listen(std::function<void(std::shared_ptr<levin::connection>)> on_accept) {
        loop.call_get([&] {
            server = std::make_unique<levin::listener>(
                    loop, oxen::quic::Address{"127.0.0.1", 0}, MAX_BODY, std::move(on_accept));
        });
    }

    // Connects a client to a server, each with the given handlers.
    void connect_pair(levin::handlers server_h, levin::handlers client_h) {
        std::promise<void> accepted, connected;
        listen([&](std::shared_ptr<levin::connection> c) {
            c->set_handlers(server_h);
            server_conn = std::move(c);
            accepted.set_value();
        });
        loop.call([&] {
            levin::connect(
                    loop,
                    server->address(),
                    std::nullopt,
                    5s,
                    MAX_BODY,
                    [&](std::shared_ptr<levin::connection> c) {
                        if (c)
                            c->set_handlers(client_h);
                        client_conn = std::move(c);
                        connected.set_value();
                    });
        });
        auto a = accepted.get_future(), c = connected.get_future();
        get(a);
        get(c);
        ASSERT_TRUE(client_conn);
        EXPECT_TRUE(server_conn->incoming());
        EXPECT_FALSE(client_conn->incoming());
    }
};

// A peer we drive by hand over a plain socket, to send it what a real one wouldn't.
struct raw_peer {
    int fd;
    explicit raw_peer(const oxen::quic::Address& to) : fd{::socket(AF_INET, SOCK_STREAM, 0)} {
        if (::connect(fd, static_cast<const sockaddr*>(to), to.socklen()) != 0)
            throw std::runtime_error{"raw connect failed"};
    }
    ~raw_peer() { ::close(fd); }
    void send(std::string_view data) const {
        while (!data.empty()) {
            auto n = ::send(fd, data.data(), data.size(), 0);
            if (n <= 0)
                throw std::runtime_error{"raw send failed"};
            data.remove_prefix(n);
        }
    }
};

}  // namespace

TEST_F(levin_connection, notify) {
    std::promise<std::pair<uint32_t, std::string>> got;
    connect_pair(
            {.on_notify = [&](levin::connection&,
                              uint32_t cmd,
                              std::string body) { got.set_value({cmd, std::move(body)}); }},
            {});
    loop.call([&] { client_conn->notify(123, bytes("hi")); });
    auto f = got.get_future();
    EXPECT_EQ(get(f), std::make_pair(123u, "hi"s));
}

TEST_F(levin_connection, invoke) {
    connect_pair(
            {.on_invoke =
                     [](levin::connection&, uint32_t cmd, std::string body) {
                         return std::pair{static_cast<int32_t>(cmd) + 1, body + " back"};
                     }},
            {});
    std::promise<std::pair<int32_t, std::string>> got;
    loop.call([&] {
        client_conn->invoke(41, bytes("there"), 5s, [&](int32_t code, std::string body) {
            got.set_value({code, std::move(body)});
        });
    });
    auto f = got.get_future();
    EXPECT_EQ(get(f), std::make_pair(42, "there back"s));
}

TEST_F(levin_connection, unhandled_invoke) {
    connect_pair({}, {});
    std::promise<int32_t> got;
    loop.call([&] {
        client_conn->invoke(1, {}, 5s, [&](int32_t code, std::string) { got.set_value(code); });
    });
    auto f = got.get_future();
    EXPECT_EQ(get(f), levin::ERROR_HANDLER_NOT_DEFINED);
}

// Each side invokes the other at once: requests and responses interleave on both streams, and
// each response still reaches the invoke it answers.
TEST_F(levin_connection, crossed_invokes) {
    auto echo = [](levin::connection&, uint32_t cmd, std::string body) {
        return std::pair{static_cast<int32_t>(cmd), body};
    };
    connect_pair({.on_invoke = echo}, {.on_invoke = echo});

    std::promise<std::string> client_got, server_got;
    loop.call([&] {
        client_conn->invoke(1, bytes("from client"), 5s, [&](int32_t, std::string body) {
            client_got.set_value(std::move(body));
        });
        server_conn->invoke(1, bytes("from server"), 5s, [&](int32_t, std::string body) {
            server_got.set_value(std::move(body));
        });
    });
    auto c = client_got.get_future(), s = server_got.get_future();
    EXPECT_EQ(get(c), "from client");
    EXPECT_EQ(get(s), "from server");
}

TEST_F(levin_connection, responses_in_order) {
    connect_pair(
            {.on_invoke = [](levin::connection&,
                             uint32_t cmd,
                             std::string body) { return std::pair{0, body}; }},
            {});
    std::vector<std::string> got;
    std::promise<void> done;
    loop.call([&] {
        for (int i = 0; i < 20; i++)
            client_conn->invoke(7, bytes(std::to_string(i)), 5s, [&](int32_t, std::string body) {
                got.push_back(std::move(body));
                if (got.size() == 20)
                    done.set_value();
            });
    });
    auto f = done.get_future();
    get(f);
    for (int i = 0; i < 20; i++)
        EXPECT_EQ(got[i], std::to_string(i));
}

TEST_F(levin_connection, large_frames) {
    const std::string big(5'000'000, 'z');
    connect_pair(
            {.on_invoke =
                     [&](levin::connection&, uint32_t, std::string body) {
                         return std::pair{static_cast<int32_t>(body.size() == big.size()), big};
                     }},
            {});
    std::promise<std::pair<int32_t, size_t>> got;
    loop.call([&] {
        client_conn->invoke(1, bytes(big), 5s, [&](int32_t code, std::string body) {
            got.set_value({code, body.size()});
        });
    });
    auto f = got.get_future();
    EXPECT_EQ(get(f), std::make_pair(1, big.size()));
}

// Frames sent from several threads at once (each through the loop) arrive whole.
TEST_F(levin_connection, sends_from_many_threads) {
    constexpr int THREADS = 8, EACH = 200;
    std::atomic<int> received{0}, bad{0};
    std::promise<void> done;
    connect_pair(
            {.on_notify =
                     [&](levin::connection&, uint32_t cmd, std::string body) {
                         if (body != std::string(1000 + cmd, static_cast<char>('a' + cmd % 26)))
                             ++bad;
                         if (++received == THREADS * EACH)
                             done.set_value();
                     }},
            {});
    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; t++)
        threads.emplace_back([&, t] {
            for (int i = 0; i < EACH; i++) {
                uint32_t cmd = t * EACH + i;
                loop.call([&, cmd] {
                    client_conn->notify(
                            cmd, bytes(std::string(1000 + cmd, static_cast<char>('a' + cmd % 26))));
                });
            }
        });
    for (auto& t : threads)
        t.join();
    auto f = done.get_future();
    get(f);
    EXPECT_EQ(bad, 0);
}

TEST_F(levin_connection, close_sends_queued_data_first) {
    const std::string big(3'000'000, 'q');
    std::promise<size_t> got;
    std::promise<void> server_closed;
    connect_pair(
            {.on_notify = [&](levin::connection&,
                              uint32_t,
                              std::string body) { got.set_value(body.size()); },
             .on_close = [&](levin::connection&) { server_closed.set_value(); }},
            {});
    loop.call([&] {
        client_conn->notify(1, bytes(big));
        client_conn->close();
    });
    auto f = got.get_future();
    EXPECT_EQ(get(f), big.size());
    auto c = server_closed.get_future();
    get(c);
}

// A peer that never answers: the invoke times out, which closes the connection.
TEST_F(levin_connection, invoke_timeout_closes) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)), 0);
    ASSERT_EQ(::listen(fd, 1), 0);
    socklen_t len = sizeof(sin);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sin), &len);
    oxen::quic::Address silent{&sin};

    std::promise<int32_t> code;
    std::promise<void> closed;
    loop.call([&] {
        levin::connect(loop, silent, std::nullopt, 5s, MAX_BODY, [&](auto c) {
            client_conn = std::move(c);
            client_conn->set_handlers(
                    {.on_close = [&](levin::connection&) { closed.set_value(); }});
            client_conn->invoke(1, {}, 200ms, [&](int32_t rc, std::string) { code.set_value(rc); });
        });
    });
    auto f = code.get_future();
    EXPECT_EQ(get(f), levin::ERROR_TIMEDOUT);
    auto c = closed.get_future();
    get(c);
    ::close(fd);
}

TEST_F(levin_connection, pending_invokes_fail_on_close) {
    connect_pair({}, {});
    std::promise<int32_t> code;
    std::promise<void> server_closed;
    // The server closes before answering
    loop.call_get([&] {
        server_conn->set_handlers({.on_invoke = [&](levin::connection& c, uint32_t, std::string) {
            c.close();
            return std::pair{0, std::string{}};
        }});
        client_conn->invoke(1, {}, 5s, [&](int32_t rc, std::string) { code.set_value(rc); });
    });
    auto f = code.get_future();
    EXPECT_EQ(get(f), levin::ERROR_CONNECTION_DESTROYED);
}

TEST_F(levin_connection, unexpected_response_closes) {
    std::promise<void> closed;
    listen([&](std::shared_ptr<levin::connection> c) {
        c->set_handlers({.on_close = [&](levin::connection&) { closed.set_value(); }});
        server_conn = std::move(c);
    });
    raw_peer peer{server->address()};
    peer.send(levin::make_response(5, 1, bytes("unasked")));
    auto f = closed.get_future();
    get(f);
}

// Only a version 1 frame can be a response; from an older peer, even one flagged as a response is
// a request.
TEST_F(levin_connection, version_0_frame_is_a_request) {
    std::promise<uint32_t> invoked;
    listen([&](std::shared_ptr<levin::connection> c) {
        c->set_handlers({.on_invoke = [&](levin::connection&, uint32_t cmd, std::string) {
            invoked.set_value(cmd);
            return std::pair{0, std::string{}};
        }});
        server_conn = std::move(c);
    });
    levin::header h;
    h.expect_response = true;
    h.command = 77;
    h.flags = levin::FLAG_RESPONSE;
    h.protocol_version = 0;
    auto head = h.encode();
    raw_peer peer{server->address()};
    peer.send({reinterpret_cast<const char*>(head.data()), head.size()});
    auto f = invoked.get_future();
    EXPECT_EQ(get(f), 77u);
}

TEST_F(levin_connection, noise_frames_skipped) {
    std::promise<uint32_t> notified;
    std::promise<void> closed;
    listen([&](std::shared_ptr<levin::connection> c) {
        c->set_handlers(
                {.on_notify = [&](levin::connection&,
                                  uint32_t cmd,
                                  std::string) { notified.set_value(cmd); },
                 .on_close = [&](levin::connection&) { closed.set_value(); }});
        server_conn = std::move(c);
    });
    levin::header noise;
    noise.body_size = 100;
    noise.flags = 0x04 | 0x08;
    auto head = noise.encode();
    raw_peer peer{server->address()};
    peer.send({reinterpret_cast<const char*>(head.data()), head.size()});
    peer.send(std::string(100, '\0'));
    peer.send(levin::make_request(9, {}, false));
    auto f = notified.get_future();
    EXPECT_EQ(get(f), 9u);
    EXPECT_EQ(closed.get_future().wait_for(0s), std::future_status::timeout);
    // The peer's socket closes as the test ends, after the promise is gone
    loop.call_get([&] { server_conn->set_handlers({}); });
}

TEST_F(levin_connection, bad_signature_closes) {
    std::promise<void> closed;
    listen([&](std::shared_ptr<levin::connection> c) {
        c->set_handlers({.on_close = [&](levin::connection&) { closed.set_value(); }});
        server_conn = std::move(c);
    });
    raw_peer peer{server->address()};
    peer.send("GET / HTTP/1.1\r\n\r\n");
    auto f = closed.get_future();
    get(f);
}

TEST_F(levin_connection, connect_failure) {
    // Grab a free port, then stop listening on it
    std::optional<oxen::quic::Address> addr;
    listen([](auto) {});
    addr = server->address();
    loop.call_get([&] { server.reset(); });

    std::promise<bool> got;
    loop.call([&] {
        levin::connect(loop, *addr, std::nullopt, 5s, MAX_BODY, [&](auto c) {
            got.set_value(c != nullptr);
        });
    });
    auto f = got.get_future();
    EXPECT_FALSE(get(f));
}

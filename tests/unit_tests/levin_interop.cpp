// The levin connection talking to the epee levin implementation, which current nodes run: the
// strongest evidence short of the network itself that the two are wire-compatible.

#include <gtest/gtest.h>

#include <future>

#include "cryptonote_config.h"
#include "epee/net/abstract_tcp_server2.h"
#include "epee/net/connection_basic.hpp"
#include "epee/net/levin_protocol_handler_async.h"
#include "p2p/levin/connection.h"

using namespace nodetool;
using namespace std::literals;

namespace {

struct epee_context : epee::net_utils::connection_context_base {};
using epee_server =
        epee::net_utils::boosted_tcp_server<epee::levin::async_protocol_handler<epee_context>>;

std::string as_string(std::span<const uint8_t> b) {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}
std::span<const unsigned char> bytes(std::string_view s) {
    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

template <typename T>
T get(std::future<T>& f) {
    if (f.wait_for(10s) != std::future_status::ready)
        throw std::runtime_error{"timed out"};
    return f.get();
}

struct epee_handler : epee::levin::levin_commands_handler<epee_context> {
    std::promise<epee::connection_id_t> connected;
    std::promise<std::pair<int, std::string>> notified;

    int invoke(int command, std::span<const uint8_t> in, std::string& out, epee_context&) override {
        out = as_string(in) + " (from epee)";
        return command + 1;
    }
    int notify(int command, std::span<const uint8_t> in, epee_context&) override {
        notified.set_value({command, as_string(in)});
        return 1;
    }
    void on_connection_new(epee_context& c) override { connected.set_value(c.m_connection_id); }
};

}  // namespace

TEST(levin_interop, epee) {
    epee_handler handler;
    // A p2p server, as current nodes run, which (unlike an RPC one) sends large frames in chunks
    // and is rate limited; the limits are a node's defaults, not the throttle's own 16kB/s.
    epee::net_utils::connection_basic::set_rate_up_limit(cryptonote::p2p::DEFAULT_LIMIT_RATE_UP);
    epee::net_utils::connection_basic::set_rate_down_limit(
            cryptonote::p2p::DEFAULT_LIMIT_RATE_DOWN);
    epee_server server{epee::net_utils::e_connection_type_P2P};
    server.get_config_object().set_handler(&handler);
    server.get_config_object().m_invoke_timeout = 5s;
    ASSERT_TRUE(server.init_server(0, "127.0.0.1"));
    ASSERT_TRUE(server.run_server(2, false));
    const oxen::quic::Address epee_addr{
            "127.0.0.1", static_cast<uint16_t>(server.get_binded_port())};

    oxen::quic::Loop loop;
    std::shared_ptr<levin::connection> conn;
    std::promise<std::pair<uint32_t, std::string>> we_were_notified;
    {
        std::promise<bool> connected;
        loop.call([&] {
            levin::connect(loop, epee_addr, std::nullopt, 5s, 50'000'000, [&](auto c) {
                conn = std::move(c);
                if (conn)
                    conn->set_handlers(
                            {.on_invoke =
                                     [](levin::connection&, uint32_t cmd, std::string body) {
                                         return std::pair{
                                                 static_cast<int32_t>(cmd) * 2,
                                                 body + " (from us)"};
                                     },
                             .on_notify =
                                     [&](levin::connection&, uint32_t cmd, std::string body) {
                                         we_were_notified.set_value({cmd, std::move(body)});
                                     }});
                connected.set_value(conn != nullptr);
            });
        });
        auto f = connected.get_future();
        ASSERT_TRUE(get(f));
    }
    auto id_future = handler.connected.get_future();
    const auto epee_conn_id = get(id_future);
    auto& epee_config = server.get_config_object();

    // We invoke epee
    {
        std::promise<std::pair<int32_t, std::string>> reply;
        loop.call([&] {
            conn->invoke(100, bytes("hello"), 5s, [&](int32_t code, std::string body) {
                reply.set_value({code, std::move(body)});
            });
        });
        auto f = reply.get_future();
        EXPECT_EQ(get(f), std::make_pair(101, "hello (from epee)"s));
    }

    // We notify epee
    {
        loop.call([&] { conn->notify(200, bytes("note")); });
        auto f = handler.notified.get_future();
        EXPECT_EQ(get(f), std::make_pair(200, "note"s));
    }

    // epee invokes us, with a body big enough that epee sends it in chunks, and gets a big reply
    {
        const std::string big(1'000'000, 'e');
        std::promise<std::pair<int, size_t>> reply;
        int r = epee_config.invoke_async(
                300,
                bytes(big),
                epee_conn_id,
                [&](int code, std::span<const uint8_t> buff, epee_context&) {
                    reply.set_value({code, buff.size()});
                },
                5s);
        EXPECT_EQ(r, 1);
        auto f = reply.get_future();
        EXPECT_EQ(get(f), std::make_pair(600, big.size() + " (from us)"s.size()));
    }

    // epee notifies us
    {
        epee_config.notify(400, bytes("from epee"), epee_conn_id);
        auto f = we_were_notified.get_future();
        EXPECT_EQ(get(f), std::make_pair(400u, "from epee"s));
    }

    loop.call_get([&] { conn.reset(); });
    server.send_stop_signal();
    EXPECT_TRUE(server.server_stop());
}

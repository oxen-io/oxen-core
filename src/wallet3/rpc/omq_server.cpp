#include "omq_server.h"

#include <oxenc/variant.h>
#include <oxenmq/auth.h>
#include <oxenmq/oxenmq.h>

#include <wallet3/config/config.hpp>

#include "commands.h"
#include "request_handler.h"

// TODO: get logging working in wallet3 and remove this
#include <iostream>

namespace {

// OMQ RPC responses consist of [CODE, DATA] for code we (partially) mimic HTTP error codes: 200
// means success, anything else means failure.  (We don't have codes for Forbidden or Not Found
// because those happen at the OMQ protocol layer).
constexpr std::string_view OMQ_OK{"200"sv}, OMQ_BAD_REQUEST{"400"sv}, OMQ_ERROR{"500"sv};

}  // anonymous namespace

namespace wallet::rpc {

using namespace cryptonote::rpc;
using oxenmq::AuthLevel;

void OmqServer::set_omq(std::shared_ptr<oxenmq::OxenMQ> omq_in, wallet::rpc::Config config) {
    omq = omq_in;

    omq->listen_plain("ipc://"s + config.sockname);

    // TODO: parametrize auth
    omq->add_category(
            "rpc", AuthLevel::none, 0 /*no reserved threads*/, 100 /*max queued requests*/);
    // TODO: actually make restricted category require auth
    omq->add_category(
            "restricted", AuthLevel::none, 0 /*no reserved threads*/, 100 /*max queued requests*/);
    // TODO: admin commands for wallet RPC?
    // omq->add_category("admin", oxenmq::AuthLevel::admin, 1 /* one reserved admin command thread
    // */);
    for (auto& cmd : rpc_commands) {
        omq->add_request_command(
                cmd.second->is_restricted ? "restricted" : "rpc",
                cmd.first,
                [name = std::string_view{cmd.first}, &call = *cmd.second, this](
                        oxenmq::Message& m) {
                    if (m.data.size() > 1)
                        m.send_reply(
                                OMQ_BAD_REQUEST,
                                "Bad request: RPC commands must have at most one data part "
                                "(received " +
                                        std::to_string(m.data.size()) + ")");

                    rpc_request request{};
                    request.context.admin = m.access.auth >= AuthLevel::admin;
                    request.context.source = rpc_source::omq;
                    request.context.remote = m.remote;
                    if (!m.data.empty())
                        request.body = m.data[0];

                    try {
                        auto result = var::visit(
                                [](auto&& v) -> std::string {
                                    using T = decltype(v);
                                    if constexpr (std::is_same_v<oxenc::bt_value&&, T>)
                                        return bt_serialize(std::move(v));
                                    else if constexpr (std::is_same_v<nlohmann::json&&, T>)
                                        return v.dump();
                                    else {
                                        static_assert(std::is_same_v<std::string&&, T>);
                                        return std::move(v);
                                    }
                                },
                                call.invoke(std::move(request), request_handler));
                        m.send_reply(OMQ_OK, std::move(result));
                        return;
                    } catch (const parse_error& e) {
                        // This isn't really WARNable as it's the client fault; log at info level
                        // instead.
                        //
                        // TODO: for various parsing errors there are still some stupid forced
                        // ERROR-level warnings that get generated deep inside epee, for example
                        // when passing a string or number instead of a JSON object.  If you want to
                        // find some, `grep number2 epee` (for real).
                        std::cout << "OMQ RPC request '"
                                  << (call.is_restricted ? "restricted." : "rpc.") << name
                                  << "' called with invalid/unparseable data: " << e.what() << "\n";
                        m.send_reply(OMQ_BAD_REQUEST, "Unable to parse request: "s + e.what());
                        return;
                    } catch (const rpc_error& e) {
                        std::cout << "OMQ RPC request '"
                                  << (call.is_restricted ? "restricted." : "rpc.") << name
                                  << "' failed with: " << e.what() << "\n";
                        m.send_reply(OMQ_ERROR, e.what());
                        return;
                    } catch (const std::exception& e) {
                        std::cout << "OMQ RPC request '"
                                  << (call.is_restricted ? "restricted." : "rpc.") << name
                                  << "' "
                                     "raised an exception: "
                                  << e.what() << "\n";
                    } catch (...) {
                        std::cout << "OMQ RPC request '"
                                  << (call.is_restricted ? "restricted." : "rpc.") << name
                                  << "' "
                                     "raised an unknown exception"
                                  << "\n";
                    }
                    // Don't include the exception message in case it contains something that we
                    // don't want go back to the user.  If we want to support it eventually we could
                    // add some sort of `rpc::user_visible_exception` that carries a message to send
                    // back to the user.
                    m.send_reply(OMQ_ERROR, "An exception occured while processing your request");
                });
    }
}

}  // namespace wallet::rpc

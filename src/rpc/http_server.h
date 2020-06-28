// Copyright (c) 2018-2020, The Loki Project
// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <uWebSockets/App.h>
#include "common/command_line.h"
#include "common/password.h"
#include "core_rpc_server.h"

namespace cryptonote::rpc {

  using HttpRequest = uWS::HttpRequest;
  using HttpResponse = uWS::HttpResponse<false/*SSL*/>;

  using http_response_code = std::pair<int, std::string_view>;

  /************************************************************************/
  /* Core HTTP RPC server                                                 */
  /************************************************************************/
  class http_server
  {
  public:
    static const command_line::arg_descriptor<uint16_t, false, true, 2> arg_rpc_bind_port;
    static const command_line::arg_descriptor<uint16_t> arg_rpc_restricted_bind_port;
    static const command_line::arg_descriptor<bool> arg_restricted_rpc;
    static const command_line::arg_descriptor<bool> arg_public_node;

    static void init_options(boost::program_options::options_description& desc);

    http_server(
        core_rpc_server& server,
        const boost::program_options::variables_map& vm,
        const bool restricted,
        uint16_t port
        );

    ~http_server();

    /// Starts the event loop in the thread handling http requests.  Core must have been initialized
    /// and LokiMQ started.  Will propagate an exception from the thread if startup fails.
    void start();

    /// Closes the http server connection.  Can safely be called multiple times, or to abort a
    /// startup if called before start().
    ///
    /// \param join - if true, wait for the proxy thread to exit.  If false then joining will occur
    /// during destruction.
    void shutdown(bool join = false);

    /// Checks for required authentication, if enabled.  If authentication fails, sets a "failed"
    /// response and returns false; if authentication isn't required or passes, returns true (and
    /// doesn't touch the response).
    bool check_auth(HttpRequest& req, HttpResponse& res);

    /// Handles a request for a base url, e.g. /foo (but not /json_rpc).  `call` is the callback
    /// we've already mapped the request to; restricted commands have also already been rejected
    /// (unless the RPC is unrestricted).
    void handle_base_request(
        HttpResponse& res,
        HttpRequest& req,
        const rpc_command& call);

    /// Handles a POST request to /json_rpc.
    void handle_json_rpc_request(HttpResponse& res, HttpRequest& req);

    // Posts a callback to the uWebSockets thread loop controlling this connection; all writes must
    // be done from that thread, and so this method is provided to defer a callback from another
    // thread into that one.  The function should have signature `void ()`.
    template <typename Func>
    void loop_defer(Func&& f) {
      m_loop->defer(std::forward<Func>(f));
    }

    // Sends an error response and finalizes the response.  If body is empty, uses the default error
    // response text.
    void error_response(
        HttpResponse& res,
        http_response_code code,
        std::optional<std::string_view> body = std::nullopt) const;

    // Similar to the above, but for JSON RPC requests: we send "200 OK" at the HTTP layer; the
    // error code and message gets encoded in JSON inside the response body.
    void jsonrpc_error_response(
        HttpResponse& res,
        int code,
        std::string message,
        std::optional<epee::serialization::storage_entry> = std::nullopt) const;

    const std::string& server_header() { return m_server_header; }

  private:

    void create_rpc_endpoints(uWS::App& http);

    // The core rpc server which handles the internal requests
    core_rpc_server& m_server;
    // The uWebSockets event loop pointer (so that we can inject a callback to shut it down)
    uWS::Loop* m_loop{nullptr};
    // The socket(s) we are listening on
    std::vector<us_listen_socket_t*> m_listen_socks;
    // The thread in which the uWebSockets event listener is running
    std::thread m_rpc_thread;
    // A promise we send from outside into the event loop thread to signal it to start.  We sent
    // "true" to go ahead with binding + starting the event loop, or false to abort.
    std::promise<bool> m_startup_promise;
    // A future (promise held by the thread) that delivers us the listening uSockets sockets so
    // that, when we want to shut down, we can tell uWebSockets to close them (which will then run
    // off the end of the event loop).  This also doubles to propagate listen exceptions back to us.
    std::future<std::vector<us_listen_socket_t*>> m_startup_success;
    // Whether we have sent the startup/shutdown signals
    bool m_sent_startup{false}, m_sent_shutdown{false};
    // An optional required login for this HTTP RPC interface
    std::optional<tools::login> m_login;
    // Whether this is restricted, i.e. public.  Unrestricted allows admin commands.
    bool m_restricted;
    // Cached string we send for the Server header; full version if unrestricted, just the major
    // version if restricted
    std::string m_server_header;
  };

} // namespace cryptonote::rpc

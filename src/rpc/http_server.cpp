
#include "http_server.h"
#include <chrono>
#include <exception>
#include <oxenc/variant.h>
#include "common/command_line.h"
#include "common/string_util.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "epee/net/jsonrpc_structs.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/rpc_args.h"
#include "version.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "daemon.rpc"

namespace cryptonote::rpc {

  const command_line::arg_descriptor<std::vector<std::string>> http_server::arg_rpc_public{
    "rpc-public",
    "Specifies an IP:PORT to listen on for public (restricted) RPC requests; can be specified multiple times."
  };

  const command_line::arg_descriptor<std::vector<std::string>, false, true, 2> http_server::arg_rpc_admin{
    "rpc-admin",
    "Specifies an IP:PORT to listen on for admin (unrestricted) RPC requests; can be specified multiple times. Specify \"none\" to disable.",
    {"127.0.0.1:" + std::to_string(config::RPC_DEFAULT_PORT), "[::1]:" + std::to_string(config::RPC_DEFAULT_PORT)},
    {{ &cryptonote::arg_testnet_on, &cryptonote::arg_devnet_on }},
    [](std::array<bool, 2> testnet_devnet, bool defaulted, std::vector<std::string> val) {
      auto& [testnet, devnet] = testnet_devnet;
      if (defaulted && (testnet || devnet)) {
        auto port = std::to_string(testnet ? config::testnet::RPC_DEFAULT_PORT : config::devnet::RPC_DEFAULT_PORT);
        val = {"127.0.0.1:" + port, "[::1]:" + port};
      }
      return val;
    }
  };

  const command_line::arg_descriptor<uint16_t> http_server::arg_rpc_bind_port = {
      "rpc-bind-port",
      "Port for RPC server; deprecated, use --rpc-public or --rpc-admin instead.",
      0
  };

  const command_line::arg_descriptor<uint16_t> http_server::arg_rpc_restricted_bind_port = {
      "rpc-restricted-bind-port"
    , "Port for restricted RPC server; deprecated, use --rpc-public instead"
    , 0
    };

  const command_line::arg_descriptor<bool> http_server::arg_restricted_rpc = {
      "restricted-rpc"
    , "Deprecated, use --rpc-public instead"
    , false
    };

  // This option doesn't do anything anymore, but keep it here for now in case people added it to
  // config files/startup flags.
  const command_line::arg_descriptor<bool> http_server::arg_public_node = {
      "public-node"
    , "Deprecated; use --rpc-public option instead"
    , false
    };

  namespace { void long_poll_trigger(cryptonote::tx_memory_pool&); }

  //-----------------------------------------------------------------------------------
  void http_server::init_options(boost::program_options::options_description& desc, boost::program_options::options_description& hidden)
  {
    command_line::add_arg(desc, arg_rpc_public);
    command_line::add_arg(desc, arg_rpc_admin);

    command_line::add_arg(hidden, arg_rpc_bind_port);
    command_line::add_arg(hidden, arg_rpc_restricted_bind_port);
    command_line::add_arg(hidden, arg_restricted_rpc);
    command_line::add_arg(hidden, arg_public_node);

    cryptonote::long_poll_trigger = long_poll_trigger;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  http_server::http_server(
      core_rpc_server& server,
      rpc_args rpc_config,
      bool restricted,
      std::vector<std::tuple<std::string, uint16_t, bool>> bind)
    : m_server{server}, m_restricted{restricted}
  {
    // uWS is designed to work from a single thread, which is good (we pull off the requests and
    // then stick them into the LMQ job queue to be scheduled along with other jobs).  But as a
    // consequence, we need to create everything inside that thread.  We *also* need to get the
    // (thread local) event loop pointer back from the thread so that we can shut it down later
    // (injecting a callback into it is one of the few thread-safe things we can do across threads).
    //
    // Things we need in the owning thread, fulfilled from the http thread:

    // - the uWS::Loop* for the event loop thread (which is thread_local).  We can get this during
    //   thread startup, after the thread does basic initialization.
    std::promise<uWS::Loop*> loop_promise;
    auto loop_future = loop_promise.get_future();

    // - the us_listen_socket_t* on which the server is listening.  We can't get this until we
    //   actually start listening, so wait until `start()` for it.  (We also double-purpose it to
    //   send back an exception if one fires during startup).
    std::promise<std::vector<us_listen_socket_t*>> startup_success_promise;
    m_startup_success = startup_success_promise.get_future();

    // Things we need to send from the owning thread to the event loop thread:
    // - a signal when the thread should bind to the port and start the event loop (when we call
    //   start()).
    //m_startup_promise

    m_rpc_thread = std::thread{[this, rpc_config=std::move(rpc_config), bind=std::move(bind)] (
        std::promise<uWS::Loop*> loop_promise,
        std::future<bool> startup_future,
        std::promise<std::vector<us_listen_socket_t*>> startup_success) {
      uWS::App http;
      try {
        create_rpc_endpoints(http);
      } catch (...) {
        loop_promise.set_exception(std::current_exception());
        return;
      }
      loop_promise.set_value(uWS::Loop::get());
      if (!startup_future.get())
        // False means cancel, i.e. we got destroyed/shutdown without start() being called
        return;

      m_login = rpc_config.login;

      m_cors = {rpc_config.access_control_origins.begin(), rpc_config.access_control_origins.end()};

      std::vector<us_listen_socket_t*> listening;
      try {
        bool required_bind_failed = false;
        for (const auto& [addr, port, required] : bind)
          http.listen(addr, port, [&listening, req=required, &required_bind_failed](us_listen_socket_t* sock) {
            if (sock) listening.push_back(sock);
            else if (req) required_bind_failed = true;
          });

        if (listening.empty() || required_bind_failed) {
          std::ostringstream error;
          error << "RPC HTTP server failed to bind; ";
          if (listening.empty()) error << "no valid bind address(es) given";
          error << "tried to bind to:";
          for (const auto& [addr, port, required] : bind)
            error << ' ' << addr << ':' << port;
          throw std::runtime_error(error.str());
        }
      } catch (...) {
        startup_success.set_exception(std::current_exception());
        return;
      }
      startup_success.set_value(std::move(listening));

      http.run();
    }, std::move(loop_promise), m_startup_promise.get_future(), std::move(startup_success_promise)};

    m_loop = loop_future.get();
  }

  void http_server::create_rpc_endpoints(uWS::App& http)
  {
    auto access_denied = [this](HttpResponse* res, HttpRequest* req) {
      MINFO("Forbidden HTTP request for restricted endpoint " << req->getMethod() << " " << req->getUrl());
      error_response(*res, HTTP_FORBIDDEN);
    };

    for (auto& [name, call] : rpc_commands) {
      if (call->is_legacy || call->is_binary) {
        if (!call->is_public && m_restricted)
          http.any("/" + name, access_denied);
        else
          http.any("/" + name, [this, &call=*call](HttpResponse* res, HttpRequest* req) {
            if (m_login && !check_auth(*req, *res))
              return;
            handle_base_request(*res, *req, call);
          });
      }
    }
    http.post("/json_rpc", [this](HttpResponse* res, HttpRequest* req) {
      if (m_login && !check_auth(*req, *res))
        return;
      handle_json_rpc_request(*res, *req);
    });

    // Fallback to send a 404 for anything else:
    http.any("/*", [this](HttpResponse* res, HttpRequest* req) {
      if (m_login && !check_auth(*req, *res))
        return;
      MINFO("Invalid HTTP request for " << req->getMethod() << " " << req->getUrl());
      error_response(*res, HTTP_NOT_FOUND);
    });
  }

  namespace {

  struct call_data {
    http_server& http;
    core_rpc_server& core_rpc;
    HttpResponse& res;
    std::string uri;
    const rpc_command* call{nullptr};
    rpc_request request{};
    bool aborted{false};
    bool replied{false};
    bool jsonrpc{false};
    std::string jsonrpc_id; // pre-formatted json value
    std::vector<std::pair<std::string, std::string>> extra_headers; // Extra headers to send

    // If we have to drop the request because we are overloaded we want to reply with an error (so
    // that we close the connection instead of leaking it and leaving it hanging).  We don't do
    // this, of course, if the request got aborted and replied to.
    ~call_data() {
      if (replied || aborted) return;
      http.loop_defer([&http=http, &res=res, jsonrpc=jsonrpc] {
        if (jsonrpc)
          http.jsonrpc_error_response(res, -32003, "Server busy, try again later");
        else
          http.error_response(res, http_server::HTTP_SERVICE_UNAVAILABLE, "Server busy, try again later");
      });
    }

    call_data(const call_data&) = delete;
    call_data(call_data&&) = delete;
    call_data& operator=(const call_data&) = delete;
    call_data& operator=(call_data&&) = delete;

    // Wrappers around .http.jsonrpc_error_response and .http.error_response that do nothing if the
    // request is already replied to, and otherwise set `replied` and forward everything passed in
    // to http.<method>(...).
    template <typename... T>
    auto jsonrpc_error_response(T&&... args) {
        if (replied || aborted) return;
        replied = true;
        return http.jsonrpc_error_response(std::forward<T>(args)...);
    }
    template <typename... T>
    auto error_response(T&&... args) {
        if (replied || aborted) return;
        replied = true;
        return http.error_response(std::forward<T>(args)...);
    }
  };

  // Queues a response for the HTTP thread to handle; the response can be in multiple string pieces
  // to be concatenated together.
  void queue_response(std::shared_ptr<call_data> data, std::vector<std::string> body)
  {
    auto& http = data->http;
    data->replied = true;
    http.loop_defer([data=std::move(data), body=std::move(body)] {
      if (data->aborted)
        return;
      data->res.cork([data=std::move(data), body=std::move(body)] {
        auto& res = data->res;
        res.writeHeader("Server", data->http.server_header());
        res.writeHeader("Content-Type", data->call->is_binary ? "application/octet-stream"sv : "application/json"sv);
        if (data->http.closing()) res.writeHeader("Connection", "close");
        for (const auto& [name, value] : data->extra_headers)
          res.writeHeader(name, value);

        for (const auto& piece : body)
          res.write(piece);

        res.end();
        if (data->http.closing()) res.close();
      });
    });
  }

  // Wrapper around the above that takes a single string
  void queue_response(std::shared_ptr<call_data> data, std::string body)
  {
    std::vector<std::string> b;
    b.push_back(std::move(body));
    queue_response(std::move(data), std::move(b));
  }

  void invoke_txpool_hashes_bin(std::shared_ptr<call_data> data);

  // Invokes the actual RPC request; this is called (via oxenmq) from some random LMQ worker thread,
  // which means we can't just write our reply; instead we have to post it to the uWS loop.
  void invoke_rpc(std::shared_ptr<call_data> dataptr)
  {
    auto& data = *dataptr;
    if (data.aborted) return;

    // Replace the default tx pool hashes callback with our own (which adds long poll support):
    if (std::string_view{data.uri}.substr(1) == rpc::GET_TRANSACTION_POOL_HASHES_BIN::names()[0])
      return invoke_txpool_hashes_bin(std::move(dataptr));

    const bool time_logging = LOG_ENABLED(Debug);
    std::chrono::steady_clock::time_point start;
    if (time_logging)
      start = std::chrono::steady_clock::now();

    std::vector<std::string> result;
    result.reserve(data.jsonrpc ? 3 : 1);
    if (data.jsonrpc)
    {
      result.emplace_back(R"({"jsonrpc":"2.0","id":)");
      result.back() += data.jsonrpc_id;
      result.back() += R"(,"result":)";
    }

    int json_error = -32603;
    std::string json_message = "Internal error";
    std::string http_message;

    try {
      result.push_back(data.call->invoke(std::move(data.request), data.core_rpc));
      json_error = 0;
    } catch (const parse_error& e) {
      // This isn't really WARNable as it's the client fault; log at info level instead.
      MINFO("HTTP RPC request '" << data.uri << "' called with invalid/unparseable data: " << e.what());
      json_error = -32602;
      http_message = "Unable to parse request: "s + e.what();
      json_message = "Invalid params";
    } catch (const rpc_error& e) {
      MWARNING("HTTP RPC request '" << data.uri << "' failed with: " << e.what());
      json_error = e.code;
      json_message = e.message;
      http_message = e.message;
    } catch (const std::exception& e) {
      MWARNING("HTTP RPC request '" << data.uri << "' raised an exception: " << e.what());
    } catch (...) {
      MWARNING("HTTP RPC request '" << data.uri << "' raised an unknown exception");
    }

    if (json_error != 0) {
      data.http.loop_defer([data=std::move(dataptr), json_error, msg=std::move(data.jsonrpc ? json_message : http_message)] {
        if (data->jsonrpc)
          data->jsonrpc_error_response(data->res, json_error, msg);
        else
          data->error_response(data->res, http_server::HTTP_ERROR, msg.empty() ? std::nullopt : std::make_optional<std::string_view>(msg));
      });
      return;
    }

    if (data.jsonrpc)
      result.emplace_back("}\n");

    std::string call_duration;
    if (time_logging)
      call_duration = " in " + tools::friendly_duration(std::chrono::steady_clock::now() - start);
    if (LOG_ENABLED(Info)) {
      size_t bytes = 0;
      for (const auto& r : result) bytes += r.size();
      MINFO("HTTP RPC " << data.uri << " [" << data.request.context.remote << "] OK (" << bytes << " bytes)" << call_duration);
    }

    queue_response(std::move(dataptr), std::move(result));
  }

  std::string pool_hashes_response(std::vector<crypto::hash>&& pool_hashes) {
    GET_TRANSACTION_POOL_HASHES_BIN::response res{};
    res.tx_hashes = std::move(pool_hashes);
    res.status = STATUS_OK;

    std::string response;
    epee::serialization::store_t_to_binary(res, response);
    return response;
  }

  std::list<std::pair<std::shared_ptr<call_data>, std::chrono::steady_clock::time_point>> long_pollers;
  std::mutex long_poll_mutex;

  // HTTP-only long-polling support for the transaction pool hashes command
  void invoke_txpool_hashes_bin(std::shared_ptr<call_data> data) {
    GET_TRANSACTION_POOL_HASHES_BIN::request req{};
    std::string_view body;
    if (auto body_sv = data->request.body_view())
      body = *body_sv;
    else
      throw parse_error{"Internal error: got unexpected request body type"};

    if (!epee::serialization::load_t_from_binary(req, body))
      throw parse_error{"Failed to parse binary data parameters"};

    std::vector<crypto::hash> pool_hashes;
    data->core_rpc.get_core().get_pool().get_transaction_hashes(pool_hashes, data->request.context.admin, req.blinked_txs_only /*include_only_blinked*/);

    if (req.long_poll)
    {
      crypto::hash checksum{};
      for (const auto& h : pool_hashes) checksum ^= h;

      if (req.tx_pool_checksum == checksum) {
        // Hashes match, which means we need to defer this request until later.
        std::lock_guard lock{long_poll_mutex};
        MTRACE("Deferring long poll request from " << data->request.context.remote << ": long polling requested and remote's checksum matches current pool (" << checksum << ")");
        long_pollers.emplace_back(std::move(data), std::chrono::steady_clock::now() + GET_TRANSACTION_POOL_HASHES_BIN::long_poll_timeout);
        return;
      }

      MTRACE("Ignoring long poll request from " << data->request.context.remote << ": pool hash mismatch (remote: " << req.tx_pool_checksum << ", local: " << checksum << ")");
    }

    // Either not a long poll request or checksum didn't match
    queue_response(std::move(data), pool_hashes_response(std::move(pool_hashes)));
  }

  // This get invoked (from cryptonote_core.cpp) whenever the mempool is added to.  We queue
  // responses for everyone currently waiting.
  void long_poll_trigger(tx_memory_pool &pool) {
    std::lock_guard lock{long_poll_mutex};
    if (long_pollers.empty())
      return;

    MDEBUG("TX pool changed; sending tx pool to " << long_pollers.size() << " pending long poll connections");

    std::optional<std::string> body_public, body_admin;

    for (auto& [dataptr, expiry]: long_pollers)
    {
      auto& data = *dataptr;
      auto& body = data.request.context.admin ? body_admin : body_public;
      if (!body)
      {
        std::vector<crypto::hash> pool_hashes;
        pool.get_transaction_hashes(pool_hashes, data.request.context.admin, true /*include_only_blinked*/);
        body = pool_hashes_response(std::move(pool_hashes));
      }
      MTRACE("Sending deferred long poll pool update to " << data.request.context.remote);
      queue_response(std::move(dataptr), *body);
    }
    long_pollers.clear();
  }

  std::string long_poll_timeout_body;

  // Called periodically to clear expired Starts up a periodic timer for checking for expired long poll requests.  We run this only once
  // a second because we don't really care if we time out at *precisely* 15 seconds.
  void long_poll_process_timeouts() {
    std::lock_guard lock{long_poll_mutex};

    if (long_pollers.empty())
      return;

    if (long_poll_timeout_body.empty())
    {
      GET_TRANSACTION_POOL_HASHES_BIN::response res{};
      res.status = STATUS_TX_LONG_POLL_TIMED_OUT;
      epee::serialization::store_t_to_binary(res, long_poll_timeout_body);
    }

    int count = 0;
    auto now = std::chrono::steady_clock::now();
    for (auto it = long_pollers.begin(); it != long_pollers.end(); )
    {
      if (it->second < now)
      {
        MTRACE("Sending long poll timeout to " << it->first->request.context.remote);
        queue_response(std::move(it->first), long_poll_timeout_body);
        it = long_pollers.erase(it);
        count++;
      }
      else
        ++it;
    }

    if (count > 0)
      MDEBUG("Timed out " << count << " long poll connections");
    else
      MTRACE("None of " << long_pollers.size() << " established long poll connections reached timeout");
  }

  } // anonymous namespace

  void http_server::handle_base_request(
        HttpResponse& res,
        HttpRequest& req,
        const rpc_command& call)
  {
    std::shared_ptr<call_data> data{new call_data{*this, m_server, res, std::string{req.getUrl()}, &call}};
    auto& request = data->request;
    request.body = ""s;
    request.context.admin = !m_restricted;
    request.context.source = rpc_source::http;
    request.context.remote = get_remote_address(res);
    handle_cors(req, data->extra_headers);
    MTRACE("Received " << req.getMethod() << " " << req.getUrl() << " request from " << request.context.remote);

    res.onAborted([data] { data->aborted = true; });
    res.onData([data=std::move(data)](std::string_view d, bool done) mutable {
      var::get<std::string>(data->request.body) += d;
      if (!done)
        return;

      auto& omq = data->core_rpc.get_core().get_omq();
      std::string cat{data->call->is_public ? "rpc" : "admin"};
      std::string cmd{"http:" + data->uri}; // Used for LMQ job logging; prefixed with http: so we can distinguish it
      std::string remote{data->request.context.remote};
      omq.inject_task(std::move(cat), std::move(cmd), std::move(remote), [data=std::move(data)] { invoke_rpc(std::move(data)); });
    });
  }

  void http_server::handle_json_rpc_request(HttpResponse& res, HttpRequest& req)
  {
    std::shared_ptr<call_data> data{new call_data{*this, m_server, res, std::string{req.getUrl()}}};
    data->jsonrpc = true;
    auto& request = data->request;
    request.context.admin = !m_restricted;
    request.context.source = rpc_source::http;
    request.context.remote = get_remote_address(res);
    handle_cors(req, data->extra_headers);

    res.onAborted([data] { data->aborted = true; });
    res.onData([buffer=""s, data, restricted=m_restricted](std::string_view d, bool done) mutable {
      if (!done) {
        buffer += d;
        return;
      }

      std::string_view body;
      if (buffer.empty())
        body = d; // bypass copying the string_view to a string
      else
        body = (buffer += d);

      auto& [ps, st_entry] = var::get<jsonrpc_params>(data->request.body = jsonrpc_params{});
      if(!ps.load_from_json(body))
        return data->jsonrpc_error_response(data->res, -32700, "Parse error");

      epee::serialization::storage_entry id{std::string{}};
      ps.get_value("id", id, nullptr);

      std::string method;
      if(!ps.get_value("method", method, nullptr))
      {
        MINFO("Invalid JSON RPC request from " << data->request.context.remote << ": no 'method' in request");
        return data->jsonrpc_error_response(data->res, -32600, "Invalid Request", id);
      }

      auto it = rpc_commands.find(method);
      if (it == rpc_commands.end() || it->second->is_binary)
      {
        MINFO("Invalid JSON RPC request from " << data->request.context.remote << ": method '" << method << "' is invalid");
        return data->jsonrpc_error_response(data->res, -32601, "Method not found", id);
      }

      data->call = it->second.get();
      if (restricted && !data->call->is_public)
      {
        MWARNING("Invalid JSON RPC request from " << data->request.context.remote << ": method '" << method << "' is restricted");
        return data->jsonrpc_error_response(data->res, 403, "Forbidden; this command is not available over public RPC", id);
      }

      MDEBUG("Incoming JSON RPC request for " << method << " from " << data->request.context.remote);

      {
        std::ostringstream o;
        epee::serialization::dump_as_json(o, id, 0 /*indent*/, false /*newlines*/);
        data->jsonrpc_id = o.str();
      }

      // Try to load "params" into a generic epee value; if it fails (because there is no "params")
      // then we replace request.body with an empty string (instead of the epee jsonrpc_params
      // alternative) to signal that no params were provided at all.
      if (!ps.get_value("params", st_entry, nullptr))
        data->request.body = ""sv;

      auto& omq = data->core_rpc.get_core().get_omq();
      std::string cat{data->call->is_public ? "rpc" : "admin"};
      std::string cmd{"jsonrpc:" + method}; // Used for LMQ job logging; prefixed with jsonrpc: so we can distinguish it
      std::string remote{data->request.context.remote};
      omq.inject_task(std::move(cat), std::move(cmd), std::move(remote), [data=std::move(data)] { invoke_rpc(std::move(data)); });
    });
  }

  static std::unordered_set<oxenmq::OxenMQ*> timer_started;

  void http_server::start()
  {
    if (m_sent_startup)
      throw std::logic_error{"Cannot call http_server::start() more than once"};

    auto net = m_server.nettype();
    m_server_header = "oxend/"s + (m_restricted ? std::to_string(OXEN_VERSION[0]) : std::string{OXEN_VERSION_FULL})
      + (net == network_type::MAINNET ? " mainnet" : net == network_type::TESTNET ? " testnet" : net == network_type::DEVNET ? " devnet" : net == network_type::FAKECHAIN ? " fakenet" : " unknown net");

    m_startup_promise.set_value(true);
    m_sent_startup = true;
    m_listen_socks = m_startup_success.get();

    auto& omq = m_server.get_core().get_omq();
    if (timer_started.insert(&omq).second)
      omq.add_timer(long_poll_process_timeouts, 1s);
  }

  void http_server::shutdown(bool join)
  {
    if (!m_rpc_thread.joinable())
      return;

    if (!m_sent_shutdown)
    {
      MTRACE("initiating shutdown");
      if (!m_sent_startup)
      {
        m_startup_promise.set_value(false);
        m_sent_startup = true;
      }
      else if (!m_listen_socks.empty())
      {
        loop_defer([this] {
          MTRACE("closing " << m_listen_socks.size() << " listening sockets");
          for (auto* s : m_listen_socks)
            us_listen_socket_close(/*ssl=*/false, s);
          m_listen_socks.clear();

          m_closing = true;

          {
            // Destroy any pending long poll connections as well
            MTRACE("closing pending long poll requests");
            std::lock_guard lock{long_poll_mutex};
            for (auto it = long_pollers.begin(); it != long_pollers.end(); )
            {
              if (&it->first->http != this)
                continue; // Belongs to some other http_server instance
              it->first->aborted = true;
              it->first->res.close();
              it = long_pollers.erase(it);
            }
          }
        });
      }
      m_sent_shutdown = true;
    }

    MTRACE("joining rpc thread");
    if (join)
      m_rpc_thread.join();
    MTRACE("done shutdown");
  }

  http_server::~http_server()
  {
    shutdown(true);
  }


} // namespace cryptonote::rpc

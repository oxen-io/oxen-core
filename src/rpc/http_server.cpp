
#include "http_server.h"
#include <chrono>
#include <exception>
#include <lokimq/base64.h>
#include <boost/endian/conversion.hpp>
#include "common/string_util.h"
#include "net/jsonrpc_structs.h" // epee
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/rpc_args.h"
#include "version.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon.rpc"

namespace cryptonote::rpc {

  /// Checks an Authorization header for Basic login credentials.
  ///
  /// We don't support Digest because it it is deprecated, expensive, and useless: any
  /// authentication should either be constrained to a localhost connection or done over HTTPS (in
  /// which case Basic is perfectly fine).  It's expensive in that it requires multiple requests in
  /// order to request a nonce, and requires considerable code to proper support (e.g. with nonce
  /// tracking, etc.).  Given that it adds nothing security-wise it it is not worth supporting.
  ///
  /// Takes the auth header and a callback to invoke to check the username/password which should
  /// return true if the user is allowed, false if denied.  The callback should be callable with two
  /// std::string_view's: username and password.
  template <typename Callback>
  std::optional<std::string_view> check_authorization(std::string_view auth_header, Callback check_login) {
    constexpr std::optional<std::string_view> fail = "Basic realm=\"lokid rpc\", charset=\"UTF-8\""sv;
    auto parts = tools::split_any(auth_header, " \t\r\n", true);
    if (parts.size() < 2 || parts[0] != "Basic"sv || !lokimq::is_base64(parts[1]))
      return fail;
    auto login = lokimq::from_base64(parts[1]);
    auto colon = login.find(':');
    if (colon == std::string_view::npos)
      return fail;
    if (check_login(std::string_view{login}.substr(0, colon), std::string_view{login}.substr(colon+1)))
      return std::nullopt;
    return fail;
  }


  const command_line::arg_descriptor<uint16_t, false, true, 2> http_server::arg_rpc_bind_port = {
      "rpc-bind-port"
    , "Port for RPC server"
    , config::RPC_DEFAULT_PORT
    , {{ &cryptonote::arg_testnet_on, &cryptonote::arg_stagenet_on }}
    , [](std::array<bool, 2> testnet_stagenet, bool defaulted, uint16_t val) {
        auto [testnet, stagenet] = testnet_stagenet;
        return
          (defaulted && testnet) ? config::testnet::RPC_DEFAULT_PORT :
          (defaulted && stagenet) ? config::stagenet::RPC_DEFAULT_PORT :
          val;
      }
    };

  const command_line::arg_descriptor<uint16_t> http_server::arg_rpc_restricted_bind_port = {
      "rpc-restricted-bind-port"
    , "Port for restricted RPC server"
    , 0
    };

  const command_line::arg_descriptor<bool> http_server::arg_restricted_rpc = {
      "restricted-rpc"
    , "Restrict RPC to view only commands and do not return privacy sensitive data in RPC calls"
    , false
    };

  const command_line::arg_descriptor<bool> http_server::arg_public_node = {
      "public-node"
    , "Allow other users to use the node as a remote (restricted RPC mode, view-only commands) and advertise it over P2P"
    , false
    };

  namespace { void long_poll_trigger(cryptonote::tx_memory_pool&); }

  //-----------------------------------------------------------------------------------
  void http_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_port);
    command_line::add_arg(desc, arg_rpc_restricted_bind_port);
    command_line::add_arg(desc, arg_restricted_rpc);
    command_line::add_arg(desc, arg_public_node);

    cryptonote::long_poll_trigger = long_poll_trigger;
  }

  static constexpr http_response_code
    HTTP_OK{200, "OK"sv},
    HTTP_BAD_REQUEST{400, "Bad Request"sv},
    HTTP_FORBIDDEN{403, "Forbidden"sv},
    HTTP_NOT_FOUND{404, "Not Found"sv},
    HTTP_ERROR{500, "Internal Server Error"sv},
    HTTP_SERVICE_UNAVAILABLE{503, "Service Unavailable"sv};


  // Sends an error response and finalizes the response.
  void http_server::error_response(
      HttpResponse& res,
      http_response_code code,
      std::optional<std::string_view> body) const {
    res.writeStatus(std::to_string(code.first) + " " + std::string{code.second});
    res.writeHeader("Server", m_server_header);
    res.writeHeader("Content-Type", "text/plain");
    if (body)
      res.end(*body);
    else
      res.end(std::string{code.second} + "\n");
  }

  // Similar to the above, but for JSON errors (which are 200 OK + error embedded in JSON)
  void http_server::jsonrpc_error_response(HttpResponse& res, int code, std::string message, std::optional<epee::serialization::storage_entry> id) const
  {
    epee::json_rpc::error_response rsp;
    rsp.jsonrpc = "2.0";
    if (id)
      rsp.id = *id;
    rsp.error.code = code;
    rsp.error.message = std::move(message);
    std::string body;
    epee::serialization::store_t_to_json(rsp, body);
    res.writeStatus("200 OK"sv);
    res.writeHeader("Server", m_server_header);
    res.writeHeader("Content-Type", "application/json");
    res.end(body);
  }

  //------------------------------------------------------------------------------------------------------------------------------
  http_server::http_server(
      core_rpc_server& server,
      const boost::program_options::variables_map& vm,
      const bool restricted,
      uint16_t port
      ) : m_server{server}, m_restricted{restricted}
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

    m_rpc_thread = std::thread{[this, rpc_config=cryptonote::rpc_args::process(vm), port] (
        std::promise<uWS::Loop*> loop_promise,
        std::future<bool> startup_future,
        std::promise<std::vector<us_listen_socket_t*>> startup_success) {
      uWS::App http;
      try {
        create_rpc_endpoints(http);
      } catch (...) {
        loop_promise.set_exception(std::current_exception());
      }
      loop_promise.set_value(uWS::Loop::get());
      if (!startup_future.get())
        // False means cancel, i.e. we got destroyed/shutdown without start() being called
        return;

      std::vector<std::pair<std::string /*addr*/, bool /*required*/>> bind_addr;
      if (!rpc_config.bind_ip.empty())
        bind_addr.emplace_back(rpc_config.bind_ip, rpc_config.require_ipv4);
      if (rpc_config.use_ipv6 && !rpc_config.bind_ipv6_address.empty())
        bind_addr.emplace_back(rpc_config.bind_ipv6_address, true);

      std::vector<us_listen_socket_t*> listening;
      try {
        bool bad = false;
        int good = 0;
        for (const auto& [addr, required] : bind_addr)
          http.listen(addr, port, [&listening, req=required, &good, &bad](us_listen_socket_t* sock) {
            listening.push_back(sock);
            if (sock != nullptr) good++;
            else if (req) bad = true;
          });

        if (!good || bad) {
          std::ostringstream error;
          error << "RPC HTTP server failed to bind; ";
          if (listening.empty()) error << "no valid bind address(es) given";
          else {
            error << "tried to bind to:";
            for (const auto& [addr, required] : bind_addr)
              error << ' ' << addr << ':' << port;
          }
          throw std::logic_error(error.str());
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

  bool http_server::check_auth(HttpRequest& req, HttpResponse& res)
  {
    if (auto www_auth = check_authorization(req.getHeader("authorization"),
          [this] (const std::string_view user, const std::string_view pass) {
            return user == m_login->username && pass == m_login->password.password().view(); }))
    {
      res.writeStatus("401 Unauthorized");
      res.writeHeader("Server", m_server_header);
      res.writeHeader("WWW-Authenticate", *www_auth);
      res.writeHeader("Content-Type", "text/plain");
      if (req.getMethod() != "HEAD"sv)
        res.end("Login required");
      return false;
    }
    return true;
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

    // If we have to drop the request because we are overloaded we want to reply with an error (so
    // that we close the connection instead of leaking it and leaving it hanging).  We don't do
    // this, of course, if the request got aborted and replied to.
    ~call_data() {
      if (replied || aborted) return;
      http.loop_defer([&http=http, &res=res, jsonrpc=jsonrpc] {
        if (jsonrpc)
          http.jsonrpc_error_response(res, -32003, "Server busy, try again later");
        else
          http.error_response(res, HTTP_SERVICE_UNAVAILABLE, "Server busy, try again later");
      });
    }

    call_data(const call_data&) = delete;
    call_data(call_data&&) = delete;
    call_data& operator=(const call_data&) = delete;
    call_data& operator=(call_data&&) = delete;
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
      data->res.cork([&res=data->res, &svr=data->http.server_header(), body=std::move(body), binary=data->call->is_binary] {
        res.writeHeader("Server", svr);
        res.writeHeader("Content-Type", binary ? "application/octet-stream"sv : "application/json"sv);
        for (const auto& piece : body)
          res.write(piece);
        res.end();
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

  // Invokes the actual RPC request; this is called (via lokimq) from some random LMQ worker thread,
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
    } catch (const std::exception& e) {
      MWARNING("HTTP RPC request '" << data.uri << "' raised an exception: " << e.what());
    } catch (...) {
      MWARNING("HTTP RPC request '" << data.uri << "' raised an unknown exception");
    }

    if (json_error != 0) {
      data.replied = true;
      data.http.loop_defer([data=std::move(dataptr), json_error, msg=std::move(data.jsonrpc ? json_message : http_message)] {
        if (data->aborted) return;
        if (data->jsonrpc)
          data->http.jsonrpc_error_response(data->res, json_error, msg);
        else
          data->http.error_response(data->res, HTTP_ERROR, msg.empty() ? std::nullopt : std::make_optional<std::string_view>(msg));
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
    if (!epee::serialization::load_t_from_binary(req, std::get<std::string_view>(data->request.body)))
      throw parse_error{"Failed to parse binary data parameters"};

    std::vector<crypto::hash> pool_hashes;
    data->core_rpc.get_core().get_pool().get_transaction_hashes(pool_hashes, data->request.context.admin);

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
        pool.get_transaction_hashes(pool_hashes, data.request.context.admin);
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

  std::string get_remote_address(HttpResponse& res) {
    std::ostringstream result;
    bool first = true;
    auto addr = res.getRemoteAddress();
    if (addr.size() == 4)
    { // IPv4, packed into bytes
      for (auto c : addr) {
        if (first) first = false;
        else result << '.';
        result << +static_cast<uint8_t>(c);
      }
    }
    else if (addr.size() == 16)
    {
      // IPv6, packed into bytes.  Interpret as a series of 8 big-endian shorts and convert to hex,
      // joined with :.  But we also want to drop leading insignificant 0's (i.e. '34f' instead of
      // '034f'), and we want to collapse the longest sequence of 0's that we come across (so that,
      // for example, localhost becomes `::1` instead of `0:0:0:0:0:0:0:1`).
      std::array<uint16_t, 8> a;
      std::memcpy(a.data(), addr.data(), 16);
      for (auto& x : a) boost::endian::big_to_native_inplace(x);

      size_t zero_start = 0, zero_end = 0;
      for (size_t i = 0, start = 0, end = 0; i < a.size(); i++) {
        if (a[i] != 0)
          continue;
        if (end != i) // This zero value starts a new zero sequence
          start = i;
        end = i + 1;
        if (end - start > zero_end - zero_start)
        {
          zero_end = end;
          zero_start = start;
        }
      }
      result << '[' << std::hex;
      for (size_t i = 0; i < a.size(); i++)
      {
        if (i >= zero_start && i < zero_end)
        {
          if (i == zero_start) result << "::";
          continue;
        }
        if (i > 0 && i != zero_end)
          result << ':';
        result << a[i];
      }
      result << ']';
    }
    else
      result << "{unknown:" << lokimq::to_hex(addr) << "}";
    return result.str();
  }

  } // anonymous namespace

  void http_server::handle_base_request(
        HttpResponse& res,
        HttpRequest& req,
        const rpc_command& call)
  {
    std::shared_ptr<call_data> data{new call_data{*this, m_server, res, std::string{req.getUrl()}, &call}};
    auto& request = data->request;
    request.context.admin = !m_restricted;
    request.context.source = rpc_source::http;
    request.context.remote = get_remote_address(res);
    MTRACE("Received " << req.getMethod() << " " << req.getUrl() << " request from " << request.context.remote);

    res.onAborted([data] { data->aborted = true; });
    res.onData([buffer=""s, data=std::move(data)](std::string_view d, bool done) mutable {
      if (!done) {
        buffer += d;
        return;
      }

      if (buffer.empty())
        data->request.body = d; // bypass copying the string_view to a string
      else
        data->request.body = (buffer += d);

      auto& lmq = data->core_rpc.get_core().get_lmq();
      std::string cat{data->call->is_public ? "rpc" : "admin"};
      std::string cmd{"http:" + data->uri}; // Used for LMQ job logging; prefixed with http: so we can distinguish it
      std::string remote{data->request.context.remote};
      lmq.inject_task(std::move(cat), std::move(cmd), std::move(remote), [data=std::move(data)] { invoke_rpc(std::move(data)); });
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

      auto& epee_stuff = std::get<jsonrpc_params>(data->request.body = jsonrpc_params{});
      auto& [ps, st_entry] = epee_stuff;
      if(!ps.load_from_json(body))
        return data->http.jsonrpc_error_response(data->res, -32700, "Parse error");

      epee::serialization::storage_entry id{std::string{}};
      ps.get_value("id", id, nullptr);

      std::string method;
      if(!ps.get_value("method", method, nullptr))
      {
        MINFO("Invalid JSON RPC request from " << data->request.context.remote << ": no 'method' in request");
        return data->http.jsonrpc_error_response(data->res, -32600, "Invalid Request", id);
      }

      auto it = rpc_commands.find(method);
      if (it == rpc_commands.end() || it->second->is_binary)
      {
        MINFO("Invalid JSON RPC request from " << data->request.context.remote << ": method '" << method << "' is invalid");
        return data->http.jsonrpc_error_response(data->res, -32601, "Method not found", id);
      }

      data->call = it->second.get();
      if (restricted && !data->call->is_public)
      {
        MWARNING("Invalid JSON RPC request from " << data->request.context.remote << ": method '" << method << "' is restricted");
        return data->http.jsonrpc_error_response(data->res, 403, "Forbidden; this command is not available over public RPC", id);
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
      if (!ps.get_value("params", epee_stuff.second, nullptr))
        data->request.body = ""sv;

      auto& lmq = data->core_rpc.get_core().get_lmq();
      std::string cat{data->call->is_public ? "rpc" : "admin"};
      std::string cmd{"jsonrpc:" + method}; // Used for LMQ job logging; prefixed with jsonrpc: so we can distinguish it
      std::string remote{data->request.context.remote};
      lmq.inject_task(std::move(cat), std::move(cmd), std::move(remote), [data=std::move(data)] { invoke_rpc(std::move(data)); });
    });
  }

  static std::unordered_set<lokimq::LokiMQ*> timer_started;

  void http_server::start()
  {
    if (m_sent_startup)
      throw std::logic_error{"Cannot call http_server::start() more than once"};

    auto net = m_server.nettype();
    m_server_header = "lokid/"s + (m_restricted ? std::to_string(LOKI_VERSION[0]) : LOKI_VERSION_FULL)
      + (net == MAINNET ? " mainnet" : net == TESTNET ? " testnet" : net == STAGENET ? " stagenet" : net == FAKECHAIN ? " fakenet" : " unknown net");

    m_startup_promise.set_value(true);
    m_sent_startup = true;
    m_listen_socks = m_startup_success.get();

    auto& lmq = m_server.get_core().get_lmq();
    if (timer_started.insert(&lmq).second)
      lmq.add_timer(long_poll_process_timeouts, 1s);
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

#pragma once

#include <uWebSockets/App.h>
#include <future>
#include <unordered_set>
#include "storages/portable_storage.h"
#include "common/password.h"
#include "version.h"

namespace cryptonote::rpc {
  using namespace std::literals;

  using HttpRequest = uWS::HttpRequest;
  using HttpResponse = uWS::HttpResponse<false/*SSL*/>;

  using http_response_code = std::pair<int, std::string_view>;

  // Base class for common RPC server functionality used by both core rpc http server and
  // wallet_rpc_server.
  class http_server_base {
  public:

    std::string get_remote_address(HttpResponse& res);

    /// Checks for required authentication, if enabled.  If authentication fails, sets a "failed"
    /// response and returns false; if authentication isn't required or passes, returns true (and
    /// doesn't touch the response).
    bool check_auth(HttpRequest& req, HttpResponse& res);

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

    // Posts a callback to the uWebSockets thread loop controlling this connection; all writes must
    // be done from that thread, and so this method is provided to defer a callback from another
    // thread into that one.  The function should have signature `void ()`.
    template <typename Func>
    void loop_defer(Func&& f) {
      m_loop->defer(std::forward<Func>(f));
    }

    const std::string& server_header() { return m_server_header; }

    static constexpr http_response_code
      HTTP_OK{200, "OK"sv},
      HTTP_BAD_REQUEST{400, "Bad Request"sv},
      HTTP_FORBIDDEN{403, "Forbidden"sv},
      HTTP_NOT_FOUND{404, "Not Found"sv},
      HTTP_ERROR{500, "Internal Server Error"sv},
      HTTP_SERVICE_UNAVAILABLE{503, "Service Unavailable"sv};

  protected:

    virtual void create_rpc_endpoints(uWS::App& http) = 0;

    /// handles cors headers by adding any needed headers to the given vector
    void handle_cors(HttpRequest& req, std::vector<std::pair<std::string, std::string>>& extra_headers);

    // The uWebSockets event loop pointer (so that we can inject a callback to shut it down)
    uWS::Loop* m_loop{nullptr};
    // The socket(s) we are listening on
    std::vector<us_listen_socket_t*> m_listen_socks;
    // The thread in which the uWebSockets event listener is running
    std::thread m_rpc_thread;
    // An optional required login for this HTTP RPC interface
    std::optional<tools::login> m_login;
    // Cached string we send for the Server header
    std::string m_server_header = "Loki RPC HTTP/"s + LOKI_VERSION_STR;
    // Access-Control-Allow-Origin header values; if one of these match the incoming Origin header
    // we return it in the ACAO header; otherwise (or if this is empty) we omit the header entirely.
    std::unordered_set<std::string> m_cors;
    // If true then always reply with 'Access-Control-Allow-Origin: *' to allow anything.
    bool m_cors_any = false;
  };
}

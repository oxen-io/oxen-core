
#include "http_server_base.h"
#include <lokimq/base64.h>
#include <lokimq/hex.h>
#include "common/string_util.h"

// epee:
#include "net/jsonrpc_structs.h"
#include "storages/portable_storage_template_helper.h"

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
  /// std::string_view's: username and password.  The realm should be a simple string (no quotes).
  template <typename Callback>
  std::optional<std::string> check_authorization(std::string_view auth_header, std::string_view realm, Callback check_login) {
    std::string fail = "Basic realm=\"" + std::string{realm} + "\", charset=\"UTF-8\"";
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



  bool http_server_base::check_auth(HttpRequest& req, HttpResponse& res)
  {
    if (auto www_auth = check_authorization(req.getHeader("authorization"), "lokid rpc",
          [this] (const std::string_view user, const std::string_view pass) {
            return user == m_login->username && pass == m_login->password.password().view(); }))
    {
      res.writeStatus("401 Unauthorized");
      res.writeHeader("Server", m_server_header);
      res.writeHeader("WWW-Authenticate", *www_auth);
      res.writeHeader("Content-Type", "text/plain");
      if (req.getMethod() != "HEAD"sv)
        res.end("Login required\n");
      return false;
    }
    return true;
  }

  // Sends an error response and finalizes the response.
  void http_server_base::error_response(
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
  void http_server_base::jsonrpc_error_response(HttpResponse& res, int code, std::string message, std::optional<epee::serialization::storage_entry> id) const
  {
    epee::json_rpc::error_response rsp;
    rsp.jsonrpc = "2.0";
    if (id)
      rsp.id = *id;
    rsp.error.code = code;
    rsp.error.message = std::move(message);
    std::string body;
    epee::serialization::store_t_to_json(rsp, body);
    if (body.capacity() > body.size())
      body += '\n';
    res.writeStatus("200 OK"sv);
    res.writeHeader("Server", m_server_header);
    res.writeHeader("Content-Type", "application/json");
    res.end(body);
  }

  std::string http_server_base::get_remote_address(HttpResponse& res) {
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

  void http_server_base::handle_cors(HttpRequest& req, std::vector<std::pair<std::string, std::string>>& extra_headers) {
    if (m_cors_any)
      extra_headers.emplace_back("Access-Control-Allow-Origin", "*");
    else if (!m_cors.empty()) {
      if (std::string origin{req.getHeader("origin")}; !origin.empty() && m_cors.count(origin)) {
        extra_headers.emplace_back("Access-Control-Allow-Origin", "*");
        extra_headers.emplace_back("Vary", "Origin");
      }
    }
  }
}

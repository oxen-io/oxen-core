#pragma once
#include <chrono>
#include <stdexcept>
#include <mutex>
#include <shared_mutex>
#include <string_view>

#include "storages/portable_storage_template_helper.h"
#include "net/jsonrpc_structs.h"
#include "memwipe.h"

#include "common/meta.h"
#include "version.h"

#include <cpr/session.h>
#include <cpr/cprtypes.h>
#include <cpr/error.h>
#include <cpr/auth.h>

namespace cryptonote::rpc {

using namespace std::literals;


/// base class for all exceptions thrown by http_client
class http_client_error : public std::runtime_error {
public:
  http_client_error(const char* what) : std::runtime_error{what} {}
  http_client_error(const std::string& what) : std::runtime_error{what} {}
};


/// Exception class thrown on HTTP communication errors (for example, failure to connect).  `what()`
/// contains a description of the error, while `code` can be used to programmatically handle
/// different error conditions.
class http_client_connect_error : public http_client_error {
public:
  http_client_connect_error(const cpr::Error& err, const std::string& prefix);
  cpr::ErrorCode code; ///< The error code value as returned by cpr
};

/// Exception thrown if we fail to deserialize response data.  It can also be thrown if we fail to
/// *serialize* the request, though that is not common and indicates a fundamentally broken request
/// class.
class http_client_serialization_error : public http_client_error {
public:
  using http_client_error::http_client_error;
};

/// Exception class thrown for a request that receives an error response from the remote.  This can
/// either be an HTTP error response (i.e. did not receive status 200) or a JSON-RPC error.
class http_client_response_error : public http_client_error {
public:
  http_client_response_error(bool http_error, int64_t code, const std::string& what)
    : http_client_error(what), http_error{http_error}, code{code} {}
  bool http_error; // true for HTTP errors, false for JSON errors
  int64_t code;
};

/// Class for accessing a remote node for binary, json, or json rpc requests
///
/// This class is thread-safe but not multithreaded (i.e. only one thread can be making a request at
/// a time).  Parameters (such as base_url) have their own lock and can be set even while a request
/// is underway in another thread (the changed parameters will not take effect until the next
/// request).
class http_client
{
public:
  /// Constructs an http client.
  /// \param base_url - the base url for requests; see set_base_url().  If omitted here, it must be
  /// specified via set_base_url before making requests.
  explicit http_client(std::string base_url_ = "")
  {
    if (!base_url_.empty())
      set_base_url(std::move(base_url_));
    session.SetUserAgent("loki rpc client v"s + LOKI_VERSION_STR);
  }

  /// Sets the base_url to the given one. Will have / appended if it doesn't already end in /.  The
  /// URL must be a full URL, include protocol (http:// or https://).  This call does not validate
  /// the given URL: passing something invalid here will not be caught until you attempt to make a
  /// request.  (You can call parse_url if you want to perform some sanity checks first).
  void set_base_url(std::string base_url);

  /// Returns the current base URL
  std::string get_base_url() const;

  /// Parses the given url into [protocol, hostname, port, uri].  Throws http_client_error if the
  /// URL is not parseable.  For a literal IPv6 address (which must be surrounded in [ ]) the
  /// hostname is returned with the surrounding [ ].  Port is optional and will be set to 0 if
  /// not explicitly specified in the URL.
  ///
  /// Note that this does non-exhaustive validation of the url; it will catch common errors, but
  /// does not attempt to do complete URL validation.
  ///
  /// Example                                       Return value
  /// https://example.com:1234/some/path?foo        ["https", "example.com", 1234, "/some/path?foo"]
  /// blah://example.com                            ["blah", "example.com", 0, ""]
  /// example.com:1234/                             ["", "example.com", 1234, "/"]
  /// http://[a:b::1]:80/                           ["http", "[a:b::1]", 1234, "/"]
  static std::tuple<std::string, std::string, uint16_t, std::string> parse_url(const std::string& url);

  /// Parses the current base url by passing it to parse_url().  Equivalent to
  /// `parse_url(c.get_base_url())`, but slightly more efficient.
  std::tuple<std::string, std::string, uint16_t, std::string> parse_base_url() const;

  /// Replaces the timeout for future requests with the given value.  0 = no timeout.  Default is
  /// 15s.
  void set_timeout(std::chrono::milliseconds timeout);

  /// Gets the timeout.  0 = no timeout.
  std::chrono::milliseconds get_timeout() const;

  /// Attempts to cancel an existing request by resetting the active timeout to 1ms.  Note that any
  /// subsequent request will reset the active timeout to the current value configured via
  /// set_timeout().
  void cancel();

  /// Sets a username and password to use for authentication.  If both are empty then authentication
  /// is disabled.
  void set_auth(std::string_view username = ""sv, std::string_view password = ""sv);

  /// Sets a proxy server for http/https requests.  If empty, clears the current proxy.
  void set_proxy(std::string proxy = "");

  /// Returns the proxy server, if any.
  std::string get_proxy() const;

  /// Sets up HTTPS client certificate and key for connecting to a remote node that requires HTTPS
  /// client authentication (this is relatively uncommon).  Both values are the path to a
  /// PEM-encoded file.  If either are empty then HTTPS client certificates are disabled.
  void set_https_client_cert(std::string cert_path, std::string key_path);

  /// Specifies a CA certificate bundle file to use to verify the server's certificate instead of
  /// using the operating system's CA certificates.  This is typically used to verify self-signed
  /// certificates.  If the path is empty then the OS CA certificates are used.
  void set_https_cainfo(std::string cainfo_bundle_path);

  /// Disable HTTPS certificate validation.  This is a bad idea: it effectively makes HTTPS
  /// insecure.
  void set_insecure_https(bool insecure);

  /// Copies parameters (base url, timeout, authentication) from another http_client.
  void copy_params_from(const http_client& other);

  /// Makes a JSON-RPC request; that is, a POST request to /json_rpc with a proper JSON-RPC wrapper
  /// around the serialized json data as the body.  On a successful response the response is
  /// deserialized into a RPC::response which is returned.
  ///
  /// \tparam RPC - the RPC base class; subtypes RPC::request and RPC::response are used for the
  /// request and response, respectively.
  ///
  /// \param method - the end-point to be passed as the "method" parameter of the JSON-RPC request.
  /// \param req - the request to be serialized and sent as the JSON-RPC "params" value.
  ///
  /// \returns RPC::request, deserialized from the response.
  ///
  /// \throws rpc::http_client_error on connection-related failure
  /// \throws rpc::http_client_serialization_error on a serialization failure
  /// \throws rpc::http_client_response_error on a successful HTTP request that returns a json_rpc
  /// error, or on an HTTP request that returns an HTTP error code.
  template <typename RPC>
  typename RPC::response json_rpc(std::string_view method, const typename RPC::request& req)
  {
    epee::json_rpc::request<const typename RPC::request&> jsonrpc_req{"2.0", std::string{method}, json_rpc_id++, req};

    std::string req_serialized;
    if(!epee::serialization::store_t_to_json(jsonrpc_req, req_serialized))
      throw http_client_serialization_error{"Failed to serialize " + tools::type_name(typeid(typename RPC::request))
        + " for json_rpc request for " + std::string{method}};

    cpr::Response res = post("json_rpc", std::move(req_serialized), {{"Content-Type", "application/json; charset=utf-8"}});

    epee::json_rpc::response_with_error<typename RPC::response> resp{};
    if (!epee::serialization::load_t_from_json(resp, res.text))
      throw http_client_serialization_error{"Failed to deserialize response for json_rpc request for " + std::string{method}};

    if(resp.error.code || resp.error.message.size())
      throw http_client_response_error{false, resp.error.code,
        "JSON RPC returned an error response: " + (resp.error.message.empty() ? "(no message)" : resp.error.message)};

    return std::move(resp.result);
  }

  /// Makes a binary request; that is, a POST request to /target with the binary-serialized request
  /// as the body.  The response is binary-deserialized into a RPC::response which is returned.
  ///
  /// \tparam RPC - the RPC base class; subtypes RPC::request and RPC::response are used for the
  /// request and response, respectively.
  ///
  /// \param target - the end-point, without a leading /, to be concatenated with the base_url given
  /// construction.  For example "foo" used with a base url of "https://example.com" will post to
  /// https://example.com/foo.
  /// \param req - the request to be serialized and sent as JSON.
  ///
  /// \returns RPC::request, deserialized from the response.
  ///
  /// \throws rpc::http_client_error on connection-related failure
  /// \throws rpc::http_client_serialization_error on a serialization failure
  template <typename RPC>
  typename RPC::response binary(std::string_view target_, const typename RPC::request& req)
  {
    std::string target{target_};
    std::string req_serialized;
    if(!epee::serialization::store_t_to_binary(req, req_serialized))
      throw http_client_serialization_error{"Failed to serialize " + tools::type_name(typeid(typename RPC::request))
        + " for binary request /" + target};

    cpr::Response res = post(target, std::move(req_serialized), {{"Content-Type", "application/octet-stream"}});

    typename RPC::response result;
    if (!epee::serialization::load_t_from_binary(result, res.text))
      throw http_client_serialization_error{"Failed to deserialize response for binary request for /" + target};

    return result;
  }

  /// Makes a "legacy" JSON request; that is, a POST request to /target with the serialized json
  /// as the body.  The response is deserialized into a RPC::response which is returned.
  ///
  /// Note: this is *not* a JSON-RPC request, but rather a plain JSON request where the body is the
  /// direct dump of the given request value.  See json_rpc if you want to do a JSON-RPC request
  /// instead.
  ///
  /// \tparam RPC - the RPC base class; subtypes RPC::request and RPC::response are used for the
  /// request and response, respectively.
  ///
  /// \param target - the end-point, without a leading /, to be concatenated with the base_url given
  /// construction.  For example "foo" used with a base url of "https://example.com" will post to
  /// https://example.com/foo.
  /// \param req - the request to be serialized and sent as JSON.
  ///
  /// \returns RPC::request, deserialized from the response.
  ///
  /// \throws rpc::http_client_error on connection-related failure
  /// \throws rpc::http_client_serialization_error on a serialization failure
  template <typename RPC>
  typename RPC::response json(std::string_view target_, const typename RPC::request& req)
  {
    std::string target{target_};
    std::string req_serialized;
    if(!epee::serialization::store_t_to_json(req, req_serialized))
      throw http_client_serialization_error{"Failed to serialize " + tools::type_name(typeid(typename RPC::request))
        + " for json request /" + target};

    cpr::Response res = post(target, std::move(req_serialized), {{"Content-Type", "application/json; charset=utf-8"}});

    typename RPC::response result;
    if (!epee::serialization::load_t_from_json(result, res.text))
      throw http_client_serialization_error{"Failed to deserialize response for json request for /" + target};

    return result;
  }

  // Makes a post request.
  cpr::Response post(const std::string& uri, cpr::Body body, cpr::Header header);

  uint64_t get_bytes_sent() const { return bytes_sent; }
  uint64_t get_bytes_received() const { return bytes_received; }

private:

  class WipedAuth : public cpr::Authentication {
  public:
    WipedAuth(std::string_view username, std::string_view password);
    ~WipedAuth() override;
  };

  cpr::Session session;
  cpr::Url base_url;
  std::optional<cpr::Timeout> timeout{15s};
  std::optional<WipedAuth> auth;
  std::string proxy;
  std::optional<std::pair<cpr::ssl::CertFile, cpr::ssl::KeyFile>> client_cert;
  bool verify_https = true;
  std::optional<cpr::ssl::CaInfo> ca_info;
  // Whether we need to apply the above to the session when making the next request
  bool apply_timeout = true, apply_auth = false, apply_proxy = false, apply_ssl = false;

  mutable std::shared_mutex params_mutex;
  mutable std::mutex session_mutex;
  std::atomic<int> json_rpc_id = 0;

  std::atomic<uint64_t> bytes_sent = 0;
  std::atomic<uint64_t> bytes_received = 0;
};

}

#pragma once

#include <nlohmann/json.hpp>
#include <oxenmq/bt_serialize.h>
#include "json_bt.h"


namespace cryptonote::rpc {

using nlohmann::json;
using oxen::json_to_bt;

using rpc_input = std::variant<std::monostate, nlohmann::json, oxenmq::bt_dict_consumer>;

/// Exception when trying to invoke an RPC command that indicate a parameter parse failure (will
/// give an invalid params error for JSON-RPC, for example).
struct parse_error : std::runtime_error { using std::runtime_error::runtime_error; };

/// Exception used to signal various types of errors with a request back to the caller.  This
/// exception indicates that the caller did something wrong: bad data, invalid value, etc., but
/// don't indicate a local problem (and so we'll log them only at debug).  For more serious,
/// internal errors a command should throw some other stl error (e.g. std::runtime_error or
/// perhaps std::logic_error), which will result in a local daemon warning (and a generic internal
/// error response to the user).
///
/// For JSON RPC these become an error response with the code as the error.code value and the
/// string as the error.message.
/// For HTTP JSON these become a 500 Internal Server Error response with the message as the body.
/// For OxenMQ the code becomes the first part of the response and the message becomes the
/// second part of the response.
struct rpc_error : std::runtime_error {
  /// \param code - a signed, 16-bit numeric code.  0 must not be used (as it is used for a
  /// success code in OxenMQ), and values in the -32xxx range are reserved by JSON-RPC.
  ///
  /// \param message - a message to send along with the error code (see general description above).
  rpc_error(int16_t code, std::string message)
    : std::runtime_error{"RPC error " + std::to_string(code) + ": " + message},
      code{code}, message{std::move(message)} {}

  int16_t code;
  std::string message;
};

enum struct rpc_source : uint8_t { internal, http, omq };

/// Contains the context of the invocation, which must be filled out by the glue code (e.g. HTTP
/// RPC server) with requester-specific context details.
struct rpc_context {
  // Specifies that the requestor has admin permissions (e.g. is on an unrestricted RPC port, or
  // is a local internal request).  This can be used to provide different results for an admin
  // versus non-admin when invoking a public RPC command.  (Note that non-public RPC commands do
  // not need to check this field for authentication: a non-public invoke() is not called in the
  // first place if attempted by a public requestor).
  bool admin = false;

  // The RPC engine source of the request, i.e. internal, HTTP, OMQ
  rpc_source source = rpc_source::internal;

  // A free-form identifier (meant for humans) identifiying the remote address of the request;
  // this might be IP:PORT, or could contain a pubkey, or ...
  std::string remote;
};

struct rpc_request {
  // The request body:
  // - for an HTTP, non-JSONRPC POST request the string or string_view will be populated with the
  // unparsed request body.
  // - for an HTTP JSONRPC request with a "params" value the nlohmann::json will be set to the
  // parsed "params" value of the request.
  // - for OMQ requests with a data part the string or string_view will be set to the provided value
  // - for all other requests (i.e. JSONRPC with no params; HTTP GET requests; no-data OMQ
  // requests) the variant will contain a std::monostate.
  //
  // If something goes wrong, throw.
  std::variant<std::monostate, std::string_view, std::string, nlohmann::json> body;

  // Returns a string_view of the body, if the body is a string or string_view.  Returns
  // std::nullopt if the body is empty (std::monostate) or parsed jsonrpc params.
  std::optional<std::string_view> body_view() const {
    if (auto* sv = std::get_if<std::string_view>(&body)) return *sv;
    if (auto* s = std::get_if<std::string>(&body)) return *s;
    return std::nullopt;
  }

  // Values to pass through to the invoke() call
  rpc_context context;
};

// Note: to use, parse_request(RPC, rpc_input) must be defined for each typename RPC
// this is used on.
template <typename RPC, typename RPCServer, typename RPCCallback>
auto make_invoke() {
  return [](rpc_request&& request, RPCServer& server) -> typename RPCCallback::result_type {
    RPC rpc{};

    try {
      if (auto body = request.body_view()) {
        if (body->front() == 'd') { // Looks like a bt dict
          rpc.set_bt();
          parse_request(rpc, oxenmq::bt_dict_consumer{*body});
        }
        else
          parse_request(rpc, json::parse(*body));
      } else if (auto* j = std::get_if<json>(&request.body)) {
        parse_request(rpc, std::move(*j));
      } else {
        assert(std::holds_alternative<std::monostate>(request.body));
        parse_request(rpc, std::monostate{});
      }
    } catch (const std::exception& e) {
      throw parse_error{"Failed to parse request parameters: "s + e.what()};
    }

    server.invoke(rpc, std::move(request.context));

    if (rpc.response.is_null())
      rpc.response = json::object();

    if (rpc.is_bt())
      return json_to_bt(std::move(rpc.response));
    else
      return std::move(rpc.response);
  };
}

} // namespace cryptonote::rpc

#pragma once

#include <nlohmann/json.hpp>

#include "common/json_binary_proxy.h"

namespace cryptonote::rpc {

/// Returns a constexpr std::array of string_views from an arbitrary list of string literals
/// Used to specify RPC names as:
/// static constexpr auto names() { return NAMES("primary_name", "some_alias"); }
template <size_t... N>
constexpr std::array<std::string_view, sizeof...(N)> NAMES(const char (&... names)[N]) {
    static_assert(sizeof...(N) > 0, "RPC command must have at least one name");
    return {std::string_view{names, N - 1}...};
}

/// Base class that all RPC commands must inherit from (either directly or via one or more of the
/// below tags).  Inheriting from this (and no others) gives you a private, json, non-legacy RPC
/// command.  For OMQ RPC the command will be available at `admin.whatever`; for HTTP RPC it'll be
/// at `whatever`.  This base class is also where response objects are stored.
struct RPC_COMMAND {
  private:
    bool bt = false;

  public:
    /// Indicates whether this response is to be bt (true) or json (false) encoded.  Do not set.
    bool is_bt() const { return bt; }

    /// Called early in the request to indicate that this request is a bt-encoded one.
    void set_bt();

    /// The response data.  For bt-encoded responses we convert this on the fly, with the
    /// following notes:
    /// - boolean values become 0 or 1
    /// - key-value pairs with null values are omitted from the object
    /// - other null values are not permitted at all: an exception will be raised if the json
    /// contains such a value.
    /// - double values are not permitted; if a double is absolutely needed then check `is_bt`
    /// and, when bt, encode it in some documented, endpoint-specific way.
    /// - binary values in strings *are* permitted, but the caller must take care because they
    /// will not be permitted for actual json responses (json serialization will fail): the caller
    /// is expected to do something like:
    ///
    ///     std::string binary = some_binary_data();
    ///     cmd.response["binary_value"] = is_bt ? binary : oxenmq::to_hex(binary);
    ///
    /// or, more conveniently, using the shortcut interface:
    ///
    ///     cmd.response_hex["binary_value"] = some_binary_data();
    ///
    nlohmann::json response;

    /// Proxy object that is used to set binary data in `response`, encoding it as hex if this
    /// data is being returned as json.  If this response is to be bt-encoded then the binary
    /// value is left as-is (which isn't valid for json, but can be transported inside the json
    /// value as we never dump() when going to bt-encoded).
    ///
    /// Usage:
    ///   std::string data = "abc";
    ///   rpc.response_hex["foo"]["bar"] = data; // json: "616263", bt: "abc"
    tools::json_binary_proxy response_hex{response, tools::json_binary_proxy::fmt::hex};

    /// Proxy object that encodes binary data as base64 for json, leaving it as binary for
    /// bt-encoded responses.
    ///
    /// Usage:
    ///   std::string data = "abc";
    ///   rpc.response_b64["foo"]["bar"] = data; // json: "YWJj", bt: "abc"
    tools::json_binary_proxy response_b64{response, tools::json_binary_proxy::fmt::base64};
};

/// Tag types that are used (via inheritance) to set rpc endpoint properties

/// Specifies that the RPC call is public (i.e. available through restricted rpc).  If this is
/// *not* inherited from then the command is restricted (i.e. only available to admins).  For OMQ,
/// PUBLIC commands are available at `rpc.command` (versus non-PUBLIC ones at `admin.command`).
struct PUBLIC : virtual RPC_COMMAND {};

/// For Wallet RPC, specifies that the RPC call is restricted, meaning the user must authenticate
/// to the RPC listener by some means.
struct RESTRICTED : virtual RPC_COMMAND {};

/// Specifies that the RPC call takes no input arguments.  (A dictionary of parameters may still
/// be passed, but will be ignored).
struct NO_ARGS : virtual RPC_COMMAND {};

/// Specifies a "legacy" JSON RPC command, available via HTTP JSON at /whatever (in addition to
/// json_rpc as "whatever").  When accessed via legacy mode the result is just the .result element
/// of the JSON RPC response.  (Only applies to the HTTP RPC interface, and does nothing if BINARY
/// if specified).
struct LEGACY : virtual RPC_COMMAND {};

}  // namespace cryptonote::rpc

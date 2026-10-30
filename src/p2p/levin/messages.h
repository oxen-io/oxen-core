#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include "connection.h"
#include "serialization/levin_kv/levin_kv.h"

// Levin bodies are levin_kv messages, of a command's (or notify's) request or response struct.
namespace nodetool::levin {

template <typename T>
std::string encode(const T& msg) {
    return levin_kv::encode(msg);
}

template <typename T>
std::optional<T> decode(std::span<const uint8_t> body) {
    std::optional<T> msg{std::in_place};
    if (!levin_kv::decode(body, *msg))
        msg.reset();
    return msg;
}

// What the requests that `Owner` handles, keyed by command id in a dispatch table, are dispatched
// to: functions that decode the body, call the handler, and (for invokes) encode its response
// into `out`.  They return the handler's return code, or ERROR_FORMAT if the body doesn't parse.
template <typename Owner, typename Context>
using invoke_fn = int (*)(Owner&, std::span<const uint8_t> in, std::string& out, Context&);
template <typename Owner, typename Context>
using notify_fn = int (*)(Owner&, std::span<const uint8_t> in, Context&);
template <typename Owner, typename Context>
using invoke_table = std::unordered_map<int, invoke_fn<Owner, Context>>;
template <typename Owner, typename Context>
using notify_table = std::unordered_map<int, notify_fn<Owner, Context>>;

namespace detail {
    template <typename T>
    struct handler_traits;
    template <typename O, typename Req, typename Rsp, typename Ctx>
    struct handler_traits<int (O::*)(Req&, Rsp&, Ctx&)> {
        using owner = O;
        using request = Req;
        using response = Rsp;
        using context = Ctx;
    };
    template <typename O, typename Req, typename Ctx>
    struct handler_traits<int (O::*)(Req&, Ctx&)> {
        using owner = O;
        using request = Req;
        using context = Ctx;
    };
    template <auto Handler>
    using owner_t = typename handler_traits<decltype(Handler)>::owner;
    template <auto Handler>
    using context_t = typename handler_traits<decltype(Handler)>::context;

    template <typename COMMAND, auto Handler>
    int invoke(
            owner_t<Handler>& owner,
            std::span<const uint8_t> in,
            std::string& out,
            context_t<Handler>& context) {
        auto req = decode<typename COMMAND::request>(in);
        if (!req)
            return ERROR_FORMAT;
        typename COMMAND::response rsp{};
        const int code = (owner.*Handler)(*req, rsp, context);
        out = encode(rsp);
        return code;
    }

    template <typename NOTIFY, auto Handler>
    int notify(owner_t<Handler>& owner, std::span<const uint8_t> in, context_t<Handler>& context) {
        auto req = decode<typename NOTIFY::request>(in);
        if (!req)
            return ERROR_FORMAT;
        return (owner.*Handler)(*req, context);
    }
}  // namespace detail

// The dispatch table entry for invoked COMMAND, handled by the member function Handler.
template <typename COMMAND, auto Handler>
constexpr auto invoke_entry() {
    using T = detail::handler_traits<decltype(Handler)>;
    static_assert(std::is_same_v<typename T::request, typename COMMAND::request>);
    static_assert(std::is_same_v<typename T::response, typename COMMAND::response>);
    return std::pair{int{COMMAND::ID}, &detail::invoke<COMMAND, Handler>};
}

// The dispatch table entry for NOTIFY, handled by the member function Handler.
template <typename NOTIFY, auto Handler>
constexpr auto notify_entry() {
    using T = detail::handler_traits<decltype(Handler)>;
    static_assert(std::is_same_v<typename T::request, typename NOTIFY::request>);
    return std::pair{int{NOTIFY::ID}, &detail::notify<NOTIFY, Handler>};
}

}  // namespace nodetool::levin

#ifndef JSONRPC_STRUCTS_H
#define JSONRPC_STRUCTS_H

#include <cstdint>
#include <string>

#include "../serialization/keyvalue_serialization.h"
#include "../storages/portable_storage_base.h"

namespace epee::json_rpc {
template <typename t_param>
struct request {
    std::string jsonrpc;
    std::string method;
    epee::serialization::storage_entry id{};
    t_param params{};

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(jsonrpc)
    KV_SERIALIZE(id)
    KV_SERIALIZE(method)
    KV_SERIALIZE(params)
    END_KV_SERIALIZE_MAP()
};

struct error {
    int64_t code{0};
    std::string message;

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(code)
    KV_SERIALIZE(message)
    END_KV_SERIALIZE_MAP()
};

template <typename t_param, bool with_error = false>
struct response {
    std::string jsonrpc;
    t_param result{};
    epee::serialization::storage_entry id{};
    json_rpc::error error{};

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(jsonrpc)
    KV_SERIALIZE(id)
    KV_SERIALIZE(result)
    if (with_error)
        KV_SERIALIZE(error)
    END_KV_SERIALIZE_MAP()
};

template <typename T>
using response_with_error = response<T, true>;

struct error_response {
    std::string jsonrpc;
    json_rpc::error error{};
    epee::serialization::storage_entry id{};

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(jsonrpc)
    KV_SERIALIZE(id)
    KV_SERIALIZE(error)
    END_KV_SERIALIZE_MAP()
};
}  // namespace epee::json_rpc

#endif /* JSONRPC_STRUCTS_H */

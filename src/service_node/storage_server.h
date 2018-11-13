#pragma once

#include "net/http_server_impl_base.h"
#include "loki-storage-server/storage/include/Storage.hpp"

#include <cstdio>

namespace service_node
{
  using connection_context = epee::net_utils::connection_context_base;
  using http_request_info = epee::net_utils::http::http_request_info;
  using http_response_info = epee::net_utils::http::http_response_info;

  class storage_server : public epee::http_server_impl_base<storage_server>
  {
   public:
    storage_server(const std::string& db_path);
    bool handle_http_request(const http_request_info &query_info,
                             http_response_info &response,
                             connection_context &m_conn_context) override;
    bool handle_http_request_map(const http_request_info &query_info,
                                 http_response_info &response_info,
                                 connection_context &m_conn_context);
    bool on_store_message(const http_request_info& query_info, http_response_info& response);
    bool on_retrieve_message(const http_request_info& query_info, http_response_info& response);

   private:
    Storage m_storage;
  };
} // namespace service_node

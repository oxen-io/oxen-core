#include "http_server.h"
#include "Storage.hpp"
#include "pow.hpp"

#include <numeric>
#include <unordered_map>
#include <vector>
#include <stdint.h>

namespace service_node {

  using http_header_info = epee::net_utils::http::http_header_info;

  storage_server::~storage_server() {
  }

  storage_server::storage_server(const std::string& db_path)
    : m_storage(new Storage(db_path))
  {}

  bool storage_server::handle_http_request_map(const http_request_info& query_info,
                                               http_response_info& response_info,
                                               connection_context& m_conn_context)
  {
    bool handled = false;
    // TODO: check if we're the recipient or if the request should be forwarded
    switch (query_info.m_http_method) {
      case epee::net_utils::http::http_method_get:
        if (query_info.m_URI == "/retrieve") {
          handled = on_retrieve_message(query_info, response_info);
        }
        break;

      case epee::net_utils::http::http_method_post:
        if (query_info.m_URI == "/store") {
          printf("handling store request\n");
          handled = on_store_message(query_info, response_info);
        }
        break;

      default:
        break;
    }
    return handled;
  }
  bool storage_server::handle_http_request(const http_request_info& query_info,
                                           http_response_info& response,
                                           connection_context& m_conn_context)
  {
    LOG_PRINT_L2("HTTP [" << m_conn_context.m_remote_address.host_str() << "] " << query_info.m_http_method_str << " "
                          << query_info.m_URI);
    response.m_response_code = 200;
    response.m_response_comment = "Ok";
    if (!handle_http_request_map(query_info, response, m_conn_context)) {
        response.m_response_code = 404;
        response.m_response_comment = "Not found";
    }
    return true;
  }

  bool parseHeaders(const http_header_info& header_info,
                           std::unordered_map<std::string, std::string&> required_fields,
                           http_response_info& response)
  {
    for (const auto& pair : header_info.m_etc_fields) {
    const auto it = required_fields.find(pair.first);
      if (it != required_fields.end()) {
        it->second.assign(pair.second);
      }
    }

    std::string missingFields = std::accumulate(
      std::begin(required_fields),
      std::end(required_fields),
      std::string(""),
      [](std::string result, const std::pair<std::string, std::string>& pair) {
        if (pair.second.empty())
          return result += pair.first + ",";
        return result;
      });

    if (!missingFields.empty()) {
      missingFields.pop_back(); // trailing comma
      response.m_body = "Missing fields in header: " + missingFields;
      response.m_response_code = 400;
      return false;
    }

    return true;
  }

  bool storage_server::on_store_message(const http_request_info& query_info, http_response_info& response)
  {
    std::string recipient;
    std::string timestamp;
    std::string powNonce;
    std::string ttl;
    std::string messageHash;

    const std::unordered_map<std::string, std::string&> required_fields {
      { "X-Loki-recipient", recipient },
      { "X-Loki-timestamp", timestamp },
      { "X-Loki-pow-nonce", powNonce },
      { "X-Loki-ttl", ttl }
    };

    if (!parseHeaders(query_info.m_header_info, required_fields, response))
      return true;

    std::vector<uint8_t> bytes(std::begin(query_info.m_body), std::end(query_info.m_body));

    printf("checking PoW");
    if (!checkPoW(powNonce, timestamp, ttl, recipient, bytes, messageHash)) {
      response.m_body = "Could not validate Proof of Work";
      response.m_response_code = 403;
      return true;
    }
    printf("ok\nhash: %s\n", messageHash.c_str());

    int ttlInt;
    try {
      ttlInt = std::stoi(ttl);
    } catch(...) {
      response.m_body = "Invalid ttl";
      response.m_response_code = 400;
      return true;
    }

    bool success;
    try {
      success = m_storage->store(messageHash, recipient, bytes, ttlInt);
    } catch(std::exception e) {
      printf("Caught exception : %s\n", e.what());
    }

    // TODO: should this be just another exception?
    if (!success) {
      response.m_body = "Message already present";
      response.m_response_code = 409;
    }

    return true;
  }

  bool storage_server::on_retrieve_message(const http_request_info& query_info, http_response_info& response)
  {
    std::string recipient;
    std::string lastHash;

    const std::unordered_map<std::string, std::string&> required_fields {
      { "X-Loki-recipient", recipient },
      { "X-Loki-last-hash", lastHash },
    };

    if (!parseHeaders(query_info.m_header_info, required_fields, response))
      return true;

    bool success;
    std::vector<storage::Item> items;
    std::string body = "{\"messages\": [";

    try {
      success = m_storage->retrieve(recipient, items, lastHash);
    } catch (std::exception e) {
      printf("Caught exception: %s\n", e.what());
    }

    if (success) {
      response.m_mime_tipe = "application/json";
      response.m_header_info.m_content_type = " application/json";

      // TODO: use proper json serialization
      response.m_body = "{\"messages\": [";
      for (const auto& item : items) {
        response.m_body += "{";
        response.m_body += "\"hash\":\"" + item.hash + "\",";
        response.m_body += "\"timestamp\":\"" + std::to_string(item.timestamp) + "\",";
        response.m_body += "\"data\":\"";
        response.m_body.append(std::begin(item.bytes), std::end(item.bytes));
        response.m_body += "\"";
        response.m_body += "},";
      }
      if (items.size() > 0)
        response.m_body.pop_back();
      response.m_body += "]}";
    } else {
      response.m_body = "Could not retrieve data";
      response.m_response_code = 400;
    }

    return true;
  }
} // namespace service_node

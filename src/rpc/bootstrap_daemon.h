#pragma  once

#include <functional>
#include <vector>

#include "rpc/http_client.h"
#include "rpc/core_rpc_server_commands_defs.h"

namespace cryptonote
{

  class bootstrap_daemon
  {
  public:
    bootstrap_daemon(std::function<std::optional<std::string>()> get_next_public_node);
    bootstrap_daemon(const std::string &address, const std::optional<std::pair<std::string_view, std::string_view>> &credentials);

    std::string address() const noexcept;
    std::optional<uint64_t> get_height();
    // Called when a request has failed either internally or for some external reason; the next
    // request will attempt to use a different bootstrap server (if configured).
    void set_failed() { m_failed = true; }

    template <class RPC, std::enable_if_t<std::is_base_of_v<rpc::RPC_COMMAND, RPC>, int> = 0>
    bool invoke(const typename RPC::request& req, typename RPC::response& res)
    {
      if (!switch_server_if_needed())
        return false;

      try {
        if constexpr (std::is_base_of_v<rpc::LEGACY, RPC>)
          // TODO: post-8.x hard fork we can remove this one and let everything go through the
          // non-binary json_rpc version instead (because all legacy json commands are callable via
          // json_rpc as of daemon 8.x).
          res = m_http_client.json<RPC>(RPC::names().front(), req);
        else if constexpr (std::is_base_of_v<rpc::BINARY, RPC>)
          res = m_http_client.binary<RPC>(RPC::names().front(), req);
        else
          res = m_http_client.json_rpc<RPC>(RPC::names().front(), req);
      } catch (const std::exception& e) {
        MWARNING("bootstrap daemon request failed: " << e.what());
        set_failed();
        return false;
      }
      return true;
    }

  private:
    bool set_server(std::string address, const std::optional<std::pair<std::string_view, std::string_view>> &credentials = std::nullopt);
    bool switch_server_if_needed();

  private:
    rpc::http_client m_http_client;
    std::function<std::optional<std::string>()> m_get_next_public_node;
    bool m_failed = false;
  };

}

#include "bootstrap_daemon.h"

#include <stdexcept>

#include "common/string_util.h"
#include "crypto/crypto.h"
#include "cryptonote_core/cryptonote_core.h"
#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon.rpc.bootstrap_daemon"

namespace cryptonote
{

  bootstrap_daemon::bootstrap_daemon(std::function<std::optional<std::string>()> get_next_public_node)
    : m_get_next_public_node(get_next_public_node)
  {
  }

  bootstrap_daemon::bootstrap_daemon(const std::string &address, const std::optional<std::pair<std::string_view, std::string_view>> &credentials)
    : bootstrap_daemon(nullptr)
  {
    if (!set_server(address, credentials))
    {
      throw std::runtime_error("invalid bootstrap daemon address or credentials");
    }
  }

  std::string bootstrap_daemon::address() const noexcept
  {
    return m_http_client.get_base_url();
  }

  std::optional<uint64_t> bootstrap_daemon::get_height()
  {
    // query bootstrap daemon's height
    rpc::GET_HEIGHT::response res{};
    if (!invoke<rpc::GET_HEIGHT>({}, res))
    {
      return std::nullopt;
    }

    if (res.status != cryptonote::rpc::STATUS_OK)
    {
      return std::nullopt;
    }

    return res.height;
  }

  bool bootstrap_daemon::set_server(std::string url, const std::optional<std::pair<std::string_view, std::string_view>> &credentials /* = std::nullopt */)
  {
    if (!tools::starts_with(url, "http://") && !tools::starts_with(url, "https://"))
      url.insert(0, "http://");
    m_http_client.set_base_url(std::move(url));
    if (credentials)
      m_http_client.set_auth(credentials->first, credentials->second);
    else
      m_http_client.set_auth();

    MINFO("Changed bootstrap daemon address to " << url);
    return true;
  }


  bool bootstrap_daemon::switch_server_if_needed()
  {
    if (!m_failed || !m_get_next_public_node)
      return true;

    const std::optional<std::string> address = m_get_next_public_node();
    if (address) {
      m_failed = false;
      return set_server(*address);
    }

    return false;
  }

}

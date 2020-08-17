#include "http_client.h"
#include <chrono>
#include <regex>
#include <cpr/cpr.h>
#include "common/string_util.h"
#include "cpr/ssl_options.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "rpc.http_client"

namespace cryptonote::rpc {

http_client_connect_error::http_client_connect_error(const cpr::Error& err, const std::string& prefix) :
  http_client_error{prefix + err.message},
  code{err.code}
{}

void http_client::set_base_url(std::string base_url_) {
  std::lock_guard lock{params_mutex};
  if (!base_url_.empty() && base_url_.back() != '/')
    base_url_ += '/';
  base_url = cpr::Url{std::move(base_url_)};
}
std::string http_client::get_base_url() const {
  std::shared_lock lock{params_mutex};
  return base_url.str();
}

void http_client::set_timeout(std::chrono::milliseconds timeout_) {
  std::lock_guard lock{params_mutex};
  if (timeout_ > 0s)
    timeout = timeout_;
  else
    timeout.reset();
  apply_timeout = true;
}

std::chrono::milliseconds http_client::get_timeout() const {
  std::shared_lock lock{params_mutex};
  return timeout ? timeout->ms : 0s;
}

void http_client::cancel() {
  // We *don't* take a session lock here, which is a little dirty, but resetting the timeout seems
  // small enough as to not cause issues when done from another thread.
  session.SetTimeout(1ms);
}

http_client::WipedAuth::WipedAuth(std::string_view username, std::string_view password)
  : Authentication("", "")
{
  auth_string_.clear();
  auth_string_.reserve(username.size() + 1 + password.size());
  auth_string_ += username;
  auth_string_ += ':';
  auth_string_ += password;
}

http_client::WipedAuth::~WipedAuth() {
  memwipe(auth_string_.data(), auth_string_.size());
}

void http_client::set_auth(std::string_view username, std::string_view password) {
  std::lock_guard lock{params_mutex};
  if (username.empty() && password.empty()) {
    if (auth) {
      auth.reset();
      apply_auth = true;
    }
  } else {
    auth.emplace(username, password);
    apply_auth = true;
  }
}

void http_client::set_proxy(std::string proxy_) {
  std::lock_guard lock{params_mutex};
  if (proxy != proxy_) {
    proxy = std::move(proxy_);
    apply_proxy = true;
  }
}

std::string http_client::get_proxy() const {
  std::shared_lock lock{params_mutex};
  return proxy;
}

void http_client::set_https_client_cert(std::string cert_path, std::string key_path) {
  std::lock_guard lock{params_mutex};
  if (cert_path.empty() || key_path.empty()) {
    if (client_cert) {
      client_cert.reset();
      apply_ssl = true;
    }
  } else {
    client_cert.emplace(std::move(cert_path), std::move(key_path));
    apply_ssl = true;
  }
}

void http_client::set_insecure_https(bool insecure) {
  std::lock_guard lock{params_mutex};
  if (insecure != !verify_https) {
    verify_https = !insecure;
    apply_ssl = true;
  }
}

void http_client::set_https_cainfo(std::string cainfo_bundle_path) {
  std::lock_guard lock{params_mutex};
  if (cainfo_bundle_path.empty()) {
    if (ca_info) {
      ca_info.reset();
      apply_ssl = true;
    }
  } else {
    ca_info.emplace(std::move(cainfo_bundle_path));
  }
}


void http_client::copy_params_from(const http_client& other) {
  std::unique_lock lock{params_mutex, std::defer_lock};
  std::shared_lock olock{other.params_mutex, std::defer_lock};
  std::lock(lock, olock);

  base_url = other.base_url;
  timeout = other.timeout;
  auth = other.auth;
}


cpr::Response http_client::post(const std::string& uri, cpr::Body body, cpr::Header header) {
  if (base_url.str().empty())
    throw http_client_error{"Cannot submit request: no base url has been set"};

  cpr::Response res;
  {
    std::shared_lock plock{params_mutex};
    std::chrono::steady_clock::time_point start;
    if (LOG_ENABLED(Debug))
      start = std::chrono::steady_clock::now();
    auto url = base_url + uri;

    // See if we need to update any of the session paramters; we do it here with only the parameter
    // lock, then actually load the setting below once we have the session lock.
    std::optional<cpr::Timeout> new_timeout;
    if (apply_timeout) {
      new_timeout = timeout ? *timeout : cpr::Timeout{0ms};
      apply_timeout = false;
    }
    std::optional<cpr::Authentication> new_auth;
    if (apply_auth) {
      new_auth = auth ? *auth : cpr::Authentication{"", ""};
      apply_auth = false;
    }
    std::optional<cpr::Proxies> new_proxy;
    if (apply_proxy) {
      if (proxy.empty())
        new_proxy.emplace();
      else
        new_proxy = cpr::Proxies{{{"http", proxy}, {"https", proxy}}};
      apply_proxy = false;
    }

    std::optional<cpr::SslOptions> new_ssl_opts;
    if (apply_ssl) {
      new_ssl_opts.emplace();
      if (client_cert) {
        new_ssl_opts->SetOption(client_cert->first);
        new_ssl_opts->SetOption(client_cert->second);
      }
      if (!verify_https) {
        MWARNING("HTTPS certificate verification disabled; this connection is not secure");
        new_ssl_opts->SetOption(cpr::ssl::VerifyHost(false));
        new_ssl_opts->SetOption(cpr::ssl::VerifyPeer(false));
        new_ssl_opts->SetOption(cpr::ssl::VerifyStatus(false));
      }
      if (ca_info) {
        new_ssl_opts->SetOption(*ca_info);
      }
    }

    plock.unlock();

    {
      std::lock_guard slock{session_mutex};

      if (new_auth) session.SetAuth(*new_auth);
      if (new_timeout) session.SetTimeout(*new_timeout);
      if (new_proxy) session.SetProxies(*std::move(new_proxy));
      if (new_ssl_opts) session.SetSslOptions(*new_ssl_opts);

      MDEBUG("Submitting post request to " << url);
      session.SetUrl(url);
      session.SetHeader(header);
      session.SetBody(std::move(body));

      res = session.Post();
    }

    MDEBUG(url << ": " <<
        (res.error.code != cpr::ErrorCode::OK ? res.error.message : res.status_line) <<
        ", sent " << res.uploaded_bytes << " bytes, received " << res.downloaded_bytes << " bytes in " <<
        tools::friendly_duration(std::chrono::steady_clock::now() - start));

    bytes_sent += res.uploaded_bytes;
    bytes_received += res.downloaded_bytes;
  }

  if (res.error.code != cpr::ErrorCode::OK)
    throw http_client_connect_error(res.error, "HTTP request failed: ");

  if (res.status_code != 200)
    throw http_client_response_error(true, res.status_code, "HTTP request failed; server returned " +
        (res.status_line.empty() ? std::to_string(res.status_code) : res.status_line));

  return res;
}

static const std::regex rexp_match_url{R"(^(?:([a-zA-Z][a-zA-Z0-9.+-]*)://)?(?:(\[[0-9a-fA-F:.]*\])|([^\[\]/:?]*))(?::(\d+))?)", std::regex::optimize};
//                                            proto                              ipv6               ipv4/host         port

std::tuple<std::string, std::string, uint16_t, std::string> http_client::parse_url(const std::string& url) {
  std::string proto, host, uri;
  uint16_t port = 0;

  std::smatch result;
  if (!std::regex_search(url, result, rexp_match_url))
    throw http_client_error{"Failed to parse URL: " + url};

  if (result[1].matched)
    proto = result[1];
  host = result[result[2].matched ? 2 : 3];
  if (result[4].matched) {
    auto port_str = result[4].str();
    if (!tools::parse_int(port_str, port))
      throw http_client_error{"Failed to parse URL: invalid port '" + port_str + "'"}; // i.e. most likely some port value > 65535
  }
  uri = result.suffix();

  return {std::move(proto), std::move(host), port, std::move(uri)};
}

std::tuple<std::string, std::string, uint16_t, std::string> http_client::parse_base_url() const {
  std::shared_lock lock{params_mutex};
  return parse_url(base_url.str());
}

}

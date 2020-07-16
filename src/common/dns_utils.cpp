// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "common/dns_utils.h"
// check local first (in the event of static or in-source compilation of libunbound)
#include "common/string_util.h"
#include "unbound.h"

#include <chrono>
#include <optional>
#include <stdexcept>
#include <cstdlib>
#include <cstdio>
#include "include_base_utils.h"
#include "common/threadpool.h"
#include "crypto/crypto.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "net.dns"

using namespace std::literals;
static constexpr std::array DEFAULT_DNS_PUBLIC_ADDR =
{
  "194.150.168.168"sv,    // CCC (Germany)
  "80.67.169.40"sv,       // FDN (France)
  "89.233.43.71"sv,       // http://censurfridns.dk (Denmark)
  "109.69.8.51"sv,        // punCAT (Spain)
  "193.58.251.251"sv,     // SkyDNS (Russia)
};

namespace
{

/*
 * The following two functions were taken from unbound-anchor.c, from
 * the unbound library packaged with this source.  The license and source
 * can be found in $PROJECT_ROOT/external/unbound
 */

/* Cert builtin commented out until it's used, as the compiler complains

// return the built in root update certificate
static const char*
get_builtin_cert(void)
{
	return
// The ICANN CA fetched at 24 Sep 2010.  Valid to 2028
"-----BEGIN CERTIFICATE-----\n"
"MIIDdzCCAl+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBdMQ4wDAYDVQQKEwVJQ0FO\n"
"TjEmMCQGA1UECxMdSUNBTk4gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNV\n"
"BAMTDUlDQU5OIFJvb3QgQ0ExCzAJBgNVBAYTAlVTMB4XDTA5MTIyMzA0MTkxMloX\n"
"DTI5MTIxODA0MTkxMlowXTEOMAwGA1UEChMFSUNBTk4xJjAkBgNVBAsTHUlDQU5O\n"
"IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1JQ0FOTiBSb290IENB\n"
"MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKDb\n"
"cLhPNNqc1NB+u+oVvOnJESofYS9qub0/PXagmgr37pNublVThIzyLPGCJ8gPms9S\n"
"G1TaKNIsMI7d+5IgMy3WyPEOECGIcfqEIktdR1YWfJufXcMReZwU4v/AdKzdOdfg\n"
"ONiwc6r70duEr1IiqPbVm5T05l1e6D+HkAvHGnf1LtOPGs4CHQdpIUcy2kauAEy2\n"
"paKcOcHASvbTHK7TbbvHGPB+7faAztABLoneErruEcumetcNfPMIjXKdv1V1E3C7\n"
"MSJKy+jAqqQJqjZoQGB0necZgUMiUv7JK1IPQRM2CXJllcyJrm9WFxY0c1KjBO29\n"
"iIKK69fcglKcBuFShUECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
"Af8EBAMCAf4wHQYDVR0OBBYEFLpS6UmDJIZSL8eZzfyNa2kITcBQMA0GCSqGSIb3\n"
"DQEBCwUAA4IBAQAP8emCogqHny2UYFqywEuhLys7R9UKmYY4suzGO4nkbgfPFMfH\n"
"6M+Zj6owwxlwueZt1j/IaCayoKU3QsrYYoDRolpILh+FPwx7wseUEV8ZKpWsoDoD\n"
"2JFbLg2cfB8u/OlE4RYmcxxFSmXBg0yQ8/IoQt/bxOcEEhhiQ168H2yE5rxJMt9h\n"
"15nu5JBSewrCkYqYYmaxyOC3WrVGfHZxVI7MpIFcGdvSb2a1uyuua8l0BKgk3ujF\n"
"0/wsHNeP22qNyVO+XVBzrM8fk8BSUFuiT/6tZTYXRtEt5aKQZgXbKU5dUF3jT9qg\n"
"j/Br5BZw3X/zd325TvnswzMC1+ljLzHnQGGk\n"
"-----END CERTIFICATE-----\n"
		;
}
*/

/** return the built in root DS trust anchor */
constexpr auto get_builtin_ds()
{
  return std::array{
    ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5\n",
    ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
  };
}

/************************************************************
 ************************************************************
 ***********************************************************/

} // anonymous namespace

namespace tools
{

static constexpr const char *get_record_name(int record_type)
{
  switch (record_type)
  {
    case DNS_TYPE_A: return "A";
    case DNS_TYPE_TXT: return "TXT";
    case DNS_TYPE_AAAA: return "AAAA";
    default: return "unknown";
  }
}

// fuck it, I'm tired of dealing with getnameinfo()/inet_ntop/etc
std::optional<std::string> ipv4_to_string(const char* src, size_t len)
{
  if (len < 4)
  {
    MERROR("Invalid IPv4 address: " << std::string(src, len));
    return std::nullopt;
  }

  std::stringstream ss;
  unsigned int bytes[4];
  for (int i = 0; i < 4; i++)
  {
    unsigned char a = src[i];
    bytes[i] = a;
  }
  ss << bytes[0] << "."
     << bytes[1] << "."
     << bytes[2] << "."
     << bytes[3];
  return ss.str();
}

// this obviously will need to change, but is here to reflect the above
// stop-gap measure and to make the tests pass at least...
std::optional<std::string> ipv6_to_string(const char* src, size_t len)
{
  if (len < 8)
  {
    MERROR("Invalid IPv4 address: " << std::string(src, len));
    return std::nullopt;
  }

  std::stringstream ss;
  unsigned int bytes[8];
  for (int i = 0; i < 8; i++)
  {
    unsigned char a = src[i];
    bytes[i] = a;
  }
  ss << bytes[0] << ":"
     << bytes[1] << ":"
     << bytes[2] << ":"
     << bytes[3] << ":"
     << bytes[4] << ":"
     << bytes[5] << ":"
     << bytes[6] << ":"
     << bytes[7];
  return ss.str();
}

std::optional<std::string> txt_to_string(const char* src, size_t len)
{
  if (len == 0)
    return std::nullopt;
  return std::string(src+1, len-1);
}

void ub_ctx_deleter::operator()(ub_ctx* ctx) {
  ub_ctx_delete(ctx);
}

namespace {

struct ub_result_deleter {
  void operator()(ub_result* result) {
    ub_resolve_free(result);
  }
};

using ub_result_ptr = std::unique_ptr<ub_result, ub_result_deleter>;

void add_anchors(ub_ctx *ctx)
{
  for (const char* ds : get_builtin_ds())
  {
    MINFO("adding trust anchor: " << *ds);
    ub_ctx_add_ta(ctx, const_cast<char*>(ds));
  }
}

} // anonymous namespace

DNSResolver::DNSResolver()
{
  int use_dns_public = 0;
  std::vector<std::string> dns_public_addr;
  const char *DNS_PUBLIC = getenv("DNS_PUBLIC");
  if (DNS_PUBLIC)
  {
    dns_public_addr = tools::dns_utils::parse_dns_public(DNS_PUBLIC);
    if (!dns_public_addr.empty())
    {
      MGINFO("Using public DNS server(s): " << tools::join(", ", dns_public_addr) << " (TCP)");
      use_dns_public = 1;
    }
    else
    {
      MERROR("Failed to parse DNS_PUBLIC");
    }
  }

  // init libunbound context
  m_ctx = ub_ctx_create();

  if (use_dns_public)
  {
    for (const auto &ip: dns_public_addr)
      ub_ctx_set_fwd(m_ctx, ip.c_str());
    ub_ctx_set_option(m_ctx, "do-udp:", "no");
    ub_ctx_set_option(m_ctx, "do-tcp:", "yes");
  }
  else {
    // look for "/etc/resolv.conf" and "/etc/hosts" or platform equivalent
    ub_ctx_resolvconf(m_ctx, NULL);
    ub_ctx_hosts(m_ctx, NULL);
  }

  add_anchors(m_ctx);

  if (!DNS_PUBLIC)
  {
    // TODO(loki): Don't probe moneropulse for Loki
#if 0
    // if no DNS_PUBLIC specified, we try a lookup to what we know
    // should be a valid DNSSEC record, and switch to known good
    // DNSSEC resolvers if verification fails
    bool available, valid;
    static const char *probe_hostname = "updates.moneropulse.org";
    auto records = get_txt_record(probe_hostname, available, valid);
    if (!valid)
    {
      MINFO("Failed to verify DNSSEC record from " << probe_hostname << ", falling back to TCP with well known DNSSEC resolvers");
      ub_ctx_delete(m_ctx);
      m_ctx = ub_ctx_create();
      add_anchors(m_ctx);
      for (const auto &ip: DEFAULT_DNS_PUBLIC_ADDR)
        ub_ctx_set_fwd(m_ctx, string_copy(ip));
      ub_ctx_set_option(m_ctx, string_copy("do-udp:"), string_copy("no"));
      ub_ctx_set_option(m_ctx, string_copy("do-tcp:"), string_copy("yes"));
    }
#endif
  }
}

std::vector<std::string> DNSResolver::get_record(const std::string& url, int record_type, std::optional<std::string> (*reader)(const char *,size_t), bool& dnssec_available, bool& dnssec_valid)
{
  std::vector<std::string> addresses;
  dnssec_available = false;
  dnssec_valid = false;

  if (url.find('.') == std::string::npos)
  {
    return addresses;
  }

  ub_result* result_raw = nullptr;
  // call DNS resolver, blocking.  if return value not zero, something went wrong
  if (!ub_resolve(m_ctx, url.c_str(), record_type, DNS_CLASS_IN, &result_raw))
  {
    // destructor takes care of cleanup
    ub_result_ptr result{result_raw};

    dnssec_available = (result->secure || result->bogus);
    dnssec_valid = result->secure && !result->bogus;
    if (result->havedata)
    {
      for (size_t i=0; result->data[i] != NULL; i++)
      {
        if (auto res = (*reader)(result->data[i], result->len[i]))
        {
          MINFO("Found \"" << *res << "\" in " << get_record_name(record_type) << " record for " << url);
          addresses.push_back(*res);
        }
      }
    }
  }

  return addresses;
}

std::vector<std::string> DNSResolver::get_ipv4(const std::string& url, bool& dnssec_available, bool& dnssec_valid)
{
  return get_record(url, DNS_TYPE_A, ipv4_to_string, dnssec_available, dnssec_valid);
}

std::vector<std::string> DNSResolver::get_ipv6(const std::string& url, bool& dnssec_available, bool& dnssec_valid)
{
  return get_record(url, DNS_TYPE_AAAA, ipv6_to_string, dnssec_available, dnssec_valid);
}

std::vector<std::string> DNSResolver::get_txt_record(const std::string& url, bool& dnssec_available, bool& dnssec_valid)
{
  return get_record(url, DNS_TYPE_TXT, txt_to_string, dnssec_available, dnssec_valid);
}

namespace {
  // Data pack that we pass into the unbound callback:
  struct dns_results {
    int& all_done;
    const std::string& hostname;
    const char* record_name;
    std::vector<std::string>& results;
    std::optional<std::string> (*reader)(const char*, size_t);
    int async_id{0};
    bool done{false};
    bool dnssec;
    bool dnssec_required;

    dns_results(int& a, const std::string& h, const char* rn, std::vector<std::string>& r, std::optional<std::string> (*rdr)(const char*, size_t), bool dnssec, bool dnssec_req)
      : all_done{a}, hostname{h}, record_name{rn}, results{r}, reader{rdr}, dnssec{dnssec}, dnssec_required{dnssec_req}
    {}
  };
}

extern "C" void DNSResolver_async_callback(void* data, int err, ub_result* result_raw)
{
  ub_result_ptr result{result_raw};
  auto &res = *static_cast<dns_results*>(data);
  res.all_done++;
  res.done = true;
  if (err)
    MWARNING("resolution of " << res.hostname << " failed: " << ub_strerror(err));
  else if ((res.dnssec || res.dnssec_required) && result->bogus)
    MWARNING("resolution of " << res.hostname << " failed DNSSEC validation: " << result->why_bogus);
  else if (res.dnssec_required && !result->secure)
    MWARNING("resolution of " << res.hostname << " failed: DNSSEC validate is required but is not available");
  else if (result->havedata)
  {
    for (size_t i = 0; result->data[i] != NULL; i++)
    {
      if (auto r = (*res.reader)(result->data[i], result->len[i]))
      {
        MINFO("Found \"" << *r << "\" in " << res.record_name << " record for " << res.hostname);
        res.results.push_back(*r);
      }
    }
  }
}

std::vector<std::vector<std::string>> DNSResolver::get_many(int type, const std::vector<std::string>& hostnames, std::chrono::milliseconds timeout, bool dnssec, bool dnssec_required)
{
  auto* reader = type == DNS_TYPE_A ? ipv4_to_string : type == DNS_TYPE_AAAA ? ipv6_to_string : type == DNS_TYPE_TXT ? txt_to_string : nullptr;
  if (!reader)
    throw std::invalid_argument("Invalid lookup type: " + std::to_string(type));

  std::vector<std::vector<std::string>> results;
  if (hostnames.empty())
    return results;

  int num_done = 0;
  std::vector<dns_results> result_packs;
  results.reserve(hostnames.size());
  result_packs.reserve(hostnames.size());
  ub_ctx_async(m_ctx, true); // Tells libunbound to use a thread instead of a fork

  // Initiate lookups:
  for (auto& host : hostnames)
  {
    auto& pack = result_packs.emplace_back(num_done, host, get_record_name(type), results.emplace_back(), reader, dnssec, dnssec_required);
    int err = ub_resolve_async(m_ctx, host.c_str(), type, DNS_CLASS_IN, static_cast<void*>(&pack), DNSResolver_async_callback, &pack.async_id);
    if (err)
    {
      MWARNING("unable to initiate lookup for " << host << ": " << ub_strerror(err));
      num_done++;
      pack.done = true;
    }
  }

  // Wait for results
  auto expiry = std::chrono::steady_clock::now() + timeout;
  while (num_done < (int)results.size() && std::chrono::steady_clock::now() < expiry)
  {
    std::this_thread::sleep_for(5ms);
    int err = ub_process(m_ctx);
    if (err)
    {
      MWARNING("ub_process returned an error while waiting for async results: " << ub_strerror(err));
      break;
    }
  }

  // Cancel any outstanding requests
  for (auto& pack : result_packs)
  {
    if (!pack.done)
      ub_cancel(m_ctx, pack.async_id);
  }

  return results;
}

std::string DNSResolver::get_dns_format_from_oa_address(std::string_view addr_v)
{
  std::string addr{addr_v};
  auto first_at = addr.find("@");
  if (first_at == std::string::npos)
    return addr;

  // convert name@domain.tld to name.domain.tld
  addr.replace(first_at, 1, ".");

  return addr;
}

DNSResolver& DNSResolver::instance()
{
  static DNSResolver staticInstance;
  return staticInstance;
}

DNSResolver DNSResolver::create()
{
  return DNSResolver();
}

namespace dns_utils
{

//-----------------------------------------------------------------------
// TODO: parse the string in a less stupid way, probably with regex
std::string address_from_txt_record(std::string_view s)
{
  // make sure the txt record has the addr_type and find it
  constexpr auto addr_type = "oa1:xmr"sv;
  if (auto pos = s.find(addr_type); pos != std::string_view::npos)
    s.remove_prefix(pos + addr_type.size()); // remove it and everything before it
  else
    return {}; // not found.

  constexpr auto recipient_address = "recipient_address="sv;
  if (auto pos = s.find(recipient_address); pos != std::string_view::npos)
    s.remove_prefix(pos + recipient_address.size()); // delete it and everything up to it
  else
    return {}; // not found

  // find the next semicolon
  if (auto pos = s.find(';'); pos != std::string::npos)
  {
    // length of address == 95, we can at least validate that much here
    if (pos == 95)
      return std::string{s.substr(0, 95)};
    else if (pos == 106) // length of address == 106 --> integrated address
      return std::string{s.substr(0, 106)};
  }
  return {};
}
/**
 * @brief gets a loki address from the TXT record of a DNS entry
 *
 * gets the loki address from the TXT record of the DNS entry associated
 * with <url>.  If this lookup fails, or the TXT record does not contain an
 * XMR address in the correct format, returns an empty string.  <dnssec_valid>
 * will be set true or false according to whether or not the DNS query passes
 * DNSSEC validation.
 *
 * @param url the url to look up
 * @param dnssec_valid return-by-reference for DNSSEC status of query
 *
 * @return a loki address (as a string) or an empty string
 */
std::vector<std::string> addresses_from_url(const std::string_view url, bool& dnssec_valid)
{
  std::vector<std::string> addresses;
  // get txt records
  bool dnssec_available, dnssec_isvalid;
  std::string oa_addr = DNSResolver::instance().get_dns_format_from_oa_address(url);
  auto records = DNSResolver::instance().get_txt_record(oa_addr, dnssec_available, dnssec_isvalid);

  // TODO: update this to allow for conveying that dnssec was not available
  if (dnssec_available && dnssec_isvalid)
  {
    dnssec_valid = true;
  }
  else dnssec_valid = false;

  // for each txt record, try to find a loki address in it.
  for (auto& rec : records)
  {
    std::string addr = address_from_txt_record(rec);
    if (addr.size())
    {
      addresses.push_back(std::move(addr));
    }
  }
  return addresses;
}

std::string get_account_address_as_str_from_url(const std::string_view url, bool& dnssec_valid,
    std::function<std::string(const std::string_view, const std::vector<std::string>&, bool)> dns_confirm)
{
  // attempt to get address from dns query
  auto addresses = addresses_from_url(url, dnssec_valid);
  if (addresses.empty())
  {
    LOG_ERROR("wrong address: " << url);
    return {};
  }
  return dns_confirm(url, addresses, dnssec_valid);
}

namespace
{
  bool dns_records_match(const std::vector<std::string>& a, const std::vector<std::string>& b)
  {
    if (a.size() != b.size()) return false;

    for (const auto& record_in_a : a)
    {
      bool ok = false;
      for (const auto& record_in_b : b)
      {
	if (record_in_a == record_in_b)
	{
	  ok = true;
	  break;
	}
      }
      if (!ok) return false;
    }

    return true;
  }
}

bool load_txt_records_from_dns(std::vector<std::string> &good_records, const std::vector<std::string> &dns_urls)
{
  // Prevent infinite recursion when distributing
  if (dns_urls.empty()) return false;

  std::vector<std::vector<std::string> > records;
  records.resize(dns_urls.size());

  size_t first_index = crypto::rand_idx(dns_urls.size());

  // send all requests in parallel
  std::deque<bool> avail(dns_urls.size(), false), valid(dns_urls.size(), false);
  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter;
  for (size_t n = 0; n < dns_urls.size(); ++n)
  {
    tpool.submit(&waiter,[n, dns_urls, &records, &avail, &valid](){
      records[n] = tools::DNSResolver::instance().get_txt_record(dns_urls[n], avail[n], valid[n]); 
    });
  }
  waiter.wait(&tpool);

  size_t cur_index = first_index;
  do
  {
    const std::string &url = dns_urls[cur_index];
    if (!avail[cur_index])
    {
      records[cur_index].clear();
      LOG_PRINT_L2("DNSSEC not available for hostname: " << url << ", skipping.");
    }
    if (!valid[cur_index])
    {
      records[cur_index].clear();
      LOG_PRINT_L2("DNSSEC validation failed for hostname: " << url << ", skipping.");
    }

    cur_index++;
    if (cur_index == dns_urls.size())
    {
      cur_index = 0;
    }
  } while (cur_index != first_index);

  size_t num_valid_records = 0;

  for( const auto& record_set : records)
  {
    if (record_set.size() != 0)
    {
      num_valid_records++;
    }
  }

  if (num_valid_records < 2)
  {
    LOG_PRINT_L0("WARNING: no two valid DNS TXT records were received");
    return false;
  }

  int good_records_index = -1;
  for (size_t i = 0; i < records.size() - 1; ++i)
  {
    if (records[i].size() == 0) continue;

    for (size_t j = i + 1; j < records.size(); ++j)
    {
      if (dns_records_match(records[i], records[j]))
      {
        good_records_index = i;
        break;
      }
    }
    if (good_records_index >= 0) break;
  }

  if (good_records_index < 0)
  {
    LOG_PRINT_L0("WARNING: no two DNS TXT records matched");
    return false;
  }

  good_records = records[good_records_index];
  return true;
}

std::vector<std::string> parse_dns_public(const char *s)
{
  unsigned ip0, ip1, ip2, ip3;
  char c;
  std::vector<std::string> dns_public_addr;
  if (s == "tcp"sv)
  {
    for (auto& default_dns : DEFAULT_DNS_PUBLIC_ADDR)
      dns_public_addr.emplace_back(default_dns);
    LOG_PRINT_L0("Using default public DNS server(s): " << tools::join(", ", dns_public_addr) << " (TCP)");
  }
  else if (std::sscanf(s, "tcp://%u.%u.%u.%u%c", &ip0, &ip1, &ip2, &ip3, &c) == 4)
  {
    if (ip0 > 255 || ip1 > 255 || ip2 > 255 || ip3 > 255)
    {
      MERROR("Invalid IP: " << s << ", using default");
    }
    else
    {
      dns_public_addr.emplace_back(s + 6);
    }
  }
  else
  {
    MERROR("Invalid DNS_PUBLIC contents, ignored");
  }
  return dns_public_addr;
}

}  // namespace tools::dns_utils

}  // namespace tools

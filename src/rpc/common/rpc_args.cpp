// Copyright (c) 2014-2019, The Monero Project
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
//
#include "rpc_args.h"

#include <boost/version.hpp>
#include <boost/asio/ip/address.hpp>
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/string_util.h"

using namespace std::literals;

namespace cryptonote
{

  rpc_args::descriptors::descriptors()
     : rpc_bind_ip({"rpc-bind-ip", rpc_args::tr("Specify IP to bind RPC server"), "127.0.0.1"})
     , rpc_bind_ipv6_address({"rpc-bind-ipv6-address", rpc_args::tr("Specify IPv6 address to bind RPC server"), "::1"})
     , rpc_use_ipv6({"rpc-use-ipv6", rpc_args::tr("Allow IPv6 for RPC"), false})
     , rpc_ignore_ipv4({"rpc-ignore-ipv4", rpc_args::tr("Ignore unsuccessful IPv4 bind for RPC"), false})
     , rpc_login({"rpc-login", rpc_args::tr("Specify username[:password] required for RPC server"), "", true})
     , confirm_external_bind({"confirm-external-bind", rpc_args::tr("Confirm rpc bind IP value is NOT a loopback (local) IP")})
     , rpc_access_control_origins({"rpc-access-control-origins", rpc_args::tr("Specify a comma separated list of origins to allow cross origin resource sharing"), ""})
     , zmq_rpc_bind_ip({"zmq-rpc-bind-ip", rpc_args::tr("Deprecated option, ignored."), ""})
     , zmq_rpc_bind_port({"zmq-rpc-bind-port", rpc_args::tr("Deprecated option, ignored."), ""})
  {}

  const char* rpc_args::tr(const char* str) { return i18n_translate(str, "cryptonote::rpc_args"); }

  void rpc_args::init_options(boost::program_options::options_description& desc, boost::program_options::options_description& hidden)
  {
    const descriptors arg{};
    command_line::add_arg(desc, arg.rpc_bind_ip);
    command_line::add_arg(desc, arg.rpc_bind_ipv6_address);
    command_line::add_arg(desc, arg.rpc_use_ipv6);
    command_line::add_arg(desc, arg.rpc_ignore_ipv4);
    command_line::add_arg(desc, arg.rpc_login);
    command_line::add_arg(desc, arg.confirm_external_bind);
    command_line::add_arg(desc, arg.rpc_access_control_origins);
    command_line::add_arg(hidden, arg.zmq_rpc_bind_ip);
    command_line::add_arg(hidden, arg.zmq_rpc_bind_port);
  }

  // Checks an IP address for validity; throws on problem.
  static void check_ip(const std::string& ip, bool allow_external, const std::string& option_name) {
    boost::system::error_code ec{};
    const auto parsed_ip =
#if BOOST_VERSION >= 106600
      boost::asio::ip::make_address(ip, ec);
#else
      boost::asio::ip::address::from_string(ip, ec);
#endif
    if (ec)
      throw std::runtime_error{tr("Invalid IP address given for --") + option_name};

    if (!parsed_ip.is_loopback() && !allow_external)
      throw std::runtime_error{
        "--" + option_name +
        tr(" permits inbound unencrypted external connections. Consider SSH tunnel or SSL proxy instead. Override with --confirm-external-bind")};
  }

  rpc_args rpc_args::process(const boost::program_options::variables_map& vm)
  {
    const descriptors arg{};
    rpc_args config{};

    if (!command_line::is_arg_defaulted(vm, arg.rpc_bind_ip)) {
      config.bind_ip = command_line::get_arg(vm, arg.rpc_bind_ip);
      check_ip(*config.bind_ip, command_line::get_arg(vm, arg.confirm_external_bind), arg.rpc_bind_ip.name);
    }
    if (!command_line::is_arg_defaulted(vm, arg.rpc_bind_ipv6_address))
      config.bind_ipv6_address = command_line::get_arg(vm, arg.rpc_bind_ipv6_address);
    config.use_ipv6 = command_line::get_arg(vm, arg.rpc_use_ipv6);
    config.require_ipv4 = !command_line::get_arg(vm, arg.rpc_ignore_ipv4);
    if (config.bind_ipv6_address && !config.bind_ipv6_address->empty())
    {
      // allow square braces, but remove them here if present
      auto& ipv6 = *config.bind_ipv6_address;
      if (ipv6.size() > 2 && ipv6.front() == '[' && ipv6.back() == ']')
        ipv6 = ipv6.substr(1, ipv6.size() - 2);
      check_ip(ipv6, command_line::get_arg(vm, arg.confirm_external_bind), arg.rpc_bind_ipv6_address.name);
    }

    auto verify = [](bool verify) { return tools::password_container::prompt(verify, "RPC server password"); };
    if (command_line::has_arg(vm, arg.rpc_login))
      config.login = tools::login::parse(command_line::get_arg(vm, arg.rpc_login), true, verify);
    else if (const char *env_rpc_login = std::getenv("RPC_LOGIN"); env_rpc_login != nullptr && std::strlen(env_rpc_login))
      config.login = tools::login::parse(env_rpc_login, true, verify);

    if (config.login && config.login->username.empty())
      throw std::runtime_error{tr("Username specified with --") + std::string{arg.rpc_login.name} + " cannot be empty"};

    auto access_control_origins_input = command_line::get_arg(vm, arg.rpc_access_control_origins);
    if (!access_control_origins_input.empty())
    {
      // FIXME: this requirement makes no sense.
      if (!config.login)
        throw std::runtime_error{"--"s + arg.rpc_access_control_origins.name + tr(" requires RPC server password --") + arg.rpc_login.name + tr(" cannot be empty")};

      auto aco_entries = tools::split_any(access_control_origins_input, ", \t", true);
      std::vector<std::string> access_control_origins;
      access_control_origins.reserve(aco_entries.size());
      for (auto& aco : aco_entries) access_control_origins.emplace_back(aco);
    }

    return config;
  }
}

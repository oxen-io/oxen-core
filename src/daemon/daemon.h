// Copyright (c) 2018-2020, The Loki Project
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

#pragma once
#include <boost/program_options.hpp>
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "p2p/net_node.h"
#include "rpc/core_rpc_server.h"
#include "rpc/http_server.h"
#include "rpc/lmq_server.h"

#include "blocks/blocks.h"
#include "rpc/core_rpc_server.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "epee/misc_log_ex.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize
{

// Parse an IP:PORT string into a {IP,PORT} pair.  Throws if the string value is not valid.  Accepts
// both IPv4 and IPv6 addresses, but the latter must be specified in square brackets, e.g. [::1]:2345,
// and will be returned *without* square brackets.
std::pair<std::string, uint16_t> parse_ip_port(std::string_view ip_port, const std::string& argname);

class daemon {
public:
  static void init_options(boost::program_options::options_description& option_spec, boost::program_options::options_description& hidden);

  daemon(boost::program_options::variables_map vm);
  ~daemon();

  bool run(bool interactive = false);
  void stop();

private:

  boost::program_options::variables_map vm;

  /// 💩
  using protocol_handler = cryptonote::t_cryptonote_protocol_handler<cryptonote::core>;
  using node_server = nodetool::node_server<protocol_handler>;

  // Core objects; these are in unique ptrs because we want daemon to be movable and most of these
  // are not movable, and std::unique_ptr is a sort of pre-C++17 poor man's std::optional.
  std::unique_ptr<cryptonote::core> core;
  std::unique_ptr<protocol_handler> protocol;
  std::unique_ptr<node_server> p2p;
  std::unique_ptr<cryptonote::rpc::core_rpc_server> rpc;
  std::optional<cryptonote::rpc::http_server> http_rpc_admin, http_rpc_public;
  std::unique_ptr<cryptonote::rpc::lmq_rpc> lmq_rpc;
};

} // namespace daemonize

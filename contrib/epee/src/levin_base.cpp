// Copyright (c) 2019, The Monero Project
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

#include "epee/net/levin_base.h"

namespace epee
{
namespace levin
{
  bucket_head2 make_header(uint32_t command, uint64_t msg_size, uint32_t flags, bool expect_response) noexcept
  {
    bucket_head2 head = {0};
    head.m_signature = LEVIN_SIGNATURE;
    head.m_have_to_return_data = expect_response;
    head.m_cb = msg_size;

    head.m_command = command;
    head.m_protocol_version = LEVIN_PROTOCOL_VER_1;
    head.m_flags = flags;
    return head;
  }

  std::string make_notify(int command, std::span<const std::uint8_t> payload)
  {
    const bucket_head2 head = make_header(command, payload.size(), LEVIN_PACKET_REQUEST, false);
    std::string result;
    result.reserve(sizeof(head) + payload.size());
    result.append(reinterpret_cast<const char*>(&head), sizeof(head));
    result.append(reinterpret_cast<const char*>(payload.data()), payload.size());
    return result;
  }
} // levin
} // epee

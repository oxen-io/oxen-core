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
#include <cstring>

#include "epee/int-util.h"

using namespace std::literals;

namespace epee
{
namespace levin
{
  bucket_head2 make_header(uint32_t command, uint64_t msg_size, uint32_t flags, bool expect_response) noexcept
  {
    bucket_head2 head = {0};
    head.m_signature = SWAP64LE(LEVIN_SIGNATURE);
    head.m_have_to_return_data = expect_response;
    head.m_cb = SWAP64LE(msg_size);

    head.m_command = SWAP32LE(command);
    head.m_protocol_version = SWAP32LE(LEVIN_PROTOCOL_VER_1);
    head.m_flags = SWAP32LE(flags);
    return head;
  }

  std::string make_notify(int command, epee::span<const std::uint8_t> payload)
  {
    const bucket_head2 head = make_header(command, payload.size(), LEVIN_PACKET_REQUEST, false);
    std::string result;
    result.reserve(sizeof(head) + payload.size());
    result.append(reinterpret_cast<const char*>(&head), sizeof(head));
    result.append(reinterpret_cast<const char*>(payload.data()), payload.size());
    return result;
  }

  std::string make_noise_notify(const std::size_t noise_bytes)
  {
    static constexpr const std::uint32_t flags =
        LEVIN_PACKET_BEGIN | LEVIN_PACKET_END;

    if (noise_bytes < sizeof(bucket_head2))
      return ""s;

    std::string buffer(noise_bytes, char(0));
    const bucket_head2 head = make_header(0, noise_bytes - sizeof(bucket_head2), flags, false);
    std::memcpy(buffer.data(), &head, sizeof(head));

    return buffer;
  }

  std::string make_fragmented_notify(const std::string_view noise_message, int command, epee::span<const std::uint8_t> payload)
  {
    std::string result;
    const size_t noise_size = noise_message.size();
    if (noise_size < sizeof(bucket_head2) * 2)
      return result;

    if (payload.size() <= noise_size - sizeof(bucket_head2))
    {
      /* The entire message can be sent at once, and the levin binary parser
         will ignore extra bytes. So just pad with zeroes and otherwise send
         a "normal", not fragmented message. */
      auto padding = noise_message.substr(sizeof(bucket_head2) + payload.size());

      const bucket_head2 head = make_header(command, noise_size - sizeof(bucket_head2), LEVIN_PACKET_REQUEST, false);
      result.reserve(sizeof(head) + payload.size() + padding.size());
      result.append(reinterpret_cast<const char*>(&head), sizeof(head));
      result.append(reinterpret_cast<const char*>(payload.data()), payload.size());
      result.append(padding);
      return result;
    }

    // fragment message
    const size_t payload_space = noise_size - sizeof(bucket_head2);
    const size_t expected_fragments = ((payload.size() - 2) / payload_space) + 1;

    result.reserve((expected_fragments + 1) * noise_size); // +1 here overselects for internal bucket_head2 value

    bucket_head2 head = make_header(0, noise_size - sizeof(bucket_head2), LEVIN_PACKET_BEGIN, false);
    result.append(reinterpret_cast<const char*>(&head), sizeof(head));

    head.m_command = command;
    head.m_flags = LEVIN_PACKET_REQUEST;
    head.m_cb = payload.size();
    result.append(reinterpret_cast<const char*>(&head), sizeof(head));

    size_t copy_size = payload.remove_prefix(payload_space - sizeof(bucket_head2));
    result.append(reinterpret_cast<const char*>(payload.data()) - copy_size, copy_size);

    head.m_command = 0;
    head.m_flags = 0;
    head.m_cb = noise_size - sizeof(bucket_head2);

    while (!payload.empty())
    {
      copy_size = payload.remove_prefix(payload_space);

      if (payload.empty())
        head.m_flags = LEVIN_PACKET_END;

      result.append(reinterpret_cast<const char*>(&head), sizeof(head));
      result.append(reinterpret_cast<const char*>(payload.data()) - copy_size, copy_size);
    }

    result.append(noise_message.substr(copy_size + sizeof(bucket_head2)));

    return result;
  }
} // levin
} // epee

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

#include "levin_notify.h"

#include <algorithm>
#include <oxen/quic/utils.hpp>

#include "common/varint.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "p2p/net_node.h"

namespace cryptonote::levin {

using epee::connection_id_t;

namespace {
    constexpr std::size_t connection_id_reserve_size = 100;

    std::string make_tx_payload(std::vector<std::string>&& txs, const bool pad) {
        NOTIFY_NEW_TRANSACTIONS::request request{};
        request.txs = std::move(txs);

        if (pad) {
            size_t bytes = 9 /* header */ + 4 /* 1 + 'txs' */ +
                           tools::get_varint_data(request.txs.size()).size();
            for (auto tx_blob_it = request.txs.begin(); tx_blob_it != request.txs.end();
                 ++tx_blob_it)
                bytes += tools::get_varint_data(tx_blob_it->size()).size() + tx_blob_it->size();

            // stuff some dummy bytes in to stay safe from traffic volume analysis
            static constexpr const size_t granularity = 1024;
            size_t padding = granularity - bytes % granularity;
            const size_t overhead = 2 /* 1 + '_' */ + tools::get_varint_data(padding).size();
            if (overhead > padding)
                padding = 0;
            else
                padding -= overhead;
            request._ = std::string(padding, ' ');

            std::string arg_buff;
            epee::serialization::store_t_to_binary(request, arg_buff);

            // we probably lowballed the payload size a bit, so added a but too much. Fix this now.
            size_t remove = arg_buff.size() % granularity;
            if (remove > request._.size())
                request._.clear();
            else
                request._.resize(request._.size() - remove);
            // if the size of _ moved enough, we might lose byte in size encoding, we don't care
        }

        std::string fullBlob;
        if (!epee::serialization::store_t_to_binary(request, fullBlob))
            throw std::runtime_error{"Failed to serialize to epee binary format"};

        return fullBlob;
    }
}  // namespace

namespace detail {
    struct zone {
        zone(boost::asio::io_service& io_service, std::shared_ptr<connections> p2p) :
                p2p(std::move(p2p)), strand(io_service) {}

        const std::shared_ptr<connections> p2p;
        // The levin `foreach_connection` is serialized with a mutex, so flood notifications go
        // through a strand rather than having threads contend for it.
        boost::asio::io_service::strand strand;
    };
}  // namespace detail

namespace {
    //! Sends a message to every active connection
    class flood_notify {
        std::shared_ptr<detail::zone> zone_;
        epee::shared_sv message_;  // Requires manual copy
        connection_id_t source_;

      public:
        explicit flood_notify(
                std::shared_ptr<detail::zone> zone,
                epee::shared_sv message,
                const connection_id_t& source) :
                zone_(std::move(zone)), message_(message), source_(source) {}

        flood_notify(flood_notify&&) = default;
        flood_notify(const flood_notify& source) :
                zone_(source.zone_), message_(source.message_), source_(source.source_) {}

        void operator()() const {
            if (!zone_ || !zone_->p2p)
                return;

            assert(zone_->strand.running_in_this_thread());

            std::vector<connection_id_t> connections;
            connections.reserve(connection_id_reserve_size);
            zone_->p2p->foreach_connection([this, &connections](detail::p2p_context& context) {
                if (this->source_ != context.m_connection_id)
                    connections.emplace_back(context.m_connection_id);
                return true;
            });

            for (const connection_id_t& connection : connections)
                zone_->p2p->send(message_, connection);
        }
    };
}  // namespace

notify::notify(boost::asio::io_service& service, std::shared_ptr<connections> p2p) :
        zone_(std::make_shared<detail::zone>(service, std::move(p2p))) {
    if (!zone_->p2p)
        throw std::logic_error{"cryptonote::levin::notify cannot have nullptr p2p argument"};
}

notify::~notify() noexcept {}

bool notify::send_txs(
        std::vector<std::string> txs, const connection_id_t& source, const bool pad_txs) {
    if (!zone_)
        return false;

    std::sort(txs.begin(), txs.end());  // don't leak receive order

    const std::string payload = make_tx_payload(std::move(txs), pad_txs);
    epee::shared_sv message{epee::levin::make_notify(
            NOTIFY_NEW_TRANSACTIONS::ID,
            oxen::quic::reinterpret_span<const std::uint8_t>(std::span{payload}))};

    zone_->strand.dispatch(flood_notify{zone_, std::move(message), source}, std::allocator<void>{});

    return true;
}
}  // namespace cryptonote::levin

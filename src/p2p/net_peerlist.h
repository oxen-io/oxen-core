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
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>
#include <iosfwd>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "common/fs.h"
#include "common/random.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "epee/net/enums.h"
#include "epee/net/local_ip.h"
#include "p2p_protocol_defs.h"

namespace nodetool {
struct peerlist_types {
    std::vector<peerlist_entry> white;
    std::vector<peerlist_entry> gray;
    std::vector<anchor_peerlist_entry> anchor;
};

class peerlist_storage {
  public:
    peerlist_storage() : m_types{} {}

    //! \return Peers stored in stream `src` in `new_format` (portable archive or older
    //! non-portable).
    static std::optional<peerlist_storage> open(std::istream& src, const bool new_format);

    //! \return Peers stored in file at `path`
    static std::optional<peerlist_storage> open(const fs::path& path);

    peerlist_storage(peerlist_storage&&) = default;
    peerlist_storage(const peerlist_storage&) = delete;

    ~peerlist_storage() noexcept;

    peerlist_storage& operator=(peerlist_storage&&) = default;
    peerlist_storage& operator=(const peerlist_storage&) = delete;

    //! Save peers from `this` and `other` in stream `dest`.
    bool store(std::ostream& dest, const peerlist_types& other) const;

    //! Save peers from `this` and `other` in one file at `path`.
    bool store(const fs::path& path, const peerlist_types& other) const;

    //! \return Peers in `zone` and from remove from `this`.
    peerlist_types take_zone(epee::net_utils::zone zone);

  private:
    peerlist_types m_types;
};

/************************************************************************/
/*                                                                      */
/************************************************************************/
class peerlist_manager {
  public:
    bool init(peerlist_types&& peers, bool allow_local_ip);
    size_t get_white_peers_count() {
        std::lock_guard lock{m_peerlist_lock};
        return m_peers_white.size();
    }
    size_t get_gray_peers_count() {
        std::lock_guard lock{m_peerlist_lock};
        return m_peers_gray.size();
    }
    bool merge_peerlist(
            const std::vector<peerlist_entry>& outer_bs,
            const std::function<bool(const peerlist_entry&)>& f = NULL);
    bool get_peerlist_head(
            std::vector<peerlist_entry>& bs_head,
            bool anonymize,
            uint32_t depth = cryptonote::p2p::DEFAULT_PEERS_IN_HANDSHAKE);
    void get_peerlist(std::vector<peerlist_entry>& pl_gray, std::vector<peerlist_entry>& pl_white);
    void get_peerlist(peerlist_types& peers);
    bool get_white_peer_by_index(peerlist_entry& p, size_t i);
    bool get_gray_peer_by_index(peerlist_entry& p, size_t i);
    template <typename F>
    bool foreach (bool white, const F& f);
    bool append_with_peer_white(const peerlist_entry& pr);
    bool append_with_peer_gray(const peerlist_entry& pr);
    bool append_with_peer_anchor(const anchor_peerlist_entry& ple);
    bool set_peer_just_seen(
            peerid_type peer, const epee::net_utils::network_address& addr, uint32_t pruning_seed);
    bool is_host_allowed(const epee::net_utils::network_address& address);
    bool get_random_gray_peer(peerlist_entry& pe);
    bool remove_from_peer_gray(const peerlist_entry& pe);
    bool get_and_empty_anchor_peerlist(std::vector<anchor_peerlist_entry>& apl);
    bool remove_from_peer_anchor(const epee::net_utils::network_address& addr);
    bool remove_from_peer_white(const peerlist_entry& pe);

  private:
    struct by_time {};
    struct by_id {};
    struct by_addr {};

    struct modify_all_but_id {
        modify_all_but_id(const peerlist_entry& ple) : m_ple(ple) {}
        void operator()(peerlist_entry& e) { e.id = m_ple.id; }

      private:
        const peerlist_entry& m_ple;
    };

    struct modify_all {
        modify_all(const peerlist_entry& ple) : m_ple(ple) {}
        void operator()(peerlist_entry& e) { e = m_ple; }

      private:
        const peerlist_entry& m_ple;
    };

    struct modify_last_seen {
        modify_last_seen(time_t last_seen) : m_last_seen(last_seen) {}
        void operator()(peerlist_entry& e) { e.last_seen = m_last_seen; }

      private:
        time_t m_last_seen;
    };

    using peers_indexed = boost::multi_index_container<
            peerlist_entry,
            boost::multi_index::indexed_by<
                    // access by peerlist_entry::net_adress
                    boost::multi_index::ordered_unique<
                            boost::multi_index::tag<by_addr>,
                            boost::multi_index::member<
                                    peerlist_entry,
                                    epee::net_utils::network_address,
                                    &peerlist_entry::adr>>,
                    // sort by peerlist_entry::last_seen<
                    boost::multi_index::ordered_non_unique<
                            boost::multi_index::tag<by_time>,
                            boost::multi_index::
                                    member<peerlist_entry, int64_t, &peerlist_entry::last_seen>>>>;

    using anchor_peers_indexed = boost::multi_index_container<
            anchor_peerlist_entry,
            boost::multi_index::indexed_by<
                    // access by anchor_peerlist_entry::net_adress
                    boost::multi_index::ordered_unique<
                            boost::multi_index::tag<by_addr>,
                            boost::multi_index::member<
                                    anchor_peerlist_entry,
                                    epee::net_utils::network_address,
                                    &anchor_peerlist_entry::adr>>,
                    // sort by anchor_peerlist_entry::first_seen
                    boost::multi_index::ordered_non_unique<
                            boost::multi_index::tag<by_time>,
                            boost::multi_index::member<
                                    anchor_peerlist_entry,
                                    int64_t,
                                    &anchor_peerlist_entry::first_seen>>>>;

  private:
    void trim_white_peerlist();
    void trim_gray_peerlist();

    friend class boost::serialization::access;
    std::recursive_mutex m_peerlist_lock;
    std::string m_config_folder;
    bool m_allow_local_ip;

    peers_indexed m_peers_gray;
    peers_indexed m_peers_white;
    anchor_peers_indexed m_peers_anchor;
};
//--------------------------------------------------------------------------------------------------
template <typename F>
bool peerlist_manager::foreach (bool white, const F& f) {
    std::lock_guard lock{m_peerlist_lock};
    auto& by_time_index = white ? m_peers_white.get<by_time>() : m_peers_gray.get<by_time>();
    for (auto it = by_time_index.rbegin(); it != by_time_index.rend(); ++it)
        if (!f(*it))
            return false;
    return true;
}
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
}  // namespace nodetool

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

#include "net_peerlist.h"

#include <algorithm>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/archive/portable_binary_oarchive.hpp>
#include <boost/range/join.hpp>
#include <boost/serialization/version.hpp>
#include <fstream>
#include <functional>
#include <iterator>

#include "common/fs.h"
#include "logging/oxen_logger.h"
#include "net_peerlist_boost_serialization.h"

namespace nodetool {
namespace {
    auto logcat = oxen::log::Cat("p2p");

    constexpr unsigned CURRENT_PEERLIST_STORAGE_ARCHIVE_VER = 6;

    // An entry relayed without a history (by a peer that predates the field, or that never heard
    // one) says nothing about a peer whose history we know.  Any relayed history does replace what
    // we knew: if it is out of date, it costs at most passing over the peer once while syncing,
    // until the peer itself tells us otherwise.
    void keep_known_history(peerlist_entry& updated, const peerlist_entry& known) {
        if (!updated.history)
            updated.history = known.history;
    }

    template <typename Elem, typename Archive>
    std::vector<Elem> load_peers(Archive& a, unsigned ver) {
        // at v6, we drop existing peerlists, because annoying change
        if (ver < 6)
            return {};

        uint64_t size = 0;
        a & size;

        Elem ple{};

        std::vector<Elem> elems{};
        elems.reserve(size);
        while (size--) {
            a & ple;
            elems.push_back(std::move(ple));
        }

        return elems;
    }

    template <typename Archive, typename Range>
    void save_peers(Archive& a, const Range& elems) {
        const uint64_t size = elems.size();
        a & size;
        for (const auto& elem : elems)
            a & elem;
    }

    template <typename Container, typename T>
    void add_peers(Container& dest, std::vector<T>&& src) {
        dest.insert(std::make_move_iterator(src.begin()), std::make_move_iterator(src.end()));
    }

    template <typename Container, typename Range>
    void copy_peers(Container& dest, const Range& src) {
        std::copy(src.begin(), src.end(), std::back_inserter(dest));
    }
}  // namespace

struct peerlist_join {
    const peerlist_types& ours;
    const peerlist_types& other;
};

template <typename Archive>
void serialize(Archive& a, peerlist_types& elem, unsigned ver) {
    elem.white = load_peers<peerlist_entry>(a, ver);
    elem.gray = load_peers<peerlist_entry>(a, ver);
    elem.anchor = load_peers<anchor_peerlist_entry>(a, ver);

    if (ver == 0) {
        // from v1, we do not store the peer id anymore
        peerid_type peer_id{};
        a & peer_id;
    }
}

template <typename Archive>
void serialize(Archive& a, peerlist_join elem, unsigned ver) {
    save_peers(a, boost::range::join(elem.ours.white, elem.other.white));
    save_peers(a, boost::range::join(elem.ours.gray, elem.other.gray));
    save_peers(a, boost::range::join(elem.ours.anchor, elem.other.anchor));
}

std::optional<peerlist_storage> peerlist_storage::open(std::istream& src, const bool new_format) {
    try {
        peerlist_storage out{};
        if (new_format) {
            boost::archive::portable_binary_iarchive a{src};
            a >> out.m_types;
        } else {
            boost::archive::binary_iarchive a{src};
            a >> out.m_types;
        }

        if (src.good())
            return {std::move(out)};
    } catch (const std::exception& e) {
    }

    return std::nullopt;
}

std::optional<peerlist_storage> peerlist_storage::open(const fs::path& path) {
    std::ifstream src_file{path, std::ios::binary};
    if (src_file.fail())
        return std::nullopt;

    std::optional<peerlist_storage> out = open(src_file, true);
    if (!out) {
        // if failed, try reading in unportable mode
        auto unportable = path;
        unportable += ".unportable";
        fs::copy_file(path, unportable, fs::copy_options::overwrite_existing);
        src_file.close();
        src_file.open(path, std::ios_base::binary);
        if (src_file.fail())
            return std::nullopt;

        out = open(src_file, false);
        if (!out) {
            // This is different from the `return std::nullopt` cases above. Those
            // cases could fail due to bad file permissions, so a shutdown is
            // likely more appropriate.
            log::warning(
                    globallogcat, "Failed to load p2p config file, falling back to default config");
            out.emplace();
        }
    }

    return out;
}

peerlist_storage::~peerlist_storage() noexcept {}

bool peerlist_storage::store(std::ostream& dest, const peerlist_types& other) const {
    try {
        boost::archive::portable_binary_oarchive a{dest};
        const peerlist_join pj{std::cref(m_types), std::cref(other)};
        a << pj;
        return dest.good();
    } catch (const boost::archive::archive_exception& e) {
    }

    return false;
}

bool peerlist_storage::store(const fs::path& path, const peerlist_types& other) const {
    std::ofstream dest_file{path, std::ios::binary | std::ios::trunc};
    if (dest_file.fail())
        return false;

    return store(dest_file, other);
}

peerlist_types peerlist_storage::take() {
    return std::exchange(m_types, {});
}

bool peerlist_manager::init(peerlist_types&& peers, bool allow_local_ip) {
    std::unique_lock lock{m_peerlist_lock};

    if (!m_peers_white.empty() || !m_peers_gray.empty() || !m_peers_anchor.empty())
        return false;

    add_peers(m_peers_white.get<by_addr>(), std::move(peers.white));
    add_peers(m_peers_gray.get<by_addr>(), std::move(peers.gray));
    add_peers(m_peers_anchor.get<by_addr>(), std::move(peers.anchor));
    m_allow_local_ip = allow_local_ip;
    return true;
}

void peerlist_manager::get_peerlist(
        std::vector<peerlist_entry>& pl_gray, std::vector<peerlist_entry>& pl_white) {
    std::lock_guard lock{m_peerlist_lock};
    copy_peers(pl_gray, m_peers_gray.get<by_addr>());
    copy_peers(pl_white, m_peers_white.get<by_addr>());
}

void peerlist_manager::get_peerlist(peerlist_types& peers) {
    std::lock_guard lock{m_peerlist_lock};
    peers.white.reserve(peers.white.size() + m_peers_white.size());
    peers.gray.reserve(peers.gray.size() + m_peers_gray.size());
    peers.anchor.reserve(peers.anchor.size() + m_peers_anchor.size());

    copy_peers(peers.white, m_peers_white.get<by_addr>());
    copy_peers(peers.gray, m_peers_gray.get<by_addr>());
    copy_peers(peers.anchor, m_peers_anchor.get<by_addr>());
}

//--------------------------------------------------------------------------------------------------
void peerlist_manager::trim_gray_peerlist() {
    while (m_peers_gray.size() > cryptonote::p2p::LOCAL_GRAY_PEERLIST_LIMIT) {
        peers_indexed::index<by_time>::type& sorted_index = m_peers_gray.get<by_time>();
        sorted_index.erase(sorted_index.begin());
    }
}
//--------------------------------------------------------------------------------------------------
void peerlist_manager::trim_white_peerlist() {
    while (m_peers_white.size() > cryptonote::p2p::LOCAL_WHITE_PEERLIST_LIMIT) {
        peers_indexed::index<by_time>::type& sorted_index = m_peers_white.get<by_time>();
        sorted_index.erase(sorted_index.begin());
    }
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::merge_peerlist(
        const std::vector<peerlist_entry>& outer_bs,
        const std::function<bool(const peerlist_entry&)>& f) {
    std::unique_lock lock{m_peerlist_lock};
    for (const peerlist_entry& be : outer_bs) {
        if (!f || f(be))
            append_with_peer_gray(be);
    }
    // delete extra elements
    trim_gray_peerlist();
    return true;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::get_white_peer_by_index(peerlist_entry& p, size_t i) {
    std::unique_lock lock{m_peerlist_lock};
    if (i >= m_peers_white.size())
        return false;

    peers_indexed::index<by_time>::type& by_time_index = m_peers_white.get<by_time>();
    p = *std::prev(by_time_index.end(), i + 1);
    return true;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::get_gray_peer_by_index(peerlist_entry& p, size_t i) {
    std::unique_lock lock{m_peerlist_lock};
    if (i >= m_peers_gray.size())
        return false;

    peers_indexed::index<by_time>::type& by_time_index = m_peers_gray.get<by_time>();
    p = *std::prev(by_time_index.end(), i + 1);
    return true;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::is_host_allowed(const oxen::quic::Address& address) {
    // never allow loopback ip
    if (net::is_loopback(address))
        return false;

    if (!m_allow_local_ip && net::is_local(address))
        return false;

    return true;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::get_peerlist_head(
        std::vector<peerlist_entry>& bs_head, bool anonymize, uint32_t depth) {
    std::unique_lock lock{m_peerlist_lock};
    auto& by_time_index = m_peers_white.get<by_time>();
    uint32_t cnt = 0;

    // picks a random set of peers within the whole set, rather pick the first depth elements.
    // The intent is that if someone asks twice, they can't easily tell:
    // - this address was not in the first list, but is in the second, so the only way this can be
    // is if its last_seen was recently reset, so this means the target node recently had a new
    // connection to that address
    // - this address was in the first list, and not in the second, which means either the address
    // was moved to the gray list (if it's not accessible, which the attacker can check if
    // the address accepts incoming connections) or it was the oldest to still fit in the 250 items,
    // so its last_seen is old.
    //
    // See Cao, Tong et al. "Exploring the Monero Peer-to-Peer Network".
    // https://eprint.iacr.org/2019/411
    //
    const uint32_t pick_depth = anonymize ? m_peers_white.size() : depth;
    bs_head.reserve(pick_depth);
    for (auto it = by_time_index.rbegin(); it != by_time_index.rend(); ++it) {
        if (cnt++ >= pick_depth)
            break;

        bs_head.push_back(*it);
    }

    if (anonymize) {
        std::shuffle(bs_head.begin(), bs_head.end(), tools::rng);
        if (bs_head.size() > depth)
            bs_head.resize(depth);
        for (auto& e : bs_head)
            e.last_seen = 0;
    }

    return true;
}

bool peerlist_manager::set_peer_just_seen(
        peerid_type peer, const oxen::quic::Address& addr, std::optional<uint64_t> history) try {
    if (!is_host_allowed(addr))
        return true;

    std::lock_guard lock{m_peerlist_lock};
    const peerlist_entry ple{
            .adr = addr,
            .id = peer,
            .last_seen = static_cast<int64_t>(time(nullptr)),
            .history = history};
    // This comes from the peer itself, so unlike what append_with_peer_white is given it replaces
    // the whole entry, last seen time and history included.
    auto by_addr_it = m_peers_white.get<by_addr>().find(addr);
    if (by_addr_it != m_peers_white.get<by_addr>().end()) {
        m_peers_white.replace(by_addr_it, ple);
        return true;
    }
    return append_with_peer_white(ple);
} catch (const std::exception& e) {
    log::error(logcat, "Exception in peerlist_manager::set_peer_just_seen(): {}", e.what());
    return false;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::append_with_peer_white(const peerlist_entry& ple) try {
    if (!is_host_allowed(ple.adr))
        return true;

    std::lock_guard lock{m_peerlist_lock};
    // find in white list
    auto by_addr_it_wt = m_peers_white.get<by_addr>().find(ple.adr);
    if (by_addr_it_wt == m_peers_white.get<by_addr>().end()) {
        // put new record into white list
        m_peers_white.insert(ple);
        trim_white_peerlist();
    } else {
        // update record in white list
        peerlist_entry new_ple = ple;
        new_ple.last_seen = by_addr_it_wt->last_seen;  // do not overwrite the last seen timestamp,
                                                       // incoming peer list are untrusted
        keep_known_history(new_ple, *by_addr_it_wt);
        m_peers_white.replace(by_addr_it_wt, new_ple);
    }
    // remove from gray list, if need
    auto by_addr_it_gr = m_peers_gray.get<by_addr>().find(ple.adr);
    if (by_addr_it_gr != m_peers_gray.get<by_addr>().end()) {
        m_peers_gray.erase(by_addr_it_gr);
    }
    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in peerlist_manager::append_with_peer_white(): {}", e.what());
    return false;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::append_with_peer_gray(const peerlist_entry& ple) try {
    if (!is_host_allowed(ple.adr))
        return true;

    std::lock_guard lock{m_peerlist_lock};
    // find in white list
    auto by_addr_it_wt = m_peers_white.get<by_addr>().find(ple.adr);
    if (by_addr_it_wt != m_peers_white.get<by_addr>().end())
        return true;

    // update gray list
    auto by_addr_it_gr = m_peers_gray.get<by_addr>().find(ple.adr);
    if (by_addr_it_gr == m_peers_gray.get<by_addr>().end()) {
        // put new record into white list
        m_peers_gray.insert(ple);
        trim_gray_peerlist();
    } else {
        // update record in gray list
        peerlist_entry new_ple = ple;
        new_ple.last_seen = by_addr_it_gr->last_seen;  // do not overwrite the last seen timestamp,
                                                       // incoming peer list are untrusted
        keep_known_history(new_ple, *by_addr_it_gr);
        m_peers_gray.replace(by_addr_it_gr, new_ple);
    }
    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in peerlist_manager::append_with_peer_gray(): {}", e.what());
    return false;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::append_with_peer_anchor(const anchor_peerlist_entry& ple) try {
    std::lock_guard lock{m_peerlist_lock};

    auto by_addr_it_anchor = m_peers_anchor.get<by_addr>().find(ple.adr);

    if (by_addr_it_anchor == m_peers_anchor.get<by_addr>().end()) {
        m_peers_anchor.insert(ple);
    }

    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in peerlist_manager::append_with_peer_anchor(): {}", e.what());
    return false;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::get_random_gray_peer(peerlist_entry& pe) try {
    std::lock_guard lock{m_peerlist_lock};

    if (m_peers_gray.empty()) {
        return false;
    }

    size_t random_index = crypto::rand_idx(m_peers_gray.size());

    peers_indexed::index<by_time>::type& by_time_index = m_peers_gray.get<by_time>();
    pe = *std::prev(by_time_index.end(), random_index + 1);

    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in peerlist_manager::get_random_gray_peer(): {}", e.what());
    return false;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::remove_from_peer_white(const peerlist_entry& pe) try {
    std::lock_guard lock{m_peerlist_lock};

    peers_indexed::index_iterator<by_addr>::type iterator =
            m_peers_white.get<by_addr>().find(pe.adr);

    if (iterator != m_peers_white.get<by_addr>().end()) {
        m_peers_white.erase(iterator);
    }

    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in peerlist_manager::remove_from_peer_white(): {}", e.what());
    return false;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::remove_from_peer_gray(const peerlist_entry& pe) try {
    std::lock_guard lock{m_peerlist_lock};

    peers_indexed::index_iterator<by_addr>::type iterator =
            m_peers_gray.get<by_addr>().find(pe.adr);

    if (iterator != m_peers_gray.get<by_addr>().end()) {
        m_peers_gray.erase(iterator);
    }

    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in peerlist_manager::remove_from_peer_gray(): {}", e.what());
    return false;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::get_and_empty_anchor_peerlist(std::vector<anchor_peerlist_entry>& apl) try {
    std::lock_guard lock{m_peerlist_lock};

    auto begin = m_peers_anchor.get<by_time>().begin();
    auto end = m_peers_anchor.get<by_time>().end();

    std::for_each(begin, end, [&apl](const anchor_peerlist_entry& a) { apl.push_back(a); });

    m_peers_anchor.get<by_time>().clear();

    return true;
} catch (const std::exception& e) {
    log::error(
            logcat, "Exception in peerlist_manager::get_and_empty_anchor_peerlist(): {}", e.what());
    return false;
}
//--------------------------------------------------------------------------------------------------
bool peerlist_manager::remove_from_peer_anchor(const oxen::quic::Address& addr) try {
    std::lock_guard lock{m_peerlist_lock};

    anchor_peers_indexed::index_iterator<by_addr>::type iterator =
            m_peers_anchor.get<by_addr>().find(addr);

    if (iterator != m_peers_anchor.get<by_addr>().end()) {
        m_peers_anchor.erase(iterator);
    }

    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in peerlist_manager::remove_from_peer_anchor(): {}", e.what());
    return false;
}

}  // namespace nodetool

BOOST_CLASS_VERSION(nodetool::peerlist_types, nodetool::CURRENT_PEERLIST_STORAGE_ARCHIVE_VER);
BOOST_CLASS_VERSION(nodetool::peerlist_join, nodetool::CURRENT_PEERLIST_STORAGE_ARCHIVE_VER);

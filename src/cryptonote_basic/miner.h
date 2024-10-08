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

#include <atomic>
#include <thread>

#include "common/fs.h"
#include "common/periodic_task.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_basic/verification_context.h"
#ifdef _WIN32
#include <windows.h>
#endif

namespace boost::program_options {
class variables_map;
class options_description;
}  // namespace boost::program_options

namespace cryptonote {
using namespace std::literals;

struct i_miner_handler {
    virtual bool handle_block_found(block& b, block_verification_context& bvc) = 0;
    virtual bool create_next_miner_block_template(
            block& b,
            const account_public_address& adr,
            difficulty_type& diffic,
            uint64_t& height,
            uint64_t& expected_reward,
            const std::string& ex_nonce) = 0;

  protected:
    ~i_miner_handler(){};
};

/************************************************************************/
/*                                                                      */
/************************************************************************/
class miner {
  public:
    using get_block_hash_cb =
            std::function<bool(const cryptonote::block&, uint64_t, unsigned int, crypto::hash&)>;
    using handle_block_found_cb = std::function<bool(block& b, block_verification_context& bvc)>;
    using create_next_miner_block_template_cb = std::function<bool(
            block& b,
            const account_public_address& adr,
            difficulty_type& diffic,
            uint64_t& height,
            uint64_t& expected_reward,
            const std::string& ex_nonce)>;

    miner(get_block_hash_cb hash,
          handle_block_found_cb found,
          create_next_miner_block_template_cb create);
    ~miner();
    bool init(const boost::program_options::variables_map& vm, network_type nettype);
    static void init_options(boost::program_options::options_description& desc);
    bool set_block_template(
            const block& bl, const difficulty_type& diffic, uint64_t height, uint64_t block_reward);
    bool on_block_chain_update();
    bool start(
            const account_public_address& adr,
            int threads_count,
            int stop_after = 0,
            bool slow_mining = false);
    double get_speed() const;
    uint32_t get_threads_count() const;
    bool stop();
    bool is_mining() const;
    const account_public_address& get_mining_address() const;
    bool on_idle();
    void on_synchronized();
    // synchronous analog (for fast calls)
    static bool find_nonce_for_given_block(
            const get_block_hash_cb& gbh,
            block& bl,
            const difficulty_type& diffic,
            uint64_t height);
    void pause();
    void resume();
    uint64_t get_block_reward() const { return m_block_reward; }

  private:
    bool worker_thread(uint32_t index, bool slow_mining = false);
    bool request_block_template();
    void update_hashrate();

    struct miner_config {
        uint64_t current_extra_message_index;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(current_extra_message_index)
        END_KV_SERIALIZE_MAP()
    };

    std::atomic<bool> m_stop;
    uint64_t m_stop_height = std::numeric_limits<uint64_t>::max();
    std::mutex m_template_lock;
    block m_template;
    std::atomic<uint32_t> m_template_no = 0;
    std::atomic<uint32_t> m_starter_nonce;
    difficulty_type m_diffic = 0;
    uint64_t m_height = 0;
    std::atomic<int> m_threads_total = 0;
    std::atomic<int> m_pausers_count = 0;
    std::mutex m_miners_count_mutex;

    std::list<std::thread> m_threads;
    std::mutex m_threads_lock;
    get_block_hash_cb m_get_block_hash;
    handle_block_found_cb m_handle_block_found;
    create_next_miner_block_template_cb m_create_next_miner_block_template;
    account_public_address m_mine_address;
    tools::periodic_task m_update_block_template_interval{"mining block template updater", 5s};
    tools::periodic_task m_update_hashrate_interval{"mining hash rate updater", 2s};

    mutable std::mutex m_hashrate_mutex;
    std::optional<std::chrono::steady_clock::time_point> m_last_hr_update;
    std::atomic<uint64_t> m_hashes = 0;
    double m_current_hash_rate = 0.0;

    bool m_do_mining = false;
    std::atomic<uint64_t> m_block_reward = 0;
};
}  // namespace cryptonote

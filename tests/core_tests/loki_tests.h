// Copyright (c) 2014-2018, The Monero Project
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
#include "chaingen.h"

/************************************************************************/
/*                                                                      */
/************************************************************************/

void                                      loki_register_callback                  (std::vector<test_event_entry> &events, std::string const &callback_name, loki_callback callback);
std::vector<std::pair<uint8_t, uint64_t>> loki_generate_sequential_hard_fork_table(uint8_t max_hf_version = cryptonote::network_version_count - 1);

struct loki_checkpointing_alt_chain_handle_alt_blocks_at_tip                         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_checkpointing_alt_chain_more_service_node_checkpoints_less_pow_overtakes : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_checkpointing_alt_chain_receive_checkpoint_votes_should_reorg_back       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_checkpointing_alt_chain_with_increasing_service_node_checkpoints         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_checkpointing_service_node_checkpoint_from_votes                         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_checkpointing_service_node_checkpoints_check_reorg_windows               : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_core_block_reward_unpenalized                                            : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_core_governance_batched_reward                                           : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_core_test_deregister_preferred                                           : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_core_test_deregister_safety_buffer                                       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_core_test_deregister_too_old                                             : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_core_test_deregister_zero_fee                                            : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_core_test_deregister_on_split                                            : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_core_test_state_change_ip_penalty_disallow_dupes                         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_service_nodes_alt_quorums                                                : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_service_nodes_checkpoint_quorum_size                                     : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_service_nodes_gen_nodes                                                  : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_service_nodes_test_rollback                                              : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct loki_service_nodes_test_swarms_basic                                          : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };


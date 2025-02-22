#pragma once

#include <future>
#include <memory>

#include "decoy.hpp"

namespace cryptonote {
struct transaction;
}

namespace wallet {
class Wallet;
class Block;

class DaemonComms {
  public:
    virtual void set_remote(std::string_view address) = 0;

    virtual void propogate_config() = 0;

    virtual int64_t get_height() = 0;

    /* Called by a wallet to tell the daemon comms it exists, as well
     * as what height it needs to sync from.  Updates existing registration
     * if the wallet is already registered.
     *
     * A wallet should call this:
     *   On creation, to inform the daemon comms that it exists and wishes to sync.  Pass
     * new_wallet=true. If the wallet recieves blocks from daemon comms which are in the future for
     *   it.  In this case, it is telling the daemon comms to start syncing from
     *   earlier in the chain.  Pass check_sync_height=true.
     *   When the wallet finishes processing a batch of blocks.  Pass check_sync_height=false.
     */
    virtual void register_wallet(
            Wallet& wallet,
            int64_t height,
            bool check_sync_height = false,
            bool new_wallet = false) = 0;

    virtual void deregister_wallet(Wallet& wallet, std::promise<void>& p) = 0;

    virtual std::pair<int64_t, int64_t> get_fee_parameters() = 0;

    // Called by the wallet to fetch the necessary information to make a ring signature. The indexes
    // are a global reference used by the daemon to uniquely identify outputs. In our distribution
    // we find the earliest and latest indexes that are available and simply pick numbers between
    // the indexes according to our distribution function.
    virtual std::future<std::vector<Decoy>> fetch_decoys(
            const std::vector<int64_t>& indexes, bool with_txid = false) = 0;

    virtual std::future<std::string> submit_transaction(
            const cryptonote::transaction& tx, bool blink) = 0;

    virtual std::future<std::pair<std::string, crypto::hash>> ons_names_to_owners(
            const std::string& name_hash, uint16_t type) = 0;
};

}  // namespace wallet

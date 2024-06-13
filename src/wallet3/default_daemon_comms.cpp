#include "default_daemon_comms.hpp"

#include <common/string_util.h>
#include <cryptonote_basic/cryptonote_format_utils.h>

#include <iostream>
#include <cpptrace/cpptrace.hpp>

#include "block.hpp"
#include "block_tx.hpp"
#include "common/guts.h"
#include "wallet.hpp"
#include "wallet2½.hpp"

namespace wallet {
static auto logcat = oxen::log::Cat("wallet");

void DefaultDaemonComms::on_get_blocks_response(std::vector<std::string> response) {
    if (not response.size()) {
        oxen::log::warning(logcat, "on_get_blocks_response(): empty get_blocks response");
        return;
    }

    const auto& status = response[0];
    if (status != "OK" and status != "END") {
        oxen::log::warning(logcat, "get_blocks response: {}", response[0]);
        return;
    }

    // "OK" response with no blocks may mean we requested blocks past the end of the chain
    // TODO: decide/confirm this behavior on the daemon side of things
    if (response.size() == 1) {
        oxen::log::warning(logcat, "get_blocks response.size() == 1");
        return;
    }

    std::vector<Block> blocks;
    try {
        auto itr = response.cbegin();
        itr++;
        while (itr != response.cend()) {
            const auto& block_str = *itr;
            auto block_dict = oxenc::bt_dict_consumer{block_str};

            Block& b = blocks.emplace_back();

            if (block_dict.key() != "hash")
                return;
            b.hash = tools::make_from_guts<crypto::hash>(block_dict.consume_string_view());

            if (block_dict.key() != "height")
                return;
            b.height = block_dict.consume_integer<int64_t>();

            if (block_dict.key() != "timestamp")
                return;
            b.timestamp = block_dict.consume_integer<int64_t>();

            if (block_dict.key() != "transactions")
                return;
            auto txs_list = block_dict.consume_list_consumer();

            while (not txs_list.is_finished()) {
                if (not txs_list.is_dict())
                    return;

                BlockTX tx;

                auto tx_dict = txs_list.consume_dict_consumer();

                if (tx_dict.key() != "global_indices")
                    return;
                tx.global_indices = tx_dict.consume_list<std::vector<int64_t>>();

                if (tx_dict.key() != "hash")
                    return;
                tx.hash = tools::make_from_guts<crypto::hash>(tx_dict.consume_string_view());

                if (tx_dict.key() != "tx")
                    return;

                tx.tx = wallet25::tx_from_blob(tx_dict.consume_string_view());

                if (not tx_dict.is_finished())
                    return;

                b.transactions.push_back(tx);
            }

            if (not block_dict.is_finished())
                return;

            itr++;
        }
    } catch (const std::exception& e) {
        oxen::log::warning(logcat, "exception thrown: {}", e.what());
        return;
    }

    if (blocks.size() == 0) {
        oxen::log::warning(logcat, "received no blocks, but server said response OK");
        return;
    }

    int64_t start_height = blocks.front().height;
    int64_t end_height = blocks.back().height;

    omq->job(
            [blocks = std::move(blocks), this]() {
                for_each_wallet(
                        [&](std::shared_ptr<Wallet> wallet) { wallet->add_blocks(blocks); });
            },
            sync_thread);

    if (status == "END") {
        omq->job(
                [this, old = this->sync_from_height, start_height, end_height]() {
                    // if a new wallet hasn't been added requesting to sync from lower,
                    // we should be done syncing all wallets
                    if (old <= this->sync_from_height)
                        syncing = false;
                    got_blocks(start_height, end_height);
                },
                sync_thread);
    } else {
        omq->job(
                [this, start_height, end_height]() { got_blocks(start_height, end_height); },
                sync_thread);
    }
}

void DefaultDaemonComms::request_top_block_info() {
    oxen::log::trace(logcat, "request top block called");
    auto timeout_job = [self = weak_from_this()]() {
        if (auto comms = self.lock())
            comms->request_top_block_info();
    };

    omq->cancel_timer(status_timer);
    if (top_block_height == 0) {
        omq->add_timer(status_timer, timeout_job, 3s);
    } else
        omq->add_timer(status_timer, timeout_job, 15s);

    oxen::log::trace(logcat, "requesting rpc.get_height");
    omq->request(
            conn,
            "rpc.get_height",
            [this](bool ok, std::vector<std::string> response) {
                oxen::log::trace(logcat, "rpc get_height response");
                if (not ok or response.size() != 2 or response[0] != "200")
                    return;

                oxenc::bt_dict_consumer dc{response[1]};

                int64_t new_height = 0;
                crypto::hash new_hash;

                if (not dc.skip_until("hash")) {
                    oxen::log::warning(
                            logcat, "bad response from rpc.get_height, key 'hash' missing");
                    throw cpptrace::runtime_error(
                            "bad response from rpc.get_height, key 'hash' missing");
                }
                new_hash = tools::make_from_guts<crypto::hash>(dc.consume_string_view());

                if (not dc.skip_until("height")) {
                    oxen::log::warning(
                            logcat, "bad response from rpc.get_height, key 'height' missing");
                    throw cpptrace::runtime_error(
                            "bad response from rpc.get_height, key 'height' missing");
                }
                new_height = dc.consume_integer<int64_t>();

                bool got_new = (new_height > (top_block_height + 1));
                top_block_hash = new_hash;

                // RPC response is chain length, not top height
                top_block_height = new_height - 1;
                omq->job(
                        [this]() {
                            for_each_wallet([this](auto wallet) {
                                wallet->update_top_block_info(top_block_height, top_block_hash);
                            });
                        },
                        sync_thread);

                if (got_new) {
                    omq->job(
                            [this]() {
                                if (not syncing)
                                    start_syncing();
                            },
                            sync_thread);
                }
            },
            "de");

    oxen::log::trace(logcat, "requesting rpc.get_fee_estimate");
    omq->request(
            conn,
            "rpc.get_fee_estimate",
            [this](bool ok, std::vector<std::string> response) {
                oxen::log::trace(logcat, "rpc get_fee estimate response");
                if (not ok or response.size() != 2 or response[0] != "200")
                    return;

                oxenc::bt_dict_consumer dc{response[1]};

                int64_t new_fee_per_byte = 0;
                int64_t new_fee_per_output = 0;

                if (not dc.skip_until("fee_per_byte")) {
                    oxen::log::warning(
                            logcat,
                            "bad response from rpc.get_fee_estimate, key 'fee_per_byte' missing");
                    throw cpptrace::runtime_error(
                            "bad response from rpc.get_fee_estimate, key 'fee_per_byte' missing");
                }
                new_fee_per_byte = dc.consume_integer<int64_t>();

                if (not dc.skip_until("fee_per_output")) {
                    oxen::log::warning(
                            logcat,
                            "bad response from rpc.get_fee_estimate, key 'fee_per_output' missing");
                    throw cpptrace::runtime_error(
                            "bad response from rpc.get_fee_estimate, key 'fee_per_output' missing");
                }
                new_fee_per_output = dc.consume_integer<int64_t>();

                fee_per_byte = new_fee_per_byte;
                fee_per_output = new_fee_per_output;
            },
            "de");
}

DefaultDaemonComms::DefaultDaemonComms(std::shared_ptr<oxenmq::OxenMQ> omq, DaemonCommsConfig cfg) :
        omq(omq), config(cfg), sync_thread(omq->add_tagged_thread("sync")) {
    omq->MAX_MSG_SIZE = max_response_size;
}

void DefaultDaemonComms::set_remote(std::string_view address) {
    oxen::log::info(logcat, "Set remote called with address: {}", address);
    try {
        remote = oxenmq::address{address};
    } catch (...) {
        // TODO: handle this properly
        throw;
    }

    oxen::log::info(logcat, "Trying to connect to remote oxend");
    conn = omq->connect_remote(
            remote,
            // Callback for success case of connect remote
            [](auto) { oxen::log::info(logcat, "successfully connected via OMQ"); },
            // Callback for failure case of connect remote
            [](auto, auto reason) {
                oxen::log::error(
                        logcat,
                        "Daemon Comms was not successful in connecting to remote oxend. Reason: {}",
                        reason);
            });

    request_top_block_info();
}

void DefaultDaemonComms::propogate_config() {
    // This should refresh everywhere when a member in the config changes
    set_remote(config.address);
}

void DefaultDaemonComms::get_blocks() {
    auto req_cb = [this](bool ok, std::vector<std::string> response) {
        if (not ok or response.size() == 0) {
            // TODO: error logging/handling

            // Retry after a delay to not spam/spin
            auto timer = std::make_shared<oxenmq::TimerID>();
            auto& timer_ref = *timer;
            omq->add_timer(
                    timer_ref,
                    [this, timer = std::move(timer)] {
                        omq->cancel_timer(*timer);
                        get_blocks();
                    },
                    500ms,
                    true,
                    sync_thread);
            return;
        }

        on_get_blocks_response(response);
    };

    std::map<std::string, int64_t> req_params_dict{
            {"max_count", max_sync_blocks},
            {"size_limit", max_response_size},
            {"start_height", sync_from_height}};

    omq->request(conn, "rpc.get_blocks", req_cb, oxenc::bt_serialize(req_params_dict));
}

std::future<std::vector<Decoy>> DefaultDaemonComms::fetch_decoys(
        const std::vector<int64_t>& indexes, bool with_txid) {
    auto p = std::make_shared<std::promise<std::vector<Decoy>>>();
    auto fut = p->get_future();
    auto req_cb = [p = std::move(p), with_txid, indexes = indexes](
                          bool ok, std::vector<std::string> response) {
        if (not ok or response.size() == 0) {
            // TODO: error logging/handling
            return;
        }

        // if not OK
        if (response[0] != "200") {
            oxen::log::warning(logcat, "get_outputs response not ok: {}", response[0]);
            if (response.size() == 2)
                oxen::log::warning(logcat, " -- error: \"{}\"", response[1]);
            return;
        }

        // "OK" response with no outputs
        // TODO: decide/confirm this behavior on the daemon side of things
        if (response.size() == 1) {
            oxen::log::warning(logcat, "get_blocks response.size() == 1");
            return;
        }

        std::vector<Decoy> outputs;
        size_t i = 0;
        try {
            auto outer_dict = oxenc::bt_dict_consumer(response[1]);

            if (outer_dict.key() != "outs")
                return;

            auto outputs_list = outer_dict.consume_list_consumer();

            while (not outputs_list.is_finished()) {
                auto output_dict = outputs_list.consume_dict_consumer();

                Decoy& o = outputs.emplace_back();

                o.global_index = indexes[i++];

                if (output_dict.key() != "height")
                    return;
                o.height = output_dict.consume_integer<int64_t>();

                if (output_dict.key() != "key")
                    return;
                o.key = tools::make_from_guts<crypto::public_key>(
                        output_dict.consume_string_view());

                if (output_dict.key() != "mask")
                    return;
                o.mask = tools::make_from_guts<rct::key>(output_dict.consume_string_view());

                if (with_txid) {
                    if (output_dict.key() != "txid")
                        return;
                    o.txid = output_dict.consume_string_view();
                }

                if (output_dict.key() != "unlocked")
                    return;
                o.unlocked = output_dict.consume_integer<bool>();

                if (not output_dict.is_finished())
                    return;
            }
        } catch (const std::exception& e) {
            oxen::log::warning(logcat, "exception thrown: {}", e.what());
            return;
        }

        if (outputs.size() == 0) {
            oxen::log::warning(logcat, "received no outputs, but server said response OK");
            return;
        }

        p->set_value(std::move(outputs));
    };  // req_cb

    oxenc::bt_dict req_params_dict;
    oxenc::bt_list decoy_list_bt;
    for (auto index : indexes) {
        decoy_list_bt.push_back(index);
    }
    req_params_dict["get_txid"] = with_txid;
    req_params_dict["outputs"] = std::move(decoy_list_bt);
    omq->request(conn, "rpc.get_outs", req_cb, oxenc::bt_serialize(req_params_dict));

    return fut;
}

std::future<std::string> DefaultDaemonComms::submit_transaction(
        const cryptonote::transaction& tx, bool blink) {
    auto p = std::make_shared<std::promise<std::string>>();
    auto fut = p->get_future();
    auto req_cb = [p = std::move(p)](bool ok, std::vector<std::string> response) {
        try {
            if (not ok or response.size() != 2 or response[0] != "200")
                throw cpptrace::runtime_error{"Unknown Error"};

            oxenc::bt_dict_consumer dc{response[1]};
            if (dc.skip_until("reason"))
                throw cpptrace::runtime_error{
                        "Submit Transaction rejected, reason: " + dc.consume_string()};

            if (not dc.skip_until("status"))
                throw cpptrace::runtime_error{"Invalid response from daemon"};

            auto status = dc.consume_string();

            if (status != "OK")
                throw cpptrace::runtime_error{"Submit Transaction rejected, reason: " + status};

            p->set_value("OK");

        } catch (...) {
            p->set_exception(std::current_exception());
        }
    };

    std::string tx_str;
    if (not cryptonote::tx_to_blob(tx, tx_str))
        throw cpptrace::runtime_error{"wallet daemon comms, failed to serialize transaction"};

    oxenc::bt_dict req_params_dict;

    req_params_dict["blink"] = blink;
    req_params_dict["tx"] = tx_str;

    omq->request(conn, "rpc.submit_transaction", req_cb, oxenc::bt_serialize(req_params_dict));

    return fut;
}

std::future<std::pair<std::string, crypto::hash>> DefaultDaemonComms::ons_names_to_owners(
        const std::string& name_hash, const uint16_t type) {
    auto p = std::make_shared<std::promise<std::pair<std::string, crypto::hash>>>();
    auto fut = p->get_future();
    auto req_cb = [p = std::move(p)](bool ok, std::vector<std::string> response) {
        try {
            oxenc::bt_dict_consumer dc{response[1]};

            if (not dc.skip_until("result"))
                throw cpptrace::runtime_error{"Invalid response from daemon"};

            auto result_list = dc.consume_list_consumer();
            auto result = result_list.consume_dict_consumer();

            crypto::hash prev_txid;
            std::string curr_owner;

            if (not result.skip_until("owner"))
                throw cpptrace::runtime_error{"Invalid response from daemon"};

            curr_owner = dc.consume_string();

            if (not result.skip_until("txid"))
                throw cpptrace::runtime_error{"Invalid response from daemon"};

            tools::load_from_hex_guts(dc.consume_string(), prev_txid);

            p->set_value(std::make_pair(curr_owner, prev_txid));
        } catch (...) {
            p->set_exception(std::current_exception());
        }
    };

    oxenc::bt_dict req_params_dict{
            {"name_hash", oxenc::bt_list{{name_hash}}}, {"type", oxenc::bt_list{{type}}}};

    omq->request(conn, "rpc.ons_names_to_owners", req_cb, oxenc::bt_serialize(req_params_dict));

    return fut;
}

void DefaultDaemonComms::register_wallet(
        wallet::Wallet& wallet, int64_t height, bool check_sync_height, bool new_wallet) {
    oxen::log::trace(logcat, "Daemon Comms register_wallet called");
    omq->job(
            [this, w = wallet.shared_from_this(), height, check_sync_height, new_wallet]() {
                oxen::log::trace(logcat, "register_wallet lambda called");
                if (wallets.count(w))
                    wallets[w] = height;
                else if (new_wallet)
                    wallets.emplace(w, height);

                if (check_sync_height) {
                    if (wallets.size() == 1)  // if it's the only wallet
                        sync_from_height = height;
                    else
                        sync_from_height = std::min(sync_from_height, height);
                }
                start_syncing();
            },
            sync_thread);
}

std::pair<int64_t, int64_t> DefaultDaemonComms::get_fee_parameters() {
    return std::make_pair(fee_per_byte, fee_per_output);
}

void DefaultDaemonComms::deregister_wallet(wallet::Wallet& wallet, std::promise<void>& p) {
    oxen::log::trace(logcat, "Daemon Comms deregister_wallet called");
    auto dereg_finish = [this, &p]() mutable { p.set_value(); };

    omq->job(
            [this, w = wallet.shared_from_this(), &p, dereg_finish]() mutable {
                wallets.erase(w);
                w.reset();

                // this fulfills the promise after any functions waiting on this thread
                // have completed, so all references to wallet from here should be gone.
                omq->job(dereg_finish, sync_thread);
                auto itr = std::min_element(
                        wallets.begin(), wallets.end(), [](const auto& l, const auto& r) {
                            return l.second < r.second;
                        });
                if (itr != wallets.end())
                    sync_from_height = itr->second;
                else {
                    sync_from_height = 0;
                    syncing = false;
                }

                oxen::log::debug(
                        logcat,
                        "deregister_wallet() setting sync_from_height to {}",
                        sync_from_height);
                if (sync_from_height != 0 and sync_from_height == top_block_height)
                    syncing = false;
            },
            sync_thread);
}

void DefaultDaemonComms::for_each_wallet(std::function<void(std::shared_ptr<Wallet>)> func) {
    for (auto [wallet, h] : wallets) {
        func(wallet);
    }
}

void DefaultDaemonComms::got_blocks(int64_t start_height, int64_t end_height) {
    if (start_height == sync_from_height)
        sync_from_height = end_height + 1;

    // if we get caught up, or all wallets are removed, no need to request more blocks
    if (not syncing)
        return;

    get_blocks();
}

void DefaultDaemonComms::start_syncing() {
    if ((not syncing and sync_from_height <= top_block_height) or (top_block_height == 0)) {
        syncing = true;
        oxen::log::debug(logcat, "Start Syncing");
        get_blocks();
    }
}

}  // namespace wallet

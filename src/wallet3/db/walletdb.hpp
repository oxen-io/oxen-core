#pragma once

#include <SQLiteCpp/SQLiteCpp.h>

#include <optional>
#include <sqlitedb/database.hpp>

#include "wallet3/output.hpp"
#include "wallet3/walletkeys.hpp"

namespace crypto {
struct hash;
struct key_image;
}  // namespace crypto

namespace wallet {
struct Output;
struct Block;

class WalletDB : public db::Database {
  public:
    using db::Database::Database;

    ~WalletDB();

    // Get a DB transaction.  This will revert any changes done to the db
    // while it exists when it is destroyed unless commit() is called on it.
    SQLite::Transaction db_transaction() { return SQLite::Transaction{db}; }

    // Create the database schema for the current version of the wallet db.
    // Migration code will live elsewhere.
    void create_schema(cryptonote::network_type nettype = cryptonote::network_type::TESTNET);

    // Helpers to access the metadata table
    void set_metadata_int(const std::string& id, int64_t val);
    int64_t get_metadata_int(const std::string& id);
    void set_metadata_text(const std::string& id, const std::string& val);
    std::string get_metadata_text(const std::string& id);
    void set_metadata_blob(const std::string& id, std::string_view data);
    std::string get_metadata_blob(const std::string& id);

    template <typename T>
    void set_metadata_blob_guts(const std::string& id, const T& val) {
        set_metadata_blob(id, tools::view_guts(val));
    }

    template <typename T>
    T get_metadata_blob_guts(const std::string& id) {
        return prepared_get<db::blob_guts<T>>("SELECT val_binary FROM metadata WHERE id = ?", id);
    };

    cryptonote::network_type network_type();

    void add_address(int32_t major_index, int32_t minor_index, const std::string& address);

    std::string get_address(int32_t major_index, int32_t minor_index);

    void store_block(const Block& block);

    void pop_block();

    void store_transaction(
            const crypto::hash& tx_hash, const int64_t height, const std::vector<Output>& outputs);

    void store_spends(
            const crypto::hash& tx_hash,
            const int64_t height,
            const std::vector<crypto::key_image>& spends);

    // The height of the last block added to the database.
    int64_t last_scan_height();

    // The current chain height, as far as we know.
    int64_t scan_target_height();

    // Returns the height of the highest block in the database
    int64_t current_height();

    // Update the top block height and hash.
    void update_top_block_info(int64_t height, const crypto::hash& hash);

    // Get available balance across all subaddresses
    int64_t overall_balance();

    // Get unlocked balance across all subaddresses
    int64_t unlocked_balance();

    // Get available balance with amount above an optional minimum amount.
    // TODO: subaddress specification
    int64_t available_balance(std::optional<int64_t> min_amount);

    // Selects all outputs with amount above an optional minimum amount.
    // TODO: subaddress specification
    std::vector<Output> available_outputs(std::optional<int64_t> min_amount);

    // Gets the total number of outputs on the chain.  Since all Oxen outputs are RingCT
    // and thus mixable, this can be used for decoy selection.
    int64_t chain_output_count();

    // Saves keys to the database, will check if keys match if already exists and throw if different
    void save_keys(const std::shared_ptr<WalletKeys> keys);

    // Loads keys from an already created database
    std::optional<DBKeys> load_keys();
};
}  // namespace wallet

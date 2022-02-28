#pragma once

#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlitedb/database.hpp>

#include "output.hpp"

#include <optional>

namespace crypto
{
  struct hash;
  struct key_image;
}

namespace wallet
{
  struct Output;
  struct Block;

  class WalletDB : public db::Database
  {
  public:
    using db::Database::Database;

    // Get a DB transaction.  This will revert any changes done to the db
    // while it exists when it is destroyed unless commit() is called on it.
    SQLite::Transaction db_transaction()
    {
      return SQLite::Transaction{db};
    }

    // Create the database schema for the current version of the wallet db.
    // Migration code will live elsewhere.
    void
    create_schema();

    void
    store_block(const Block& block);

    void
    store_transaction(const crypto::hash& tx_hash,
        const int64_t height,
        const std::vector<Output>& outputs);

    void
    store_spends(const crypto::hash& tx_hash,
        const int64_t height,
        const std::vector<crypto::key_image>& spends);

    // The height of the last block added to the database.
    int64_t
    last_scan_height();

    // The current chain height, as far as we know.
    int64_t
    scan_target_height();

    // Update the top block height and hash.
    void
    update_top_block_info(int64_t height, const crypto::hash& hash);

    // Get available balance across all subaddresses
    int64_t
    overall_balance();

    // Get available balance with amount above an optional minimum amount.
    // TODO: subaddress specification
    int64_t
    available_balance(std::optional<int64_t> min_amount);

    // Selects all outputs with amount above an optional minimum amount.
    // TODO: subaddress specification
    std::vector<Output>
    available_outputs(std::optional<int64_t> min_amount);

    // Gets the total number of outputs on the chain.  Since all Oxen outputs are RingCT
    // and thus mixable, this can be used for decoy selection.
    int64_t
    chain_output_count();
  };
}

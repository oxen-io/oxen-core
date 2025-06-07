#include <blockchain_db/sqlite/db_sqlite.h>

namespace test {

inline fs::path check_if_copy_filename(fs::path db_path) {
  if (db_path.u8string() != u8":memory:")
      db_path += u8"-copy";
  return db_path;
}

class BlockchainSQLiteTest : public cryptonote::BlockchainSQLite
{
    private:
        fs::path filename;
public:
  BlockchainSQLiteTest(cryptonote::network_type nettype, fs::path db_path)
    : BlockchainSQLite(nettype, db_path), filename{std::move(db_path)} {};


  BlockchainSQLiteTest(BlockchainSQLiteTest &other)
    : BlockchainSQLiteTest(other.nettype, check_if_copy_filename(other.filename)) {

    SQLite::Transaction transaction {
      db,
      SQLite::TransactionBehavior::IMMEDIATE
    };

    auto insert_payment_accrued = prepared_st(
      "INSERT INTO batched_payments_accrued (address, payout_offset, amount) VALUES (?, ?, ?)");

    for (const auto& [address, offset, amount]: other.prepared_results<db::blob, std::optional<int>, int64_t>(
                "SELECT address, payout_offset, amount FROM batched_payments_accrued")) {
      db::exec_query(insert_payment_accrued, db::blob_binder{address.data}, offset, amount);
      insert_payment_accrued->reset();
    }

    transaction.commit();

    update_height(other.height);
  }

  // Helper functions, used in testing to assess the state of the database
  uint64_t batching_count(cryptonote::hf hf) {
    return prepared_get<int64_t>("SELECT count(*) FROM batched_payments_accrued WHERE amount >= {}"_format(hf >= cryptonote::hf::hf22_eth_fixup ? 1 : 1000));
  }
};

}

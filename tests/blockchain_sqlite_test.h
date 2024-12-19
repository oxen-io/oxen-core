#include <blockchain_db/sqlite/db_sqlite.h>

namespace test {

inline fs::path check_if_copy_filename(std::string_view db_path) {
  return (db_path != ":memory:") ? fs::path(std::string(db_path) + "-copy") : fs::path(std::string(db_path));
}

class BlockchainSQLiteTest : public cryptonote::BlockchainSQLite
{
public:
  BlockchainSQLiteTest(cryptonote::network_type nettype, fs::path db_path)
    : BlockchainSQLite(nettype, db_path) {};


  BlockchainSQLiteTest(BlockchainSQLiteTest &other)
    : BlockchainSQLiteTest(other.m_nettype, check_if_copy_filename(other.filename)) {
    auto all_payments_accrued = db::get_all<std::string, int, int64_t>(
            other.prepared_st("SELECT address, payout_offset, amount FROM batched_payments_accrued"));
    auto all_payments_paid = db::get_all<std::string, int64_t, int64_t>(
            other.prepared_st("SELECT address, amount, height_paid FROM batched_payments_raw"));

    SQLite::Transaction transaction {
      db,
      SQLite::TransactionBehavior::IMMEDIATE
    };

    auto insert_payment_paid = prepared_st(
      "INSERT INTO batched_payments_raw (address, amount, height_paid) VALUES (?, ?, ?)");

    for (auto& [address, amount, height_paid]: all_payments_paid) {
      db::exec_query(insert_payment_paid, address, amount, height_paid);
      insert_payment_paid->reset();
    }

    auto insert_payment_accrued = prepared_st(
      "INSERT INTO batched_payments_accrued (address, payout_offset, amount) VALUES (?, ?, ?)");

    for (auto& [address, offset, amount]: all_payments_accrued) {
      db::exec_query(insert_payment_accrued, address, offset, amount);
      insert_payment_accrued->reset();
    }

    transaction.commit();

    update_height(other.height);
  }

  // Helper functions, used in testing to assess the state of the database
  uint64_t batching_count() {
    return prepared_get<int64_t>("SELECT count(*) FROM batched_payments_accrued WHERE amount >= 1000");
  }
  std::optional<uint64_t> retrieve_amount_by_address(const std::string& address) {
    if (auto maybe = prepared_maybe_get<int64_t>("SELECT amount FROM batched_payments_accrued WHERE address = ?"))
      return *maybe;
    return std::nullopt;
  }
};

}

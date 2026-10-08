#include <blockchain_db/sqlite/rewards_db.h>

#include "common/fs.h"

namespace test {

inline fs::path check_if_copy_filename(fs::path db_path) {
  if (db_path.u8string() != u8":memory:")
      db_path += u8"-copy";
  return db_path;
}

// Holds the database for RewardsDBTest; a base class (rather than a member) so that it gets
// constructed before, and destroyed after, the RewardsDB base that uses it.
struct rewards_test_sql {
  session::sqlite::Database sql;
};

class RewardsDBTest : private rewards_test_sql, public cryptonote::RewardsDB
{
    private:
        fs::path filename;
public:
  RewardsDBTest(cryptonote::network_type nettype, fs::path db_path)
    : rewards_test_sql{session::sqlite::Database{db_path}}, RewardsDB(nettype, sql), filename{std::move(db_path)} {};


  RewardsDBTest(RewardsDBTest &other)
    : RewardsDBTest(other.nettype, check_if_copy_filename(other.filename)) {

    auto conn = db.conn();
    SQLite::Transaction transaction {
      conn.sql,
      SQLite::TransactionBehavior::IMMEDIATE
    };

    auto other_conn = other.db.conn();
    for (const auto& [address, offset, amount]: other_conn.prepared_results<session::sqlite::blob, std::optional<int>, int64_t>(
                "SELECT address, payout_offset, amount FROM batched_payments_accrued"))
      conn.prepared_exec(
          "INSERT INTO batched_payments_accrued (address, payout_offset, amount) VALUES (?, ?, ?)",
          address, offset, amount);

    transaction.commit();

    update_height(other.height);
  }

  // Helper functions, used in testing to assess the state of the database
  uint64_t batching_count(cryptonote::hf hf) {
    return db.conn().prepared_get<int64_t>("SELECT count(*) FROM batched_payments_accrued WHERE amount >= {}"_format(hf >= cryptonote::hf::hf22_eth_fixup ? 1 : 1000));
  }
};

}

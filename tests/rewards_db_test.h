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
    copy_state_from(other);
  }

  using RewardsDB::publish_block;
  using RewardsDB::save_payments;

  // Helper functions, used in testing to assess the state of the database
  uint64_t batching_count(cryptonote::hf hf) {
    const int64_t min = hf >= cryptonote::hf::hf22_eth_fixup ? 1 : 1000;
    uint64_t count = 0;
    for (const auto& [addr, row] : get_accrued_rows())
      count += row.amount >= min;
    return count;
  }
};

}

#include "database.hpp"

#include <sqlite3.h>
#include <fmt/core.h>
#include <mutex>

namespace db
{

  std::string multi_in_query(std::string_view prefix, size_t count, std::string_view suffix)
  {
    std::string query;
    query.reserve(prefix.size() + (count == 0 ? 0 : 2 * count - 1) + suffix.size());
    query += prefix;
    for (size_t i = 0; i < count; i++)
    {
      if (i > 0)
        query += ',';
      query += '?';
    }
    query += suffix;
    return query;
  }

  Database::StatementWrapper Database::prepared_st(const std::string& query)
  {
    std::unordered_map<std::string, SQLite::Statement>* sts;
    {
      std::shared_lock rlock{prepared_sts_mutex};
      if (auto it = prepared_sts.find(std::this_thread::get_id()); it != prepared_sts.end())
        sts = &it->second;
      else
      {
        rlock.unlock();
        std::unique_lock wlock{prepared_sts_mutex};
        sts = &prepared_sts.try_emplace(std::this_thread::get_id()).first->second;
      }
    }
    if (auto qit = sts->find(query); qit != sts->end())
      return StatementWrapper{qit->second};
    return StatementWrapper{sts->try_emplace(query, db, query).first->second};
  }

  Database::Database(const fs::path& db_path, const std::string_view db_password)
        : db{db_path.u8string(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE | SQLite::OPEN_FULLMUTEX, 5000/*ms*/}
  {
    // Don't fail on these because we can still work even if they fail
    if (int rc = db.tryExec("PRAGMA journal_mode = WAL"); rc != SQLITE_OK)
      MERROR("Failed to set journal mode to WAL: {}" << sqlite3_errstr(rc));

    if (int rc = db.tryExec("PRAGMA synchronous = NORMAL"); rc != SQLITE_OK)
      MERROR("Failed to set synchronous mode to NORMAL: {}" << sqlite3_errstr(rc));

    if (int rc = db.tryExec("PRAGMA foreign_keys = ON");
        rc != SQLITE_OK) {
      auto m = fmt::format("Failed to enable foreign keys constraints: {}", sqlite3_errstr(rc));
      MERROR(m);
      throw std::runtime_error{m};
    }
    int fk_enabled = db.execAndGet("PRAGMA foreign_keys").getInt();
    if (fk_enabled != 1) {
      MERROR("Failed to enable foreign key constraints; perhaps this sqlite3 is compiled without it?");
      throw std::runtime_error{"Foreign key support is required"};
    }

    // FIXME: SQLite / SQLiteCPP may not have encryption available
    //       so this may fail, or worse silently fail and do nothing
    if (not db_password.empty())
    {
      db.key(std::string{db_password});
    }
  }

}  // namespace db

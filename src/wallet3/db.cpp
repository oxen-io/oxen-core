#include <db.hpp>

namespace wallet
{

  namespace
  {

    void InitDB(std::shared_ptr<SQLite::Database> db)
    {
      db.exec("CREATE TABLE outputs ("
              "id INTEGER PRIMARY KEY,"
              "amount INTEGER,"
              "output_index INTEGER,"
              "unlock_time INTEGER,"
              "block_height INTEGER,"
              "block_time INTEGER,"
              "spending INTEGER," // boolean
              "spent_height INTEGER,"
              "spent_time INTEGER,"
              "tx_hash BLOB," // FIXME: should this be TEXT?
              "pubkey BLOB," // FIXME: should this be TEXT?
              ")");

      // CHECK (id = 0) restricts this table to a single row
      db.exec("CREATE TABLE metadata ("
              "id INTEGER PRIMARY KEY CHECK (id = 0),"
              "balance INTEGER,"
              "unlocked_balance INTEGER,"
              "last_scan_height INTEGER,"
              ")");


      // insert metadata row as default
      db.exec("INSERT INTO metadata VALUES (NULL,0,0,0)");

    }


    std::shared_ptr<SQLite::Database> OpenOrCreateDB(std::string_view filename, std::string_view password, bool create)
    {
      auto flags = SQLite::OPEN_READWRITE;
      if (create) flags |= SQLite::OPEN_CREATE;

      std::shared_ptr<SQLite::Database> db{filename, flags};

      db.key(password);

      if (create) InitDB(db);

      // TODO: confirm correct schema exists if opening existing db

      return db;
    }


  } // namespace wallet::{anonymous}


  std::shared_ptr<SQLite::Database> CreateDB(std::string_view filename, std::string_view password)
  {
    try
    {
      return OpenOrCreateDB(filename, password, /* create = */ true);
    }
    catch (const std::exception& e)
    {
      // TODO: error reporting/handling, e.g. file alredy exists
      return nullptr;
    }
  }

  std::shared_ptr<SQLite::Database> OpenDB(std::string_view filename, std::string_view password)
  {
    try
    {
      return OpenOrCreateDB(filename, password, /* create = */ false);
    }
    catch (const std::exception& e)
    {
      // TODO: error reporting/handling, e.g. catching wrong password, file does not exist
      return nullptr;
    }
  }

}


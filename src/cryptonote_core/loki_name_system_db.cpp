#include "loki_name_system_db.h"

#include "checkpoints/checkpoints.h"
#include "common/loki.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/tx_extra.h"

#include "sqlite/sqlite3.h"

extern "C"
{
#include "sodium.h"
}

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "lns"

namespace lns
{
enum struct lns_sql_type
{
  save_user,
  save_setting,
  save_mapping,
  expire_mapping,

  get_sentinel_start,
  get_user,
  get_setting,
  get_mapping,
  get_sentinel_end,
};

enum lns_db_setting_row
{
  lns_db_setting_row_id,
  lns_db_setting_row_top_height,
  lns_db_setting_row_top_hash,
  lns_db_setting_row_version,
};

enum user_record_row
{
  user_record_row_id,
  user_record_row_public_key,
};

enum mapping_record_row
{
  mapping_record_row_id,
  mapping_record_row_type,
  mapping_record_row_name,
  mapping_record_row_value,
  mapping_record_row_register_height,
  mapping_record_row_user_id,
};

static void sql_copy_blob(sqlite3_stmt *statement, int row, void *dest, int dest_size)
{
  void const *blob = sqlite3_column_blob(statement, row);
  int blob_len     = sqlite3_column_bytes(statement, row);
  assert(blob_len == dest_size);
  memcpy(dest, blob, std::min(dest_size, blob_len));
}

static bool sql_run_statement(lns_sql_type type, sqlite3_stmt *statement, void *context)
{
  bool data_loaded = false;
  bool result      = false;

  for (bool infinite_loop = true; infinite_loop;)
  {
    int step_result = sqlite3_step(statement);
    switch (step_result)
    {
      case SQLITE_ROW:
      {
        switch (type)
        {
          default:
          {
            MERROR("Unhandled lns type enum with value: " << (int)type << ", in: " << __func__);
          }
          break;

          case lns_sql_type::get_user:
          {
            auto *entry = reinterpret_cast<user_record *>(context);
            entry->id   = sqlite3_column_int(statement, user_record_row_id);
            sql_copy_blob(statement, user_record_row_public_key, entry->key.data, sizeof(entry->key.data));
            data_loaded = true;
          }
          break;

          case lns_sql_type::get_setting:
          {
            auto *entry       = reinterpret_cast<settings_record *>(context);
            entry->top_height = static_cast<uint64_t>(sqlite3_column_int64(statement, lns_db_setting_row_top_height));
            sql_copy_blob(statement, lns_db_setting_row_top_hash, entry->top_hash.data, sizeof(entry->top_hash.data));
            entry->version = sqlite3_column_int(statement, lns_db_setting_row_version);
            data_loaded = true;
          }
          break;

          case lns_sql_type::get_mapping:
          {
            auto *entry = reinterpret_cast<mapping_record *>(context);
            entry->type = static_cast<uint16_t>(sqlite3_column_int(statement, mapping_record_row_type));
            entry->register_height = static_cast<uint16_t>(sqlite3_column_int(statement, mapping_record_row_register_height));
            entry->user_id = sqlite3_column_int(statement, mapping_record_row_user_id);

            int name_len  = sqlite3_column_bytes(statement, mapping_record_row_name);
            int value_len = sqlite3_column_bytes(statement, mapping_record_row_value);
            auto *value   = reinterpret_cast<char const *>(sqlite3_column_text(statement, mapping_record_row_value));
            if (validate_lns_name_value_mapping_lengths(entry->type, name_len, value, value_len))
            {
              auto *name  = reinterpret_cast<char const *>(sqlite3_column_text(statement, mapping_record_row_name));
              entry->name = std::string(name, name_len);

              entry->value = std::string(value, value_len);
              data_loaded = true;
            }
          }
          break;
        }
      }
      break;

      case SQLITE_BUSY: break;
      case SQLITE_DONE:
      {
        infinite_loop = false;
        result        = (type > lns_sql_type::get_sentinel_start && type < lns_sql_type::get_sentinel_end) ? data_loaded : true;
        break;
      }

      default:
      {
        LOG_PRINT_L1("Failed to execute statement: " << sqlite3_sql(statement) <<", reason: " << sqlite3_errstr(step_result));
        infinite_loop = false;
        break;
      }
    }
  }

  sqlite3_reset(statement);
  sqlite3_clear_bindings(statement);
  return result;
}

static bool sql_compile_statement(sqlite3 *db, char const *query, int query_len, sqlite3_stmt **statement)
{
  int prepare_result = sqlite3_prepare_v2(db, query, query_len, statement, nullptr);
  bool result        = prepare_result == SQLITE_OK;
  if (!result) MERROR("Can not compile SQL statement: " << query << ", reason: " << sqlite3_errstr(prepare_result));
  return result;
}

sqlite3 *init_loki_name_system(char const *file_path)
{
  sqlite3 *result = nullptr;
  int sql_init    = sqlite3_initialize();
  if (sql_init != SQLITE_OK)
  {
    MERROR("Failed to initialize sqlite3: " << sqlite3_errstr(sql_init));
    return nullptr;
  }

  int sql_open = sqlite3_open(file_path, &result);
  if (sql_open != SQLITE_OK)
  {
    MERROR("Failed to open LNS db at: " << file_path << ", reason: " << sqlite3_errstr(sql_init));
    return nullptr;
  }

  return result;
}

uint64_t lokinet_expiry_blocks(cryptonote::network_type nettype, uint64_t *renew_window)
{
  uint64_t renew_window_ = BLOCKS_EXPECTED_IN_DAYS(31);
  uint64_t result        = BLOCKS_EXPECTED_IN_YEARS(1) + renew_window_;
  if (nettype == cryptonote::FAKECHAIN)
  {
    renew_window_ = 10;
    result        = 10 + renew_window_;
  }
  else if (nettype == cryptonote::TESTNET)
  {
    renew_window_ = BLOCKS_EXPECTED_IN_DAYS(1);
    result        = BLOCKS_EXPECTED_IN_DAYS(1) + renew_window_;
  }

  if (renew_window) *renew_window = renew_window_;
  return result;
}

bool validate_lns_name_value_mapping_lengths(uint16_t type, int name_len, char const *value, int value_len)
{
  int max_name_len             = lns::GENERIC_NAME_MAX;
  int max_value_len            = lns::GENERIC_VALUE_MAX;
  bool value_require_exact_len = true;

  if (type == static_cast<uint16_t>(mapping_type::blockchain))
  {
    max_name_len  = BLOCKCHAIN_NAME_MAX;
    max_value_len = BLOCKCHAIN_WALLET_ADDRESS_LENGTH;
  }
  else if (type == static_cast<uint16_t>(mapping_type::lokinet))
  {
    max_name_len  = LOKINET_DOMAIN_NAME_MAX;
    max_value_len = LOKINET_ADDRESS_LENGTH;
  }
  else if (type == static_cast<uint16_t>(mapping_type::messenger))
  {
    max_name_len  = MESSENGER_DISPLAY_NAME_MAX;
    max_value_len = MESSENGER_PUBLIC_KEY_LENGTH;
  }
  else
  {
    value_require_exact_len = false;
  }

  if (name_len > max_name_len || name_len == 0)
    return false;

  if (value_require_exact_len)
  {
    if (value_len != max_value_len)
      return false;
  }
  else
  {
    if (value_len > max_value_len || value_len == 0)
      return false;
  }

  // NOTE: Messenger public keys are 33 bytes, with the first byte being 0x05 and the remaining 32 being the public key.
  if (type == static_cast<uint16_t>(mapping_type::messenger))
  {
    if (value[0] != 0x05)
      return false;
  }
  return true;
}

bool validate_lns_entry(cryptonote::transaction const &tx, cryptonote::tx_extra_loki_name_system const &entry)
{
  if (!validate_lns_name_value_mapping_lengths(entry.type, static_cast<int>(entry.name.size()), entry.value.data(), static_cast<int>(entry.value.size())))
  {
    LOG_PRINT_L1("LNS TX " << cryptonote::get_transaction_hash(tx) << " Failed name: " << entry.name << "or value: " << entry.value << " validation");
    return false;
  }

  // TODO: Validate burn amount in the tx_extra

  crypto::hash hash = entry.make_signature_hash();
  if (crypto_sign_ed25519_verify_detached(entry.signature.data, reinterpret_cast<const unsigned char *>(hash.data), sizeof(hash.data), entry.owner.data) != 0)
  {
    LOG_PRINT_L1("LNS TX " << cryptonote::get_transaction_hash(tx) << " Failed signature validation");
    return false;
  }

  return true;
}

constexpr char BUILD_TABLE_SQL[] = R"FOO(
CREATE TABLE IF NOT EXISTS "user"(
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "public_key" BLOB NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS "settings" (
    "top_height" INTEGER NOT NULL,
    "top_hash" VARCHAR NOT NULL,
    "version" INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS "mappings" (
    "id" INTEGER PRIMARY KEY NOT NULL,
    "type" INTEGER NOT NULL,
    "name" VARCHAR NOT NULL,
    "value" BLOB NOT NULL,
    "register_height" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS "name_type_id" ON mappings(name, type);
)FOO";

static bool build_default_tables(sqlite3 *db)
{
  char *table_err_msg = nullptr;
  int table_created   = sqlite3_exec(db, BUILD_TABLE_SQL, nullptr /*callback*/, nullptr /*callback context*/, &table_err_msg);
  if (table_created != SQLITE_OK)
  {
    MERROR("Can not generate SQL table for LNS: " << (table_err_msg ? table_err_msg : "??"));
    sqlite3_free(table_err_msg);
    return false;
  }

  return true;
}

enum struct db_version : int { v1, };
auto constexpr DB_VERSION = db_version::v1;
bool name_system_db::init(cryptonote::network_type nettype, sqlite3 *db, uint64_t top_height, crypto::hash const &top_hash)
{
  if (!db) return false;
  this->db      = db;
  this->nettype = nettype;

  char constexpr EXPIRE_MAPPINGS_SQL[] = R"FOO(DELETE FROM "mappings" WHERE "type" = ? AND "register_height" < ?)FOO";

  char constexpr DROP_TABLE_SQL[] = R"FOO(
DROP TABLE IF EXISTS "user";
DROP TABLE IF EXISTS "settings";
DROP TABLE IF EXISTS "mappings";
)FOO";

  char constexpr SAVE_SETTINGS_SQL[] = R"FOO(
    INSERT OR REPLACE INTO settings
    (rowid, top_height, top_hash, version)
    VALUES (1,?,?,?);
)FOO";

  char constexpr GET_MAPPING_SQL[] = R"FOO(SELECT * FROM mappings WHERE "type" = ? AND "value" = ?)FOO";

  char constexpr SAVE_MAPPING_SQL[] =
      "INSERT INTO mappings "
      "(type, name, value, register_height, user_id)"
      "VALUES (?,?,?,?,?);";

  char constexpr FORCE_SAVE_MAPPING_SQL[] =
      "INSERT OR REPLACE INTO mappings "
      "(type, name, value, register_height, user_id)"
      "VALUES (?,?,?,?,?);";

  char constexpr GET_SETTINGS_SQL[]    = R"FOO(SELECT * FROM settings WHERE "id" = 0)FOO";
  char constexpr SAVE_USER_SQL[]       = R"FOO(INSERT INTO user (public_key) VALUES (?);)FOO";
  char constexpr GET_USER_BY_KEY_SQL[] = R"FOO(SELECT * FROM user WHERE "public_key" = ?)FOO";
  char constexpr GET_USER_BY_ID_SQL[]  = R"FOO(SELECT * FROM user WHERE "id" = ?)FOO";

  if (!build_default_tables(db))
    return false;

  if (!sql_compile_statement(db, SAVE_USER_SQL,          loki::array_count(SAVE_USER_SQL),       &save_user_sql)    ||
      !sql_compile_statement(db, SAVE_MAPPING_SQL,       loki::array_count(SAVE_MAPPING_SQL),    &save_mapping_sql) ||
      !sql_compile_statement(db, SAVE_SETTINGS_SQL,      loki::array_count(SAVE_SETTINGS_SQL),   &save_settings_sql) ||
      !sql_compile_statement(db, FORCE_SAVE_MAPPING_SQL, loki::array_count(FORCE_SAVE_MAPPING_SQL), &force_save_mapping_sql) ||
      !sql_compile_statement(db, GET_USER_BY_KEY_SQL,    loki::array_count(GET_USER_BY_KEY_SQL), &get_user_by_key_sql) ||
      !sql_compile_statement(db, GET_USER_BY_ID_SQL,     loki::array_count(GET_USER_BY_ID_SQL),  &get_user_by_id_sql) ||
      !sql_compile_statement(db, GET_MAPPING_SQL,        loki::array_count(GET_MAPPING_SQL),     &get_mapping_sql) ||
      !sql_compile_statement(db, GET_SETTINGS_SQL,       loki::array_count(GET_SETTINGS_SQL),    &get_settings_sql) ||
      !sql_compile_statement(db, EXPIRE_MAPPINGS_SQL,    loki::array_count(EXPIRE_MAPPINGS_SQL), &expire_mapping_sql)
      )
  {
    return false;
  }

  if (settings_record settings = get_settings())
  {
    if (settings.top_height == top_height && settings.top_hash == top_hash)
    {
      this->last_processed_height = settings.top_height;
      assert(settings.version == static_cast<int>(DB_VERSION));
    }
    else
    {
      sqlite3_exec(db, DROP_TABLE_SQL, nullptr /*callback*/, nullptr /*callback context*/, nullptr);
      if (!build_default_tables(db)) return false;
    }
  }

  return true;
}

static bool process_loki_name_system_tx(cryptonote::network_type nettype,
                                        uint64_t block_height,
                                        const cryptonote::transaction &tx,
                                        cryptonote::tx_extra_loki_name_system &tx_extra)
{
  if (!cryptonote::get_loki_name_system_from_tx_extra(tx.extra, tx_extra))
  {
    LOG_PRINT_L1("TX: " << tx.type << " " << get_transaction_hash(tx) << ", didn't have loki name service in the tx_extra");
    return false;
  }

  if (!validate_lns_entry(tx, tx_extra))
  {
    assert("Failed to validate acquire name service. Should already have failed validation prior" == nullptr);
    LOG_PRINT_L1("LNS TX: Failed to validate for tx: " << get_transaction_hash(tx) << ". This should have failed validation earlier");
    return false;
  }

  return true;
}

enum struct sql_transaction_type
{
    begin,
    commit,
    rollback,
    count,
};

static bool sql_transaction(sqlite3 *db, sql_transaction_type type)
{
  char *sql_err            = nullptr;
  char const *const CMDS[] = {
      "BEGIN;",
      "END;",
      "ROLLBACK;",
  };

  static_assert(loki::array_count(CMDS) == static_cast<int>(sql_transaction_type::count), "Unexpected enum to string mismatch");
  if (sqlite3_exec(db, CMDS[static_cast<int>(type)], NULL, NULL, &sql_err) != SQLITE_OK)
  {
    MERROR("Can not execute transactional step: " << CMDS[static_cast<int>(type)] << ", reason: " << (sql_err ? sql_err : "??"));
    sqlite3_free(sql_err);
    return false;
  }

  return true;
}

bool name_system_db::add_block(const cryptonote::block &block, const std::vector<cryptonote::transaction> &txs)
{
  uint64_t height = cryptonote::get_block_height(block);
  if (last_processed_height >= height)
      return true;

  if (block.major_version >= cryptonote::network_version_14_blink_lns)
  {
    for (cryptonote::transaction const &tx : txs)
    {
      if (tx.type != cryptonote::txtype::loki_name_system)
        continue;

      cryptonote::tx_extra_loki_name_system entry = {};
      if (!process_loki_name_system_tx(nettype, height, tx, entry))
        continue;

      bool transaction_begun = false;
      int64_t user_id        = 0;
      if (user_record user = get_user_by_key(entry.owner)) user_id = user.id;

      if (user_id == 0)
      {
        transaction_begun = sql_transaction(db, sql_transaction_type::begin);
        if (!save_user(entry.owner, &user_id))
        {
          LOG_PRINT_L1("Failed to save LNS user to DB tx: " << cryptonote::get_transaction_hash(tx) << ", type: " << (uint16_t)entry.type << ", name: " << entry.name << ", user: " << entry.owner);
          if (transaction_begun && !sql_transaction(db, sql_transaction_type::rollback))
          {
            MERROR("Failed to rollback transaction in LNS DB");
            return false;
          }

          continue;
        }
      }
      assert(user_id != 0);

      if (!transaction_begun)
        transaction_begun = sql_transaction(db, sql_transaction_type::begin);

      if (save_mapping(static_cast<uint16_t>(entry.type), entry.name, entry.value.data(), entry.value.size(), height, user_id))
      {
        if (transaction_begun && !sql_transaction(db, sql_transaction_type::commit))
        {
          MERROR("Failed to commit user and or mapping transaction to LNS DB");
          return false;
        }
      }
      else
      {
        LOG_PRINT_L1("Failed to save LNS entry to DB tx: " << cryptonote::get_transaction_hash(tx)
                                                           << ", type: " << (uint16_t)entry.type
                                                           << ", name: " << entry.name << ", user: " << entry.owner);
        if (transaction_begun && !sql_transaction(db, sql_transaction_type::rollback))
        {
          MERROR("Failed to rollback transaction in LNS DB");
          return false;
        }
      }
    }

    if (!expire_mappings(height))
    {
      MERROR("Failed to expire mappings in LNS DB");
      return false;
    }
  }

  last_processed_height = height;
  save_settings(height, cryptonote::get_block_hash(block), static_cast<int>(DB_VERSION));
  return true;
}

bool name_system_db::save_user(crypto::ed25519_public_key const &key, int64_t *row_id)
{
  sqlite3_stmt *statement = save_user_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_blob(statement, 1 /*sql param index*/, &key, sizeof(key), nullptr /*destructor*/);
  bool result = sql_run_statement(lns_sql_type::save_user, statement, nullptr);
  if (row_id) *row_id = sqlite3_last_insert_rowid(db);
  return result;
}

bool name_system_db::save_mapping(uint16_t type, std::string const &name, void const *value, int value_len, uint64_t height, int64_t user_id)
{
  sqlite3_stmt *statement = save_mapping_sql;
  if (type == static_cast<uint16_t>(mapping_type::lokinet))
  {
    if (mapping_record record = get_mapping(type, value, value_len))
    {
      // NOTE: Early out here, instead of trying to save (and fail) since we already payed for the lookup
      if (record.user_id != user_id)
        return false;

      uint64_t renew_window        = 0;
      uint64_t expiry_blocks       = lokinet_expiry_blocks(nettype, &renew_window);
      uint64_t renew_window_offset = expiry_blocks - renew_window;
      uint64_t min_renew_height    = record.register_height + renew_window_offset;

      if (min_renew_height > height)
        return false; // Trying to renew too early

      statement = force_save_mapping_sql;
    }
  }

  sqlite3_bind_int  (statement, mapping_record_row_type, type);
  sqlite3_bind_text (statement, mapping_record_row_name, name.c_str(), name.size(), nullptr /*destructor*/);
  sqlite3_bind_blob (statement, mapping_record_row_value, value, value_len, nullptr /*destructor*/);
  sqlite3_bind_int64(statement, mapping_record_row_register_height, static_cast<int64_t>(height));
  sqlite3_bind_int64(statement, mapping_record_row_user_id, user_id);
  bool result = sql_run_statement(lns_sql_type::save_mapping, statement, nullptr);
  return result;
}

bool name_system_db::save_settings(uint64_t top_height, crypto::hash const &top_hash, int version)
{
  sqlite3_stmt *statement = save_settings_sql;
  sqlite3_bind_blob (statement, lns_db_setting_row_top_hash,   top_hash.data, sizeof(top_hash), nullptr /*destructor*/);
  sqlite3_bind_int64(statement, lns_db_setting_row_top_height, top_height);
  sqlite3_bind_int  (statement, lns_db_setting_row_version,    version);
  bool result = sql_run_statement(lns_sql_type::save_setting, statement, nullptr);
  return result;
}

bool name_system_db::expire_mappings(uint64_t height)
{
  uint64_t lifetime = lokinet_expiry_blocks(nettype, nullptr);
  if (height < lifetime)
      return true;

  uint64_t expire_height  = height - lifetime;
  sqlite3_stmt *statement = expire_mapping_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_int      (statement, 1 /*sql param index*/, static_cast<int>(mapping_type::lokinet));
  sqlite3_bind_int64    (statement, 2 /*sql param index*/, expire_height);

  bool result = sql_run_statement(lns_sql_type::expire_mapping, statement, nullptr);
  return result;
}

user_record name_system_db::get_user_by_key(crypto::ed25519_public_key const &key) const
{
  sqlite3_stmt *statement = get_user_by_key_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_blob(statement, 1 /*sql param index*/, &key, sizeof(key), nullptr /*destructor*/);

  user_record result = {};
  result.loaded      = sql_run_statement(lns_sql_type::get_user, statement, &result);
  return result;
}

user_record name_system_db::get_user_by_id(int user_id) const
{
  sqlite3_stmt *statement = get_user_by_id_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_int(statement, 1 /*sql param index*/, user_id);

  user_record result = {};
  result.loaded      = sql_run_statement(lns_sql_type::get_user, statement, &result);
  return result;
}

mapping_record name_system_db::get_mapping(uint16_t type, void const *value, size_t value_len) const
{
  sqlite3_stmt *statement = get_mapping_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_int(statement, 1 /*sql param index*/, type);
  sqlite3_bind_blob(statement, 2 /*sql param index*/, value, value_len, nullptr /*destructor*/);

  mapping_record result = {};
  result.loaded         = sql_run_statement(lns_sql_type::get_mapping, statement, &result);
  return result;
}

mapping_record name_system_db::get_mapping(uint16_t type, std::string const &value) const
{
  mapping_record result = get_mapping(type, value.data(), value.size());
  return result;
}

settings_record name_system_db::get_settings() const
{
  sqlite3_stmt *statement = get_user_by_id_sql;
  settings_record result  = {};
  result.loaded           = sql_run_statement(lns_sql_type::get_setting, statement, &result);
  return result;
}

}; // namespace service_nodes

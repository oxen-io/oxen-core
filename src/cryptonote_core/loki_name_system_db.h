#ifndef LOKI_NAME_SYSTEM_DB_H
#define LOKI_NAME_SYSTEM_DB_H

#include "crypto/crypto.h"
#include "cryptonote_config.h"

#include <string>

struct sqlite3;
struct sqlite3_stmt;
namespace cryptonote
{
struct checkpoint_t;
struct block;
struct transaction;
struct tx_extra_loki_name_system;
struct account_address;
}; // namespace cryptonote

namespace lns
{
constexpr uint64_t BURN_REQUIREMENT                 = 100 * COIN;
constexpr uint64_t BLOCKCHAIN_NAME_MAX              = 95;
constexpr uint64_t BLOCKCHAIN_WALLET_ADDRESS_LENGTH = 69;
constexpr uint64_t LOKINET_DOMAIN_NAME_MAX          = 253;
constexpr uint64_t LOKINET_ADDRESS_LENGTH           = 32;
constexpr uint64_t LOKINET_NAME_LIFETIME            = BLOCKS_EXPECTED_IN_YEARS(1) + BLOCKS_EXPECTED_IN_DAYS(31);
constexpr uint64_t MESSENGER_DISPLAY_NAME_MAX       = 30;
constexpr uint64_t MESSENGER_PUBLIC_KEY_LENGTH      = 33;

constexpr uint64_t GENERIC_NAME_MAX  = 255;
constexpr uint64_t GENERIC_VALUE_MAX = 255;

sqlite3     *init_loki_name_system(char const *file_path);
bool         validate_lns_name_value_mapping_lengths(uint16_t type, int name_len, char const *value, int value_len);
bool         validate_lns_entry(cryptonote::transaction const &tx, cryptonote::tx_extra_loki_name_system const &entry);

struct user_record
{
  operator bool() const { return loaded; }
  bool loaded;

  int64_t id;
  crypto::ed25519_public_key key;
};

struct settings_record
{
  operator bool() const { return loaded; }
  bool loaded;

  uint64_t     top_height;
  crypto::hash top_hash;
  int          version;
};

enum struct mapping_type : uint16_t
{
  blockchain,
  lokinet,
  messenger,
};

struct mapping_record
{
  operator bool() const { return loaded; }
  bool loaded;

  uint16_t    type; // alias to lns::mapping_type
  std::string name;
  std::string value;
  uint64_t    register_height;
  int64_t     user_id;
};

struct name_system_db
{
  sqlite3      *db                    = nullptr;
  sqlite3_stmt *save_user_cmd         = nullptr;
  sqlite3_stmt *save_mapping_cmd      = nullptr;
  sqlite3_stmt *save_settings_cmd     = nullptr;
  sqlite3_stmt *get_user_by_key_cmd   = nullptr;
  sqlite3_stmt *get_user_by_id_cmd    = nullptr;
  sqlite3_stmt *get_mapping_cmd       = nullptr;
  sqlite3_stmt *get_settings_cmd      = nullptr;

  bool            init           (sqlite3 *db, uint64_t top_height, crypto::hash const &top_hash);
  bool            add_block      (cryptonote::network_type nettype, const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs);
  uint64_t        height         () { return last_processed_height; }

  bool            save_user      (crypto::ed25519_public_key const &key, int64_t *row_id);
  bool            save_mapping   (uint16_t type, std::string const &name, void const *value, int value_len, uint64_t register_height, int64_t user_id);
  bool            save_settings  (uint64_t top_height, crypto::hash const &top_hash, int version);

  user_record     get_user_by_key(crypto::ed25519_public_key const &key) const;
  user_record     get_user_by_id (int user_id) const;
  mapping_record  get_mapping    (uint16_t type, void const *value, size_t value_len) const;
  mapping_record  get_mapping    (uint16_t type, std::string const &value) const;
  settings_record get_settings   () const;

private:
  uint64_t last_processed_height = 0;
};

}; // namespace service_nodes
#endif // LOKI_NAME_SYSTEM_DB_H

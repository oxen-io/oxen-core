#ifndef LOKI_NAME_SYSTEM_H
#define LOKI_NAME_SYSTEM_H

#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "span.h"
#include "cryptonote_basic/tx_extra.h"
#include <lokimq/hex.h>

#include <string>

struct sqlite3;
struct sqlite3_stmt;
namespace cryptonote
{
struct checkpoint_t;
struct block;
class transaction;
struct account_address;
struct tx_extra_loki_name_system;
class Blockchain;
}; // namespace cryptonote

namespace lns
{

constexpr size_t WALLET_NAME_MAX                  = 96;
constexpr size_t WALLET_ACCOUNT_BINARY_LENGTH     = 2 * sizeof(crypto::public_key);
constexpr size_t LOKINET_DOMAIN_NAME_MAX          = 253;
constexpr size_t LOKINET_ADDRESS_BINARY_LENGTH    = sizeof(crypto::ed25519_public_key);
constexpr size_t SESSION_DISPLAY_NAME_MAX         = 64;
constexpr size_t SESSION_PUBLIC_KEY_BINARY_LENGTH = 1 + sizeof(crypto::ed25519_public_key); // Session keys at prefixed with 0x05 + ed25519 key

struct mapping_value
{
  static size_t constexpr BUFFER_SIZE = 255;
  std::array<uint8_t, BUFFER_SIZE> buffer;
  size_t len;

  std::string               to_string() const { return std::string(reinterpret_cast<char const *>(buffer.data()), len); }
  epee::span<const uint8_t> to_span()   const { return epee::span<const uint8_t>(reinterpret_cast<const uint8_t *>(buffer.data()), len); }
  std::string               to_readable_value(cryptonote::network_type nettype, mapping_type type) const;
  bool operator==(mapping_value const &other) const { return other.len    == len && memcmp(buffer.data(), other.buffer.data(), len) == 0; }
  bool operator==(std::string   const &other) const { return other.size() == len && memcmp(buffer.data(), other.data(), len) == 0; }
};
inline std::ostream &operator<<(std::ostream &os, mapping_value const &v) { return os << lokimq::to_hex({reinterpret_cast<char const *>(v.buffer.data()), v.len}); }

inline char const *mapping_type_str(mapping_type type)
{
  switch(type)
  {
    case mapping_type::lokinet_1year:   return "lokinet_1year";
    case mapping_type::lokinet_2years:  return "lokinet_2years";
    case mapping_type::lokinet_5years:  return "lokinet_5years";
    case mapping_type::lokinet_10years: return "lokinet_10years";
    case mapping_type::session:         return "session";
    case mapping_type::wallet:          return "wallet";
    default: assert(false);             return "xx_unhandled_type";
  }
}
inline std::ostream &operator<<(std::ostream &os, mapping_type type) { return os << mapping_type_str(type); }
constexpr bool mapping_type_allowed(uint8_t hf_version, mapping_type type) { return type == mapping_type::session; }
constexpr bool is_lokinet_type     (lns::mapping_type type)                { return type >= mapping_type::lokinet_1year && type <= mapping_type::lokinet_10years; }
sqlite3       *init_loki_name_system(char const *file_path);

uint64_t constexpr NO_EXPIRY = static_cast<uint64_t>(-1);
// return: The number of blocks until expiry from the registration height, if there is no expiration NO_EXPIRY is returned.
uint64_t     expiry_blocks(cryptonote::network_type nettype, mapping_type type, uint64_t *renew_window = nullptr);
bool         validate_lns_name(mapping_type type, std::string name, std::string *reason = nullptr);

generic_signature  make_monero_signature(crypto::hash const &hash, crypto::public_key const &pkey, crypto::secret_key const &skey);
generic_signature  make_ed25519_signature(crypto::hash const &hash, crypto::ed25519_secret_key const &skey);
generic_owner      make_monero_owner(cryptonote::account_public_address const &owner, bool is_subaddress);
generic_owner      make_ed25519_owner(crypto::ed25519_public_key const &pkey);
bool               parse_owner_to_generic_owner(cryptonote::network_type nettype, std::string const &owner, generic_owner &key, std::string *reason);
crypto::hash       tx_extra_signature_hash(epee::span<const uint8_t> value, generic_owner const *owner, generic_owner const *backup_owner, crypto::hash const &prev_txid);

// Validate a human readable mapping value representation in 'value' and write the binary form into 'blob'.
// value: if type is session, 66 character hex string of an ed25519 public key
//                   lokinet, 52 character base32z string of an ed25519 public key
//                   wallet,  the wallet public address string
// blob: (optional) if function returns true, validate_mapping_value will convert the 'value' into a binary format suitable for encryption in encrypt_mapping_value(...)
bool         validate_mapping_value(cryptonote::network_type nettype, mapping_type type, std::string const &value, mapping_value *blob = nullptr, std::string *reason = nullptr);
bool         validate_encrypted_mapping_value(mapping_type type, std::string const &value, std::string *reason = nullptr);

// Converts a human readable case-insensitive string denoting the mapping type into a value suitable for storing into the LNS DB.
// Currently only accepts "session"
// mapping_type: (optional) if function returns true, the uint16_t value of the 'type' will be set
bool         validate_mapping_type(std::string const &type, mapping_type *mapping_type, std::string *reason);

crypto::hash name_to_hash(std::string const &name);        // Takes a human readable name and hashes it.
std::string  name_to_base64_hash(std::string const &name); // Takes a human readable name, hashes it and returns a base64 representation of the hash, suitable for storage into the LNS DB.

// Takes a binary value and encrypts it using 'name' as a secret key or vice versa, suitable for storing into the LNS DB.
// Only basic overflow validation is attempted, values should be pre-validated in the validate* functions.
bool         encrypt_mapping_value(std::string const &name, mapping_value const &value, mapping_value &encrypted_value);
bool         decrypt_mapping_value(std::string const &name, mapping_value const &encrypted_value, mapping_value &value);

struct owner_record
{
  operator bool() const { return loaded; }
  bool loaded;

  int64_t id;
  generic_owner address;
};

struct settings_record
{
  operator bool() const { return loaded; }
  bool loaded;

  uint64_t     top_height;
  crypto::hash top_hash;
  int          version;
};

struct mapping_record
{
  // NOTE: We keep expired entries in the DB indefinitely because we need to
  // keep all LNS entries indefinitely to support large blockchain detachments.
  // A mapping_record forms a linked list of TXID's which allows us to revert
  // the LNS DB to any arbitrary height at a small additional storage cost.
  // return: if the record is still active and hasn't expired.
  bool active(cryptonote::network_type nettype, uint64_t blockchain_height) const;
  operator bool() const { return loaded; }

  bool          loaded;
  int64_t       id;
  mapping_type  type;
  std::string   name_hash; // name hashed and represented in base64 encoding
  mapping_value encrypted_value;
  uint64_t      register_height;
  uint64_t      update_height;
  crypto::hash  txid;
  crypto::hash  prev_txid;
  int64_t       owner_id;
  int64_t       backup_owner_id;
  generic_owner owner;
  generic_owner backup_owner;
};

struct name_system_db;
class sql_compiled_statement final
{
public:
  /// The name_system_db upon which this object operates
  name_system_db& nsdb;
  /// The stored, owned statement
  sqlite3_stmt* statement = nullptr;

  /// Constructor; takes a reference to the name_system_db.
  explicit sql_compiled_statement(name_system_db& nsdb) : nsdb{nsdb} {}

  /// Non-copyable (because we own an internal sqlite3 statement handle)
  sql_compiled_statement(const sql_compiled_statement&) = delete;
  sql_compiled_statement& operator=(const sql_compiled_statement&) = delete;

  /// Move construction; ownership of the internal statement handle, if present, is transferred to
  /// the new object.
  sql_compiled_statement(sql_compiled_statement&& from) : nsdb{from.nsdb}, statement{from.statement} { from.statement = nullptr; }

  /// Move copying.  The referenced name_system_db must be the same.  Ownership of the internal
  /// statement handle is transferred.  If the target already has a statement handle then it is
  /// destroyed.
  sql_compiled_statement& operator=(sql_compiled_statement&& from);

  /// Destroys the internal sqlite3 statement on destruction
  ~sql_compiled_statement();

  /// Attempts to prepare the given statement.  MERRORs and returns false on failure.  If the object
  /// already has a prepare statement then it is finalized first.
  bool compile(lokimq::string_view query, bool optimise_for_multiple_usage = true);

  template <size_t N>
  bool compile(const char (&query)[N], bool optimise_for_multiple_usage = true)
  {
    return compile({&query[0], N}, optimise_for_multiple_usage);
  }

  /// Returns true if the object owns a prepared statement
  explicit operator bool() const { return statement != nullptr; }

};

struct name_system_db
{
  bool                        init        (cryptonote::Blockchain const *blockchain, cryptonote::network_type nettype, sqlite3 *db);
  bool                        add_block   (const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs);

  cryptonote::network_type    network_type() const { return nettype; }
  uint64_t                    height      () const { return last_processed_height; }

  // Signifies the blockchain has reorganized commences the rollback and pruning procedures.
  void                        block_detach   (cryptonote::Blockchain const &blockchain, uint64_t new_blockchain_height);
  bool                        save_owner     (generic_owner const &owner, int64_t *row_id);
  bool                        save_mapping   (crypto::hash const &tx_hash, cryptonote::tx_extra_loki_name_system const &src, uint64_t height, int64_t owner_id, int64_t backup_owner_id = 0);
  bool                        save_settings  (uint64_t top_height, crypto::hash const &top_hash, int version);

  // Delete all mappings that are registered on height or newer followed by deleting all owners no longer referenced in the DB
  bool                        prune_db(uint64_t height);

  owner_record                get_owner_by_key      (generic_owner const &owner);
  owner_record                get_owner_by_id       (int64_t owner_id);
  mapping_record              get_mapping           (mapping_type type, std::string const &name_base64_hash);
  std::vector<mapping_record> get_mappings          (std::vector<uint16_t> const &types, std::string const &name_base64_hash);
  std::vector<mapping_record> get_mappings_by_owner (generic_owner const &key);
  std::vector<mapping_record> get_mappings_by_owners(std::vector<generic_owner> const &keys);
  settings_record             get_settings          ();

  // entry: (optional) if function returns true, the Loki Name System entry in the TX extra is copied into 'entry'
  bool                        validate_lns_tx       (uint8_t hf_version, uint64_t blockchain_height, cryptonote::transaction const &tx, cryptonote::tx_extra_loki_name_system *entry = nullptr, std::string *reason = nullptr);

  // Destructor; closes the sqlite3 database if one is open
  ~name_system_db();

  sqlite3 *db               = nullptr;
  bool    transaction_begun = false;
private:
  cryptonote::network_type nettype;
  uint64_t last_processed_height = 0;
  sql_compiled_statement save_owner_sql{*this};
  sql_compiled_statement save_mapping_sql{*this};
  sql_compiled_statement save_settings_sql{*this};
  sql_compiled_statement get_owner_by_key_sql{*this};
  sql_compiled_statement get_owner_by_id_sql{*this};
  sql_compiled_statement get_mapping_sql{*this};
  sql_compiled_statement get_settings_sql{*this};
  sql_compiled_statement prune_mappings_sql{*this};
  sql_compiled_statement prune_owners_sql{*this};
  sql_compiled_statement get_mappings_by_owner_sql{*this};
  sql_compiled_statement get_mappings_on_height_and_newer_sql{*this};
};

}; // namespace service_nodes
#endif // LOKI_NAME_SYSTEM_H

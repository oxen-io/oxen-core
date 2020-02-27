#include "loki_name_system.h"

#include "checkpoints/checkpoints.h"
#include "common/loki.h"
#include "common/util.h"
#include "common/base32z.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/blockchain.h"
#include "loki_economy.h"
#include "string_coding.h"

#include <lokimq/hex.h>

#include <sqlite3.h>

extern "C"
{
#include <sodium.h>
}

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "lns"

namespace lns
{
enum struct lns_sql_type
{
  save_owner,
  save_setting,
  save_mapping,
  pruning,

  get_sentinel_start,
  get_mapping,
  get_mappings,
  get_mappings_by_owner,
  get_mappings_by_owners,
  get_mappings_on_height_and_newer,
  get_owner,
  get_setting,
  get_sentinel_end,
};

enum struct lns_db_setting_row
{
  id,
  top_height,
  top_hash,
  version,
};

enum struct owner_record_row
{
  id,
  public_key,
};

enum struct mapping_record_row
{
  id,
  type,
  name_hash,
  encrypted_value,
  txid,
  prev_txid,
  register_height,
  owner_id,
  backup_owner_id,
  _count,
};

static bool sql_copy_blob(sqlite3_stmt *statement, int row, void *dest, int dest_size)
{
  void const *blob = sqlite3_column_blob(statement, row);
  int blob_len     = sqlite3_column_bytes(statement, row);
  assert(blob_len == dest_size);
  if (blob_len != dest_size)
  {
    LOG_PRINT_L0("Unexpected blob size=" << blob_len << ", in LNS DB does not match expected size=" << dest_size);
    return false;
  }

  memcpy(dest, blob, blob_len);
  return true;
}

static bool sql_run_statement(cryptonote::network_type nettype, lns_sql_type type, sqlite3_stmt *statement, void *context)
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

          case lns_sql_type::get_owner:
          {
            auto *entry = reinterpret_cast<owner_record *>(context);
            entry->id   = sqlite3_column_int(statement, static_cast<int>(owner_record_row::id));
            if (!sql_copy_blob(statement, static_cast<int>(owner_record_row::public_key), entry->key.data, sizeof(entry->key.data)))
              return false;
            data_loaded = true;
          }
          break;

          case lns_sql_type::get_setting:
          {
            auto *entry       = reinterpret_cast<settings_record *>(context);
            entry->top_height = static_cast<uint64_t>(sqlite3_column_int64(statement, static_cast<int>(lns_db_setting_row::top_height)));
            if (!sql_copy_blob(statement, static_cast<int>(lns_db_setting_row::top_hash), entry->top_hash.data, sizeof(entry->top_hash.data)))
              return false;
            entry->version = sqlite3_column_int(statement, static_cast<int>(lns_db_setting_row::version));
            data_loaded = true;
          }
          break;

          case lns_sql_type::get_mappings_on_height_and_newer: /* FALLTHRU */
          case lns_sql_type::get_mappings_by_owners: /* FALLTHRU */
          case lns_sql_type::get_mappings_by_owner: /* FALLTHRU */
          case lns_sql_type::get_mappings: /* FALLTHRU */
          case lns_sql_type::get_mapping:
          {
            mapping_record tmp_entry = {};
            int type_int = static_cast<uint16_t>(sqlite3_column_int(statement, static_cast<int>(mapping_record_row::type)));
            if (type_int >= tools::enum_count<mapping_type>)
              return false;

            tmp_entry.type            = static_cast<mapping_type>(type_int);
            tmp_entry.register_height = static_cast<uint16_t>(sqlite3_column_int(statement, static_cast<int>(mapping_record_row::register_height)));
            tmp_entry.owner_id        = sqlite3_column_int(statement, static_cast<int>(mapping_record_row::owner_id));
            tmp_entry.backup_owner_id = sqlite3_column_int(statement, static_cast<int>(mapping_record_row::backup_owner_id));

            // Copy encrypted_value
            {
              size_t value_len = static_cast<size_t>(sqlite3_column_bytes(statement, static_cast<int>(mapping_record_row::encrypted_value)));
              auto *value      = reinterpret_cast<char const *>(sqlite3_column_text(statement, static_cast<int>(mapping_record_row::encrypted_value)));
              if (value_len > tmp_entry.encrypted_value.buffer.size())
              {
                  MERROR("Unexpected encrypted value blob with size=" << value_len << ", in LNS db larger than the available size=" << tmp_entry.encrypted_value.buffer.size());
                  return false;
              }
              tmp_entry.encrypted_value.len = value_len;
              memcpy(&tmp_entry.encrypted_value.buffer[0], value, value_len);
            }

            // Copy name hash
            {
              size_t value_len = static_cast<size_t>(sqlite3_column_bytes(statement, static_cast<int>(mapping_record_row::name_hash)));
              auto *value      = reinterpret_cast<char const *>(sqlite3_column_text(statement, static_cast<int>(mapping_record_row::name_hash)));
              tmp_entry.name_hash.append(value, value_len);
            }

            if (!sql_copy_blob(statement, static_cast<int>(mapping_record_row::txid), tmp_entry.txid.data, sizeof(tmp_entry.txid)))
              return false;

            if (!sql_copy_blob(statement, static_cast<int>(mapping_record_row::prev_txid), tmp_entry.prev_txid.data, sizeof(tmp_entry.prev_txid)))
              return false;

            int owner_column = tools::enum_count<mapping_record_row>;
            if (!sql_copy_blob(statement, owner_column, tmp_entry.owner.data, sizeof(tmp_entry.owner)))
              return false;

            if (tmp_entry.backup_owner_id > 0)
            {
              if (!sql_copy_blob(statement, owner_column + 1, tmp_entry.backup_owner.data, sizeof(tmp_entry.backup_owner)))
                return false;
            }

            tmp_entry.loaded = true;
            data_loaded      = true;
            if (type == lns_sql_type::get_mapping)
            {
              auto *entry = reinterpret_cast<mapping_record *>(context);
              *entry      = std::move(tmp_entry);
            }
            else
            {
              auto *records = reinterpret_cast<std::vector<mapping_record> *>(context);
              records->emplace_back(std::move(tmp_entry));
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

bool mapping_record::active(cryptonote::network_type nettype, uint64_t blockchain_height) const
{
  if (!loaded) return false;
  uint64_t expiry_blocks = lns::expiry_blocks(nettype, static_cast<lns::mapping_type>(type));
  uint64_t const last_active_height = expiry_blocks == NO_EXPIRY ? NO_EXPIRY : (register_height + expiry_blocks);
  return last_active_height >= (blockchain_height - 1);
}

static bool sql_compile_statement(sqlite3 *db, char const *query, int query_len, sqlite3_stmt **statement, bool optimise_for_multiple_usage = true)
{
#if SQLITE_VERSION_NUMBER >= 3020000
  int prepare_result = sqlite3_prepare_v3(db, query, query_len, optimise_for_multiple_usage ? SQLITE_PREPARE_PERSISTENT : 0, statement, nullptr /*pzTail*/);
#else
  int prepare_result = sqlite3_prepare_v2(db, query, query_len, statement, nullptr /*pzTail*/);
#endif

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

uint64_t expiry_blocks(cryptonote::network_type nettype, mapping_type type, uint64_t *renew_window)
{
  uint64_t renew_window_ = 0;
  uint64_t result        = NO_EXPIRY;
  if (is_lokinet_type(type))
  {
    renew_window_ = BLOCKS_EXPECTED_IN_DAYS(31);

    if (type == mapping_type::lokinet_1year)        result = BLOCKS_EXPECTED_IN_YEARS(1);
    else if (type == mapping_type::lokinet_2years)  result = BLOCKS_EXPECTED_IN_YEARS(2);
    else if (type == mapping_type::lokinet_5years)  result = BLOCKS_EXPECTED_IN_YEARS(5);
    else if (type == mapping_type::lokinet_10years) result = BLOCKS_EXPECTED_IN_YEARS(10);

    result += renew_window_;
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
  }

  if (renew_window) *renew_window = renew_window_;
  return result;
}

crypto::hash tx_extra_signature_hash(epee::span<const uint8_t> blob, crypto::hash const &prev_txid)
{
  static_assert(sizeof(crypto::hash) == crypto_generichash_BYTES, "Using libsodium generichash for signature hash, require we fit into crypto::hash");
  crypto::hash result = {};
  if (blob.size() <= mapping_value::BUFFER_SIZE)
  {
    unsigned char buffer[mapping_value::BUFFER_SIZE + sizeof(prev_txid)] = {};
    size_t buffer_len                                                = blob.size() + sizeof(prev_txid);
    memcpy(buffer, blob.data(), blob.size());
    memcpy(buffer + blob.size(), prev_txid.data, sizeof(prev_txid));
    crypto_generichash(reinterpret_cast<unsigned char *>(result.data), sizeof(result), buffer, buffer_len, NULL /*key*/, 0 /*key_len*/);
  }
  else
  {
    MERROR("Unexpected blob len=" << blob.size() << " greater than the blob backing buffer capacity=" << mapping_value::BUFFER_SIZE);
  }

  return result;
}

static bool char_is_num(char c)
{
  bool result = c >= '0' && c <= '9';
  return result;
}

static bool char_is_alpha(char c)
{
  bool result = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  return result;
}

static bool char_is_alphanum(char c)
{
  bool result = char_is_num(c) || char_is_alpha(c);
  return result;
}

bool validate_lns_name(mapping_type type, std::string const &name, std::string *reason)
{
  std::stringstream err_stream;
  LOKI_DEFER { if (reason) *reason = err_stream.str(); };

  size_t max_name_len = 0;
  if (type == mapping_type::session)      max_name_len = lns::SESSION_DISPLAY_NAME_MAX;
  else if (type == mapping_type::wallet)  max_name_len = lns::WALLET_NAME_MAX;
  else if (is_lokinet_type(type))         max_name_len = lns::LOKINET_DOMAIN_NAME_MAX;
  else
  {
    if (reason) err_stream << "LNS type=" << type << ", specifies unhandled mapping type in name validation";
    return false;
  }

  // NOTE: Validate name length
  if (name.empty() || name.size() > max_name_len)
  {
    if (reason)
    {
      err_stream << "LNS type=" << type << ", specifies mapping from name -> value where the name's length=" << name.size() << " is 0 or exceeds the maximum length=" << max_name_len << ", given name=" << name;
    }
    return false;
  }

  // NOTE: Validate domain specific requirements
  if (type == mapping_type::session)
  {
  }
  else if (is_lokinet_type(type))
  {
    // Domain has to start with a letter or digit, and can have letters, digits, or hyphens in between and must end with a .loki
    // ^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.loki$
    {
      char const SHORTEST_DOMAIN[] = "a.loki";
      if (name.size() < static_cast<int>(loki::char_count(SHORTEST_DOMAIN)))
      {
        if (reason)
        {
          err_stream << "LNS type=lokinet, specifies mapping from name -> value where the name is shorter than the shortest possible name=" << SHORTEST_DOMAIN << ", given name=" << name;
        }
        return false;
      }
    }

    if (!char_is_alphanum(name[0])) // Must start with alphanumeric
    {
      if (reason)
      {
        err_stream << "LNS type=lokinet, specifies mapping from name -> value where the name does not start with an alphanumeric character, name=" << name;
      }
      return false;
    }

    char const SUFFIX[]     = ".loki";
    char const *name_suffix = name.data() + (name.size() - loki::char_count(SUFFIX));
    if (memcmp(name_suffix, SUFFIX, loki::char_count(SUFFIX)) != 0) // Must end with .loki
    {
      if (reason)
      {
        err_stream << "LNS type=lokinet, specifies mapping from name -> value where the name does not end with the domain .loki, name=" << name;
      }
      return false;
    }

    char const *char_preceeding_suffix = name_suffix - 1;
    if (!char_is_alphanum(char_preceeding_suffix[0])) // Characted preceeding suffix must be alphanumeric
    {
      if (reason)
      {
        err_stream << "LNS type=lokinet, specifies mapping from name -> value where the character preceeding the <char>.loki is not alphanumeric, char=" << char_preceeding_suffix[0] << ", name=" << name;
      }
      return false;
    }

    char const *begin = name.data() + 1;
    char const *end   = char_preceeding_suffix;
    for (char const *it = begin; it < end; it++) // Inbetween start and preceeding suffix, alphanumeric and hyphen characters permitted
    {
      char c = it[0];
      if (!(char_is_alphanum(c) || c == '-'))
      {
        if (reason)
        {
          err_stream << "LNS type=lokinet, specifies mapping from name -> value where the domain name contains more than the permitted alphanumeric or hyphen characters name=" << name;
        }
        return false;
      }
    }
  }

  return true;
}

static bool check_lengths(mapping_type type, std::string const &value, size_t max, bool binary_val, std::string *reason)
{
  bool result = (value.size() == max);
  if (!result)
  {
    if (reason)
    {
      std::stringstream err_stream;
      err_stream << "LNS type=" << type << ", specifies mapping from name_hash->encrypted_value where the value's length=" << value.size() << ", does not equal the required length=" << max << ", given value=";
      if (binary_val) err_stream << epee::to_hex::string(epee::span<const uint8_t>(reinterpret_cast<uint8_t const *>(value.data()), value.size()));
      else            err_stream << value;
      *reason = err_stream.str();
    }
  }

  return result;
}

bool validate_mapping_value(cryptonote::network_type nettype, mapping_type type, std::string const &value, mapping_value *blob, std::string *reason)
{
  if (blob) *blob = {};
  std::stringstream err_stream;

  // Check length of the value
  cryptonote::address_parse_info addr_info = {};
  if (type == mapping_type::wallet)
  {
    if (value.empty() || !get_account_address_from_str(addr_info, nettype, value))
    {
      if (reason)
      {
        if (value.empty())
        {
          err_stream << "The value=" << value;
          err_stream << ", mapping into the wallet address, specifies a wallet address of 0 length";
        }
        else
        {
          err_stream << "Could not convert the wallet address string, check it is correct, value=" << value;
        }
        *reason = err_stream.str();
      }
      return false;
    }
  }
  else
  {
    int max_value_len = 0;
    if (is_lokinet_type(type))              max_value_len = (LOKINET_ADDRESS_BINARY_LENGTH * 2);
    else if (type == mapping_type::session) max_value_len = (SESSION_PUBLIC_KEY_BINARY_LENGTH * 2);
    else
    {
      if (reason)
      {
        err_stream << "Unhandled type passed into: " << __func__;
        *reason = err_stream.str();
      }
      return false;
    }

    if (!check_lengths(type, value, max_value_len, false /*binary_val*/, reason))
      return false;
  }

  // Validate blob contents and generate the binary form if possible
  if (type == mapping_type::wallet)
  {
    if (blob)
    {
      blob->len = sizeof(addr_info.address);
      memcpy(blob->buffer.data(), &addr_info.address, blob->len);
    }
  }
  else if (is_lokinet_type(type))
  {
    if (value.size() != 52)
    {
      if (reason)
      {
        err_stream << "The lokinet value=" << value << ", should be a 52 char base32z string, length=" << value.size();
        *reason = err_stream.str();
      }
      return false;
    }

    crypto::ed25519_public_key pkey;
    if (!base32z::decode(value, pkey))
    {
      if (reason)
      {
        err_stream << "The value=" << value << ", was not a decodable base32z value.";
        *reason = err_stream.str();
      }
      return false;
    }

    if (blob)
    {
      blob->len = sizeof(pkey);
      memcpy(blob->buffer.data(), pkey.data, blob->len);
    }
  }
  else
  {
    assert(type == mapping_type::session);
    // NOTE: Check value is hex
    if ((value.size() % 2) != 0)
    {
      if (reason)
      {
        err_stream << "The value=" << value << ", should be a hex string that has an even length to be convertible back into binary, length=" << value.size();
        *reason = err_stream.str();
      }
      return false;
    }
    if (!lokimq::is_hex(value))
    {
      if (reason)
      {
        err_stream << "LNS type=" << type <<", specifies name -> value mapping where the value is not a hex string given value=" << value;
        *reason = err_stream.str();
      }
      return false;
    }
    if (blob) // NOTE: Given blob, write the binary output
    {
      blob->len = value.size() / 2;
      assert(blob->len <= blob->buffer.size());
      lokimq::from_hex(value.begin(), value.end(), blob->buffer.begin());
    }

    if (!(value[0] == '0' && value[1] == '5')) // NOTE: Session public keys are 33 bytes, with the first byte being 0x05 and the remaining 32 being the public key.
    {
      if (reason)
      {
        err_stream << "LNS type=session, specifies mapping from name_hash->ed25519 key where the key is not prefixed with 53 (0x05), prefix=" << std::to_string(value[0]) << " (" << value[0] << "), given ed25519=" << value;
        *reason = err_stream.str();
      }
      return false;
    }
  }

  return true;
}

bool validate_encrypted_mapping_value(mapping_type type, std::string const &value, std::string *reason)
{
  std::stringstream err_stream;
  int max_value_len = crypto_secretbox_MACBYTES;
  if (is_lokinet_type(type)) max_value_len              += LOKINET_ADDRESS_BINARY_LENGTH;
  else if (type == mapping_type::session) max_value_len += SESSION_PUBLIC_KEY_BINARY_LENGTH;
  else if (type == mapping_type::wallet)  max_value_len += WALLET_ACCOUNT_BINARY_LENGTH;
  else
  {
    if (reason)
    {
      err_stream << "Unhandled type passed into " << __func__;
      *reason = err_stream.str();
    }
    return false;
  }

  if (!check_lengths(type, value, max_value_len, true /*binary_val*/, reason))
    return false;
  return true;
}

static std::ostream &operator<<(std::ostream &stream, cryptonote::tx_extra_loki_name_system const &data)
{
  stream << "LNS Extra={";
  if (data.is_buying())
  {
    stream << "owner=" << data.owner;
    if (data.backup_owner) stream << "backup_owner=" << data.backup_owner;
  }
  else
    stream << "signature=" << epee::string_tools::pod_to_hex(data.signature);

  stream << ", type=" << data.type << ", name_hash=" << data.name_hash << "}";
  return stream;
}

static std::string hash_to_base64(crypto::hash const &hash)
{
  std::string result = epee::string_encoding::base64_encode(reinterpret_cast<unsigned char const *>(hash.data), sizeof(hash));
  return result;
}

static bool verify_lns_signature(crypto::hash const &hash, crypto::generic_signature const &signature, crypto::generic_public_key const &key)
{
  if (!key) return false;
  if (crypto_sign_verify_detached(signature.data, reinterpret_cast<unsigned char const *>(hash.data), sizeof(hash.data), key.data) != 0)
  {
    if (!crypto::check_signature(hash, key.monero, signature.monero))
      return false;
  }

  return true;
}

static bool validate_against_previous_mapping(lns::name_system_db const &lns_db, uint64_t blockchain_height, cryptonote::transaction const &tx, cryptonote::tx_extra_loki_name_system &data, std::string *reason = nullptr)
{
  std::stringstream err_stream;
  crypto::hash expected_prev_txid = crypto::null_hash;
  std::string name_hash           = hash_to_base64(data.name_hash);
  lns::mapping_record mapping     = lns_db.get_mapping(data.type, name_hash);
  const bool updating = data.command == lns::tx_command::update;
  if (updating && !mapping)
  {
    if (reason)
    {
      err_stream <<  tx << ", " << data << ", update requested but mapping does not exist.";
      *reason = err_stream.str();
    }
    return false;
  }

  if (mapping)
  {
    expected_prev_txid = mapping.txid;
    if (updating) // We can always update unless the mapping has expired
    {
      if (!mapping.active(lns_db.network_type(), blockchain_height))
      {
        if (reason)
        {
          err_stream << tx << ", " << data << ", TX requested to update mapping that has already expired";
          *reason = err_stream.str();
        }
        return false;
      }

      if (mapping.encrypted_value == data.encrypted_value)
      {
        if (reason)
        {
          err_stream << tx << ", " <<  data << ", value to update to is already the same as the mapping value";
          *reason = err_stream.str();
        }
        return false;
      }

      // Validate signature
      {
        crypto::hash hash = tx_extra_signature_hash(epee::strspan<uint8_t>(data.encrypted_value), expected_prev_txid);
        if (!verify_lns_signature(hash, data.signature, mapping.owner) && !verify_lns_signature(hash, data.signature, mapping.backup_owner))
        {
          if (reason)
          {
            err_stream << tx << ", " << data << ", failed to verify signature for LNS update";
            *reason = err_stream.str();
          }
          return false;
        }
      }

      data.owner        = mapping.owner;
      data.backup_owner = mapping.backup_owner;
    }
    else
    {
      if (!is_lokinet_type(data.type))
      {
        if (reason)
        {
          lns::owner_record owner = lns_db.get_owner_by_id(mapping.owner_id);
          err_stream << tx << ", " << data << ", non-lokinet entries can NOT be renewed, mapping already exists with name_hash=" << mapping.name_hash << ", owner=" << owner.key << ", type=" << mapping.type;
          *reason = err_stream.str();
        }
        return false;
      }

      uint64_t renew_window              = 0;
      uint64_t expiry_blocks             = lns::expiry_blocks(lns_db.network_type(), data.type, &renew_window);
      uint64_t const renew_window_offset = expiry_blocks - renew_window;
      uint64_t const min_renew_height    = mapping.register_height + renew_window_offset;

      if (min_renew_height >= blockchain_height)
      {
        err_stream << tx << ", " << data << ", trying to renew too early, the earliest renew height=" << min_renew_height << ", urrent height=" << blockchain_height;
        *reason = err_stream.str();
        return false; // Trying to renew too early
      }

      if (mapping.active(lns_db.network_type(), blockchain_height))
      {
        // Lokinet entry expired i.e. it's no longer active. A purchase for this name is valid
        // Check that the request originates from the owner of this mapping
        lns::owner_record const requester = lns_db.get_owner_by_key(data.owner);
        if (!requester)
        {
          if (reason)
          {
            err_stream << tx << ", " << data << ", trying to renew existing mapping but owner specified in LNS extra does not exist, rejected";
            *reason = err_stream.str();
          }
          return false;
        }

        lns::owner_record const owner = lns_db.get_owner_by_id(mapping.owner_id);
        if (!owner)
        {
          if (reason)
          {
            err_stream << tx << ", " << data << ", unexpected owner_id=" << mapping.owner_id << " does not exist";
            *reason = err_stream.str();
          }
          return false;
        }

        if (requester.id != owner.id)
        {
          if (reason)
          {
            err_stream << tx << ", " << data << ", actual owner=" << owner.key << ", with owner_id=" << mapping.owner_id << ", does not match requester=" << requester.key << ", with id=" << requester.id;
            *reason = err_stream.str();
          }
          return false;
        }
      }
      // else mapping has expired, new purchase is valid
    }
  }

  if (data.prev_txid != expected_prev_txid)
  {
    if (reason)
    {
      err_stream << tx << ", " << data << ", specified prior owner txid=" << data.prev_txid << ", but LNS DB reports=" << expected_prev_txid << ", possible competing TX was submitted and accepted before this TX was processed";
      *reason = err_stream.str();
    }
    return false;
  }

  return true;
}

bool name_system_db::validate_lns_tx(uint8_t hf_version, uint64_t blockchain_height, cryptonote::transaction const &tx, cryptonote::tx_extra_loki_name_system *entry, std::string *reason) const
{
  cryptonote::tx_extra_loki_name_system entry_;
  if (!entry) entry = &entry_;
  std::stringstream err_stream;

  if (tx.type != cryptonote::txtype::loki_name_system)
  {
    if (reason)
    {
      err_stream << tx << ", uses wrong tx type, expected=" << cryptonote::txtype::loki_name_system;
      *reason = err_stream.str();
    }
    return false;
  }

  if (!cryptonote::get_loki_name_system_from_tx_extra(tx.extra, *entry))
  {
    if (reason)
    {
      err_stream << tx << ", didn't have loki name service in the tx_extra";
      *reason = err_stream.str();
    }
    return false;
  }

  if (entry->version != 0)
  {
    if (reason)
    {
      err_stream << tx << ", " << *entry << ", unexpected version=" << std::to_string(entry->version) << ", expected=0";
      *reason = err_stream.str();
    }
    return false;
  }

  if (!lns::mapping_type_allowed(hf_version, entry->type))
  {
    if (reason)
    {
      err_stream << tx << ", " << *entry << ", specifying type=" << entry->type << " that is disallowed";
      *reason = err_stream.str();
    }
    return false;
  }

  if (entry->is_buying())
  {
    if (entry->owner == entry->backup_owner)
    {
      if (reason)
      {
        err_stream << tx << ", " << *entry << ", specifying owner the same as the backup owner";
        *reason = err_stream.str();
      }
      return false;
    }

    if (!entry->owner)
    {
      if (reason)
      {
        err_stream << tx << ", " << *entry << ", can't specify LNS extra without owner";
        *reason = err_stream.str();
      }
      return false;
    }
  }
  else
  {
    if (!entry->signature)
    {
      if (reason)
      {
        err_stream << tx << ", " << *entry << ", signature to validate is the null-signature";
        *reason = err_stream.str();
      }
      return false;
    }
  }

  if (!validate_encrypted_mapping_value(entry->type, entry->encrypted_value, reason))
      return false;

  if (!validate_against_previous_mapping(*this, blockchain_height, tx, *entry, reason))
    return false;

  static const crypto::hash null_name_hash = name_to_hash(""); // Sanity check the empty name hash
  if (entry->name_hash == null_name_hash || entry->name_hash == crypto::null_hash)
  {
    if (reason)
    {
      err_stream << "LNS TX=" << cryptonote::get_transaction_hash(tx) << ", specified the null name hash";
      *reason = err_stream.str();
    }
    return false;
  }

  uint64_t burn                = cryptonote::get_burned_amount_from_tx_extra(tx.extra);
  uint64_t const burn_required = entry->is_buying() ? burn_needed(hf_version, entry->type) : 0;
  if (burn != burn_required)
  {
    if (reason)
    {
      char const *over_or_under = burn > burn_required ? "too much " : "insufficient ";
      err_stream << tx << ", " << *entry << ", burned " << over_or_under << "loki=" << burn << ", require=" << burn_required;
      if (!entry->is_buying()) err_stream << ", updating requires just the ordinary transaction fee";
      *reason = err_stream.str();
    }
    return false;
  }

  return true;
}

static std::string lowercase_string(std::string src)
{
  for (char &ch : src)
  {
    if (ch >= 'A' && ch <= 'Z')
      ch = ch + ('a' - 'A');
  }
  return src;
}

bool validate_mapping_type(std::string const &mapping_type_str, lns::mapping_type *mapping_type, std::string *reason)
{
  std::string mapping = lowercase_string(mapping_type_str);

  lns::mapping_type mapping_type_;
  if (mapping == "session") mapping_type_ = lns::mapping_type::session;
  else
  {
    if (reason) *reason = "Failed to convert lns mapping (was not proper integer, or not one of the recognised: \"session\"), string was=" + mapping_type_str;
    return false;
  }

  if (mapping_type) *mapping_type = static_cast<lns::mapping_type>(mapping_type_);
  return true;
}

crypto::hash name_to_hash(std::string const &name)
{
  crypto::hash result = {};
  static_assert(sizeof(result) >= crypto_generichash_BYTES, "Sodium can generate arbitrary length hashes, but recommend the minimum size for a secure hash must be >= crypto_generichash_BYTES");
  crypto_generichash_blake2b(reinterpret_cast<unsigned char *>(result.data),
                             sizeof(result),
                             reinterpret_cast<const unsigned char *>(name.data()),
                             static_cast<unsigned long long>(name.size()),
                             nullptr /*key*/,
                             0 /*keylen*/);
  return result;
}

std::string name_to_base64_hash(std::string const &name)
{
  crypto::hash hash  = name_to_hash(name);
  std::string result = hash_to_base64(hash);
  return result;
}

struct alignas(size_t) secretbox_secret_key_ { unsigned char data[crypto_secretbox_KEYBYTES]; };
using secretbox_secret_key = epee::mlocked<tools::scrubbed<secretbox_secret_key_>>;

static bool name_to_encryption_key(std::string const &name, secretbox_secret_key &out)
{
  static_assert(sizeof(out) >= crypto_secretbox_KEYBYTES, "Encrypting key needs to have sufficient space for running encryption functions via libsodium");
  static unsigned char constexpr SALT[crypto_pwhash_SALTBYTES] = {};
  bool result = (crypto_pwhash(out.data, sizeof(out), name.data(), name.size(), SALT, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2ID13) == 0);
  return result;
}

static unsigned char const ENCRYPTION_NONCE[crypto_secretbox_NONCEBYTES] = {}; // NOTE: Not meant to be extremely secure, just use an empty nonce
bool encrypt_mapping_value(std::string const &name, mapping_value const &value, mapping_value &encrypted_value)
{
  static_assert(mapping_value::BUFFER_SIZE >= SESSION_PUBLIC_KEY_BINARY_LENGTH + crypto_secretbox_MACBYTES, "Value blob assumes the largest size required, all other values should be able to fit into this buffer");
  static_assert(mapping_value::BUFFER_SIZE >= LOKINET_ADDRESS_BINARY_LENGTH    + crypto_secretbox_MACBYTES, "Value blob assumes the largest size required, all other values should be able to fit into this buffer");
  static_assert(mapping_value::BUFFER_SIZE >= WALLET_ACCOUNT_BINARY_LENGTH     + crypto_secretbox_MACBYTES, "Value blob assumes the largest size required, all other values should be able to fit into this buffer");

  bool result                 = false;
  size_t const encryption_len = value.len + crypto_secretbox_MACBYTES;
  if (encryption_len > encrypted_value.buffer.size())
  {
    MERROR("Encrypted value pre-allocated buffer too small=" << encrypted_value.buffer.size() << ", required=" << encryption_len);
    return result;
  }

  encrypted_value     = {};
  encrypted_value.len = encryption_len;

  secretbox_secret_key skey;
  if (name_to_encryption_key(name, skey))
    result = (crypto_secretbox_easy(encrypted_value.buffer.data(), value.buffer.data(), value.len, ENCRYPTION_NONCE, reinterpret_cast<unsigned char *>(&skey)) == 0);
  return result;
}

bool decrypt_mapping_value(std::string const &name, mapping_value const &encrypted_value, mapping_value &value)
{
  bool result = false;
  if (encrypted_value.len <= crypto_secretbox_MACBYTES)
  {
    MERROR("Encrypted value is too short=" << encrypted_value.len << ", at least required=" << crypto_secretbox_MACBYTES + 1);
    return result;
  }

  value     = {};
  value.len = encrypted_value.len - crypto_secretbox_MACBYTES;

  secretbox_secret_key skey;
  if (name_to_encryption_key(name, skey))
    result = crypto_secretbox_open_easy(value.buffer.data(), encrypted_value.buffer.data(), encrypted_value.len, ENCRYPTION_NONCE, reinterpret_cast<unsigned char *>(&skey)) == 0;
  return result;
}


static bool build_default_tables(sqlite3 *db)
{
  constexpr char BUILD_TABLE_SQL[] = R"(
CREATE TABLE IF NOT EXISTS "owner"(
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "public_key" BLOB NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS "settings" (
    "id" INTEGER PRIMARY KEY NOT NULL,
    "top_height" INTEGER NOT NULL,
    "top_hash" VARCHAR NOT NULL,
    "version" INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS "mappings" (
    "id" INTEGER PRIMARY KEY NOT NULL,
    "type" INTEGER NOT NULL,
    "name_hash" VARCHAR NOT NULL,
    "encrypted_value" BLOB NOT NULL,
    "txid" BLOB NOT NULL,
    "prev_txid" BLOB NOT NULL,
    "register_height" INTEGER NOT NULL,
    "owner_id" INTEGER NOT NULL REFERENCES "owner" ("id"),
    "backup_owner_id" INTEGER REFERENCES "owner" ("id")
);
CREATE UNIQUE INDEX IF NOT EXISTS "name_hash_type_id" ON mappings("name_hash", "type");
)";

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

static std::string sql_cmd_combine_mappings_and_owner_table(char const *suffix)
{
  std::stringstream stream;
  stream <<
R"(SELECT "mappings".*, "o1"."public_key", "o2"."public_key" FROM "mappings"
JOIN "owner" "o1" ON "mappings"."owner_id" = "o1"."id"
LEFT JOIN "owner" "o2" ON "mappings"."backup_owner_id" = "o2"."id")" << "\n";

  if (suffix)
    stream << suffix;
  return stream.str();
}

enum struct db_version { v1, };
auto constexpr DB_VERSION = db_version::v1;
bool name_system_db::init(cryptonote::network_type nettype, sqlite3 *db, uint64_t top_height, crypto::hash const &top_hash)
{
  if (!db) return false;
  this->db      = db;
  this->nettype = nettype;

  std::string const get_mappings_by_owner_str            = sql_cmd_combine_mappings_and_owner_table(R"(WHERE "o1"."public_key" = ? OR "o2"."public_key" = ?)");
  std::string const get_mappings_on_height_and_newer_str = sql_cmd_combine_mappings_and_owner_table(R"(WHERE "register_height" >= ?)");
  std::string const get_mapping_str                      = sql_cmd_combine_mappings_and_owner_table(R"(WHERE "type" = ? AND "name" = ?)");

  char constexpr GET_OWNER_BY_ID_STR[]  = R"(SELECT * FROM "owner" WHERE "id" = ?)";
  char constexpr GET_OWNER_BY_KEY_STR[] = R"(SELECT * FROM "owner" WHERE "public_key" = ?)";
  char constexpr GET_SETTINGS_STR[]     = R"(SELECT * FROM "settings" WHERE "id" = 1)";
  char constexpr PRUNE_MAPPINGS_STR[]   = R"(DELETE FROM "mappings" WHERE "register_height" >= ?)";

  char constexpr PRUNE_OWNERS_STR[] =
R"(DELETE FROM "owner"
WHERE NOT EXISTS
  (SELECT * FROM "mappings"
   WHERE "owner"."id" = "mappings"."owner_id"
   OR "owner"."id" = "mappings"."backup_owner_id"))";

  char constexpr SAVE_MAPPING_STR[]     = R"(INSERT OR REPLACE INTO "mappings" ("type", "name", "value", "txid", "prev_txid", "register_height", "owner_id", "backup_owner_id") VALUES (?,?,?,?,?,?,?,?))";
  char constexpr SAVE_OWNER_STR[]       = R"(INSERT INTO "owner" ("public_key") VALUES (?);)";
  char constexpr SAVE_SETTINGS_STR[]    = R"(INSERT OR REPLACE INTO "settings" ("id", "top_height", "top_hash", "version") VALUES (1,?,?,?))";

  sqlite3_stmt *test;

  if (!build_default_tables(db))
    return false;

  if (
      !sql_compile_statement(db, get_mappings_by_owner_str.c_str(),            get_mappings_by_owner_str.size(),            &get_mappings_by_owner_sql) ||
      !sql_compile_statement(db, get_mappings_on_height_and_newer_str.c_str(), get_mappings_on_height_and_newer_str.size(), &get_mappings_on_height_and_newer_sql) ||
      !sql_compile_statement(db, get_mapping_str.c_str(),                      get_mapping_str.size(),                      &get_mapping_sql) ||
      !sql_compile_statement(db, GET_SETTINGS_STR,                             loki::array_count(GET_SETTINGS_STR),         &get_settings_sql) ||
      !sql_compile_statement(db, GET_OWNER_BY_ID_STR,                          loki::array_count(GET_OWNER_BY_ID_STR),      &get_owner_by_id_sql) ||
      !sql_compile_statement(db, GET_OWNER_BY_KEY_STR,                         loki::array_count(GET_OWNER_BY_KEY_STR),     &get_owner_by_key_sql) ||
      !sql_compile_statement(db, PRUNE_MAPPINGS_STR,                           loki::array_count(PRUNE_MAPPINGS_STR),       &prune_mappings_sql) ||
      !sql_compile_statement(db, PRUNE_OWNERS_STR,                             loki::array_count(PRUNE_OWNERS_STR),         &prune_owners_sql) ||
      !sql_compile_statement(db, SAVE_MAPPING_STR,                             loki::array_count(SAVE_MAPPING_STR),         &save_mapping_sql) ||
      !sql_compile_statement(db, SAVE_SETTINGS_STR,                            loki::array_count(SAVE_SETTINGS_STR),        &save_settings_sql) ||
      !sql_compile_statement(db, SAVE_OWNER_STR,                               loki::array_count(SAVE_OWNER_STR),           &save_owner_sql)
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
      char constexpr DROP_TABLE_SQL[] = R"(DROP TABLE IF EXISTS "owner"; DROP TABLE IF EXISTS "settings"; DROP TABLE IF EXISTS "mappings")";
      sqlite3_exec(db, DROP_TABLE_SQL, nullptr /*callback*/, nullptr /*callback context*/, nullptr);
      if (!build_default_tables(db)) return false;
    }
  }

  return true;
}

struct scoped_db_transaction
{
  scoped_db_transaction(name_system_db &lns_db);
  ~scoped_db_transaction();
  operator bool() const { return initialised; }
  name_system_db &lns_db;
  bool commit      = false; // If true, on destruction- END the transaction otherwise ROLLBACK all SQLite events prior for the lns_db
  bool initialised = false;
};

scoped_db_transaction::scoped_db_transaction(name_system_db &lns_db)
: lns_db(lns_db)
{
  if (lns_db.transaction_begun)
  {
    MERROR("Failed to begin transaction, transaction exists previously that was not closed properly");
    return;
  }

  char *sql_err = nullptr;
  if (sqlite3_exec(lns_db.db, "BEGIN;", nullptr, nullptr, &sql_err) != SQLITE_OK)
  {
    MERROR("Failed to begin transaction " << ", reason=" << (sql_err ? sql_err : "??"));
    sqlite3_free(sql_err);
    return;
  }

  initialised              = true;
  lns_db.transaction_begun = true;
}

scoped_db_transaction::~scoped_db_transaction()
{
  if (!initialised) return;
  if (!lns_db.transaction_begun)
  {
    MERROR("Trying to apply non-existent transaction (no prior history of a db transaction beginning) to the LNS DB");
    return;
  }

  char *sql_err = nullptr;
  if (sqlite3_exec(lns_db.db, commit ? "END;" : "ROLLBACK;", NULL, NULL, &sql_err) != SQLITE_OK)
  {
    MERROR("Failed to " << (commit ? "end " : "rollback ") << " transaction to LNS DB, reason=" << (sql_err ? sql_err : "??"));
    sqlite3_free(sql_err);
    return;
  }

  lns_db.transaction_begun = false;
}

static int64_t add_or_get_owner_id(lns::name_system_db &lns_db, crypto::hash const &tx_hash, cryptonote::tx_extra_loki_name_system const &entry, crypto::generic_public_key const &key)
{
  int64_t result = 0;
  if (owner_record owner = lns_db.get_owner_by_key(key)) result = owner.id;
  if (result == 0)
  {
    if (entry.command == lns::tx_command::update)
    {
      MERROR("Owner does not exist but TX received is trying to update an existing mapping (i.e. owner should already exist). TX=" << tx_hash << " should have failed validation prior.");
      return result;
    }

    if (!lns_db.save_owner(key, &result))
    {
      LOG_PRINT_L1("Failed to save LNS owner to DB tx: " << tx_hash << ", type: " << entry.type << ", name_hash: " << entry.name_hash << ", owner: " << entry.owner);
      return result;
    }
  }
  return result;
}

static bool add_lns_entry(lns::name_system_db &lns_db, uint64_t height, cryptonote::tx_extra_loki_name_system const &entry, crypto::hash const &tx_hash)
{
  int64_t owner_id = add_or_get_owner_id(lns_db, tx_hash, entry, entry.owner);
  if (owner_id == 0)
  {
    assert(owner_id != 0);
    return false;
  }

  int64_t backup_owner_id = 0;
  if (entry.backup_owner)
  {
    backup_owner_id = add_or_get_owner_id(lns_db, tx_hash, entry, entry.backup_owner);
    if (backup_owner_id == 0)
    {
      assert(backup_owner_id != 0);
      LOG_PRINT_L1("Failed to save LNS backup owner to DB tx: " << tx_hash << ", type: " << entry.type << ", name_hash: " << entry.name_hash << ", owner: " << entry.owner);
      return false;
    }
  }

  if (!lns_db.save_mapping(tx_hash, entry, height, owner_id, backup_owner_id))
  {
    LOG_PRINT_L1("Failed to save LNS entry to DB tx: " << tx_hash << ", type: " << entry.type << ", name_hash: " << entry.name_hash << ", owner: " << entry.owner);
    return false;
  }

  return true;
}

bool name_system_db::add_block(const cryptonote::block &block, const std::vector<cryptonote::transaction> &txs)
{
  uint64_t height = cryptonote::get_block_height(block);
  if (last_processed_height >= height)
      return true;

  scoped_db_transaction db_transaction(*this);
  if (!db_transaction)
   return false;

  if (block.major_version >= cryptonote::network_version_15_lns)
  {
    for (cryptonote::transaction const &tx : txs)
    {
      if (tx.type != cryptonote::txtype::loki_name_system)
        continue;

      cryptonote::tx_extra_loki_name_system entry = {};
      std::string fail_reason;
      if (!validate_lns_tx(block.major_version, height, tx, &entry, &fail_reason))
      {
        LOG_PRINT_L0("LNS TX: Failed to validate for tx=" << get_transaction_hash(tx) << ". This should have failed validation earlier reason=" << fail_reason);
        assert("Failed to validate acquire name service. Should already have failed validation prior" == nullptr);
        return false;
      }

      crypto::hash const &tx_hash = cryptonote::get_transaction_hash(tx);
      if (!add_lns_entry(*this, height, entry, tx_hash))
        return false;
    }
  }

  last_processed_height = height;
  save_settings(height, cryptonote::get_block_hash(block), static_cast<int>(DB_VERSION));
  db_transaction.commit = true;
  return true;
}

static bool get_txid_lns_entry(cryptonote::Blockchain const &blockchain, crypto::hash txid, cryptonote::tx_extra_loki_name_system &extra)
{
  std::vector<cryptonote::transaction> txs;
  std::vector<crypto::hash> missed_txs;
  if (!blockchain.get_transactions({txid}, txs, missed_txs) || txs.empty())
    return false;

  return cryptonote::get_loki_name_system_from_tx_extra(txs[0].extra, extra);
}

static bool find_closest_valid_lns_tx_extra_in_blockchain(cryptonote::Blockchain const &blockchain,
                                                          lns::mapping_record const &mapping,
                                                          uint64_t blockchain_height,
                                                          cryptonote::tx_extra_loki_name_system &extra,
                                                          crypto::hash &tx_hash,
                                                          uint64_t &extra_height)
{
  uint64_t prev_height                             = static_cast<uint64_t>(-1);
  crypto::hash prev_txid                           = mapping.prev_txid;
  cryptonote::tx_extra_loki_name_system prev_entry = {};
  if (!get_txid_lns_entry(blockchain, prev_txid, prev_entry)) return false;

  for (;;)
  {
    std::vector<uint64_t> prev_heights = blockchain.get_transactions_heights({prev_txid});
    if (prev_heights.empty())
    {
        MERROR("Unexpected error querying TXID=" << prev_txid << ", height from DB for LNS");
      return false;
    }

    prev_height = prev_heights[0];
    if (prev_height >= blockchain_height)
    {
      // Previous owner of mapping is after the detach height, iterate back to
      // next prev entry by getting the relevant transaction, extract the LNS
      // extra and continue searching.
      if (!get_txid_lns_entry(blockchain, prev_txid, prev_entry))
          return false;
      prev_txid = prev_entry.prev_txid;
    }
    else
    {
      break;
    }
  }

  bool result = prev_height < blockchain_height && prev_txid != crypto::null_hash;
  if (result)
  {
    tx_hash      = prev_txid;
    extra        = std::move(prev_entry);
    extra_height = prev_height;
  }
  return result;
}

void name_system_db::block_detach(cryptonote::Blockchain const &blockchain, uint64_t new_blockchain_height)
{
  std::vector<mapping_record> new_mappings = {};
  {
    sqlite3_stmt *statement = get_mappings_on_height_and_newer_sql;
    sqlite3_clear_bindings(statement);
    sqlite3_bind_int(statement, 1 /*sql param index*/, new_blockchain_height);
    sql_run_statement(nettype, lns_sql_type::get_mappings_on_height_and_newer, statement, &new_mappings);
  }

  struct lns_parts
  {
    uint64_t                              height;
    crypto::hash                          tx_hash;
    cryptonote::tx_extra_loki_name_system entry;
  };

  std::vector<lns_parts> entries;
  for (auto const &mapping : new_mappings)
  {
    cryptonote::tx_extra_loki_name_system entry = {};
    uint64_t entry_height                       = 0;
    crypto::hash tx_hash                        = {};
    if (!find_closest_valid_lns_tx_extra_in_blockchain(blockchain, mapping, new_blockchain_height, entry, tx_hash, entry_height)) continue;
    entries.push_back({entry_height, tx_hash, entry});
  }

  prune_db(new_blockchain_height);
  for (auto const &lns : entries)
  {
    if (!add_lns_entry(*this, lns.height, lns.entry, lns.tx_hash))
      MERROR("Unexpected failure to add historical LNS into the DB on reorganization from tx=" << lns.tx_hash);
  }

}

bool name_system_db::save_owner(crypto::generic_public_key const &key, int64_t *row_id)
{
  sqlite3_stmt *statement = save_owner_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_blob(statement, 1 /*sql param index*/, &key, sizeof(key), nullptr /*destructor*/);
  bool result = sql_run_statement(nettype, lns_sql_type::save_owner, statement, nullptr);
  if (row_id) *row_id = sqlite3_last_insert_rowid(db);
  return result;
}

bool name_system_db::save_mapping(crypto::hash const &tx_hash, cryptonote::tx_extra_loki_name_system const &src, uint64_t height, int64_t owner_id, int64_t backup_owner_id)
{
  std::string name_hash   = hash_to_base64(src.name_hash);
  sqlite3_stmt *statement = save_mapping_sql;
  sqlite3_bind_int  (statement, static_cast<int>(mapping_record_row::type), static_cast<uint16_t>(src.type));
  sqlite3_bind_text (statement, static_cast<int>(mapping_record_row::name_hash), name_hash.data(), name_hash.size(), nullptr /*destructor*/);
  sqlite3_bind_blob (statement, static_cast<int>(mapping_record_row::encrypted_value), src.encrypted_value.data(), src.encrypted_value.size(), nullptr /*destructor*/);
  sqlite3_bind_blob (statement, static_cast<int>(mapping_record_row::txid), tx_hash.data, sizeof(tx_hash), nullptr /*destructor*/);
  sqlite3_bind_blob (statement, static_cast<int>(mapping_record_row::prev_txid), src.prev_txid.data, sizeof(src.prev_txid), nullptr /*destructor*/);
  sqlite3_bind_int64(statement, static_cast<int>(mapping_record_row::register_height), static_cast<int64_t>(height));
  sqlite3_bind_int64(statement, static_cast<int>(mapping_record_row::owner_id), owner_id);
  if (backup_owner_id != 0)
  {
    sqlite3_bind_int64(statement, static_cast<int>(mapping_record_row::backup_owner_id), backup_owner_id);
  }
  bool result = sql_run_statement(nettype, lns_sql_type::save_mapping, statement, nullptr);
  return result;
}

bool name_system_db::save_settings(uint64_t top_height, crypto::hash const &top_hash, int version)
{
  sqlite3_stmt *statement = save_settings_sql;
  sqlite3_bind_int64(statement, static_cast<int>(lns_db_setting_row::top_height), top_height);
  sqlite3_bind_blob (statement, static_cast<int>(lns_db_setting_row::top_hash),   top_hash.data, sizeof(top_hash), nullptr /*destructor*/);
  sqlite3_bind_int  (statement, static_cast<int>(lns_db_setting_row::version),    version);
  bool result = sql_run_statement(nettype, lns_sql_type::save_setting, statement, nullptr);
  return result;
}

bool name_system_db::prune_db(uint64_t height)
{
  {
    sqlite3_stmt *statement = prune_mappings_sql;
    sqlite3_bind_int64(statement, 1 /*sql param index*/, height);
    if (!sql_run_statement(nettype, lns_sql_type::pruning, statement, nullptr)) return false;
  }

  {
    sqlite3_stmt *statement = prune_owners_sql;
    if (!sql_run_statement(nettype, lns_sql_type::pruning, statement, nullptr)) return false;
  }

  return true;
}

owner_record name_system_db::get_owner_by_key(crypto::generic_public_key const &key) const
{
  sqlite3_stmt *statement = get_owner_by_key_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_blob(statement, 1 /*sql param index*/, &key, sizeof(key), nullptr /*destructor*/);

  owner_record result = {};
  result.loaded      = sql_run_statement(nettype, lns_sql_type::get_owner, statement, &result);
  return result;
}

owner_record name_system_db::get_owner_by_id(int64_t owner_id) const
{
  sqlite3_stmt *statement = get_owner_by_id_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_int(statement, 1 /*sql param index*/, owner_id);

  owner_record result = {};
  result.loaded      = sql_run_statement(nettype, lns_sql_type::get_owner, statement, &result);
  return result;
}

mapping_record name_system_db::get_mapping(mapping_type type, std::string const &name_base64_hash) const
{
  sqlite3_stmt *statement = get_mapping_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_int(statement, 1 /*sql param index*/, static_cast<uint16_t>(type));
  sqlite3_bind_text(statement, 2 /*sql param index*/, name_base64_hash.data(), name_base64_hash.size(), nullptr /*destructor*/);

  mapping_record result = {};
  result.loaded         = sql_run_statement(nettype, lns_sql_type::get_mapping, statement, &result);
  return result;
}

std::vector<mapping_record> name_system_db::get_mappings(std::vector<uint16_t> const &types, std::string const &name_base64_hash) const
{
  std::string sql_statement;
  // Generate string statement

  if (types.size())
  {
     std::string const sql1 = sql_cmd_combine_mappings_and_owner_table(R"(WHERE "name" = ')");
     char constexpr SQL2[]  = R"(' AND "type" in ()";
     char constexpr SQL3[]  = R"())";

     std::stringstream stream;
     stream << sql1 << name_base64_hash;
     stream.write(SQL2, loki::char_count(SQL2));

     for (size_t i = 0; i < types.size(); i++)
     {
       stream << types[i];
       if (i < (types.size() - 1)) stream << ", ";
    }

    stream.write(SQL3, loki::char_count(SQL3));
    sql_statement = stream.str();
  }
  else
  {
    sql_statement = R"(SELECT * FROM "mappings" JOIN "owner" ON "mappings"."owner_id" = "owner"."id" WHERE "name" = ?)";
  }

  // Compile Statement
  std::vector<mapping_record> result;
  sqlite3_stmt *statement = nullptr;
  if (!sql_compile_statement(db, sql_statement.c_str(), sql_statement.size(), &statement, false /*optimise_for_multiple_usage*/))
    return result;

  // Execute
  sql_run_statement(nettype, lns_sql_type::get_mappings, statement, &result);
  return result;
}

std::vector<mapping_record> name_system_db::get_mappings_by_owners(std::vector<crypto::generic_public_key> const &keys) const
{
  std::string sql_statement;
  // Generate string statement
  {
    std::string const sql_prefix_str = sql_cmd_combine_mappings_and_owner_table(R"(WHERE "o1"."public_key" in ()");
    char constexpr SQL_MIDDLE[]  = R"(OR "o2"."public_key" in ()";
    char constexpr SQL_SUFFIX[]  = R"())";

    std::stringstream stream;
    stream << sql_prefix_str;
    for (size_t i = 0; i < keys.size(); i++)
    {
      stream << "?";
      if (i < (keys.size() - 1)) stream << ", ";
    }
    stream << SQL_SUFFIX;

    stream << SQL_MIDDLE;
    for (size_t i = 0; i < keys.size(); i++)
    {
      stream << "?";
      if (i < (keys.size() - 1)) stream << ", ";
    }
    stream << SQL_SUFFIX;
    sql_statement = stream.str();
  }

  // Compile Statement
  std::vector<mapping_record> result;
  sqlite3_stmt *statement = nullptr;
  if (!sql_compile_statement(db, sql_statement.c_str(), sql_statement.size(), &statement, false /*optimise_for_multiple_usage*/))
    return result;

  // Bind parameters statements
  int sql_param_index = 1;
  for (size_t i = 0; i < keys.size(); i++)
    for (auto const &key : keys)
      sqlite3_bind_blob(statement, sql_param_index++, key.data, sizeof(key), nullptr /*destructor*/);

  // Execute
  sql_run_statement(nettype, lns_sql_type::get_mappings_by_owners, statement, &result);
  return result;
}

std::vector<mapping_record> name_system_db::get_mappings_by_owner(crypto::generic_public_key const &key) const
{
  std::vector<mapping_record> result = {};
  sqlite3_stmt *statement = get_mappings_by_owner_sql;
  sqlite3_clear_bindings(statement);
  sqlite3_bind_blob(statement, 1 /*sql param index*/, key.data, sizeof(key), nullptr /*destructor*/);
  sqlite3_bind_blob(statement, 2 /*sql param index*/, key.data, sizeof(key), nullptr /*destructor*/);
  sql_run_statement(nettype, lns_sql_type::get_mappings_by_owner, statement, &result);
  return result;
}

settings_record name_system_db::get_settings() const
{
  sqlite3_stmt *statement = get_settings_sql;
  settings_record result  = {};
  result.loaded           = sql_run_statement(nettype, lns_sql_type::get_setting, statement, &result);
  return result;
}
}; // namespace service_nodes

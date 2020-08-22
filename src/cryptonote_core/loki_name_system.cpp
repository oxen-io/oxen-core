#include <bitset>
#include "common/hex.h"
#include "loki_name_system.h"

#include "common/loki.h"
#include "common/string_util.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/blockchain.h"
#include "loki_economy.h"

#include <lokimq/hex.h>
#include <lokimq/base32z.h>
#include <lokimq/base64.h>

#include <sqlite3.h>

extern "C"
{
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_sign.h>
}

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "lns"

namespace lns
{

using namespace std::literals;

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

  internal_cmd,
};

enum struct lns_db_setting_column
{
  id,
  top_height,
  top_hash,
  version,
};

enum struct owner_record_column
{
  id,
  address,
};

enum struct mapping_record_column
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
  update_height,
  _count,
};

static char const *mapping_record_column_string(mapping_record_column col)
{
  switch (col)
  {
    case mapping_record_column::id: return "id";
    case mapping_record_column::type: return "type";
    case mapping_record_column::name_hash: return "name_hash";
    case mapping_record_column::encrypted_value: return "encrypted_value";
    case mapping_record_column::txid: return "txid";
    case mapping_record_column::prev_txid: return "prev_txid";
    case mapping_record_column::register_height: return "register_height";
    case mapping_record_column::update_height: return "update_height";
    case mapping_record_column::owner_id: return "owner_id";
    case mapping_record_column::backup_owner_id: return "backup_owner_id";
    default: return "xx_invalid";
  }
}

std::string lns::mapping_value::to_readable_value(cryptonote::network_type nettype, lns::mapping_type type) const
{
  std::string result;
  if (is_lokinet_type(type))
  {
    result = lokimq::to_base32z(to_view());
  }
  else if (type == lns::mapping_type::wallet)
  {
    cryptonote::address_parse_info addr_info = {};
    if (len == sizeof(addr_info))
    {
      memcpy(&addr_info, buffer.data(), len);
      result = cryptonote::get_account_address_as_str(nettype, addr_info.is_subaddress, addr_info.address);
    }
    else
      result = "(error unknown wallet address)";
  }
  else
  {
    result = lokimq::to_hex(to_view());
  }

  return result;
}

namespace {

std::string lns_extra_string(cryptonote::network_type nettype, cryptonote::tx_extra_loki_name_system const &data)
{
  std::stringstream stream;
  stream << "LNS Extra={";
  if (data.is_buying())
  {
    stream << "owner=" << data.owner.to_string(nettype);
    stream << ", backup_owner=" << (data.backup_owner ? data.backup_owner.to_string(nettype) : "(none)");
  }
  else
    stream << "signature=" << tools::type_to_hex(data.signature.data);

  stream << ", type=" << data.type << ", name_hash=" << data.name_hash << "}";
  return stream.str();
}

/// Clears any existing bindings
bool clear_bindings(sql_compiled_statement& s) {
  return SQLITE_OK == sqlite3_clear_bindings(s.statement);
}

/// Resets
bool reset(sql_compiled_statement& s) {
  return SQLITE_OK == sqlite3_reset(s.statement);
}

int step(sql_compiled_statement& s)
{
  return sqlite3_step(s.statement);
}


/// `bind()` binds a particular parameter to a statement by index.  The bind type is inferred from
/// the argument.

// Small (<=32 bits) integers
template <typename T, std::enable_if_t<std::is_integral<T>::value && (sizeof(T) <= 32), int> = 0>
bool bind(sql_compiled_statement& s, int index, const T& val) { return SQLITE_OK == sqlite3_bind_int(s.statement, index, val); }

// Big (>32 bits) integers
template <typename T, std::enable_if_t<std::is_integral<T>::value && (sizeof(T) > 32), int> = 0>
bool bind(sql_compiled_statement& s, int index, const T& val) { return SQLITE_OK == sqlite3_bind_int64(s.statement, index, val); }

// Floats/doubles
template <typename T, std::enable_if_t<std::is_floating_point<T>::value, int> = 0>
bool bind(sql_compiled_statement& s, int index, const T& val) { return SQLITE_OK == sqlite3_bind_double(s.statement, index, val); }

// Binds null
bool bind(sql_compiled_statement& s, int index, std::nullptr_t) { return SQLITE_OK == sqlite3_bind_null(s.statement, index); }

// text, from a referenced string (which must be kept alive)
bool bind(sql_compiled_statement& s, int index, std::string_view text)
{
  return SQLITE_OK == sqlite3_bind_text(s.statement, index, text.data(), text.size(), nullptr /*dtor*/);
}

/* Currently unused; comment out until needed to avoid a compiler warning
// text, from a temporary std::string; ownership of the string data is transferred to sqlite3
bool bind(sql_compiled_statement& s, int index, std::string&& text)
{
  // Assume ownership and let sqlite3 destroy when finished
  auto local_text = new std::string{std::move(text)};
  if (SQLITE_OK == sqlite3_bind_text(s.statement, index, local_text->data(), local_text->size(),
      [](void* local) { delete reinterpret_cast<std::string*>(local); }))
    return true;
  delete local_text;
  return false;
}
*/

template <typename T, typename SFINAE = void>
struct is_int_enum : std::false_type {};
template <typename T>
struct is_int_enum<T, std::enable_if_t<std::is_enum<T>::value>>
: std::integral_constant<bool, std::is_same<std::underlying_type_t<T>, int>::value> {};

// Binds, but gives index as an enum class
template <typename T, typename I, std::enable_if_t<is_int_enum<I>::value, int> = 0>
bool bind(sql_compiled_statement& s, I index, T&& val)
{
  return lns::bind(s, static_cast<int>(index), std::forward<T>(val));
}

// Blob binding; these have a different name so as to not conflict with text binding.
//
// from a referenced pointer and length (NOTE THE _blob SUFFIX IN THE NAME)
bool bind_blob(sql_compiled_statement& s, int index, const void* data, size_t len)
{
  return SQLITE_OK == sqlite3_bind_blob(s.statement, index, data, len, nullptr /*dtor*/);
}

// from a string_view
bool bind_blob(sql_compiled_statement& s, int index, std::string_view blob)
{
  return SQLITE_OK == sqlite3_bind_blob(s.statement, index, blob.data(), blob.size(), nullptr /*dtor*/);
}

/* Currently unused; comment out until needed to avoid a compiler warning
// From a std::string rvalue; sqlite3 manages ownership
bool bind_blob(sql_compiled_statement& s, int index, std::string&& blob)
{
  // Assume ownership and let sqlite3 destroy when finished
  auto local_blob = new std::string{std::move(blob)};
  if (SQLITE_OK == sqlite3_bind_blob(s.statement, index, local_blob->data(), local_blob->size(),
      [](void* local) { delete reinterpret_cast<std::string*>(local); }))
    return true;
  delete local_blob;
  return false;
}
*/

// Wrapper for bind_blob with an enum index
template <typename... T, typename I, std::enable_if_t<is_int_enum<I>::value, int> = 0>
bool bind_blob(sql_compiled_statement& s, I index, T&&... args)
{
  return bind_blob(s, static_cast<int>(index), std::forward<T>(args)...);
}

// Simple wrapper around a string_view so that you can pass a blob into `bind_all` by wrapping it
// with a `blob_view` such as:
//
// bind_all(s, 123, "text", blob_view{data, size});
//
struct blob_view {
  std::string_view data;
  /// Constructor that simply forwards anything to the `data` member constructor
  template <typename... T> explicit blob_view(T&&... args) : data{std::forward<T>(args)...} {}
};
template <typename I>
bool bind(sql_compiled_statement& s, I index, blob_view blob) {
  return bind_blob(s, index, blob.data);
}

template <int... I, typename... T>
bool bind_all_impl(sql_compiled_statement& s, std::integer_sequence<int, I...>, T&&... args) {
  clear_bindings(s);
  for (bool r : {lns::bind(s, I+1, std::forward<T>(args))...})
    if (!r)
      return false;
  return true;
}

// Full statement binding; this lets you do something like:
//
// bind_all(st, 1, "hi", 123);
//
// which is equivalent to:
//
// clear_bindings(st);
// st.bind(st, 1, 1);
// st.bind(st, 2, "hi");
// st.bind(st, 3, 123);
//
// (Binding of blobs through this interface is not supported).
template <typename... T>
bool bind_all(sql_compiled_statement& s, T&&... args)
{
  return bind_all_impl(s, std::make_integer_sequence<int, sizeof...(T)>{}, std::forward<T>(args)...);
}


/// Retrieve a type from an executed statement.

// Small (<=32 bits) integers
template <typename T, std::enable_if_t<std::is_integral<T>::value && (sizeof(T) <= 32), int> = 0>
T get(sql_compiled_statement& s, int index) { return static_cast<T>(sqlite3_column_int(s.statement, index)); }

// Big (>32 bits) integers
template <typename T, std::enable_if_t<std::is_integral<T>::value && (sizeof(T) > 32), int> = 0>
T get(sql_compiled_statement& s, int index) { return static_cast<T>(sqlite3_column_int64(s.statement, index)); }

// Floats/doubles
template <typename T, std::enable_if_t<std::is_floating_point<T>::value, int> = 0>
T get(sql_compiled_statement& s, int index) { return static_cast<T>(sqlite3_column_double(s.statement, index)); }

// text, via a string_view pointing at the text data
template <typename T, std::enable_if_t<std::is_same<T, std::string_view>::value, int> = 0>
std::string_view get(sql_compiled_statement& s, int index)
{
  return {reinterpret_cast<const char*>(sqlite3_column_text(s.statement, index)),
          static_cast<size_t>(sqlite3_column_bytes(s.statement, index))};
}

// text, copied into a std::string
template <typename T, std::enable_if_t<std::is_same<T, std::string>::value, int> = 0>
std::string get(sql_compiled_statement& s, int index)
{
  return {reinterpret_cast<const char*>(sqlite3_column_text(s.statement, index)),
          static_cast<size_t>(sqlite3_column_bytes(s.statement, index))};
}

// Forwards to any of the above, but takes an enum class instead of an int
template <typename T, typename I, std::enable_if_t<is_int_enum<I>::value, int> = 0>
T get(sql_compiled_statement& s, I index)
{
  return get<T>(s, static_cast<int>(index));
}

// Wrapper around get that assigns to the given reference.
//     get(st, 3, myvar);
// is equivalent to:
//     myvar = get<decltype(myvar)>(st, 3)
template <typename T, typename I>
void get(sql_compiled_statement& s, I index, T& val) { val = get<T>(s, index); }

// blob, via a string_view
std::string_view get_blob(sql_compiled_statement& s, int index)
{
  return {reinterpret_cast<const char*>(sqlite3_column_blob(s.statement, index)),
          static_cast<size_t>(sqlite3_column_bytes(s.statement, index))};
}

// blob, via a string_view
template <typename I, std::enable_if_t<is_int_enum<I>::value, int> = 0>
std::string_view get_blob(sql_compiled_statement& s, I index)
{
  return get_blob(s, static_cast<int>(index));
}

template <typename I>
bool sql_copy_blob(sql_compiled_statement& statement, I column, void *dest, size_t dest_size)
{
  auto blob = get_blob(statement, column);
  if (blob.size() != dest_size)
  {
    LOG_PRINT_L0("Unexpected blob size=" << blob.size() << ", in LNS DB does not match expected size=" << dest_size);
    assert(blob.size() == dest_size);
    return false;
  }

  memcpy(dest, blob.data(), blob.size());
  return true;
}

mapping_record sql_get_mapping_from_statement(sql_compiled_statement& statement)
{
  mapping_record result = {};
  auto type_int = get<uint16_t>(statement, mapping_record_column::type);
  if (type_int >= tools::enum_count<mapping_type>)
    return result;

  result.type = static_cast<mapping_type>(type_int);
  get(statement, mapping_record_column::id, result.id);
  get(statement, mapping_record_column::register_height, result.register_height);
  get(statement, mapping_record_column::update_height, result.update_height);
  get(statement, mapping_record_column::owner_id, result.owner_id);
  get(statement, mapping_record_column::backup_owner_id, result.backup_owner_id);

  // Copy encrypted_value
  {
    auto value = get<std::string_view>(statement, mapping_record_column::encrypted_value);
    if (value.size() > result.encrypted_value.buffer.size())
    {
      MERROR("Unexpected encrypted value blob with size=" << value.size() << ", in LNS db larger than the available size=" << result.encrypted_value.buffer.size());
      return result;
    }
    result.encrypted_value.len = value.size();
    memcpy(&result.encrypted_value.buffer[0], value.data(), value.size());
  }

  // Copy name hash
  {
    auto value = get<std::string_view>(statement, mapping_record_column::name_hash);
    result.name_hash.append(value.data(), value.size());
  }

  if (!sql_copy_blob(statement, mapping_record_column::txid, result.txid.data, sizeof(result.txid)))
    return result;

  if (!sql_copy_blob(statement, mapping_record_column::prev_txid, result.prev_txid.data, sizeof(result.prev_txid)))
    return result;

  int owner_column = tools::enum_count<mapping_record_column>;
  if (!sql_copy_blob(statement, owner_column, reinterpret_cast<void *>(&result.owner), sizeof(result.owner)))
    return result;

  if (result.backup_owner_id > 0)
  {
    if (!sql_copy_blob(statement, owner_column + 1, reinterpret_cast<void *>(&result.backup_owner), sizeof(result.backup_owner)))
      return result;
  }

  result.loaded = true;
  return result;
}

bool sql_run_statement(lns_sql_type type, sql_compiled_statement& statement, void *context)
{
  assert(statement);
  bool data_loaded = false;
  bool result      = false;

  for (bool infinite_loop = true; infinite_loop;)
  {
    int step_result = step(statement);
    switch (step_result)
    {
      case SQLITE_ROW:
      {
        switch (type)
        {
          default: MERROR("Unhandled lns type enum with value: " << (int)type << ", in: " << __func__); break;

          case lns_sql_type::internal_cmd: break;
          case lns_sql_type::get_owner:
          {
            auto *entry = reinterpret_cast<owner_record *>(context);
            get(statement, owner_record_column::id, entry->id);
            if (!sql_copy_blob(statement, owner_record_column::address, reinterpret_cast<void *>(&entry->address), sizeof(entry->address)))
              return false;
            data_loaded = true;
          }
          break;

          case lns_sql_type::get_setting:
          {
            auto *entry       = reinterpret_cast<settings_record *>(context);
            get(statement, lns_db_setting_column::top_height, entry->top_height);
            if (!sql_copy_blob(statement, lns_db_setting_column::top_hash, entry->top_hash.data, sizeof(entry->top_hash.data)))
              return false;
            get(statement, lns_db_setting_column::version, entry->version);
            data_loaded = true;
          }
          break;

          case lns_sql_type::get_mappings_on_height_and_newer: /* FALLTHRU */
          case lns_sql_type::get_mappings_by_owners: /* FALLTHRU */
          case lns_sql_type::get_mappings_by_owner: /* FALLTHRU */
          case lns_sql_type::get_mappings: /* FALLTHRU */
          case lns_sql_type::get_mapping:
          {
            if (mapping_record tmp_entry = sql_get_mapping_from_statement(statement))
            {
              data_loaded = true;
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
        LOG_PRINT_L1("Failed to execute statement: " << sqlite3_sql(statement.statement) <<", reason: " << sqlite3_errstr(step_result));
        infinite_loop = false;
        break;
      }
    }
  }

  reset(statement);
  clear_bindings(statement);
  return result;
}

/// Does a clear_bindings, bind_all, and then sql_run_statement.  First three arguments go to
/// sql_run_statement, the rest go to bind_all(statement, ...) (which does the clear_bindings).
template <typename... T>
bool bind_and_run(lns_sql_type type, sql_compiled_statement& statement, void *context,
    T&&... bind_args)
{
  bind_all(statement, std::forward<T>(bind_args)...);
  return sql_run_statement(type, statement, context);
}


} // end anonymous namespace


bool mapping_record::active(cryptonote::network_type nettype, uint64_t blockchain_height) const
{
  if (!loaded) return false;
  uint64_t expiry_blocks = lns::expiry_blocks(nettype, static_cast<lns::mapping_type>(type));
  uint64_t const last_active_height = expiry_blocks == NO_EXPIRY ? NO_EXPIRY : (register_height + expiry_blocks);
  return last_active_height >= (blockchain_height - 1);
}

bool sql_compiled_statement::compile(std::string_view query, bool optimise_for_multiple_usage)
{
  sqlite3_stmt* st;
#if SQLITE_VERSION_NUMBER >= 3020000
  int prepare_result = sqlite3_prepare_v3(nsdb.db, query.data(), query.size(), optimise_for_multiple_usage ? SQLITE_PREPARE_PERSISTENT : 0, &st, nullptr /*pzTail*/);
#else
  int prepare_result = sqlite3_prepare_v2(nsdb.db, query.data(), query.size(), &st, nullptr /*pzTail*/);
#endif

  if (prepare_result != SQLITE_OK) {
    MERROR("Can not compile SQL statement:\n" << query << "\nReason: " << sqlite3_errstr(prepare_result));
    return false;
  }
  sqlite3_finalize(statement);
  statement = st;
  return true;
}

sql_compiled_statement& sql_compiled_statement::operator=(sql_compiled_statement&& from)
{
  sqlite3_finalize(statement);
  statement = from.statement;
  from.statement = nullptr;
  return *this;
}

sql_compiled_statement::~sql_compiled_statement()
{
  sqlite3_finalize(statement);
}

sqlite3 *init_loki_name_system(char const *file_path, bool read_only)
{
  sqlite3 *result = nullptr;
  int sql_init    = sqlite3_initialize();
  if (sql_init != SQLITE_OK)
  {
    MERROR("Failed to initialize sqlite3: " << sqlite3_errstr(sql_init));
    return nullptr;
  }

  int const flags = read_only ? SQLITE_OPEN_READONLY : SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE;
  int sql_open    = sqlite3_open_v2(file_path, &result, flags, nullptr);
  if (sql_open != SQLITE_OK)
  {
    MERROR("Failed to open LNS db at: " << file_path << ", reason: " << sqlite3_errstr(sql_open));
    return nullptr;
  }

  /*
    (DB) Changes are appended into a separate WAL (Write Ahead Logging) file.
    A COMMIT occurs when a special record indicating a commit is appended to
    the WAL. Thus a COMMIT can happen without ever writing to the original
    database, which allows readers to continue operating from the original
    unaltered database while changes are simultaneously being committed into the
    WAL. Multiple transactions can be appended to the end of a single WAL file.
  */
  int exec = sqlite3_exec(result, "PRAGMA journal_mode = WAL", nullptr, nullptr, nullptr);
  if (exec != SQLITE_OK)
  {
    MERROR("Failed to set journal mode to WAL: " << sqlite3_errstr(exec));
    return nullptr;
  }

  /*
    In WAL mode when synchronous is NORMAL (1), the WAL file is synchronized
    before each checkpoint and the database file is synchronized after each
    completed checkpoint and the WAL file header is synchronized when a WAL file
    begins to be reused after a checkpoint, but no sync operations occur during
    most transactions.
  */
  exec = sqlite3_exec(result, "PRAGMA synchronous = NORMAL", nullptr, nullptr, nullptr);
  if (exec != SQLITE_OK)
  {
    MERROR("Failed to set synchronous mode to NORMAL: " << sqlite3_errstr(exec));
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

static uint8_t *memcpy_helper(uint8_t *dest, void const *src, size_t size)
{
  memcpy(reinterpret_cast<uint8_t *>(dest), src, size);
  return dest + size;
}

static uint8_t *memcpy_generic_owner_helper(uint8_t *dest, lns::generic_owner const *owner)
{
  if (!owner) return dest;

  uint8_t *result = memcpy_helper(dest, reinterpret_cast<uint8_t const *>(&owner->type), sizeof(owner->type));
  void const *src = &owner->wallet.address;
  size_t src_len  = sizeof(owner->wallet.address);
  if (owner->type == lns::generic_owner_sig_type::ed25519)
  {
    src     = &owner->ed25519;
    src_len = sizeof(owner->ed25519);
  }

  result = memcpy_helper(result, src, src_len);
  return result;
}

crypto::hash tx_extra_signature_hash(std::string_view value, lns::generic_owner const *owner, lns::generic_owner const *backup_owner, crypto::hash const &prev_txid)
{
  static_assert(sizeof(crypto::hash) == crypto_generichash_BYTES, "Using libsodium generichash for signature hash, require we fit into crypto::hash");
  crypto::hash result = {};
  if (value.size() > mapping_value::BUFFER_SIZE)
  {
    MERROR("Unexpected value len=" << value.size() << " greater than the expected capacity=" << mapping_value::BUFFER_SIZE);
    return result;
  }

  uint8_t buffer[mapping_value::BUFFER_SIZE + sizeof(*owner) + sizeof(*backup_owner) + sizeof(prev_txid)] = {};
  uint8_t *ptr = memcpy_helper(buffer, value.data(), value.size());
  ptr          = memcpy_generic_owner_helper(ptr, owner);
  ptr          = memcpy_generic_owner_helper(ptr, backup_owner);
  ptr          = memcpy_helper(ptr, prev_txid.data, sizeof(prev_txid));

  if (ptr > (buffer + sizeof(buffer)))
  {
    assert(ptr < buffer + sizeof(buffer));
    MERROR("Unexpected buffer overflow");
    return {};
  }

  size_t buffer_len  = ptr - buffer;
  static_assert(sizeof(owner->type) == sizeof(char), "Require byte alignment to avoid unaligned access exceptions");

  crypto_generichash(reinterpret_cast<unsigned char *>(result.data), sizeof(result), buffer, buffer_len, NULL /*key*/, 0 /*key_len*/);
  return result;
}

lns::generic_signature make_monero_signature(crypto::hash const &hash, crypto::public_key const &pkey, crypto::secret_key const &skey)
{
  lns::generic_signature result = {};
  result.type                   = lns::generic_owner_sig_type::monero;
  generate_signature(hash, pkey, skey, result.monero);
  return result;
}

lns::generic_signature make_ed25519_signature(crypto::hash const &hash, crypto::ed25519_secret_key const &skey)
{
  lns::generic_signature result = {};
  result.type                   = lns::generic_owner_sig_type::ed25519;
  crypto_sign_detached(result.ed25519.data, NULL, reinterpret_cast<unsigned char const *>(hash.data), sizeof(hash), skey.data);
  return result;
}

lns::generic_owner make_monero_owner(cryptonote::account_public_address const &owner, bool is_subaddress)
{
  lns::generic_owner result   = {};
  result.type                 = lns::generic_owner_sig_type::monero;
  result.wallet.address       = owner;
  result.wallet.is_subaddress = is_subaddress;
  return result;
}

lns::generic_owner make_ed25519_owner(crypto::ed25519_public_key const &pkey)
{
  lns::generic_owner result = {};
  result.type               = lns::generic_owner_sig_type::ed25519;
  result.ed25519            = pkey;
  return result;
}

bool parse_owner_to_generic_owner(cryptonote::network_type nettype, std::string const &owner, generic_owner &result, std::string *reason)
{
  cryptonote::address_parse_info parsed_addr;
  crypto::ed25519_public_key ed_owner;
  if (cryptonote::get_account_address_from_str(parsed_addr, nettype, owner))
  {
    result = lns::make_monero_owner(parsed_addr.address, parsed_addr.is_subaddress);
  }
  else if (owner.size() == 2*sizeof(ed_owner.data) && lokimq::is_hex(owner))
  {
    lokimq::from_hex(owner.begin(), owner.end(), ed_owner.data);
    result = lns::make_ed25519_owner(ed_owner);
  }
  else
  {
    if (reason)
    {
      char const *type_heuristic = (owner.size() == sizeof(crypto::ed25519_public_key) * 2) ? "ED25519 Key" : "Wallet address";
      *reason = type_heuristic;
      *reason += " provided could not be parsed owner=";
      *reason += owner;
    }
    return false;
  }
  return true;
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

template <typename... T>
static bool check_condition(bool condition, std::string* reason, T&&... args) {
  if (condition && reason)
  {
    std::ostringstream os;
    (os << ... << std::forward<T>(args));
    *reason = os.str();
  }
  return condition;
}

bool validate_lns_name(mapping_type type, std::string name, std::string *reason)
{
  std::stringstream err_stream;
  LOKI_DEFER { if (reason) *reason = err_stream.str(); };

  bool const is_lokinet = is_lokinet_type(type);
  size_t max_name_len   = 0;

  if (is_lokinet)                         max_name_len = lns::LOKINET_DOMAIN_NAME_MAX;
  else if (type == mapping_type::session) max_name_len = lns::SESSION_DISPLAY_NAME_MAX;
  else if (type == mapping_type::wallet)  max_name_len = lns::WALLET_NAME_MAX;
  else
  {
    if (reason) err_stream << "LNS type=" << type << ", specifies unhandled mapping type in name validation";
    return false;
  }

  // NOTE: Validate name length
  name = tools::lowercase_ascii_string(std::move(name));
  if (check_condition((name.empty() || name.size() > max_name_len), reason, "LNS type=", type, ", specifies mapping from name->value where the name's length=", name.size(), " is 0 or exceeds the maximum length=", max_name_len, ", given name=", name))
    return false;

  std::string_view name_view{name}; // Will chop this down as we validate each part

  // NOTE: Validate domain specific requirements
  if (is_lokinet)
  {
    // LOKINET
    // Domain has to start with an alphanumeric, and can have (alphanumeric or hyphens) in between, the character before the suffix <char>'.loki' must be alphanumeric followed by the suffix '.loki'
    // ^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.loki$

    if (check_condition(name == "localhost.loki", reason, "LNS type=", type, ", specifies mapping from name->value using protocol reserved name=", name))
      return false;

    auto constexpr SHORTEST_DOMAIN = "a.loki"sv;
    if (check_condition(name.size() < SHORTEST_DOMAIN.size(), reason, "LNS type=", type, ", specifies mapping from name->value where the name is shorter than the shortest possible name=", SHORTEST_DOMAIN, ", given name=", name))
      return false;

    // Must end with .loki
    auto constexpr SUFFIX = ".loki"sv;
    if (check_condition(!tools::ends_with(name_view, SUFFIX), reason, "LNS type=", type, ", specifies mapping from name->value where the name does not end with the domain .loki, name=", name))
      return false;

    name_view.remove_suffix(SUFFIX.size());

    // Must start with alphanumeric
    if (check_condition(!char_is_alphanum(name_view.front()), reason, "LNS type=", type, ", specifies mapping from name->value where the name does not start with an alphanumeric character, name=", name))
      return false;

    name_view.remove_prefix(1);

    if (!name_view.empty()) {
      // Characted preceding suffix must be alphanumeric
      if (check_condition(!char_is_alphanum(name_view.back()), reason, "LNS type=", type ,", specifies mapping from name->value where the character preceding the .loki is not alphanumeric, char=", name_view.back(), ", name=", name))
        return false;
      name_view.remove_suffix(1);
    }

    // Inbetween start and preceding suffix, (alphanumeric or hyphen) characters permitted
    if (check_condition(!std::all_of(name_view.begin(), name_view.end(), [](char c) { return char_is_alphanum(c) || c == '-'; }),
          reason, "LNS type=", type, ", specifies mapping from name->value where the domain name contains more than the permitted alphanumeric or hyphen characters, name=", name))
      return false;
  }
  else
  {
    // SESSION or WALLET
    // Name has to start with a (alphanumeric or underscore), and can have (alphanumeric, hyphens or underscores) in between and must end with a (alphanumeric or underscore)
    // ^[a-z0-9_]([a-z0-9-_]*[a-z0-9_])?$

    // Must start with (alphanumeric or underscore)
    if (check_condition(!(char_is_alphanum(name_view.front()) || name_view.front() == '_'), reason, "LNS type=", type, ", specifies mapping from name->value where the name does not start with an alphanumeric or underscore character, name=", name))
      return false;
    name_view.remove_prefix(1);

    if (!name_view.empty()) {
      // Must NOT end with a hyphen '-'
      if (check_condition(!(char_is_alphanum(name_view.back()) || name_view.back() == '_'), reason, "LNS type=", type, ", specifies mapping from name->value where the last character is a hyphen '-' which is disallowed, name=", name))
        return false;
      name_view.remove_suffix(1);
    }

    // Inbetween start and preceding suffix, (alphanumeric, hyphen or underscore) characters permitted
    if (check_condition(!std::all_of(name_view.begin(), name_view.end(), [](char c) { return char_is_alphanum(c) || c == '-' || c == '_'; }),
          reason, "LNS type=", type, ", specifies mapping from name->value where the name contains more than the permitted alphanumeric, underscore or hyphen characters, name=", name))
      return false;
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
      if (binary_val) err_stream << lokimq::to_hex(value);
      else            err_stream << value;
      *reason = err_stream.str();
    }
  }

  return result;
}

bool validate_mapping_value(cryptonote::network_type nettype, mapping_type type, std::string const &value, mapping_value *blob, std::string *reason)
{
  if (blob) *blob = {};

  // Check length of the value
  std::stringstream err_stream;
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
      blob->len = sizeof(addr_info);
      memcpy(blob->buffer.data(), &addr_info, blob->len);
    }
  }
  else if (is_lokinet_type(type))
  {
    // We need a 52 char base32z string that decodes to a 32-byte value, which really means we need
    // 51 base32z chars (=255 bits) followed by a 1-bit value ('y'=0, or 'o'=0b10000); anything else
    // in the last spot isn't a valid lokinet address.
    if (check_condition(value.size() != 52 || !lokimq::is_base32z(value) || value.back() != 'y' || value.back() != 'o',
                reason, "The lokinet value=", value, " (length=", value.size(), "), is not a valid base32z-encoded pubkey"))
      return false;

    crypto::ed25519_public_key pkey;
    lokimq::to_hex(value.begin(), value.end(), pkey.data);

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
    if (check_condition((value.size() % 2) != 0, reason, "The value=", value, ", should be a hex string that has an even length to be convertible back into binary, length=", value.size()))
      return false;

    if (check_condition(!lokimq::is_hex(value), reason, ", specifies name -> value mapping where the value is not a hex string given value="))
      return false;

    if (blob) // NOTE: Given blob, write the binary output
    {
      blob->len = value.size() / 2;
      assert(blob->len <= blob->buffer.size());
      lokimq::from_hex(value.begin(), value.end(), blob->buffer.begin());
    }

    // NOTE: Session public keys are 33 bytes, with the first byte being 0x05 and the remaining 32 being the public key.
    if (check_condition(!(value[0] == '0' && value[1] == '5'), reason, "LNS type=session, specifies mapping from name -> ed25519 key where the key is not prefixed with 53 (0x05), prefix=", std::to_string(value[0]), " (", value[0], "), given ed25519=", value))
      return false;
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

static std::string hash_to_base64(crypto::hash const &hash)
{
  return lokimq::to_base64(tools::view_guts(hash));
}

static bool verify_lns_signature(crypto::hash const &hash, lns::generic_signature const &signature, lns::generic_owner const &owner)
{
  if (!owner || !signature) return false;
  if (owner.type != signature.type) return false;
  if (signature.type == lns::generic_owner_sig_type::monero)
  {
    return crypto::check_signature(hash, owner.wallet.address.m_spend_public_key, signature.monero);
  }
  else
  {
    return (crypto_sign_verify_detached(signature.data, reinterpret_cast<unsigned char const *>(hash.data), sizeof(hash.data), owner.ed25519.data) == 0);
  }
}

static bool validate_against_previous_mapping(lns::name_system_db &lns_db, uint64_t blockchain_height, cryptonote::transaction const &tx, cryptonote::tx_extra_loki_name_system const &lns_extra, std::string *reason = nullptr)
{
  std::stringstream err_stream;
  LOKI_DEFER { if (reason && reason->empty()) *reason = err_stream.str(); };

  crypto::hash expected_prev_txid = crypto::null_hash;
  std::string name_hash           = hash_to_base64(lns_extra.name_hash);
  lns::mapping_record mapping     = lns_db.get_mapping(lns_extra.type, name_hash);

  if (check_condition(lns_extra.is_updating() && !mapping, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " update requested but mapping does not exist."))
    return false;

  if (mapping)
  {
    expected_prev_txid = mapping.txid;
    if (lns_extra.is_updating())
    {
      if (check_condition(is_lokinet_type(lns_extra.type) && !mapping.active(lns_db.network_type(), blockchain_height), reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " TX requested to update mapping that has already expired"))
        return false;


      constexpr auto SPECIFYING_SAME_VALUE_ERR = " field to update is specifying the same mapping "sv;
      if (check_condition(lns_extra.field_is_set(lns::extra_field::encrypted_value) && lns_extra.encrypted_value == mapping.encrypted_value.to_view(), reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), SPECIFYING_SAME_VALUE_ERR, "value"))
        return false;

      if (check_condition(lns_extra.field_is_set(lns::extra_field::owner) && lns_extra.owner == mapping.owner, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), SPECIFYING_SAME_VALUE_ERR, "owner"))
        return false;

      if (check_condition(lns_extra.field_is_set(lns::extra_field::backup_owner) && lns_extra.backup_owner == mapping.backup_owner, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), SPECIFYING_SAME_VALUE_ERR, "backup_owner"))
        return false;

      // Validate signature
      {
        crypto::hash hash = tx_extra_signature_hash(lns_extra.encrypted_value,
                                                    lns_extra.field_is_set(lns::extra_field::owner) ? &lns_extra.owner : nullptr,
                                                    lns_extra.field_is_set(lns::extra_field::backup_owner) ? &lns_extra.backup_owner : nullptr,
                                                    expected_prev_txid);
        if (check_condition(!hash, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " unexpectedly failed to generate signature hash, please inform the Loki developers"))
          return false;

        if (check_condition(!verify_lns_signature(hash, lns_extra.signature, mapping.owner) &&
                            !verify_lns_signature(hash, lns_extra.signature, mapping.backup_owner), reason,
                            tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " failed to verify signature for LNS update, current owner=", mapping.owner.to_string(lns_db.network_type()), ", backup owner=", mapping.backup_owner.to_string(lns_db.network_type())))
        {
          return false;
        }
      }
    }
    else
    {
      if (!is_lokinet_type(lns_extra.type))
      {
        if (check_condition(true, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " non-lokinet entries can NOT be renewed, mapping already exists with name_hash=", mapping.name_hash, ", owner=", mapping.owner.to_string(lns_db.network_type()), ", type=", mapping.type))
          return false;
      }

      if (check_condition(!(lns_extra.field_is_set(lns::extra_field::buy) || lns_extra.field_is_set(lns::extra_field::buy_no_backup)), reason,
                          " TX is buying mapping but serialized unexpected fields not relevant for buying"))
      {
        return false;
      }

      uint64_t renew_window              = 0;
      uint64_t expiry_blocks             = lns::expiry_blocks(lns_db.network_type(), lns_extra.type, &renew_window);
      uint64_t const renew_window_offset = expiry_blocks - renew_window;
      uint64_t const min_renew_height    = mapping.register_height + renew_window_offset;

      if (check_condition(min_renew_height >= blockchain_height, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " trying to renew too early, the earliest renew height=", min_renew_height, ", current height=", blockchain_height))
          return false;

      if (mapping.active(lns_db.network_type(), blockchain_height))
      {
        // Lokinet entry expired i.e. it's no longer active. A purchase for this name is valid
        // Check that the request originates from the owner of this mapping
        lns::owner_record const requester = lns_db.get_owner_by_key(lns_extra.owner);
        if (check_condition(requester, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " trying to renew existing mapping but owner specified in LNS extra does not exist, rejected"))
          return false;

        lns::owner_record const owner = lns_db.get_owner_by_id(mapping.owner_id);
        if (check_condition(owner, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " unexpected owner_id=", mapping.owner_id, " does not exist"))
          return false;

        if (check_condition(requester.id != owner.id, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " actual owner=",  mapping.owner.to_string(lns_db.network_type()), ", with owner_id=", mapping.owner_id, ", does not match requester=", requester.address.to_string(lns_db.network_type()), ", with id=", requester.id))
          return false;

      }
      // else mapping has expired, new purchase is valid
    }
  }

  if (check_condition(lns_extra.prev_txid != expected_prev_txid, reason, tx, ", ", lns_extra_string(lns_db.network_type(), lns_extra), " specified prior txid=", lns_extra.prev_txid, ", but LNS DB reports=", expected_prev_txid, ", possible competing TX was submitted and accepted before this TX was processed"))
    return false;

  return true;
}

bool name_system_db::validate_lns_tx(uint8_t hf_version, uint64_t blockchain_height, cryptonote::transaction const &tx, cryptonote::tx_extra_loki_name_system *lns_extra, std::string *reason)
{
  // -----------------------------------------------------------------------------------------------
  // Pull out LNS Extra from TX
  // -----------------------------------------------------------------------------------------------
  cryptonote::tx_extra_loki_name_system lns_extra_;
  {
    if (!lns_extra) lns_extra = &lns_extra_;
    if (check_condition(tx.type != cryptonote::txtype::loki_name_system, reason, tx, ", uses wrong tx type, expected=", cryptonote::txtype::loki_name_system))
      return false;

    if (check_condition(!cryptonote::get_field_from_tx_extra(tx.extra, *lns_extra), reason, tx, ", didn't have loki name service in the tx_extra"))
      return false;
  }


  // -----------------------------------------------------------------------------------------------
  // Check TX LNS Serialized Fields are NULL if they are not specified
  // -----------------------------------------------------------------------------------------------
  {
    constexpr auto VALUE_SPECIFIED_BUT_NOT_REQUESTED = ", given field but field is not requested to be serialised="sv;
    if (check_condition(!lns_extra->field_is_set(lns::extra_field::encrypted_value) && lns_extra->encrypted_value.size(), reason, tx, ", ", lns_extra_string(nettype, *lns_extra), VALUE_SPECIFIED_BUT_NOT_REQUESTED, "encrypted_value"))
      return false;

    if (check_condition(!lns_extra->field_is_set(lns::extra_field::owner) && lns_extra->owner, reason, tx, ", ", lns_extra_string(nettype, *lns_extra), VALUE_SPECIFIED_BUT_NOT_REQUESTED, "owner"))
      return false;

    if (check_condition(!lns_extra->field_is_set(lns::extra_field::backup_owner) && lns_extra->backup_owner, reason, tx, ", ", lns_extra_string(nettype, *lns_extra), VALUE_SPECIFIED_BUT_NOT_REQUESTED, "backup_owner"))
      return false;

    if (check_condition(!lns_extra->field_is_set(lns::extra_field::signature) && lns_extra->signature, reason, tx, ", ", lns_extra_string(nettype, *lns_extra), VALUE_SPECIFIED_BUT_NOT_REQUESTED, "signature"))
      return false;
  }

  // -----------------------------------------------------------------------------------------------
  // Simple LNS Extra Validation
  // -----------------------------------------------------------------------------------------------
  {
    if (check_condition(lns_extra->version != 0, reason, tx, ", ", lns_extra_string(nettype, *lns_extra), " unexpected version=", std::to_string(lns_extra->version), ", expected=0"))
      return false;

    if (check_condition(!lns::mapping_type_allowed(hf_version, lns_extra->type), reason, tx, ", ", lns_extra_string(nettype, *lns_extra), " specifying type=", lns_extra->type, " that is disallowed"))
      return false;

    // -----------------------------------------------------------------------------------------------
    // Serialized Values Check
    // -----------------------------------------------------------------------------------------------
    if (check_condition(!lns_extra->is_buying() && !lns_extra->is_updating(), reason, tx, ", ", lns_extra_string(nettype, *lns_extra), " TX extra does not specify valid combination of bits for serialized fields=", std::bitset<sizeof(lns_extra->fields) * 8>(static_cast<size_t>(lns_extra->fields)).to_string()))
      return false;

    if (check_condition(lns_extra->field_is_set(lns::extra_field::owner) &&
                        lns_extra->field_is_set(lns::extra_field::backup_owner) &&
                        lns_extra->owner == lns_extra->backup_owner,
                        reason, tx, ", ", lns_extra_string(nettype, *lns_extra), " specifying owner the same as the backup owner=", lns_extra->backup_owner.to_string(nettype)))
    {
      return false;
    }
   }

  // -----------------------------------------------------------------------------------------------
  // LNS Field(s) Validation
  // -----------------------------------------------------------------------------------------------
  {
    static const crypto::hash null_name_hash = name_to_hash(""); // Sanity check the empty name hash
    if (check_condition((lns_extra->name_hash == null_name_hash || lns_extra->name_hash == crypto::null_hash), reason, tx, ", ", lns_extra_string(nettype, *lns_extra), " specified the null name hash"))
        return false;

    if (lns_extra->field_is_set(lns::extra_field::encrypted_value))
    {
      if (!validate_encrypted_mapping_value(lns_extra->type, lns_extra->encrypted_value, reason))
        return false;
    }

    if (!validate_against_previous_mapping(*this, blockchain_height, tx, *lns_extra, reason))
      return false;
  }

  // -----------------------------------------------------------------------------------------------
  // Burn Validation
  // -----------------------------------------------------------------------------------------------
  {
    uint64_t burn                = cryptonote::get_burned_amount_from_tx_extra(tx.extra);
    uint64_t const burn_required = lns_extra->is_buying() ? burn_needed(hf_version, lns_extra->type) : 0;
    if (burn != burn_required)
    {
      char const *over_or_under = burn > burn_required ? "too much " : "insufficient ";
      if (check_condition(true, reason, tx, ", ", lns_extra_string(nettype, *lns_extra), " burned ", over_or_under, "loki=", burn, ", require=", burn_required))
        return false;
    }
  }

  return true;
}

bool validate_mapping_type(std::string const &mapping_type_str, lns::mapping_type *mapping_type, std::string *reason)
{
  std::string mapping = tools::lowercase_ascii_string(mapping_type_str);
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
    "address" BLOB NOT NULL UNIQUE
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
    "backup_owner_id" INTEGER REFERENCES "owner" ("id"),
    "update_height" INTEGER NOT NULL DEFAULT "register_height"
);
CREATE UNIQUE INDEX IF NOT EXISTS "name_hash_type_id" ON mappings("name_hash", "type");
CREATE INDEX IF NOT EXISTS "owner_id_index" ON mappings("owner_id");
CREATE INDEX IF NOT EXISTS "backup_owner_id_index" ON mappings("backup_owner_index");
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

static std::string sql_cmd_combine_mappings_and_owner_table(char const *suffix = nullptr)
{
  std::stringstream stream;
  stream <<
R"(SELECT "mappings".*, "o1"."address", "o2"."address" FROM "mappings"
JOIN "owner" "o1" ON "mappings"."owner_id" = "o1"."id"
LEFT JOIN "owner" "o2" ON "mappings"."backup_owner_id" = "o2"."id")" << "\n";

  if (suffix)
    stream << suffix;
  return stream.str();
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


enum struct db_version { v0, v1_track_updates };
auto constexpr DB_VERSION = db_version::v1_track_updates;
bool name_system_db::init(cryptonote::Blockchain const *blockchain, cryptonote::network_type nettype, sqlite3 *db)
{
  if (!db) return false;
  this->db      = db;
  this->nettype = nettype;

  std::string const get_mappings_by_owner_str            = sql_cmd_combine_mappings_and_owner_table(R"(WHERE ? IN ("o1"."address", "o2"."address"))");
  std::string const get_mappings_on_height_and_newer_str = sql_cmd_combine_mappings_and_owner_table(R"(WHERE "update_height" >= ?)");
  std::string const get_mapping_str                      = sql_cmd_combine_mappings_and_owner_table(R"(WHERE "type" = ? AND "name_hash" = ?)");

  char constexpr GET_SETTINGS_STR[]     = R"(SELECT * FROM "settings" WHERE "id" = 1)";
  char constexpr GET_OWNER_BY_ID_STR[]  = R"(SELECT * FROM "owner" WHERE "id" = ?)";
  char constexpr GET_OWNER_BY_KEY_STR[] = R"(SELECT * FROM "owner" WHERE "address" = ?)";
  char constexpr PRUNE_MAPPINGS_STR[]   = R"(DELETE FROM "mappings" WHERE "update_height" >= ?)";

  char constexpr PRUNE_OWNERS_STR[] =
R"(DELETE FROM "owner"
WHERE NOT EXISTS (SELECT * FROM "mappings" WHERE "owner"."id" = "mappings"."owner_id")
AND NOT EXISTS   (SELECT * FROM "mappings" WHERE "owner"."id" = "mappings"."backup_owner_id"))";

  char constexpr SAVE_MAPPING_STR[]  = R"(INSERT OR REPLACE INTO "mappings" ("type", "name_hash", "encrypted_value", "txid", "prev_txid", "register_height", "owner_id", "backup_owner_id", "update_height") VALUES (?,?,?,?,?,?,?,?,?))";
  char constexpr SAVE_OWNER_STR[]    = R"(INSERT INTO "owner" ("address") VALUES (?))";
  char constexpr SAVE_SETTINGS_STR[] = R"(INSERT OR REPLACE INTO "settings" ("id", "top_height", "top_hash", "version") VALUES (1,?,?,?))";

  if (!build_default_tables(db))
    return false;

  if (!get_settings_sql.compile(GET_SETTINGS_STR) ||
      !save_settings_sql.compile(SAVE_SETTINGS_STR))
    return false;

  // ---------------------------------------------------------------------------
  //
  // Migrate DB
  //
  // No statements (aside from settings) have been prepared yet, since the prepared statements we
  // need may require migration.  This code must thus take care to locally execute or prepare
  // whatever statements it needs.
  //
  // ---------------------------------------------------------------------------
  if (settings_record settings = get_settings())
  {
    if (settings.version != static_cast<decltype(settings.version)>(DB_VERSION))
    {
      if (!blockchain)
      {
        MERROR("Migration required, blockchain can not be nullptr");
        return false;
      }

      if (blockchain->get_db().is_read_only())
      {
        MERROR("DB is opened in read-only mode, unable to migrate LNS DB");
        return false;
      }

      if (settings.version == static_cast<decltype(settings.version)>(db_version::v0))
      {
        scoped_db_transaction db_transaction(*this);
        if (!db_transaction) return false;

        char constexpr ADD_UPDATE_HEIGHT_SQL[] = R"(ALTER TABLE "mappings" ADD "update_height" INTEGER NOT NULL DEFAULT "register_height")";
        // Don't check return here -- this one might fail because the column already exists; if so that's okay.
        sqlite3_exec(db, ADD_UPDATE_HEIGHT_SQL, nullptr /*callback*/, nullptr /*callback context*/, nullptr);

        std::vector<mapping_record> all_mappings = {};
        {
          sql_compiled_statement st{*this};
          if (!st.compile(sql_cmd_combine_mappings_and_owner_table()))
            return false;
          sql_run_statement(lns_sql_type::get_mappings, st, &all_mappings);
        }

        std::vector<crypto::hash> hashes;
        hashes.reserve(all_mappings.size());
        for (mapping_record const &record: all_mappings)
            hashes.push_back(record.txid);

        char constexpr UPDATE_MAPPING_HEIGHT[] = R"(UPDATE "mappings" SET "update_height" = ? WHERE "id" = ?)";
        sql_compiled_statement update_mapping_height{*this};
        if (!update_mapping_height.compile(UPDATE_MAPPING_HEIGHT))
          return false;

        std::vector<uint64_t> heights = blockchain->get_transactions_heights(hashes);
        for (size_t i = 0; i < all_mappings.size(); i++)
        {

          bind_and_run(lns_sql_type::internal_cmd, update_mapping_height, nullptr,
              heights[i], all_mappings[i].id);
        }

        save_settings(settings.top_height, settings.top_hash, static_cast<int>(db_version::v1_track_updates));
        db_transaction.commit = true;
      }
    }
  }

  // ---------------------------------------------------------------------------
  //
  // Prepare commonly executed sql statements
  //
  // ---------------------------------------------------------------------------
  if (!get_mappings_by_owner_sql.compile(get_mappings_by_owner_str) ||
      !get_mappings_on_height_and_newer_sql.compile(get_mappings_on_height_and_newer_str) ||
      !get_mapping_sql.compile(get_mapping_str) ||
      !get_owner_by_id_sql.compile(GET_OWNER_BY_ID_STR) ||
      !get_owner_by_key_sql.compile(GET_OWNER_BY_KEY_STR) ||
      !prune_mappings_sql.compile(PRUNE_MAPPINGS_STR) ||
      !prune_owners_sql.compile(PRUNE_OWNERS_STR) ||
      !save_mapping_sql.compile(SAVE_MAPPING_STR) ||
      !save_owner_sql.compile(SAVE_OWNER_STR)
    )
  {
    return false;
  }

  // ---------------------------------------------------------------------------
  //
  // Check settings
  //
  // ---------------------------------------------------------------------------
  if (settings_record settings = get_settings())
  {
    if (!blockchain)
    {
      assert(nettype == cryptonote::FAKECHAIN);
      return nettype == cryptonote::FAKECHAIN;
    }

    uint64_t lns_height   = 0;
    crypto::hash lns_hash = blockchain->get_tail_id(lns_height);

    // Try support out of date LNS databases by checking if the stored
    // settings->[top_hash|top_height] match what we expect. If they match, we
    // don't drop the DB but will load the missing blocks in a later step.

    cryptonote::block lns_blk = {};
    bool orphan               = false;
    if (blockchain->get_block_by_hash(settings.top_hash, lns_blk, &orphan))
    {
      bool lns_height_matches = settings.top_height == cryptonote::get_block_height(lns_blk);
      if (lns_height_matches && !orphan)
      {
        lns_height = settings.top_height;
        lns_hash   = settings.top_hash;
      }
    }

    if (settings.top_height == lns_height && settings.top_hash == lns_hash)
    {
      this->last_processed_height = settings.top_height;
      this->last_processed_hash   = settings.top_hash;
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

name_system_db::~name_system_db()
{
  if (!db) return;

  {
    scoped_db_transaction db_transaction(*this);
    save_settings(last_processed_height, last_processed_hash, static_cast<int>(DB_VERSION));
    db_transaction.commit = true;
  }

  // close_v2 starts shutting down; the actual shutdown occurs once the last prepared statement is
  // finalized (which should happen when the ..._sql members get destructed, right after this).
  sqlite3_close_v2(db);
}

static int64_t add_or_get_owner_id(lns::name_system_db &lns_db, crypto::hash const &tx_hash, cryptonote::tx_extra_loki_name_system const &entry, lns::generic_owner const &key)
{
  int64_t result = 0;
  if (owner_record owner = lns_db.get_owner_by_key(key)) result = owner.id;
  if (result == 0)
  {
    if (!lns_db.save_owner(key, &result))
    {
      LOG_PRINT_L1("Failed to save LNS owner to DB tx: " << tx_hash << ", type: " << entry.type << ", name_hash: " << entry.name_hash << ", owner: " << entry.owner.to_string(lns_db.network_type()));
      return result;
    }
  }
  return result;
}

static bool add_lns_entry(lns::name_system_db &lns_db, uint64_t height, cryptonote::tx_extra_loki_name_system const &entry, crypto::hash const &tx_hash)
{
  // -----------------------------------------------------------------------------------------------
  // New Mapping Insert or Completely Replace
  // -----------------------------------------------------------------------------------------------
  if (entry.is_buying())
  {
    int64_t owner_id = add_or_get_owner_id(lns_db, tx_hash, entry, entry.owner);
    if (owner_id == 0)
    {
      MERROR("Failed to add or get owner with key=" << entry.owner.to_string(lns_db.network_type()));
      assert(owner_id != 0);
      return false;
    }

    int64_t backup_owner_id = 0;
    if (entry.backup_owner)
    {
      backup_owner_id = add_or_get_owner_id(lns_db, tx_hash, entry, entry.backup_owner);
      if (backup_owner_id == 0)
      {
        MERROR("Failed to add or get backup owner with key=" << entry.backup_owner.to_string(lns_db.network_type()));
        assert(backup_owner_id != 0);
        return false;
      }
    }

    if (!lns_db.save_mapping(tx_hash, entry, height, owner_id, backup_owner_id))
    {
      LOG_PRINT_L1("Failed to save LNS entry to DB tx: " << tx_hash << ", type: " << entry.type << ", name_hash: " << entry.name_hash << ", owner: " << entry.owner.to_string(lns_db.network_type()));
      return false;
    }
  }
  // -----------------------------------------------------------------------------------------------
  // Update Mapping, do a SQL command of the type
  // UPDATE "mappings" SET <field> = entry.<field>, ...  WHERE type = entry.type AND name_hash = name_hash_base64
  // -----------------------------------------------------------------------------------------------
  else
  {
    // Generate the SQL command
    std::string sql_statement;
    int64_t owner_id        = 0;
    int64_t backup_owner_id = 0;
    size_t column_count     = 0;
    std::array<mapping_record_column, tools::enum_count<mapping_record_column>> columns; // Enumerate the columns we're going to update
    {
      columns[column_count++] = mapping_record_column::prev_txid;
      columns[column_count++] = mapping_record_column::txid;
      columns[column_count++] = mapping_record_column::update_height;

      if (entry.field_is_set(lns::extra_field::owner))
      {
        columns[column_count++] = mapping_record_column::owner_id;
        owner_id                = add_or_get_owner_id(lns_db, tx_hash, entry, entry.owner);
        if (owner_id == 0)
        {
          MERROR("Failed to add or get owner with key=" << entry.owner.to_string(lns_db.network_type()));
          assert(owner_id != 0);
          return false;
        }
      }

      if (entry.field_is_set(lns::extra_field::backup_owner))
      {
        columns[column_count++] = mapping_record_column::backup_owner_id;
        backup_owner_id         = add_or_get_owner_id(lns_db, tx_hash, entry, entry.backup_owner);
        if (backup_owner_id == 0)
        {
          MERROR("Failed to add or get backup owner with key=" << entry.backup_owner.to_string(lns_db.network_type()));
          assert(backup_owner_id != 0);
          return false;
        }
      }

      if (entry.field_is_set(lns::extra_field::encrypted_value))
        columns[column_count++] = mapping_record_column::encrypted_value;

      // Build the SQL statement
      std::stringstream stream;
      stream << R"(UPDATE "mappings" SET )";
      for (size_t i = 0; i < column_count; i++)
      {
        if (i) stream << ", ";
        auto column_type = columns[i];
        stream << "\"" << mapping_record_column_string(column_type) << "\" = ?";
      }

      columns[column_count++] = mapping_record_column::type;
      columns[column_count++] = mapping_record_column::name_hash;
      stream << R"( WHERE "type" = ? AND "name_hash" = ?)";
      sql_statement = stream.str();
    }

    // Compile sql statement && bind parameters to statement
    std::string const name_hash   = hash_to_base64(entry.name_hash);
    sql_compiled_statement statement{lns_db};
    {
      if (!statement.compile(sql_statement, false /*optimise_for_multiple_usage*/))
      {
        MERROR("Failed to compile SQL statement for updating LNS record=" << sql_statement);
        return false;
      }

      // Bind step
      for (size_t i = 0; i < column_count; i++)
      {
        auto column_type = columns[i];
        switch (column_type)
        {
          case mapping_record_column::type:            lns::bind(statement, i+1, static_cast<uint16_t>(entry.type)); break;
          case mapping_record_column::name_hash:       lns::bind(statement, i+1, name_hash); break;
          case mapping_record_column::encrypted_value: lns::bind(statement, i+1, blob_view{entry.encrypted_value}); break;
          case mapping_record_column::txid:            lns::bind(statement, i+1, blob_view{tx_hash.data, sizeof(tx_hash)}); break;
          case mapping_record_column::prev_txid:       lns::bind(statement, i+1, blob_view{entry.prev_txid.data, sizeof(entry.prev_txid)}); break;
          case mapping_record_column::owner_id:        lns::bind(statement, i+1, owner_id); break;
          case mapping_record_column::backup_owner_id: lns::bind(statement, i+1, backup_owner_id); break;
          case mapping_record_column::update_height:   lns::bind(statement, i+1, height); break;
          default: assert(false); return false;
        }
      }
    }

    if (!sql_run_statement(lns_sql_type::save_mapping, statement, nullptr))
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

  bool lns_parsed_from_block = false;
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

      lns_parsed_from_block = true;
    }
  }

  last_processed_height = height;
  last_processed_hash   = cryptonote::get_block_hash(block);
  if (lns_parsed_from_block)
  {
    save_settings(last_processed_height, last_processed_hash, static_cast<int>(DB_VERSION));
    db_transaction.commit = lns_parsed_from_block;
  }
  return true;
}

static bool get_txid_lns_entry(cryptonote::Blockchain const &blockchain, crypto::hash txid, cryptonote::tx_extra_loki_name_system &extra)
{
  if (txid == crypto::null_hash) return false;
  std::vector<cryptonote::transaction> txs;
  std::vector<crypto::hash> missed_txs;
  if (!blockchain.get_transactions({txid}, txs, missed_txs) || txs.empty())
    return false;

  return cryptonote::get_field_from_tx_extra(txs[0].extra, extra);
}

struct lns_update_history
{
  uint64_t value_last_update_height        = static_cast<uint64_t>(-1);
  uint64_t owner_last_update_height        = static_cast<uint64_t>(-1);
  uint64_t backup_owner_last_update_height = static_cast<uint64_t>(-1);

  void     update(uint64_t height, cryptonote::tx_extra_loki_name_system const &lns_extra);
  uint64_t newest_update_height() const;
};

void lns_update_history::update(uint64_t height, cryptonote::tx_extra_loki_name_system const &lns_extra)
{
  if (lns_extra.field_is_set(lns::extra_field::encrypted_value))
    value_last_update_height = height;

  if (lns_extra.field_is_set(lns::extra_field::owner))
    owner_last_update_height = height;

  if (lns_extra.field_is_set(lns::extra_field::backup_owner))
    backup_owner_last_update_height = height;
}

uint64_t lns_update_history::newest_update_height() const
{
  uint64_t result = std::max(std::max(value_last_update_height, owner_last_update_height), backup_owner_last_update_height);
  return result;
}

struct replay_lns_tx
{
  uint64_t                              height;
  crypto::hash                          tx_hash;
  cryptonote::tx_extra_loki_name_system entry;
};

static std::vector<replay_lns_tx> find_lns_txs_to_replay(cryptonote::Blockchain const &blockchain, lns::mapping_record const &mapping, uint64_t blockchain_height)
{
  /*
     Detach Logic
     -----------------------------------------------------------------------------------------------
     LNS Buy    @ Height 100: LNS Record={field1=a1, field2=b1, field3=c1}
     LNS Update @ Height 200: LNS Record={field1=a2                      }
     LNS Update @ Height 300: LNS Record={           field2=b2           }
     LNS Update @ Height 400: LNS Record={                      field3=c2}
     LNS Update @ Height 500: LNS Record={field1=a3, field2=b3, field3=c3}
     LNS Update @ Height 600: LNS Record={                      field3=c4}

     Blockchain detaches to height 401, the target LNS record now looks like
                                         {field1=a2, field2=b2, field3=c2}

     Our current LNS record looks like
                                         {field1=a3, field2=b3, field3=c4}

     To get all the fields back, we can't just replay the latest LNS update
     transactions in reverse chronological order back to the detach height,
     otherwise we miss the update to field1=a2 and field2=b2.

     To rebuild our LNS record, we need to iterate back until we find all the
     TX's that updated the LNS field(s) until all fields have been reverted to
     a state representative of pre-detach height.

     i.e. Go back to the closest LNS record to the detach height, at height 300.
     Next, iterate back until all LNS fields have been touched at a point in
     time before the detach height (i.e. height 200 with field=a2). Replay the
     transactions.
  */

  std::vector<replay_lns_tx> result;
  lns_update_history update_history = {};
  for (crypto::hash curr_txid = mapping.prev_txid;
       update_history.newest_update_height() >= blockchain_height;
      )
  {
    cryptonote::tx_extra_loki_name_system curr_lns_extra = {};
    if (!get_txid_lns_entry(blockchain, curr_txid, curr_lns_extra))
    {
      if (curr_txid != crypto::null_hash)
        MERROR("Unexpected error querying TXID=" << curr_txid << ", from DB for LNS");
      return result;
    }

    std::vector<uint64_t> curr_heights = blockchain.get_transactions_heights({curr_txid});
    if (curr_heights.empty())
    {
      MERROR("Unexpected error querying TXID=" << curr_txid << ", height from DB for LNS");
      return result;
    }

    if (curr_heights[0] < blockchain_height)
      result.push_back({curr_heights[0], curr_txid, curr_lns_extra});

    update_history.update(curr_heights[0], curr_lns_extra);
    curr_txid = curr_lns_extra.prev_txid;
  }

  return result;
}

void name_system_db::block_detach(cryptonote::Blockchain const &blockchain, uint64_t new_blockchain_height)
{
  std::vector<mapping_record> new_mappings = {};
  bind_and_run(lns_sql_type::get_mappings_on_height_and_newer, get_mappings_on_height_and_newer_sql, &new_mappings,
      new_blockchain_height);

  std::vector<replay_lns_tx> txs_to_replay;
  for (auto const &mapping : new_mappings)
  {
    std::vector<replay_lns_tx> replay_txs = find_lns_txs_to_replay(blockchain, mapping, new_blockchain_height);
    txs_to_replay.reserve(txs_to_replay.size() + replay_txs.size());
    txs_to_replay.insert(txs_to_replay.end(), replay_txs.begin(), replay_txs.end());
  }

  prune_db(new_blockchain_height);
  for (auto it = txs_to_replay.rbegin(); it != txs_to_replay.rend(); it++)
  {
    if (!add_lns_entry(*this, it->height, it->entry, it->tx_hash))
      MERROR("Unexpected failure to add historical LNS into the DB on reorganization from tx=" << it->tx_hash);
  }
}

bool name_system_db::save_owner(lns::generic_owner const &owner, int64_t *row_id)
{
  bool result = bind_and_run(lns_sql_type::save_owner, save_owner_sql, nullptr,
      blob_view{reinterpret_cast<const char*>(&owner), sizeof(owner)});

  if (row_id) *row_id = sqlite3_last_insert_rowid(db);
  return result;
}

bool name_system_db::save_mapping(crypto::hash const &tx_hash, cryptonote::tx_extra_loki_name_system const &src, uint64_t height, int64_t owner_id, int64_t backup_owner_id)
{
  if (!src.is_buying())
    return false;

  std::string name_hash = hash_to_base64(src.name_hash);
  auto& statement = save_mapping_sql;
  clear_bindings(statement);
  bind(statement, mapping_record_column::type, static_cast<uint16_t>(src.type));
  bind(statement, mapping_record_column::name_hash, name_hash);
  bind(statement, mapping_record_column::encrypted_value, blob_view{src.encrypted_value});
  bind(statement, mapping_record_column::txid, blob_view{tx_hash.data, sizeof(tx_hash)});
  bind(statement, mapping_record_column::prev_txid, blob_view{src.prev_txid.data, sizeof(src.prev_txid)});
  bind(statement, mapping_record_column::register_height, height);
  bind(statement, mapping_record_column::update_height, height);
  bind(statement, mapping_record_column::owner_id, owner_id);
  if (backup_owner_id != 0)
    bind(statement, mapping_record_column::backup_owner_id, backup_owner_id);
  else
    bind(statement, mapping_record_column::backup_owner_id, nullptr);

  bool result = sql_run_statement(lns_sql_type::save_mapping, statement, nullptr);
  return result;
}

bool name_system_db::save_settings(uint64_t top_height, crypto::hash const &top_hash, int version)
{
  auto& statement = save_settings_sql;
  bind(statement, lns_db_setting_column::top_height, top_height);
  bind(statement, lns_db_setting_column::top_hash, blob_view{top_hash.data, sizeof(top_hash)});
  bind(statement, lns_db_setting_column::version, version);
  bool result = sql_run_statement(lns_sql_type::save_setting, statement, nullptr);
  return result;
}

bool name_system_db::prune_db(uint64_t height)
{
  if (!bind_and_run(lns_sql_type::pruning, prune_mappings_sql, nullptr, height)) return false;
  if (!sql_run_statement(lns_sql_type::pruning, prune_owners_sql, nullptr)) return false;

  this->last_processed_height = (height - 1);
  return true;
}

owner_record name_system_db::get_owner_by_key(lns::generic_owner const &owner)
{
  owner_record result = {};
  result.loaded       = bind_and_run(lns_sql_type::get_owner, get_owner_by_key_sql, &result,
      blob_view{reinterpret_cast<const char*>(&owner), sizeof(owner)});
  return result;
}

owner_record name_system_db::get_owner_by_id(int64_t owner_id)
{
  owner_record result = {};
  result.loaded       = bind_and_run(lns_sql_type::get_owner, get_owner_by_id_sql, &result,
      owner_id);
  return result;
}

mapping_record name_system_db::get_mapping(mapping_type type, std::string const &name_base64_hash)
{
  mapping_record result = {};
  result.loaded         = bind_and_run(lns_sql_type::get_mapping, get_mapping_sql, &result,
      static_cast<uint16_t>(type), name_base64_hash);
  return result;
}

std::vector<mapping_record> name_system_db::get_mappings(std::vector<uint16_t> const &types, std::string const &name_base64_hash)
{
  std::vector<mapping_record> result;
  if (types.empty())
    return result;

  std::string sql_statement;
  sql_statement.reserve(120 + 7 * types.size());
  // Generate string statement
  if (types.size())
  {
    sql_statement += sql_cmd_combine_mappings_and_owner_table(R"(WHERE "name_hash" = ? AND "type" in ()");
    for (size_t i = 0; i < types.size(); i++)
    {
      sql_statement += std::to_string(types[i]);
      if (i < (types.size() - 1)) sql_statement += ", ";
    }
    sql_statement += ")";
  }
  else
  {
    sql_statement = R"(SELECT * FROM "mappings" JOIN "owner" ON "mappings"."owner_id" = "owner"."id" WHERE "name_hash" = ?)";
  }

  // Compile Statement
  sql_compiled_statement statement{*this};
  if (!statement.compile(sql_statement, false /*optimise_for_multiple_usage*/))
    return result;

  // Execute
  bind_and_run(lns_sql_type::get_mappings, statement, &result,
      name_base64_hash);

  return result;
}

std::vector<mapping_record> name_system_db::get_mappings_by_owners(std::vector<generic_owner> const &owners)
{
  std::string sql_statement;
  // Generate string statement
  {
    std::string const sql_prefix_str = sql_cmd_combine_mappings_and_owner_table(R"(WHERE "o1"."address" in ()");
    char constexpr SQL_MIDDLE[]  = R"() OR "o2"."address" in ()";
    char constexpr SQL_SUFFIX[]  = R"())";

    std::string placeholders;
    placeholders.reserve(3*owners.size());
    for (size_t i = 0; i < owners.size(); i++)
      placeholders += "?, ";
    if (owners.size() > 0)
      placeholders.resize(placeholders.size() - 2);

    std::ostringstream stream;
    stream << sql_prefix_str << placeholders << SQL_MIDDLE << placeholders << SQL_SUFFIX;
    sql_statement = stream.str();
  }

  // Compile Statement
  std::vector<mapping_record> result;
  sql_compiled_statement statement{*this};
  if (!statement.compile(sql_statement, false /*optimise_for_multiple_usage*/))
    return result;

  // Bind parameters statements
  int sql_param_index = 1;
  for (size_t i = 0; i < owners.size(); i++)
    for (auto const &owner : owners)
      bind_blob(statement, sql_param_index++, &owner, sizeof(owner));

  // Execute
  sql_run_statement(lns_sql_type::get_mappings_by_owners, statement, &result);
  return result;
}

std::vector<mapping_record> name_system_db::get_mappings_by_owner(generic_owner const &owner)
{
  std::vector<mapping_record> result = {};
  blob_view ownerblob{reinterpret_cast<const char*>(&owner), sizeof(owner)};
  bind_and_run(lns_sql_type::get_mappings_by_owner, get_mappings_by_owner_sql, &result,
      ownerblob, ownerblob);
  return result;
}

settings_record name_system_db::get_settings()
{
  settings_record result  = {};
  result.loaded           = sql_run_statement(lns_sql_type::get_setting, get_settings_sql, &result);
  return result;
}
}; // namespace service_nodes

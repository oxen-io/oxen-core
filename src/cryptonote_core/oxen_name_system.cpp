#include <bitset>
#include <variant>
#include <iterator>
#include <vector>
#include <algorithm>
#include "common/hex.h"
#include "cryptonote_config.h"
#include "oxen_name_system.h"

#include "common/oxen.h"
#include "common/string_util.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/blockchain.h"
#include "oxen_economy.h"

#include <oxenc/hex.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>

#include <sqlite3.h>

extern "C"
{
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>
}

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "ons"

using cryptonote::hf;

namespace ons
{

enum struct ons_sql_type
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
  get_mapping_counts,
  get_owner,
  get_setting,
  get_sentinel_end,

  internal_cmd,
};

enum struct ons_db_setting_column
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
  owner_id,
  backup_owner_id,
  update_height,
  expiration_height,
  _count,
};

static constexpr unsigned char OLD_ENCRYPTION_NONCE[crypto_secretbox_NONCEBYTES] = {};
std::pair<std::basic_string_view<unsigned char>, std::basic_string_view<unsigned char>> ons::mapping_value::value_nonce(mapping_type type) const
{
  std::pair<std::basic_string_view<unsigned char>, std::basic_string_view<unsigned char>> result;
  auto& [head, tail] = result;
  head = {buffer.data(), len};
  if ((type == mapping_type::session && len != SESSION_PUBLIC_KEY_BINARY_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
      || len < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES /* shouldn't occur, but just in case */)
    tail = {OLD_ENCRYPTION_NONCE, sizeof(OLD_ENCRYPTION_NONCE)};
  else
  {
    tail = head.substr(len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    head.remove_suffix(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  }
  return result;
}

std::string ons::mapping_value::to_readable_value(cryptonote::network_type nettype, ons::mapping_type type) const
{
  std::string result;
  if (is_lokinet_type(type))
  {
    result = oxenc::to_base32z(to_view()) + ".loki";
  } else if (type == ons::mapping_type::wallet) {
    std::optional<cryptonote::address_parse_info> addr = get_wallet_address_info();
    if(addr)
    {
      result = cryptonote::get_account_address_as_str(nettype, (*addr).is_subaddress, (*addr).address);
    } else {
      result = oxenc::to_hex(to_view());
    }
  } else {
    result = oxenc::to_hex(to_view());
  }

  return result;
}

namespace {

std::string ons_extra_string(cryptonote::network_type nettype, cryptonote::tx_extra_oxen_name_system const &data)
{
  std::stringstream stream;
  stream << "ONS Extra={";
  if (data.is_buying())
  {
    stream << "owner=" << data.owner.to_string(nettype);
    stream << ", backup_owner=" << (data.backup_owner ? data.backup_owner.to_string(nettype) : "(none)");
  }
  else if (data.is_renewing())
    stream << "renewal";
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
template <typename T, std::enable_if_t<std::is_integral_v<T> && (sizeof(T) <= 4), int> = 0>
bool bind(sql_compiled_statement& s, int index, const T& val) { return SQLITE_OK == sqlite3_bind_int(s.statement, index, val); }

// Big (>32 bits) integers
template <typename T, std::enable_if_t<std::is_integral_v<T> && (sizeof(T) > 4), int> = 0>
bool bind(sql_compiled_statement& s, int index, const T& val) { return SQLITE_OK == sqlite3_bind_int64(s.statement, index, val); }

// Floats/doubles
template <typename T, std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
bool bind(sql_compiled_statement& s, int index, const T& val) { return SQLITE_OK == sqlite3_bind_double(s.statement, index, val); }

// Binds null
bool bind(sql_compiled_statement& s, int index, std::nullptr_t) { return SQLITE_OK == sqlite3_bind_null(s.statement, index); }

// Binds a std::optional<T>: binds a T if set, otherwise binds a NULL
template <typename T>
bool bind(sql_compiled_statement& s, int index, const std::optional<T>& val) {
  if (val)
    return bind(s, index, *val);
  return bind(s, index, nullptr);
}

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

// Simple decorator around a string_view so that you can pass a blob into `bind` by wrapping it
// with a `blob_view` such as:
//
// bind(s, 123, blob_view{data, size});
// auto data = get<blob_view>(s, 2);
//
struct blob_view {
  std::string_view data;
  /// Constructor that simply forwards anything to the `data` (string_view) member constructor
  template <typename... T> explicit blob_view(T&&... args) : data{std::forward<T>(args)...} {}
};

// Binds a blob wrapped in a blob_view decorator
bool bind(sql_compiled_statement& s, int index, blob_view blob)
{
  return SQLITE_OK == sqlite3_bind_blob(s.statement, index, blob.data.data(), blob.data.size(), nullptr /*dtor*/);
}

// Binds a variant of bindable types; calls one of the above according to the contained type
template <typename... T>
bool bind(sql_compiled_statement& s, int index, const std::variant<T...>& v) {
  return var::visit([&](const auto& val) { return ons::bind(s, index, val); }, v);
}

template <typename T> constexpr bool is_int_enum_impl() {
  if constexpr (std::is_enum_v<T>)
    return std::is_same_v<std::underlying_type_t<T>, int>;
  else return false;
}
template <typename T> constexpr bool is_int_enum = is_int_enum_impl<T>();

// Binds, but gives index as an enum class
template <typename T, typename I, std::enable_if_t<is_int_enum<I>, int> = 0>
bool bind(sql_compiled_statement& s, I index, T&& val)
{
  return ons::bind(s, static_cast<int>(index), std::forward<T>(val));
}

template <int... I, typename... T>
bool bind_all_impl(sql_compiled_statement& s, std::integer_sequence<int, I...>, T&&... args) {
  clear_bindings(s);
  for (bool r : {ons::bind(s, I+1, std::forward<T>(args))...})
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

// Full statement binding from a container of bind()-able values; clears existing bindings, then
// binds the contained values.
template <typename Container>
bool bind_container(sql_compiled_statement& s, const Container& c)
{
  clear_bindings(s);
  int bind_pos = 1;
  for (const auto& v : c)
    if (!ons::bind(s, bind_pos++, v))
      return false;
  return true;
}

/// Retrieve a type from an executed statement.

// Small (<=32 bits) integers
template <typename T, std::enable_if_t<std::is_integral_v<T> && (sizeof(T) <= 32), int> = 0>
T get(sql_compiled_statement& s, int index) { return static_cast<T>(sqlite3_column_int(s.statement, index)); }

// Big (>32 bits) integers
template <typename T, std::enable_if_t<std::is_integral_v<T> && (sizeof(T) > 32), int> = 0>
T get(sql_compiled_statement& s, int index) { return static_cast<T>(sqlite3_column_int64(s.statement, index)); }

// Floats/doubles
template <typename T, std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
T get(sql_compiled_statement& s, int index) { return static_cast<T>(sqlite3_column_double(s.statement, index)); }

// text, via a string_view pointing at the text data
template <typename T, std::enable_if_t<std::is_same_v<T, std::string_view>, int> = 0>
std::string_view get(sql_compiled_statement& s, int index)
{
  return {reinterpret_cast<const char*>(sqlite3_column_text(s.statement, index)),
          static_cast<size_t>(sqlite3_column_bytes(s.statement, index))};
}

// text, copied into a std::string
template <typename T, std::enable_if_t<std::is_same_v<T, std::string>, int> = 0>
std::string get(sql_compiled_statement& s, int index)
{
  return {reinterpret_cast<const char*>(sqlite3_column_text(s.statement, index)),
          static_cast<size_t>(sqlite3_column_bytes(s.statement, index))};
}

// blob_view pointing at the blob data
template <typename T, std::enable_if_t<std::is_same_v<T, blob_view>, int> = 0>
blob_view get(sql_compiled_statement& s, int index)
{
  return blob_view{
    reinterpret_cast<const char*>(sqlite3_column_blob(s.statement, index)),
    static_cast<size_t>(sqlite3_column_bytes(s.statement, index))};
}

template <typename T> constexpr bool is_optional = false;
template <typename T> constexpr bool is_optional<std::optional<T>> = true;

// Gets a potentially null value; returns a std::nullopt if the column contains NULL, otherwise
// return a value via get<T>(...).
template <typename T, std::enable_if_t<is_optional<T>, int> = 0>
T get(sql_compiled_statement& s, int index)
{
  if (sqlite3_column_type(s.statement, index) == SQLITE_NULL)
    return std::nullopt;
  return get<typename T::value_type>(s, index);
}

// Forwards to any of the above, but takes an enum class instead of an int
template <typename T, typename I, std::enable_if_t<is_int_enum<I>, int> = 0>
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

template <typename I>
bool sql_copy_blob(sql_compiled_statement& statement, I column, void *dest, size_t dest_size)
{

  auto blob = get<blob_view>(statement, column);
  if (blob.data.size() != dest_size)
  {
    LOG_PRINT_L0("Unexpected blob size=" << blob.data.size() << ", in ONS DB does not match expected size=" << dest_size);
    assert(blob.data.size() == dest_size);
    return false;
  }

  std::memcpy(dest, blob.data.data(), blob.data.size());
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
  get(statement, mapping_record_column::update_height, result.update_height);
  get(statement, mapping_record_column::expiration_height, result.expiration_height);
  get(statement, mapping_record_column::owner_id, result.owner_id);
  get(statement, mapping_record_column::backup_owner_id, result.backup_owner_id);

  // Copy encrypted_value
  {
    auto value = get<std::string_view>(statement, mapping_record_column::encrypted_value);
    if (value.size() > result.encrypted_value.buffer.size())
    {
      MERROR("Unexpected encrypted value blob with size=" << value.size() << ", in ONS db larger than the available size=" << result.encrypted_value.buffer.size());
      return result;
    }
    result.encrypted_value.len = value.size();
    result.encrypted_value.encrypted = true;
    std::memcpy(&result.encrypted_value.buffer[0], value.data(), value.size());
  }

  // Copy name hash
  {
    auto value = get<std::string_view>(statement, mapping_record_column::name_hash);
    result.name_hash.append(value.data(), value.size());
  }

  if (!sql_copy_blob(statement, mapping_record_column::txid, result.txid.data, sizeof(result.txid)))
    return result;

  int owner_column = tools::enum_count<mapping_record_column>;
  if (!sql_copy_blob(statement, owner_column, &result.owner, sizeof(result.owner)))
    return result;

  if (result.backup_owner_id > 0)
  {
    if (!sql_copy_blob(statement, owner_column + 1, &result.backup_owner, sizeof(result.backup_owner)))
      return result;
  }

  result.loaded = true;
  return result;
}

bool sql_run_statement(ons_sql_type type, sql_compiled_statement& statement, void *context)
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
          default: MERROR("Unhandled ons type enum with value: " << (int)type << ", in: " << __func__); break;

          case ons_sql_type::internal_cmd: break;
          case ons_sql_type::get_owner:
          {
            auto *entry = reinterpret_cast<owner_record *>(context);
            get(statement, owner_record_column::id, entry->id);
            if (!sql_copy_blob(statement, owner_record_column::address, &entry->address, sizeof(entry->address)))
              return false;
            data_loaded = true;
          }
          break;

          case ons_sql_type::get_setting:
          {
            auto *entry       = reinterpret_cast<settings_record *>(context);
            get(statement, ons_db_setting_column::top_height, entry->top_height);
            if (!sql_copy_blob(statement, ons_db_setting_column::top_hash, entry->top_hash.data, sizeof(entry->top_hash.data)))
              return false;
            get(statement, ons_db_setting_column::version, entry->version);
            data_loaded = true;
          }
          break;

          case ons_sql_type::get_mappings_by_owners: [[fallthrough]];
          case ons_sql_type::get_mappings_by_owner: [[fallthrough]];
          case ons_sql_type::get_mappings: [[fallthrough]];
          case ons_sql_type::get_mapping:
          {
            if (mapping_record tmp_entry = sql_get_mapping_from_statement(statement))
            {
              data_loaded = true;
              if (type == ons_sql_type::get_mapping)
                *static_cast<mapping_record *>(context) = std::move(tmp_entry);
              else
                static_cast<std::vector<mapping_record>*>(context)->push_back(std::move(tmp_entry));
            }
          }
          break;

          case ons_sql_type::get_mapping_counts:
          {
            auto& counts = *static_cast<std::map<mapping_type, int>*>(context);
            std::underlying_type_t<mapping_type> type_val;
            int count;
            get(statement, 0, type_val);
            get(statement, 1, count);
            counts.emplace(static_cast<mapping_type>(type_val), count);
            data_loaded = true;
          }
        }
      }
      break;

      case SQLITE_BUSY: break;
      case SQLITE_DONE:
      {
        infinite_loop = false;
        result        = (type > ons_sql_type::get_sentinel_start && type < ons_sql_type::get_sentinel_end) ? data_loaded : true;
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
bool bind_and_run(ons_sql_type type, sql_compiled_statement& statement, void *context,
    T&&... bind_args)
{
  bind_all(statement, std::forward<T>(bind_args)...);
  return sql_run_statement(type, statement, context);
}


} // end anonymous namespace


bool mapping_record::active(uint64_t blockchain_height) const
{
  if (!loaded) return false;
  return !expiration_height || blockchain_height <= *expiration_height;
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

sqlite3 *init_oxen_name_system(const fs::path& file_path, bool read_only)
{
  sqlite3 *result = nullptr;
  int sql_init    = sqlite3_initialize();
  if (sql_init != SQLITE_OK)
  {
    MERROR("Failed to initialize sqlite3: " << sqlite3_errstr(sql_init));
    return nullptr;
  }

  int const flags = read_only ? SQLITE_OPEN_READONLY : SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE;
  int sql_open    = sqlite3_open_v2(file_path.u8string().c_str(), &result, flags, nullptr);
  if (sql_open != SQLITE_OK)
  {
    MERROR("Failed to open ONS db at: " << file_path << ", reason: " << sqlite3_errstr(sql_open));
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

std::vector<mapping_type> all_mapping_types(hf hf_version) {
  std::vector<mapping_type> result;
  result.reserve(2);
  if (hf_version >= hf::hf15_ons)
    result.push_back(mapping_type::session);
  if (hf_version >= hf::hf16_pulse)
    result.push_back(mapping_type::lokinet);
  if (hf_version >= hf::hf18)
    result.push_back(mapping_type::wallet);
  return result;
}

std::optional<uint64_t> expiry_blocks(cryptonote::network_type nettype, mapping_type type)
{
  std::optional<uint64_t> result;
  if (is_lokinet_type(type))
  {
    // For testnet we shorten 1-, 2-, and 5-year renewals to 1/2/5 days with 1-day renewal, but
    // leave 10 years alone to allow long-term registrations on testnet.
    const bool testnet_short = nettype == cryptonote::network_type::TESTNET && type != mapping_type::lokinet_10years;

    result = cryptonote::BLOCKS_PER_DAY * REGISTRATION_YEAR_DAYS * (
        type == mapping_type::lokinet         ? 1 :
        type == mapping_type::lokinet_2years  ? 2 :
        type == mapping_type::lokinet_5years  ? 5 :
        type == mapping_type::lokinet_10years ? 10 : 0);
    assert(result && *result);

    if (testnet_short)
      *result /= REGISTRATION_YEAR_DAYS;
    else if (nettype == cryptonote::network_type::FAKECHAIN) // For fakenet testing we shorten 1/2/5/10 years to 2/4/10/20 blocks
      *result /= (cryptonote::BLOCKS_PER_DAY * REGISTRATION_YEAR_DAYS / 2);
  }

  return result;
}

static void append_owner(std::string& buffer, const ons::generic_owner* owner)
{
  if (owner) {
    buffer += static_cast<char>(owner->type);
    buffer += owner->type == ons::generic_owner_sig_type::ed25519
        ? tools::view_guts(owner->ed25519)
        : tools::view_guts(owner->wallet.address);
  }
}

std::string tx_extra_signature(std::string_view value, ons::generic_owner const *owner, ons::generic_owner const *backup_owner, crypto::hash const &prev_txid)
{
  static_assert(sizeof(crypto::hash) == crypto_generichash_BYTES, "Using libsodium generichash for signature hash, require we fit into crypto::hash");
  if (value.size() > mapping_value::BUFFER_SIZE)
  {
    MERROR("Unexpected value len=" << value.size() << " greater than the expected capacity=" << mapping_value::BUFFER_SIZE);
    return ""s;
  }

  std::string result;
  result.reserve(mapping_value::BUFFER_SIZE + sizeof(*owner) + sizeof(*backup_owner) + sizeof(prev_txid));
  result += value;
  append_owner(result, owner);
  append_owner(result, backup_owner);
  result += tools::view_guts(prev_txid);

  return result;
}

ons::generic_signature make_ed25519_signature(crypto::hash const &hash, crypto::ed25519_secret_key const &skey)
{
  ons::generic_signature result = {};
  result.type                   = ons::generic_owner_sig_type::ed25519;
  crypto_sign_detached(result.ed25519.data, NULL, reinterpret_cast<unsigned char const *>(hash.data), sizeof(hash), skey.data);
  return result;
}

ons::generic_owner make_monero_owner(cryptonote::account_public_address const &owner, bool is_subaddress)
{
  ons::generic_owner result   = {};
  result.type                 = ons::generic_owner_sig_type::monero;
  result.wallet.address       = owner;
  result.wallet.is_subaddress = is_subaddress;
  return result;
}

ons::generic_owner make_ed25519_owner(crypto::ed25519_public_key const &pkey)
{
  ons::generic_owner result = {};
  result.type               = ons::generic_owner_sig_type::ed25519;
  result.ed25519            = pkey;
  return result;
}

bool parse_owner_to_generic_owner(cryptonote::network_type nettype, std::string_view owner, generic_owner &result, std::string *reason)
{
  cryptonote::address_parse_info parsed_addr;
  crypto::ed25519_public_key ed_owner;
  if (cryptonote::get_account_address_from_str(parsed_addr, nettype, owner))
  {
    result = ons::make_monero_owner(parsed_addr.address, parsed_addr.is_subaddress);
  }
  else if (owner.size() == 2*sizeof(ed_owner.data) && oxenc::is_hex(owner))
  {
    oxenc::from_hex(owner.begin(), owner.end(), ed_owner.data);
    result = ons::make_ed25519_owner(ed_owner);
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


// Returns true if the character is numeric, *lower-case* a-z, or any of the template char values.
template <char... Extra>
static constexpr bool char_is_alphanum_or(char c)
{
  bool result = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (... || (c == Extra));
  return result;
}
// Same as above with no extra char values.
static constexpr bool char_is_alphanum(char c) { return char_is_alphanum_or<>(c); }

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

bool validate_ons_name(mapping_type type, std::string name, std::string *reason)
{
  bool const is_lokinet = is_lokinet_type(type);
  size_t max_name_len   = 0;

  if (is_lokinet)
    max_name_len = name.find('-') != std::string::npos
      ? LOKINET_DOMAIN_NAME_MAX
      : LOKINET_DOMAIN_NAME_MAX_NOHYPHEN;
  else if (type == mapping_type::session) max_name_len = ons::SESSION_DISPLAY_NAME_MAX;
  else if (type == mapping_type::wallet)  max_name_len = ons::WALLET_NAME_MAX;
  else
  {
    if (reason)
    {
      std::stringstream err_stream;
      err_stream << "ONS type=" << mapping_type_str(type) << ", specifies unhandled mapping type in name validation";
      *reason = err_stream.str();
    }
    return false;
  }

  // NOTE: Validate name length
  name = tools::lowercase_ascii_string(name);
  if (check_condition((name.empty() || name.size() > max_name_len), reason, "ONS type=", type, ", specifies mapping from name->value where the name's length=", name.size(), " is 0 or exceeds the maximum length=", max_name_len, ", given name=", name))
    return false;

  std::string_view name_view{name}; // Will chop this down as we validate each part

  // NOTE: Validate domain specific requirements
  if (is_lokinet)
  {
    // LOKINET
    // Domain has to start with an alphanumeric, and can have (alphanumeric or hyphens) in between, the character before the suffix <char>'.loki' must be alphanumeric followed by the suffix '.loki'
    // It's *approximately* this regex, but there are some extra restrictions below
    // ^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.loki$

    // Reserved names:
    // - localhost.loki has special meaning within lokinet (it is always a CNAME to the local
    //   address)
    // - loki.loki and snode.loki are prohibited in case someone added .loki or .snode as search
    //   domains (in which case the user looking up "foo.loki" would try end up trying to resolve
    //   "foo.loki.loki").
    for (auto& reserved : {"localhost.loki"sv, "loki.loki"sv, "snode.loki"sv})
      if (check_condition(name == reserved, reason, "ONS type=", type, ", specifies mapping from name->value using protocol reserved name=", name))
        return false;

    auto constexpr SHORTEST_DOMAIN = "a.loki"sv;
    if (check_condition(name.size() < SHORTEST_DOMAIN.size(), reason, "ONS type=", type, ", specifies mapping from name->value where the name is shorter than the shortest possible name=", SHORTEST_DOMAIN, ", given name=", name))
      return false;

    // Must end with .loki
    auto constexpr SUFFIX = ".loki"sv;
    if (check_condition(!tools::ends_with(name_view, SUFFIX), reason, "ONS type=", type, ", specifies mapping from name->value where the name does not end with the domain .loki, name=", name))
      return false;

    name_view.remove_suffix(SUFFIX.size());

    // All domains containing '--' as 3rd/4th letter are reserved except for xn-- punycode domains
    if (check_condition(name_view.size() >= 4 && name_view.substr(2, 2) == "--"sv && !tools::starts_with(name_view, "xn--"sv),
          reason, "ONS type=", type, ", specifies reserved name `?\?--*.loki': ", name))
      return false;

    // Must start with alphanumeric
    if (check_condition(!char_is_alphanum(name_view.front()), reason, "ONS type=", type, ", specifies mapping from name->value where the name does not start with an alphanumeric character, name=", name))
      return false;

    name_view.remove_prefix(1);

    if (!name_view.empty()) {
      // Character preceding .loki must be alphanumeric
      if (check_condition(!char_is_alphanum(name_view.back()), reason, "ONS type=", type ,", specifies mapping from name->value where the character preceding the .loki is not alphanumeric, char=", name_view.back(), ", name=", name))
        return false;
      name_view.remove_suffix(1);
    }

    // Inbetween start and preceding suffix, (alphanumeric or hyphen) characters permitted
    if (check_condition(!std::all_of(name_view.begin(), name_view.end(), char_is_alphanum_or<'-'>),
          reason, "ONS type=", type, ", specifies mapping from name->value where the domain name contains more than the permitted alphanumeric or hyphen characters, name=", name))
      return false;
  }
  else if (type == mapping_type::session || type == mapping_type::wallet)
  {
    // SESSION & WALLET
    // Name has to start with a (alphanumeric or underscore), and can have (alphanumeric, hyphens or underscores) in between and must end with a (alphanumeric or underscore)
    // ^[a-z0-9_]([a-z0-9-_]*[a-z0-9_])?$

    // Must start with (alphanumeric or underscore)
    if (check_condition(!char_is_alphanum_or<'_'>(name_view.front()), reason, "ONS type=", type, ", specifies mapping from name->value where the name does not start with an alphanumeric or underscore character, name=", name))
      return false;
    name_view.remove_prefix(1);

    if (!name_view.empty()) {
      // Must NOT end with a hyphen '-'
      if (check_condition(!char_is_alphanum_or<'_'>(name_view.back()), reason, "ONS type=", type, ", specifies mapping from name->value where the last character is a hyphen '-' which is disallowed, name=", name))
        return false;
      name_view.remove_suffix(1);
    }

    // Inbetween start and preceding suffix, (alphanumeric, hyphen or underscore) characters permitted
    if (check_condition(!std::all_of(name_view.begin(), name_view.end(), char_is_alphanum_or<'-', '_'>),
          reason, "ONS type=", type, ", specifies mapping from name->value where the name contains more than the permitted alphanumeric, underscore or hyphen characters, name=", name))
      return false;
  }
  else
  {
    MERROR("Type not implemented");
    return false;
  }

  return true;
}

std::optional<cryptonote::address_parse_info> encrypted_wallet_value_to_info(std::string name, std::string encrypted_value, std::string nonce)
{
  std::string lower_name = tools::lowercase_ascii_string(std::move(name));
  mapping_value record(oxenc::from_hex(encrypted_value), oxenc::from_hex(nonce));
  record.decrypt(lower_name, mapping_type::wallet);
  return record.get_wallet_address_info();
}

static bool check_lengths(mapping_type type, std::string_view value, size_t max, bool binary_val, std::string *reason)
{
  bool result;
  if (type == mapping_type::wallet)
  {
    result = (value.size() == (WALLET_ACCOUNT_BINARY_LENGTH_INC_PAYMENT_ID + max) || value.size() == (WALLET_ACCOUNT_BINARY_LENGTH_NO_PAYMENT_ID + max));
  } else {
    result = (value.size() == max);
  }
  if (!result)
  {
    if (reason)
    {
      std::stringstream err_stream;
      err_stream << "ONS type=" << type << ", specifies mapping from name_hash->encrypted_value where the value's length=" << value.size() << ", does not equal the required length=" << max << ", given value=";
      if (binary_val) err_stream << oxenc::to_hex(value);
      else            err_stream << value;
      *reason = err_stream.str();
    }
  }

  return result;
}

//This function checks that the value is valid but it also will copy the value into the mapping_value buffer ready for mapping_value::encrypt()
bool mapping_value::validate(cryptonote::network_type nettype, mapping_type type, std::string_view value, mapping_value *blob, std::string *reason)
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

    // Validate blob contents and generate the binary form if possible
    if (blob)
    {
      auto iter = blob->buffer.begin();
      uint8_t identifier = 0;
      if (addr_info.is_subaddress) {
        identifier |= ONS_WALLET_TYPE_SUBADDRESS;
      } else if (addr_info.has_payment_id) {
        identifier |= ONS_WALLET_TYPE_INTEGRATED;
      }
      iter = std::copy_n(&identifier, 1, iter);
      iter = std::copy_n(addr_info.address.m_spend_public_key.data, sizeof(addr_info.address.m_spend_public_key.data), iter);
      iter = std::copy_n(addr_info.address.m_view_public_key.data, sizeof(addr_info.address.m_view_public_key.data), iter);

      size_t counter = 65;
      assert(std::distance(blob->buffer.begin(), iter) == static_cast<int>(counter));
      if (addr_info.has_payment_id) {
        std::copy_n(addr_info.payment_id.data, sizeof(addr_info.payment_id.data), iter);
        counter+=sizeof(addr_info.payment_id);
      }

      blob->len = counter;
    }
  }
  else if (is_lokinet_type(type))
  {
    // We need a 52 char base32z string that decodes to a 32-byte value, which really means we need
    // 51 base32z chars (=255 bits) followed by a 1-bit value ('y'=0, or 'o'=0b10000); anything else
    // in the last spot isn't a valid lokinet address.
    if (check_condition(value.size() != 57 || !tools::ends_with(value, ".loki") || !oxenc::is_base32z(value.substr(0, 52)) || !(value[51] == 'y' || value[51] == 'o'),
                reason, "'", value, "' is not a valid lokinet address"))
      return false;

    if (blob)
    {
      blob->len = sizeof(crypto::ed25519_public_key);
      oxenc::from_base32z(value.begin(), value.begin() + 52, blob->buffer.begin());
    }
  }
  else
  {
    assert(type == mapping_type::session);
    // NOTE: Check value is hex of the right size
    if (check_condition(value.size() != 2*SESSION_PUBLIC_KEY_BINARY_LENGTH, reason, "The value=", value, " is not the required ", 2*SESSION_PUBLIC_KEY_BINARY_LENGTH, "-character hex string session public key, length=", value.size()))
      return false;

    if (check_condition(!oxenc::is_hex(value), reason, ", specifies name -> value mapping where the value is not a hex string given value="))
      return false;

    // NOTE: Session public keys are 33 bytes, with the first byte being 0x05 and the remaining 32 being the public key.
    if (check_condition(!tools::starts_with(value, "05"), reason, "ONS type=session, specifies mapping from name -> ed25519 key where the key is not prefixed with 05, given ed25519=", value))
      return false;

    if (blob) // NOTE: Given blob, write the binary output
    {
      blob->len = value.size() / 2;
      assert(blob->len <= blob->buffer.size());
      oxenc::from_hex(value.begin(), value.end(), blob->buffer.begin());

    }
  }

  return true;
}

static_assert(SODIUM_ENCRYPTION_EXTRA_BYTES == crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(SODIUM_ENCRYPTION_EXTRA_BYTES >= crypto_secretbox_MACBYTES);
bool mapping_value::validate_encrypted(mapping_type type, std::string_view value, mapping_value* blob, std::string *reason)
{
  if (blob) *blob = {};
  std::stringstream err_stream;

  int value_len = crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

  if (is_lokinet_type(type))
    value_len += LOKINET_ADDRESS_BINARY_LENGTH;
  else if (type == mapping_type::wallet)
  {
    value_len = crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; //Add the length in check_length
  }
  else if (type == mapping_type::session)
  {
    value_len += SESSION_PUBLIC_KEY_BINARY_LENGTH;


    // Allow an HF15 argon2 encrypted value which doesn't contain a nonce:
    if (value.size() == value_len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
      value_len -= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  }
  else
  {
    if (reason)
    {
      err_stream << "Unhandled type passed into " << __func__;
      *reason = err_stream.str();
    }
    return false;
  }

  if (!check_lengths(type, value, value_len, true /*binary_val*/, reason))
    return false;

  if (blob)
  {
    blob->len = value.size();
    std::memcpy(blob->buffer.data(), value.data(), value.size());
    blob->encrypted = true;
  }

  return true;
}


mapping_value::mapping_value(std::string encrypted_value, std::string nonce): buffer{0}
{
  auto it = std::copy(encrypted_value.begin(), encrypted_value.end(), buffer.begin());
  std::copy(nonce.begin(), nonce.end(), it);
  len = encrypted_value.size() + nonce.size();
  encrypted = true;
}

mapping_value::mapping_value() : buffer{0},encrypted(false),len(0){}

std::string name_hash_bytes_to_base64(std::string_view bytes)
{
  if (bytes.size() != NAME_HASH_SIZE)
    throw std::runtime_error{"Invalid name hash: expected exactly 32 bytes"};
  return oxenc::to_base64(bytes);
}

std::optional<std::string> name_hash_input_to_base64(std::string_view input)
{
  if (input.size() == NAME_HASH_SIZE)
    return name_hash_bytes_to_base64(input);
  if (input.size() == 2*NAME_HASH_SIZE && oxenc::is_hex(input))
    return name_hash_bytes_to_base64(oxenc::from_hex(input));
  if (input.size() >= NAME_HASH_SIZE_B64_MIN && input.size() <= NAME_HASH_SIZE_B64_MAX && oxenc::is_base64(input)) {
    std::string tmp = oxenc::from_base64(input);
    if (tmp.size() == NAME_HASH_SIZE) // Could still be off from too much/too little padding
      return name_hash_bytes_to_base64(tmp);
  }
  return std::nullopt;
}

static std::string hash_to_base64(crypto::hash const &hash)
{
  return name_hash_bytes_to_base64(tools::view_guts(hash));
}

static bool verify_ons_signature(crypto::hash const &hash, ons::generic_signature const &signature, ons::generic_owner const &owner)
{
  if (!owner || !signature) return false;
  if (owner.type != signature.type) return false;
  if (signature.type == ons::generic_owner_sig_type::monero)
  {
    return crypto::check_signature(hash, owner.wallet.address.m_spend_public_key, signature.monero);
  }
  else
  {
    return (crypto_sign_verify_detached(signature.data, reinterpret_cast<unsigned char const *>(hash.data), sizeof(hash.data), owner.ed25519.data) == 0);
  }
}

static bool validate_against_previous_mapping(ons::name_system_db &ons_db, uint64_t blockchain_height, cryptonote::transaction const &tx, cryptonote::tx_extra_oxen_name_system const &ons_extra, std::string *reason)
{
  std::stringstream err_stream;
  OXEN_DEFER { if (reason && reason->empty()) *reason = err_stream.str(); };

  crypto::hash expected_prev_txid = crypto::null_hash;
  std::string name_hash           = hash_to_base64(ons_extra.name_hash);
  ons::mapping_record mapping     = ons_db.get_mapping(ons_extra.type, name_hash);

  if (ons_extra.is_updating())
  {
    // Updating: the mapping must exist and be active, the updated fields must actually change from
    // the current value, and a valid signature over the updated values must be present.

    if (check_condition(!mapping, reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), " update requested but mapping does not exist."))
      return false;
    if (check_condition(!mapping.active(blockchain_height), reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), " TX requested to update mapping that has already expired"))
      return false;
    expected_prev_txid = mapping.txid;

    constexpr auto SPECIFYING_SAME_VALUE_ERR = " field to update is specifying the same mapping "sv;
    if (check_condition(ons_extra.field_is_set(ons::extra_field::encrypted_value) && ons_extra.encrypted_value == mapping.encrypted_value.to_view(), reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), SPECIFYING_SAME_VALUE_ERR, "value"))
      return false;

    if (check_condition(ons_extra.field_is_set(ons::extra_field::owner) && ons_extra.owner == mapping.owner, reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), SPECIFYING_SAME_VALUE_ERR, "owner"))
      return false;

    if (check_condition(ons_extra.field_is_set(ons::extra_field::backup_owner) && ons_extra.backup_owner == mapping.backup_owner, reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), SPECIFYING_SAME_VALUE_ERR, "backup_owner"))
      return false;

    // Validate signature
    auto data = tx_extra_signature(
        ons_extra.encrypted_value,
        ons_extra.field_is_set(ons::extra_field::owner) ? &ons_extra.owner : nullptr,
        ons_extra.field_is_set(ons::extra_field::backup_owner) ? &ons_extra.backup_owner : nullptr,
        expected_prev_txid);
    if (check_condition(data.empty(), reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), " unexpectedly failed to generate signature, please inform the Loki developers"))
      return false;

    crypto::hash hash;
    crypto_generichash(reinterpret_cast<unsigned char*>(hash.data), sizeof(hash), reinterpret_cast<const unsigned char*>(data.data()), data.size(), nullptr /*key*/, 0 /*key_len*/);

    if (check_condition(!verify_ons_signature(hash, ons_extra.signature, mapping.owner) &&
                        !verify_ons_signature(hash, ons_extra.signature, mapping.backup_owner), reason,
                        tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), " failed to verify signature for ONS update, current owner=", mapping.owner.to_string(ons_db.network_type()), ", backup owner=", mapping.backup_owner.to_string(ons_db.network_type())))
      return false;
  }
  else if (ons_extra.is_buying())
  {
    // If buying a new name then the existing name must not be active
    if (check_condition(mapping.active(blockchain_height), reason,
          "Cannot buy an ONS name that is already registered: name_hash=", mapping.name_hash, ", type=", mapping.type,
          "; TX: ", tx, "; ", ons_extra_string(ons_db.network_type(), ons_extra)))
        return false;

    // If buying a new wallet name then the existing session name must not be active and vice versa
    // The owner of an existing name but different type is allowed to register but the owner and backup owners
    // of the new mapping must be from the same owners and backup owners of the previous mapping ie no
    // new addresses are allowed to be added as owner or backup owner.
    if (ons_extra.type == mapping_type::wallet)
    {
      ons::mapping_record session_mapping = ons_db.get_mapping(mapping_type::session, name_hash);
      if (check_condition(session_mapping.active(blockchain_height) && (!(session_mapping.owner == ons_extra.owner || session_mapping.backup_owner == ons_extra.owner) || !(!ons_extra.field_is_set(ons::extra_field::backup_owner) || session_mapping.backup_owner == ons_extra.backup_owner || session_mapping.owner == ons_extra.backup_owner)), reason,
            "Cannot buy an ONS wallet name that has an already registered session name: name_hash=", mapping.name_hash, ", type=", mapping.type,
            "; TX: ", tx, "; ", ons_extra_string(ons_db.network_type(), ons_extra)))
          return false;
    } else if (ons_extra.type == mapping_type::session) {
      ons::mapping_record wallet_mapping = ons_db.get_mapping(mapping_type::wallet, name_hash);
      if (check_condition(wallet_mapping.active(blockchain_height) && (!(wallet_mapping.owner == ons_extra.owner || wallet_mapping.backup_owner == ons_extra.owner) || !(!ons_extra.field_is_set(ons::extra_field::backup_owner) || wallet_mapping.backup_owner == ons_extra.backup_owner || wallet_mapping.owner == ons_extra.backup_owner)), reason,
            "Cannot buy an ONS session name that has an already registered wallet name: name_hash=", mapping.name_hash, ", type=", mapping.type,
            "; TX: ", tx, "; ", ons_extra_string(ons_db.network_type(), ons_extra)))
          return false;
    }
  }
  else if (ons_extra.is_renewing())
  {
    // We allow anyone to renew a name, but it has to exist and be currently active
    if (check_condition(!mapping, reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), " renewal requested but mapping does not exist."))
      return false;
    if (check_condition(!mapping.active(blockchain_height), reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), " TX requested to renew mapping that has already expired"))
      return false;
    expected_prev_txid = mapping.txid;
  }
  else
  {
    check_condition(true, reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), " is not a valid buy, update, or renew ONS tx");
    return false;
  }

  if (check_condition(ons_extra.prev_txid != expected_prev_txid, reason, tx, ", ", ons_extra_string(ons_db.network_type(), ons_extra), " specified prior txid=", ons_extra.prev_txid, ", but ONS DB reports=", expected_prev_txid, ", possible competing TX was submitted and accepted before this TX was processed"))
    return false;

  return true;
}

// Sanity check value to disallow the empty name hash
static const crypto::hash null_name_hash = name_to_hash("");

bool name_system_db::validate_ons_tx(hf hf_version, uint64_t blockchain_height, cryptonote::transaction const &tx, cryptonote::tx_extra_oxen_name_system &ons_extra, std::string *reason)
{
  // -----------------------------------------------------------------------------------------------
  // Pull out ONS Extra from TX
  // -----------------------------------------------------------------------------------------------
  {
    if (check_condition(tx.type != cryptonote::txtype::oxen_name_system, reason, tx, ", uses wrong tx type, expected=", cryptonote::txtype::oxen_name_system))
      return false;

    if (check_condition(!cryptonote::get_field_from_tx_extra(tx.extra, ons_extra), reason, tx, ", didn't have oxen name service in the tx_extra"))
      return false;
  }


  // -----------------------------------------------------------------------------------------------
  // Check TX ONS Serialized Fields are NULL if they are not specified
  // -----------------------------------------------------------------------------------------------
  {
    constexpr auto VALUE_SPECIFIED_BUT_NOT_REQUESTED = ", given field but field is not requested to be serialised="sv;
    if (check_condition(!ons_extra.field_is_set(ons::extra_field::encrypted_value) && ons_extra.encrypted_value.size(), reason, tx, ", ", ons_extra_string(nettype, ons_extra), VALUE_SPECIFIED_BUT_NOT_REQUESTED, "encrypted_value"))
      return false;

    if (check_condition(!ons_extra.field_is_set(ons::extra_field::owner) && ons_extra.owner, reason, tx, ", ", ons_extra_string(nettype, ons_extra), VALUE_SPECIFIED_BUT_NOT_REQUESTED, "owner"))
      return false;

    if (check_condition(!ons_extra.field_is_set(ons::extra_field::backup_owner) && ons_extra.backup_owner, reason, tx, ", ", ons_extra_string(nettype, ons_extra), VALUE_SPECIFIED_BUT_NOT_REQUESTED, "backup_owner"))
      return false;

    if (check_condition(!ons_extra.field_is_set(ons::extra_field::signature) && ons_extra.signature, reason, tx, ", ", ons_extra_string(nettype, ons_extra), VALUE_SPECIFIED_BUT_NOT_REQUESTED, "signature"))
      return false;
  }

  // -----------------------------------------------------------------------------------------------
  // Simple ONS Extra Validation
  // -----------------------------------------------------------------------------------------------
  {
    if (check_condition(ons_extra.version != 0, reason, tx, ", ", ons_extra_string(nettype, ons_extra), " unexpected version=", std::to_string(ons_extra.version), ", expected=0"))
      return false;

    if (check_condition(!ons::mapping_type_allowed(hf_version, ons_extra.type), reason, tx, ", ", ons_extra_string(nettype, ons_extra), " specifying type=", ons_extra.type, " is disallowed in HF", +static_cast<uint8_t>(hf_version)))
      return false;

    // -----------------------------------------------------------------------------------------------
    // Serialized Values Check
    // -----------------------------------------------------------------------------------------------
    if (check_condition(!ons_extra.is_buying() && !ons_extra.is_updating() && !ons_extra.is_renewing(), reason, tx, ", ", ons_extra_string(nettype, ons_extra), " TX extra does not specify valid combination of bits for serialized fields=", std::bitset<sizeof(ons_extra.fields) * 8>(static_cast<size_t>(ons_extra.fields)).to_string()))
      return false;

    if (check_condition(ons_extra.field_is_set(ons::extra_field::owner) &&
                        ons_extra.field_is_set(ons::extra_field::backup_owner) &&
                        ons_extra.owner == ons_extra.backup_owner,
                        reason, tx, ", ", ons_extra_string(nettype, ons_extra), " specifying owner the same as the backup owner=", ons_extra.backup_owner.to_string(nettype)))
    {
      return false;
    }
   }

  // -----------------------------------------------------------------------------------------------
  // ONS Field(s) Validation
  // -----------------------------------------------------------------------------------------------
  {
    if (check_condition((ons_extra.name_hash == null_name_hash || ons_extra.name_hash == crypto::null_hash), reason, tx, ", ", ons_extra_string(nettype, ons_extra), " specified the null name hash"))
        return false;

    if (ons_extra.field_is_set(ons::extra_field::encrypted_value))
    {
      if (!mapping_value::validate_encrypted(ons_extra.type, ons_extra.encrypted_value, nullptr, reason))
        return false;
    }

    if (!validate_against_previous_mapping(*this, blockchain_height, tx, ons_extra, reason))
      return false;


  }

  // -----------------------------------------------------------------------------------------------
  // Burn Validation
  // -----------------------------------------------------------------------------------------------
  {
    uint64_t burn                = cryptonote::get_burned_amount_from_tx_extra(tx.extra);
    uint64_t const burn_required = (ons_extra.is_buying() || ons_extra.is_renewing()) ? burn_needed(hf_version, ons_extra.type) : 0;
    if (hf_version == hf::hf18 && burn > burn_required && blockchain_height < 524'000) {
        // Testnet sync fix: PR #1433 merged that lowered fees for HF18 while testnet was already on
        // HF18, but broke syncing because earlier HF18 blocks have ONS txes at the higher fees, so
        // this allows them to pass by pretending the tx burned the right amount.
        burn = burn_required;
    }

    if (burn != burn_required)
    {
      char const *over_or_under = burn > burn_required ? "too much " : "insufficient ";
      if (check_condition(true, reason, tx, ", ", ons_extra_string(nettype, ons_extra), " burned ", over_or_under, "oxen=", burn, ", require=", burn_required))
        return false;
    }
  }

  return true;
}

bool validate_mapping_type(std::string_view mapping_type_str, hf hf_version, ons_tx_type txtype, ons::mapping_type *mapping_type, std::string *reason)
{
  std::string mapping = tools::lowercase_ascii_string(mapping_type_str);
  std::optional<ons::mapping_type> mapping_type_;
  if (txtype != ons_tx_type::renew && tools::string_iequal(mapping, "session"))
    mapping_type_ = ons::mapping_type::session;
  else if (hf_version >= hf::hf16_pulse)
  {
    if (tools::string_iequal(mapping, "lokinet"))
      mapping_type_ = ons::mapping_type::lokinet;
    else if (txtype == ons_tx_type::buy || txtype == ons_tx_type::renew)
    {
      if (tools::string_iequal_any(mapping, "lokinet_1y", "lokinet_1years")) // Can also specify "lokinet"
        mapping_type_ = ons::mapping_type::lokinet;
      else if (tools::string_iequal_any(mapping, "lokinet_2y", "lokinet_2years"))
        mapping_type_ = ons::mapping_type::lokinet_2years;
      else if (tools::string_iequal_any(mapping, "lokinet_5y", "lokinet_5years"))
        mapping_type_ = ons::mapping_type::lokinet_5years;
      else if (tools::string_iequal_any(mapping, "lokinet_10y", "lokinet_10years"))
        mapping_type_ = ons::mapping_type::lokinet_10years;
    }
  }
  if (hf_version >= hf::hf18)
  {
    if (tools::string_iequal(mapping, "wallet"))
      mapping_type_ = ons::mapping_type::wallet;
  }

  if (!mapping_type_)
  {
    if (reason) *reason = "Unsupported ONS type \"" + std::string{mapping_type_str} + "\"; supported " + (
        txtype == ons_tx_type::update ? "update types are: session, lokinet, wallet" :
        txtype == ons_tx_type::renew  ? "renew types are: lokinet_1y, lokinet_2y, lokinet_5y, lokinet_10y" :
        txtype == ons_tx_type::buy    ? "buy types are session, lokinet_1y, lokinet_2y, lokinet_5y, lokinet_10y"
                                      : "lookup types are session, lokinet, wallet");
    return false;
  }

  if (mapping_type) *mapping_type = *mapping_type_;
  return true;
}

crypto::hash name_to_hash(std::string_view name, const std::optional<crypto::hash>& key)
{
  assert(std::none_of(name.begin(), name.end(), [](char c) { return std::isupper(c); }));
  crypto::hash result = {};
  static_assert(sizeof(result) >= crypto_generichash_BYTES, "Sodium can generate arbitrary length hashes, but recommend the minimum size for a secure hash must be >= crypto_generichash_BYTES");
  crypto_generichash_blake2b(reinterpret_cast<unsigned char *>(result.data),
                             sizeof(result),
                             reinterpret_cast<const unsigned char *>(name.data()),
                             static_cast<unsigned long long>(name.size()),
                             key ? reinterpret_cast<const unsigned char*>(key->data) : nullptr,
                             key ? sizeof(key->data) : 0);
  return result;
}

std::string name_to_base64_hash(std::string_view name)
{
  crypto::hash hash  = name_to_hash(name);
  std::string result = hash_to_base64(hash);
  return result;
}

struct alignas(size_t) secretbox_secret_key {
  unsigned char data[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

  secretbox_secret_key& operator=(const crypto::hash& h) {
    static_assert(sizeof(secretbox_secret_key::data) == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    std::memcpy(data, h.data, sizeof(data));
    return *this;
  }
};

// New (8.x):
// We encrypt using xchacha20-poly1305; for the encryption key we use the (secret) keyed hash:
// H(name, key=H(name)).  Note that H(name) is public info but this keyed hash is known only to the
// resolver.
//
// Note that the name must *already* be lower-cased (we do not transform or validate that here).
//
// If the name hash is already available then it can be passed by pointer as the second argument,
// otherwise pass nullptr to calculate the hash when needed.  (Note that name_hash is not used when
// heavy=true).
static void name_to_encryption_key(std::string_view name, const crypto::hash* name_hash, secretbox_secret_key &out)
{
  static_assert(sizeof(out) == crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "Encrypting key needs to have sufficient space for running encryption functions via libsodium");

  crypto::hash name_hash_;
  if (!name_hash)
    name_hash = &(name_hash_ = name_to_hash(name));

  out = name_to_hash(name, *name_hash);
}

// Old (7.x) "heavy" encryption:
//
// We encrypt using the older xsalsa20-poly1305 encryption scheme, and for encryption key we use an
// expensive argon2 "moderate" hash of the name (with null salt).
static constexpr unsigned char OLD_ENC_SALT[crypto_pwhash_SALTBYTES] = {};
static bool name_to_encryption_key_argon2(std::string_view name, secretbox_secret_key &out)
{
  static_assert(sizeof(out) == crypto_secretbox_KEYBYTES, "Encrypting key needs to have sufficient space for running encryption functions via libsodium");
  return 0 == crypto_pwhash(
      out.data, sizeof(out.data),
      name.data(), name.size(),
      OLD_ENC_SALT,
      crypto_pwhash_OPSLIMIT_MODERATE,
      crypto_pwhash_MEMLIMIT_MODERATE,
      crypto_pwhash_ALG_ARGON2ID13);
}

bool mapping_value::encrypt(std::string_view name, const crypto::hash* name_hash, bool deprecated_heavy)
{
  assert(!encrypted);
  if (encrypted) return false;

  assert(std::none_of(name.begin(), name.end(), [](char c) { return std::isupper(c); }));

  size_t const encryption_len = len + (deprecated_heavy
      ? crypto_secretbox_MACBYTES
      : crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  if (encryption_len > buffer.size())
  {
    MERROR("Encrypted value pre-allocated buffer too small=" << buffer.size() << ", required=" << encryption_len);
    return false;
  }

  decltype(buffer) enc_buffer;
  secretbox_secret_key skey;
  if (deprecated_heavy)
  {
    if (name_to_encryption_key_argon2(name, skey))
      encrypted = (crypto_secretbox_easy(
            enc_buffer.data(),
            buffer.data(), len,
            OLD_ENCRYPTION_NONCE,
            skey.data) == 0);
  }
  else
  {
    name_to_encryption_key(name, name_hash, skey);
    unsigned long long actual_length;

    // Create a random nonce:
    auto* nonce = &enc_buffer[encryption_len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    encrypted = 0 == crypto_aead_xchacha20poly1305_ietf_encrypt(
        &enc_buffer[0], &actual_length,
        &buffer[0], len,
        nullptr, 0, // additional data
        nullptr, // nsec, always nullptr according to libsodium docs (just here for API compat)
        nonce,
        skey.data);

    if (encrypted) assert(actual_length == encryption_len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  }

  if (encrypted)
  {
    len = encryption_len;
    buffer = enc_buffer;
  }
  return encrypted;
}

bool mapping_value::decrypt(std::string_view name, mapping_type type, const crypto::hash* name_hash)
{
  assert(encrypted);
  if (!encrypted) return false;

  assert(std::none_of(name.begin(), name.end(), [](char c) { return std::isupper(c); }));

  size_t dec_length;
  decltype(buffer) dec_buffer;
  secretbox_secret_key skey;

  // Check for an old-style, argon2-based encryption, used before HF16.  (After HF16 we use a much
  // faster blake2b-hashed key, and a random nonce appended to the end.)
  if (type == mapping_type::session && len == SESSION_PUBLIC_KEY_BINARY_LENGTH + crypto_secretbox_MACBYTES)
  {
    dec_length = SESSION_PUBLIC_KEY_BINARY_LENGTH;
    encrypted = !(name_to_encryption_key_argon2(name, skey) &&
        0 == crypto_secretbox_open_easy(dec_buffer.data(), buffer.data(), len, OLD_ENCRYPTION_NONCE, skey.data));
  }
  else
  {
    switch(type) {
      case mapping_type::session: dec_length = SESSION_PUBLIC_KEY_BINARY_LENGTH; break;
      case mapping_type::lokinet: dec_length = LOKINET_ADDRESS_BINARY_LENGTH; break;
      case mapping_type::wallet: //Wallet type has variable type, check performed in check_length
        if (auto plain_len = len - crypto_aead_xchacha20poly1305_ietf_ABYTES - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
            plain_len == WALLET_ACCOUNT_BINARY_LENGTH_INC_PAYMENT_ID || plain_len == WALLET_ACCOUNT_BINARY_LENGTH_NO_PAYMENT_ID) {
          dec_length = plain_len;
        } else {
          MERROR("Invalid wallet mapping_type length passed to mapping_value::decrypt");
          return false;
        }
        break;
      default: MERROR("Invalid mapping_type passed to mapping_value::decrypt");
      return false;
    }

    auto expected_len = dec_length + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (len != expected_len)
    {
      MERROR("Encrypted value size is invalid=" << len << ", expected=" << expected_len);
      return false;
    }
    const auto& [enc, nonce] = value_nonce(type);

    name_to_encryption_key(name, name_hash, skey);
    unsigned long long actual_length;
    encrypted = !(0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
          dec_buffer.data(), &actual_length,
          nullptr, // nsec (always null for this algo)
          enc.data(), enc.size(),
          nullptr, 0, // additional data
          nonce.data(),
          skey.data));

    if (!encrypted) assert(actual_length == dec_length);
  }

  if (!encrypted) // i.e. decryption success
  {
    len = dec_length;
    buffer = dec_buffer;
  }
  return !encrypted;
}

mapping_value mapping_value::make_encrypted(std::string_view name, const crypto::hash* name_hash, bool deprecated_heavy) const
{
  mapping_value result{*this};
  result.encrypt(name, name_hash, deprecated_heavy);
  assert(result.encrypted);
  return result;
}

mapping_value mapping_value::make_decrypted(std::string_view name, const crypto::hash* name_hash) const
{
  mapping_value result{*this};
  result.encrypt(name, name_hash);
  assert(!result.encrypted);
  return result;
}

std::optional<cryptonote::address_parse_info> mapping_value::get_wallet_address_info() const
{
  assert(!encrypted);
  if (encrypted) return std::nullopt;

  cryptonote::address_parse_info addr_info{};
  auto* bufpos = &buffer[1];
  std::memcpy(&addr_info.address.m_spend_public_key.data, bufpos, 32);
  bufpos += 32;
  std::memcpy(&addr_info.address.m_view_public_key.data, bufpos, 32);
  if (buffer[0] == ONS_WALLET_TYPE_INTEGRATED) {
    bufpos += 32;
    std::copy_n(bufpos,8,addr_info.payment_id.data);
    addr_info.has_payment_id = true;
  } else if (buffer[0] == ONS_WALLET_TYPE_SUBADDRESS) {
    addr_info.is_subaddress = true;
  } else assert(buffer[0] == ONS_WALLET_TYPE_PRIMARY);
  return addr_info;
}

namespace {

bool build_default_tables(name_system_db& ons_db)
{
  std::string mappings_columns = R"(
    id INTEGER PRIMARY KEY NOT NULL,
    type INTEGER NOT NULL,
    name_hash VARCHAR NOT NULL,
    encrypted_value BLOB NOT NULL,
    txid BLOB NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES owner(id),
    backup_owner_id INTEGER REFERENCES owner(id),
    update_height INTEGER NOT NULL,
    expiration_height INTEGER
)";

  const std::string BUILD_TABLE_SQL = R"(
CREATE TABLE IF NOT EXISTS owner(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address BLOB NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY NOT NULL,
    top_height INTEGER NOT NULL,
    top_hash VARCHAR NOT NULL,
    version INTEGER NOT NULL,
    pruned_height INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mappings ()" + mappings_columns + R"();
CREATE INDEX IF NOT EXISTS owner_id_index ON mappings(owner_id);
DROP INDEX IF EXISTS backup_owner_id_index;
CREATE INDEX IF NOT EXISTS backup_owner_index ON mappings(backup_owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS name_type_update ON mappings (name_hash, type, update_height DESC);
CREATE INDEX IF NOT EXISTS mapping_type_name_exp ON mappings (type, name_hash, expiration_height DESC);
)";

  char *table_err_msg = nullptr;
  int table_created   = sqlite3_exec(ons_db.db, BUILD_TABLE_SQL.c_str(), nullptr /*callback*/, nullptr /*callback context*/, &table_err_msg);
  if (table_created != SQLITE_OK)
  {
    MERROR("Can not generate SQL table for ONS: " << (table_err_msg ? table_err_msg : "??"));
    sqlite3_free(table_err_msg);
    return false;
  }

  // In Loki 8 we dropped some columns that are no longer needed, but SQLite can't do this easily:
  // instead we have to manually recreate the table, so check it and see if the prev_txid or
  // register_height columns still exist: if so, we need to recreate.
  bool need_mappings_migration = false;
  {
    sql_compiled_statement mappings_info{ons_db};
    mappings_info.compile("PRAGMA table_info(mappings)", false);
    while (step(mappings_info) == SQLITE_ROW)
    {
      auto name = get<std::string_view>(mappings_info, 1);
      if (name == "prev_txid" || name == "register_height")
      {
        need_mappings_migration = true;
        break;
      }
    }
  }

  if (need_mappings_migration)
  {
    // Earlier version migration: we need "update_height" to exist (if this fails it's fine).
    sqlite3_exec(ons_db.db,
        "ALTER TABLE mappings ADD COLUMN update_height INTEGER NOT NULL DEFAULT register_height",
        nullptr /*callback*/, nullptr /*callback ctx*/, nullptr /*errstr*/);

    LOG_PRINT_L1("Migrating ONS mappings database to new format");
    const std::string migrate = R"(
BEGIN TRANSACTION;
ALTER TABLE mappings RENAME TO mappings_old;
CREATE TABLE mappings ()" + mappings_columns + R"();
INSERT INTO mappings
  SELECT id, type, name_hash, encrypted_value, txid, owner_id, backup_owner_id, update_height, NULL
  FROM mappings_old;
DROP TABLE mappings_old;
CREATE UNIQUE INDEX name_type_update ON mappings(name_hash, type, update_height DESC);
CREATE INDEX owner_id_index ON mappings(owner_id);
CREATE INDEX backup_owner_index ON mappings(backup_owner_id);
CREATE INDEX mapping_type_name_exp ON mappings(type, name_hash, expiration_height DESC);
COMMIT TRANSACTION;
)";

    int migrated = sqlite3_exec(ons_db.db, migrate.c_str(), nullptr /*callback*/, nullptr /*callback context*/, &table_err_msg);
    if (migrated != SQLITE_OK)
    {
      MERROR("Can not migrate SQL mappings table for ONS: " << (table_err_msg ? table_err_msg : "??"));
      sqlite3_free(table_err_msg);
      return false;
    }
  }

  // Updates to add columns; we ignore errors on these since they will fail if the column already
  // exists
  for (const auto& upgrade : {
    "ALTER TABLE settings ADD COLUMN pruned_height INTEGER NOT NULL DEFAULT 0",
  }) {
    sqlite3_exec(ons_db.db, upgrade, nullptr /*callback*/, nullptr /*callback ctx*/, nullptr /*errstr*/);
  }


  return true;
}

const std::string sql_select_mappings_and_owners_prefix = R"(
SELECT mappings.*, o1.address, o2.address, MAX(update_height)
FROM mappings
  JOIN owner o1 ON mappings.owner_id = o1.id
  LEFT JOIN owner o2 ON mappings.backup_owner_id = o2.id
)"s;
const std::string sql_select_mappings_and_owners_suffix = " GROUP BY name_hash, type";

struct scoped_db_transaction
{
  scoped_db_transaction(name_system_db &ons_db);
  ~scoped_db_transaction();
  operator bool() const { return initialised; }
  name_system_db &ons_db;
  bool commit      = false; // If true, on destruction- END the transaction otherwise ROLLBACK all SQLite events prior for the ons_db
  bool initialised = false;
};

scoped_db_transaction::scoped_db_transaction(name_system_db &ons_db)
: ons_db(ons_db)
{
  if (ons_db.transaction_begun)
  {
    MERROR("Failed to begin transaction, transaction exists previously that was not closed properly");
    return;
  }

  char *sql_err = nullptr;
  if (sqlite3_exec(ons_db.db, "BEGIN;", nullptr, nullptr, &sql_err) != SQLITE_OK)
  {
    MERROR("Failed to begin transaction " << ", reason=" << (sql_err ? sql_err : "??"));
    sqlite3_free(sql_err);
    return;
  }

  initialised              = true;
  ons_db.transaction_begun = true;
}

scoped_db_transaction::~scoped_db_transaction()
{
  if (!initialised) return;
  if (!ons_db.transaction_begun)
  {
    MERROR("Trying to apply non-existent transaction (no prior history of a db transaction beginning) to the ONS DB");
    return;
  }

  char *sql_err = nullptr;
  if (sqlite3_exec(ons_db.db, commit ? "END;" : "ROLLBACK;", NULL, NULL, &sql_err) != SQLITE_OK)
  {
    MERROR("Failed to " << (commit ? "end " : "rollback ") << " transaction to ONS DB, reason=" << (sql_err ? sql_err : "??"));
    sqlite3_free(sql_err);
    return;
  }

  ons_db.transaction_begun = false;
}


enum struct db_version { v0, v1_track_updates, v2_full_rows };
auto constexpr DB_VERSION = db_version::v2_full_rows;

constexpr auto EXPIRATION = " (expiration_height IS NULL OR expiration_height >= ?) "sv;

} // anon. namespace

bool name_system_db::init(cryptonote::Blockchain const *blockchain, cryptonote::network_type nettype, sqlite3 *db)
{
  if (!db) return false;
  this->db      = db;
  this->nettype = nettype;

  std::string const GET_MAPPINGS_BY_OWNER_STR = sql_select_mappings_and_owners_prefix
    + "WHERE ? IN (o1.address, o2.address)"
    + sql_select_mappings_and_owners_suffix;
  std::string const GET_MAPPING_STR           = sql_select_mappings_and_owners_prefix
    + "WHERE type = ? AND name_hash = ?"
    + sql_select_mappings_and_owners_suffix;

  const std::string GET_MAPPING_COUNTS_STR = R"(
    SELECT type, COUNT(*) FROM (
      SELECT DISTINCT type, name_hash FROM mappings WHERE )" + std::string{EXPIRATION} + R"(
    )
    GROUP BY type)";

  std::string const RESOLVE_STR = R"(
SELECT encrypted_value, MAX(update_height)
FROM mappings
WHERE type = ? AND name_hash = ? AND)" + std::string{EXPIRATION};

  constexpr auto GET_SETTINGS_STR     = "SELECT * FROM settings WHERE id = 1"sv;
  constexpr auto GET_OWNER_BY_ID_STR  = "SELECT * FROM owner WHERE id = ?"sv;
  constexpr auto GET_OWNER_BY_KEY_STR = "SELECT * FROM owner WHERE address = ?"sv;

  // Prune queries used when we need to rollback to remove records added after the detach point:
  constexpr auto PRUNE_MAPPINGS_STR   = "DELETE FROM mappings WHERE update_height >= ?"sv;
  constexpr auto PRUNE_OWNERS_STR = R"(
DELETE FROM owner
WHERE NOT EXISTS (SELECT * FROM mappings WHERE owner.id = mappings.owner_id)
AND NOT EXISTS   (SELECT * FROM mappings WHERE owner.id = mappings.backup_owner_id))"sv;

  constexpr auto SAVE_MAPPING_STR  = "INSERT INTO mappings (type, name_hash, encrypted_value, txid, owner_id, backup_owner_id, update_height, expiration_height) VALUES (?,?,?,?,?,?,?,?)"sv;
  constexpr auto SAVE_OWNER_STR    = "INSERT INTO owner (address) VALUES (?)"sv;
  constexpr auto SAVE_SETTINGS_STR = "INSERT OR REPLACE INTO settings (id, top_height, top_hash, version) VALUES (1,?,?,?)"sv;

  if (!build_default_tables(*this))
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
        MERROR("DB is opened in read-only mode, unable to migrate ONS DB");
        return false;
      }

      scoped_db_transaction db_transaction(*this);
      if (!db_transaction) return false;

      if (settings.version < static_cast<decltype(settings.version)>(db_version::v1_track_updates))
      {

        std::vector<mapping_record> all_mappings = {};
        {
          sql_compiled_statement st{*this};
          if (!st.compile(sql_select_mappings_and_owners_prefix + sql_select_mappings_and_owners_suffix))
            return false;
          sql_run_statement(ons_sql_type::get_mappings, st, &all_mappings);
        }

        std::vector<crypto::hash> hashes;
        hashes.reserve(all_mappings.size());
        for (mapping_record const &record: all_mappings)
            hashes.push_back(record.txid);

        constexpr auto UPDATE_MAPPING_HEIGHT = "UPDATE mappings SET update_height = ? WHERE id = ?"sv;
        sql_compiled_statement update_mapping_height{*this};
        if (!update_mapping_height.compile(UPDATE_MAPPING_HEIGHT, false))
          return false;

        std::vector<uint64_t> heights = blockchain->get_transactions_heights(hashes);
        for (size_t i = 0; i < all_mappings.size(); i++)
        {

          bind_and_run(ons_sql_type::internal_cmd, update_mapping_height, nullptr,
              heights[i], all_mappings[i].id);
        }
      }

      if (settings.version < static_cast<decltype(settings.version)>(db_version::v2_full_rows))
      {
        sql_compiled_statement prune_height{*this};
        if (!prune_height.compile("UPDATE settings SET pruned_height = (SELECT MAX(update_height) FROM mappings)", false))
          return false;

        if (step(prune_height) != SQLITE_DONE)
          return false;
      }

      save_settings(settings.top_height, settings.top_hash, static_cast<int>(db_version::v2_full_rows));
      db_transaction.commit = true;
    }
  }

  // ---------------------------------------------------------------------------
  //
  // Prepare commonly executed sql statements
  //
  // ---------------------------------------------------------------------------
  if (!get_mappings_by_owner_sql.compile(GET_MAPPINGS_BY_OWNER_STR) ||
      !get_mapping_sql.compile(GET_MAPPING_STR) ||
      !get_mapping_counts_sql.compile(GET_MAPPING_COUNTS_STR) ||
      !resolve_sql.compile(RESOLVE_STR) ||
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
      assert(nettype == cryptonote::network_type::FAKECHAIN);
      return nettype == cryptonote::network_type::FAKECHAIN;
    }

    uint64_t ons_height   = 0;
    crypto::hash ons_hash = blockchain->get_tail_id(ons_height);

    // Try support out of date ONS databases by checking if the stored
    // settings->[top_hash|top_height] match what we expect. If they match, we
    // don't drop the DB but will load the missing blocks in a later step.

    cryptonote::block ons_blk = {};
    bool orphan               = false;
    if (blockchain->get_block_by_hash(settings.top_hash, ons_blk, &orphan))
    {
      bool ons_height_matches = settings.top_height == cryptonote::get_block_height(ons_blk);
      if (ons_height_matches && !orphan)
      {
        ons_height = settings.top_height;
        ons_hash   = settings.top_hash;
      }
    }

    if (settings.top_height == ons_height && settings.top_hash == ons_hash)
    {
      this->last_processed_height = settings.top_height;
      this->last_processed_hash   = settings.top_hash;
      assert(settings.version == static_cast<int>(DB_VERSION));
    }
    else
    {
      // Otherwise we've got something unrecoverable: a top_hash + top_height that are different
      // from what we have in the blockchain, which means the ons db and blockchain are out of sync.
      // This likely means something external changed the lmdb and/or the ons.db, and we can't
      // recover from it: so just drop and recreate the tables completely and rescan from scratch.

      char constexpr DROP_TABLE_SQL[] = "DROP TABLE IF EXISTS owner; DROP TABLE IF EXISTS settings; DROP TABLE IF EXISTS mappings";
      sqlite3_exec(db, DROP_TABLE_SQL, nullptr /*callback*/, nullptr /*callback context*/, nullptr);
      if (!build_default_tables(*this)) return false;
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

namespace {

std::optional<int64_t> add_or_get_owner_id(ons::name_system_db &ons_db, crypto::hash const &tx_hash, cryptonote::tx_extra_oxen_name_system const &entry, ons::generic_owner const &key)
{
  int64_t result = 0;
  if (owner_record owner = ons_db.get_owner_by_key(key)) result = owner.id;
  if (result == 0)
  {
    if (!ons_db.save_owner(key, &result))
    {
      LOG_PRINT_L1("Failed to save ONS owner to DB tx: " << tx_hash << ", type: " << entry.type << ", name_hash: " << entry.name_hash << ", owner: " << entry.owner.to_string(ons_db.network_type()));
      return std::nullopt;
    }
  }
  if (result == 0)
    return std::nullopt;
  return result;
}

// Build a query and bind values that will create a new row at the given height by copying the
// current highest-height row values and/or updating the given update fields.
using update_variant = std::variant<uint16_t, int64_t, uint64_t, blob_view, std::string>;
std::pair<std::string, std::vector<update_variant>> update_record_query(name_system_db& ons_db, uint64_t height, const cryptonote::tx_extra_oxen_name_system& entry, const crypto::hash& tx_hash)
{
  assert(entry.is_updating() || entry.is_renewing());

  std::pair<std::string, std::vector<update_variant>> result;
  auto& [sql, bind] = result;

  sql.reserve(500);
  sql += R"(
INSERT INTO mappings (type, name_hash, txid, update_height, expiration_height, owner_id, backup_owner_id, encrypted_value)
SELECT                type, name_hash, ?,    ?)";

  bind.emplace_back(blob_view{tx_hash.data, sizeof(tx_hash)});
  bind.emplace_back(height);

  constexpr auto suffix = " FROM mappings WHERE type = ? AND name_hash = ? ORDER BY update_height DESC LIMIT 1"sv;

  if (entry.is_renewing())
  {
    sql += ", expiration_height + ?, owner_id, backup_owner_id, encrypted_value";
    bind.emplace_back(expiry_blocks(ons_db.network_type(), entry.type).value_or(0));
  }
  else
  {
    // Updating

    sql += ", expiration_height";

    if (entry.field_is_set(ons::extra_field::owner))
    {
      auto opt_id = add_or_get_owner_id(ons_db, tx_hash, entry, entry.owner);
      if (!opt_id)
      {
        MERROR("Failed to add or get owner with key=" << entry.owner.to_string(ons_db.network_type()));
        assert(opt_id);
        return {};
      }
      sql += ", ?";
      bind.emplace_back(*opt_id);
    }
    else
      sql += ", owner_id";

    if (entry.field_is_set(ons::extra_field::backup_owner))
    {
      auto opt_id = add_or_get_owner_id(ons_db, tx_hash, entry, entry.backup_owner);
      if (!opt_id)
      {
        MERROR("Failed to add or get backup owner with key=" << entry.backup_owner.to_string(ons_db.network_type()));
        assert(opt_id);
        return {};
      }

      sql += ", ?";
      bind.emplace_back(*opt_id);
    }
    else
      sql += ", backup_owner_id";

    if (entry.field_is_set(ons::extra_field::encrypted_value))
    {
      sql += ", ?";
      bind.emplace_back(blob_view{entry.encrypted_value});
    }
    else
      sql += ", encrypted_value";
  }

  sql += suffix;
  bind.emplace_back(db_mapping_type(entry.type));
  bind.emplace_back(hash_to_base64(entry.name_hash));

  return result;
}

bool add_ons_entry(ons::name_system_db &ons_db, uint64_t height, cryptonote::tx_extra_oxen_name_system const &entry, crypto::hash const &tx_hash)
{
  // -----------------------------------------------------------------------------------------------
  // New Mapping Insert or Completely Replace
  // -----------------------------------------------------------------------------------------------
  if (entry.is_buying())
  {
    auto owner_id = add_or_get_owner_id(ons_db, tx_hash, entry, entry.owner);
    if (!owner_id)
    {
      MERROR("Failed to add or get owner with key=" << entry.owner.to_string(ons_db.network_type()));
      assert(owner_id);
      return false;
    }

    std::optional<int64_t> backup_owner_id;
    if (entry.backup_owner)
    {
      backup_owner_id = add_or_get_owner_id(ons_db, tx_hash, entry, entry.backup_owner);
      if (!backup_owner_id)
      {
        MERROR("Failed to add or get backup owner with key=" << entry.backup_owner.to_string(ons_db.network_type()));
        assert(backup_owner_id);
        return false;
      }
    }

    auto expiry = expiry_blocks(ons_db.network_type(), entry.type);
    if (expiry) *expiry += height;
    if (!ons_db.save_mapping(tx_hash, entry, height, expiry, *owner_id, backup_owner_id))
    {
      LOG_PRINT_L1("Failed to save ONS entry to DB tx: " << tx_hash << ", type: " << entry.type << ", name_hash: " << entry.name_hash << ", owner: " << entry.owner.to_string(ons_db.network_type()));
      return false;
    }
  }
  // -----------------------------------------------------------------------------------------------
  // Update mapping or renewal: create a new row copies and updated from the existing top row
  // -----------------------------------------------------------------------------------------------
  else
  {
    auto [sql, bind] = update_record_query(ons_db, height, entry, tx_hash);

    if (sql.empty())
      return false; // already MERROR'd

    // Compile sql statement
    sql_compiled_statement statement{ons_db};
    if (!statement.compile(sql, false /*optimise_for_multiple_usage*/))
    {
      MERROR("Failed to compile SQL statement for updating ONS record=" << sql);
      return false;
    }

    // Bind statement parameters
    bind_container(statement, bind);

    if (!sql_run_statement(ons_sql_type::save_mapping, statement, nullptr))
      return false;
  }

  return true;
}

} // anon namespace

bool name_system_db::add_block(const cryptonote::block &block, const std::vector<cryptonote::transaction> &txs)
{
  uint64_t height = cryptonote::get_block_height(block);
  if (last_processed_height >= height)
      return true;

  scoped_db_transaction db_transaction(*this);
  if (!db_transaction)
   return false;

  bool ons_parsed_from_block = false;
  if (block.major_version >= hf::hf15_ons)
  {
    for (cryptonote::transaction const &tx : txs)
    {
      if (tx.type != cryptonote::txtype::oxen_name_system)
        continue;

      cryptonote::tx_extra_oxen_name_system entry = {};
      std::string fail_reason;
      if (!validate_ons_tx(block.major_version, height, tx, entry, &fail_reason))
      {
        MFATAL("ONS TX: Failed to validate for tx=" << get_transaction_hash(tx) << ". This should have failed validation earlier reason=" << fail_reason);
        assert("Failed to validate acquire name service. Should already have failed validation prior" == nullptr);
        return false;
      }

      crypto::hash const &tx_hash = cryptonote::get_transaction_hash(tx);
      if (!add_ons_entry(*this, height, entry, tx_hash))
        return false;

      ons_parsed_from_block = true;
    }
  }

  last_processed_height = height;
  last_processed_hash   = cryptonote::get_block_hash(block);
  if (ons_parsed_from_block)
  {
    save_settings(last_processed_height, last_processed_hash, static_cast<int>(DB_VERSION));
    db_transaction.commit = ons_parsed_from_block;
  }
  return true;
}

struct ons_update_history
{
  uint64_t value_last_update_height        = static_cast<uint64_t>(-1);
  uint64_t owner_last_update_height        = static_cast<uint64_t>(-1);
  uint64_t backup_owner_last_update_height = static_cast<uint64_t>(-1);

  void     update(uint64_t height, cryptonote::tx_extra_oxen_name_system const &ons_extra);
  uint64_t newest_update_height() const;
};

void ons_update_history::update(uint64_t height, cryptonote::tx_extra_oxen_name_system const &ons_extra)
{
  if (ons_extra.field_is_set(ons::extra_field::encrypted_value))
    value_last_update_height = height;

  if (ons_extra.field_is_set(ons::extra_field::owner))
    owner_last_update_height = height;

  if (ons_extra.field_is_set(ons::extra_field::backup_owner))
    backup_owner_last_update_height = height;
}

uint64_t ons_update_history::newest_update_height() const
{
  uint64_t result = std::max(std::max(value_last_update_height, owner_last_update_height), backup_owner_last_update_height);
  return result;
}

struct replay_ons_tx
{
  uint64_t                              height;
  crypto::hash                          tx_hash;
  cryptonote::tx_extra_oxen_name_system entry;
};

void name_system_db::block_detach(cryptonote::Blockchain const &blockchain, uint64_t new_blockchain_height)
{
  prune_db(new_blockchain_height);
}

bool name_system_db::save_owner(ons::generic_owner const &owner, int64_t *row_id)
{
  bool result = bind_and_run(ons_sql_type::save_owner, save_owner_sql, nullptr,
      blob_view{reinterpret_cast<const char*>(&owner), sizeof(owner)});

  if (row_id) *row_id = sqlite3_last_insert_rowid(db);
  return result;
}

bool name_system_db::save_mapping(crypto::hash const &tx_hash, cryptonote::tx_extra_oxen_name_system const &src, uint64_t height, std::optional<uint64_t> expiration, int64_t owner_id, std::optional<int64_t> backup_owner_id)
{
  if (!src.is_buying())
    return false;

  std::string name_hash = hash_to_base64(src.name_hash);
  auto& statement = save_mapping_sql;
  clear_bindings(statement);
  bind(statement, mapping_record_column::type, db_mapping_type(src.type));
  bind(statement, mapping_record_column::name_hash, name_hash);
  bind(statement, mapping_record_column::encrypted_value, blob_view{src.encrypted_value});
  bind(statement, mapping_record_column::txid, blob_view{tx_hash.data, sizeof(tx_hash)});
  bind(statement, mapping_record_column::update_height, height);
  bind(statement, mapping_record_column::expiration_height, expiration);
  bind(statement, mapping_record_column::owner_id, owner_id);
  bind(statement, mapping_record_column::backup_owner_id, backup_owner_id);

  bool result = sql_run_statement(ons_sql_type::save_mapping, statement, nullptr);
  return result;
}

bool name_system_db::save_settings(uint64_t top_height, crypto::hash const &top_hash, int version)
{
  auto& statement = save_settings_sql;
  bind(statement, ons_db_setting_column::top_height, top_height);
  bind(statement, ons_db_setting_column::top_hash, blob_view{top_hash.data, sizeof(top_hash)});
  bind(statement, ons_db_setting_column::version, version);
  bool result = sql_run_statement(ons_sql_type::save_setting, statement, nullptr);
  return result;
}

bool name_system_db::prune_db(uint64_t height)
{
  if (!bind_and_run(ons_sql_type::pruning, prune_mappings_sql, nullptr, height)) return false;
  if (!sql_run_statement(ons_sql_type::pruning, prune_owners_sql, nullptr)) return false;

  this->last_processed_height = (height - 1);
  return true;
}

owner_record name_system_db::get_owner_by_key(ons::generic_owner const &owner)
{
  owner_record result = {};
  result.loaded       = bind_and_run(ons_sql_type::get_owner, get_owner_by_key_sql, &result,
      blob_view{reinterpret_cast<const char*>(&owner), sizeof(owner)});
  return result;
}

owner_record name_system_db::get_owner_by_id(int64_t owner_id)
{
  owner_record result = {};
  result.loaded       = bind_and_run(ons_sql_type::get_owner, get_owner_by_id_sql, &result,
      owner_id);
  return result;
}

bool name_system_db::get_wallet_mapping(std::string str, uint64_t blockchain_height, cryptonote::address_parse_info& addr_info)
{
  std::string name = tools::lowercase_ascii_string(std::move(str));
  std::string b64_hashed_name = ons::name_to_base64_hash(name);
  if (auto record = name_system_db::resolve(mapping_type::wallet, b64_hashed_name, blockchain_height)){
    (*record).decrypt(name, mapping_type::wallet);
    std::optional<cryptonote::address_parse_info> addr = (*record).get_wallet_address_info();
    if(addr)
    {
      addr_info = *addr;
      return true;
    }
  }
  return false;
}



mapping_record name_system_db::get_mapping(mapping_type type, std::string_view name_base64_hash, std::optional<uint64_t> blockchain_height)
{
  assert(name_base64_hash.size() == 44 && name_base64_hash.back() == '=' && oxenc::is_base64(name_base64_hash));
  mapping_record result = {};
  result.loaded         = bind_and_run(ons_sql_type::get_mapping, get_mapping_sql, &result,
      db_mapping_type(type), name_base64_hash);
  if (blockchain_height && !result.active(*blockchain_height))
    result.loaded = false;
  return result;
}

std::optional<mapping_value> name_system_db::resolve(mapping_type type, std::string_view name_hash_b64, uint64_t blockchain_height)
{
  assert(name_hash_b64.size() == 44 && name_hash_b64.back() == '=' && oxenc::is_base64(name_hash_b64));
  std::optional<mapping_value> result;
  bind_all(resolve_sql, db_mapping_type(type), name_hash_b64, blockchain_height);
  if (step(resolve_sql) == SQLITE_ROW)
  {
    if (auto blob = get<std::optional<blob_view>>(resolve_sql, 0))
    {
      auto& r = result.emplace();
      assert(blob->data.size() <= r.buffer.size());
      r.len = blob->data.size();
      r.encrypted = true;
      std::copy(blob->data.begin(), blob->data.end(), r.buffer.begin());
    }
  }
  reset(resolve_sql);
  clear_bindings(resolve_sql);
  return result;
}

std::vector<mapping_record> name_system_db::get_mappings(std::vector<mapping_type> const &types, std::string_view name_base64_hash, std::optional<uint64_t> blockchain_height)
{
  assert(name_base64_hash.size() == 44 && name_base64_hash.back() == '=' && oxenc::is_base64(name_base64_hash));
  std::vector<mapping_record> result;
  if (types.empty())
    return result;

  std::string sql_statement;
  std::vector<std::variant<uint16_t, uint64_t, std::string_view>> bind;
  sql_statement.reserve(sql_select_mappings_and_owners_prefix.size() + EXPIRATION.size() + 70
      + sql_select_mappings_and_owners_suffix.size());
  sql_statement += sql_select_mappings_and_owners_prefix;
  sql_statement += "WHERE name_hash = ?";
  bind.emplace_back(name_base64_hash);

  // Generate string statement
  if (types.size())
  {
    sql_statement += " AND type IN (";

    for (size_t i = 0; i < types.size(); i++)
    {
      sql_statement += i > 0 ? ", ?" : "?";
      bind.emplace_back(db_mapping_type(types[i]));
    }
    sql_statement += ")";
  }

  if (blockchain_height)
  {
    sql_statement += " AND ";
    sql_statement += EXPIRATION;
    bind.emplace_back(*blockchain_height);
  }

  sql_statement += sql_select_mappings_and_owners_suffix;

  // Compile Statement
  sql_compiled_statement statement{*this};
  if (!statement.compile(sql_statement, false /*optimise_for_multiple_usage*/)
      || !bind_container(statement, bind))
    return result;

  // Execute
  sql_run_statement(ons_sql_type::get_mappings, statement, &result);

  return result;
}

std::vector<mapping_record> name_system_db::get_mappings_by_owners(std::vector<generic_owner> const &owners, std::optional<uint64_t> blockchain_height)
{
  std::string sql_statement;
  std::vector<std::variant<blob_view, uint64_t>> bind;
  // Generate string statement
  {
    constexpr auto SQL_WHERE_OWNER = "WHERE (o1.address IN ("sv;
    constexpr auto SQL_OR_BACKUP_OWNER  = ") OR o2.address IN ("sv;
    constexpr auto SQL_SUFFIX  = "))"sv;

    std::string placeholders;
    placeholders.reserve(3*owners.size());
    for (size_t i = 0; i < owners.size(); i++)
      placeholders += "?, ";
    if (owners.size() > 0)
      placeholders.resize(placeholders.size() - 2);

    sql_statement.reserve(sql_select_mappings_and_owners_prefix.size() + SQL_WHERE_OWNER.size() + SQL_OR_BACKUP_OWNER.size()
        + SQL_SUFFIX.size() + 2*placeholders.size() + 5 + EXPIRATION.size() + sql_select_mappings_and_owners_suffix.size());
    sql_statement += sql_select_mappings_and_owners_prefix;
    sql_statement += SQL_WHERE_OWNER;
    sql_statement += placeholders;
    sql_statement += SQL_OR_BACKUP_OWNER;
    sql_statement += placeholders;
    sql_statement += SQL_SUFFIX;

    for (int i : {0, 1})
      for (auto const &owner : owners)
        bind.emplace_back(blob_view{reinterpret_cast<const char*>(&owner), sizeof(owner)});
  }

  if (blockchain_height)
  {
    sql_statement += " AND ";
    sql_statement += EXPIRATION;
    bind.emplace_back(*blockchain_height);
  }

  sql_statement += sql_select_mappings_and_owners_suffix;

  // Compile Statement
  std::vector<mapping_record> result;
  sql_compiled_statement statement{*this};
  if (!statement.compile(sql_statement, false /*optimise_for_multiple_usage*/)
      || !bind_container(statement, bind))
    return result;

  // Execute
  sql_run_statement(ons_sql_type::get_mappings_by_owners, statement, &result);
  return result;
}

std::vector<mapping_record> name_system_db::get_mappings_by_owner(generic_owner const &owner, std::optional<uint64_t> blockchain_height)
{
  std::vector<mapping_record> result = {};
  blob_view ownerblob{reinterpret_cast<const char*>(&owner), sizeof(owner)};
  bind_and_run(ons_sql_type::get_mappings_by_owner, get_mappings_by_owner_sql, &result,
      ownerblob, ownerblob);
  if (blockchain_height)
  {
    auto end = std::remove_if(result.begin(), result.end(), [height=*blockchain_height](auto& r) { return !r.active(height); });
    result.erase(end, result.end());
  }
  return result;
}

std::map<mapping_type, int> name_system_db::get_mapping_counts(uint64_t blockchain_height) {
  std::map<mapping_type, int> result;
  bind_and_run(ons_sql_type::get_mapping_counts, get_mapping_counts_sql, &result, blockchain_height);
  return result;
}

settings_record name_system_db::get_settings()
{
  settings_record result  = {};
  result.loaded           = sql_run_statement(ons_sql_type::get_setting, get_settings_sql, &result);
  return result;
}

} // namespace ons

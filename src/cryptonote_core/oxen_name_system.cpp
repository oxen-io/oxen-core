#include "oxen_name_system.h"

#include <fmt/std.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <bitset>
#include <concepts>
#include <iterator>
#include <session/placeholders.hpp>
#include <type_traits>
#include <variant>
#include <vector>

#include "common/exception.h"
#include "common/guts.h"
#include "common/oxen.h"
#include "common/string_util.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "epee/byte_span.h"
#include "oxen_economy.h"
#include "sqlitedb/sqlite.hpp"

extern "C" {
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>
}

using cryptonote::hf;
using db::as_i64;
using db::as_u64;
using session::sqlite::bind_each;
using session::sqlite::blob_guts;
using session::sqlite::Connection;
using session::sqlite::placeholders;
using tools::span_guts;

namespace ons {

namespace log = oxen::log;
static auto logcat = log::Cat("ons");

// The columns of `mappings.*`, followed (in queries selecting mappings with their owners) by the
// owner and backup owner addresses.
enum struct mapping_record_column {
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
std::pair<std::span<const unsigned char>, std::span<const unsigned char>>
ons::mapping_value::value_nonce(mapping_type type) const {
    std::pair<std::span<const unsigned char>, std::span<const unsigned char>> result;
    auto& [head, tail] = result;
    head = {buffer.data(), len};
    if ((type == mapping_type::session &&
         len != SESSION_PUBLIC_KEY_BINARY_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES +
                         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) ||
        len < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES /* shouldn't occur, but just in case */)
        tail = {OLD_ENCRYPTION_NONCE, sizeof(OLD_ENCRYPTION_NONCE)};
    else {
        tail = head.last(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        head = head.first(len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    }
    return result;
}

std::string ons::mapping_value::to_readable_value(
        cryptonote::network_type nettype, ons::mapping_type type) const {
    std::string result;
    if (is_lokinet_type(type)) {
        result = oxenc::to_base32z(to_view()) + ".loki";
    } else if (type == ons::mapping_type::wallet) {
        std::optional<cryptonote::address_parse_info> addr = get_wallet_address_info();
        if (addr) {
            result = cryptonote::get_account_address_as_str(
                    nettype, (*addr).is_subaddress, (*addr).address);
        } else {
            result = oxenc::to_hex(to_view());
        }
    } else {
        result = oxenc::to_hex(to_view());
    }

    return result;
}

namespace {

    std::string ons_extra_string(
            cryptonote::network_type nettype, cryptonote::tx_extra_oxen_name_system const& data) {
        std::string extra = "ONS Extra={";
        auto append = std::back_inserter(extra);
        if (data.is_buying())
            fmt::format_to(
                    append,
                    "owner={}, backup_owner={}",
                    data.owner.to_string(nettype),
                    (data.backup_owner ? data.backup_owner.to_string(nettype) : "(none)"));
        else if (data.is_renewing())
            extra += "renewal";
        else
            fmt::format_to(append, "signature={}", tools::hex_guts(data.signature.data));

        fmt::format_to(append, ", type={}, name_hash={}}}", data.type, data.name_hash);
        return extra;
    }

    // Copies a BLOB column into `dest`, which must be exactly the blob's size.
    bool copy_blob(const SQLite::Column& col, void* dest, size_t dest_size) {
        auto size = static_cast<size_t>(col.getBytes());
        if (size != dest_size) {
            log::warning(
                    logcat,
                    "Unexpected blob size={}, in ONS DB does not match expected size={}",
                    size,
                    dest_size);
            assert(size == dest_size);
            return false;
        }

        std::memcpy(dest, col.getBlob(), size);
        return true;
    }

    // Binds a string's bytes as a BLOB (rather than TEXT, as a string binds by default).
    std::span<const unsigned char> blob(std::string_view s) {
        return epee::strspan<unsigned char>(s);
    }

    // Builds a mapping_record from the current row of a query selecting the mapping_record_column
    // columns.  The returned record is not `loaded` if the row is invalid.
    mapping_record mapping_from_row(SQLite::Statement& st) {
        auto col = [&st](auto c) { return st.getColumn(static_cast<int>(c)); };
        using enum mapping_record_column;

        mapping_record result = {};
        auto type_int = static_cast<uint16_t>(col(type).getInt());
        if (type_int >= tools::enum_count<mapping_type>)
            return result;

        result.type = static_cast<mapping_type>(type_int);
        result.id = col(id).getInt64();
        result.update_height = as_u64(col(update_height).getInt64());
        if (auto exp = col(expiration_height); !exp.isNull())
            result.expiration_height = as_u64(exp.getInt64());
        result.owner_id = col(owner_id).getInt64();
        result.backup_owner_id = col(backup_owner_id).getInt64();

        // Copy encrypted_value
        {
            auto value_col = col(encrypted_value);
            std::string_view value{
                    static_cast<const char*>(value_col.getBlob()),
                    static_cast<size_t>(value_col.getBytes())};
            if (value.size() > result.encrypted_value.buffer.size()) {
                log::error(
                        logcat,
                        "Unexpected encrypted value blob with size={}, in ONS db larger than the "
                        "available size={}",
                        value.size(),
                        result.encrypted_value.buffer.size());
                return result;
            }
            result.encrypted_value.len = value.size();
            result.encrypted_value.encrypted = true;
            std::memcpy(&result.encrypted_value.buffer[0], value.data(), value.size());
        }

        result.name_hash = col(name_hash).getString();

        if (!copy_blob(col(txid), result.txid.data(), result.txid.size()))
            return result;

        int owner_column = tools::enum_count<mapping_record_column>;
        if (!copy_blob(st.getColumn(owner_column), &result.owner, sizeof(result.owner)))
            return result;

        if (result.backup_owner_id > 0) {
            if (!copy_blob(
                        st.getColumn(owner_column + 1),
                        &result.backup_owner,
                        sizeof(result.backup_owner)))
                return result;
        }

        result.loaded = true;
        return result;
    }

    // Runs an (already bound) query selecting mapping_record_column columns, returning the valid
    // records.
    std::vector<mapping_record> get_mapping_records(SQLite::Statement& st) {
        std::vector<mapping_record> result;
        while (st.executeStep())
            if (auto record = mapping_from_row(st))
                result.push_back(std::move(record));
        return result;
    }

}  // end anonymous namespace

using namespace std::literals;

using stringtypemap = std::pair<std::string_view, mapping_type>;
static constexpr std::array ons_str_type_mappings = {
        stringtypemap{"5"sv, mapping_type::lokinet_10years},
        stringtypemap{"4"sv, mapping_type::lokinet_5years},
        stringtypemap{"3"sv, mapping_type::lokinet_2years},
        stringtypemap{"2"sv, mapping_type::lokinet},
        stringtypemap{"1"sv, mapping_type::wallet},
        stringtypemap{"0"sv, mapping_type::session},
        stringtypemap{"session"sv, mapping_type::session},
        stringtypemap{"wallet"sv, mapping_type::wallet},
        stringtypemap{"lokinet"sv, mapping_type::lokinet},
        stringtypemap{"lokinet_2years"sv, mapping_type::lokinet_2years},
        stringtypemap{"lokinet_5years"sv, mapping_type::lokinet_5years},
        stringtypemap{"lokinet_10years"sv, mapping_type::lokinet_10years}};

std::optional<mapping_type> parse_ons_type(std::string input, bool queryable_types_only) {
    // Lower-case the input:
    for (auto& c : input)
        if (c >= 'A' && c <= 'Z')
            c += ('A' - 'a');

    for (const auto& [str, map] : ons_str_type_mappings)
        if (str == input) {
            if (queryable_types_only && is_lokinet_type(map) && map != mapping_type::lokinet)
                return std::nullopt;
            return map;
        }

    return std::nullopt;
}

using inttypemap = std::pair<uint16_t, mapping_type>;
static constexpr std::array ons_int_type_mappings = {
        inttypemap{5, mapping_type::lokinet_10years},
        inttypemap{4, mapping_type::lokinet_5years},
        inttypemap{3, mapping_type::lokinet_2years},
        inttypemap{2, mapping_type::lokinet},
        inttypemap{1, mapping_type::wallet},
        inttypemap{0, mapping_type::session}};
std::optional<mapping_type> parse_ons_type(uint16_t input, bool queryable_types_only) {
    for (const auto& [inttype, map] : ons_int_type_mappings)
        if (inttype == input) {
            if (queryable_types_only && is_lokinet_type(map) && map != mapping_type::lokinet)
                return std::nullopt;
            return map;
        }

    return std::nullopt;
}

bool mapping_record::active(uint64_t blockchain_height) const {
    if (!loaded)
        return false;
    return !expiration_height || blockchain_height <= *expiration_height;
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

std::optional<uint64_t> expiry_blocks(cryptonote::network_type nettype, mapping_type type) {
    std::optional<uint64_t> result;
    if (is_lokinet_type(type)) {
        // For testnet we shorten 1-, 2-, and 5-year renewals to 1/2/5 days with 1-day renewal, but
        // leave 10 years alone to allow long-term registrations on testnet.
        const bool testnet_short = nettype == cryptonote::network_type::TESTNET &&
                                   type != mapping_type::lokinet_10years;

        auto bpd = get_config(nettype).BLOCKS_PER_DAY();
        result = bpd * REGISTRATION_YEAR_DAYS *
                 (type == mapping_type::lokinet           ? 1
                  : type == mapping_type::lokinet_2years  ? 2
                  : type == mapping_type::lokinet_5years  ? 5
                  : type == mapping_type::lokinet_10years ? 10
                                                          : 0);
        assert(result && *result);

        if (testnet_short)
            *result /= REGISTRATION_YEAR_DAYS;
        else if (nettype == cryptonote::network_type::FAKECHAIN)  // For fakenet testing we shorten
                                                                  // 1/2/5/10 years to 2/4/10/20
                                                                  // blocks
            *result /= (bpd * REGISTRATION_YEAR_DAYS / 2);
    }

    return result;
}

static void append_owner(std::string& buffer, const ons::generic_owner* owner) {
    if (owner) {
        buffer += static_cast<char>(owner->type);
        buffer += owner->type == ons::generic_owner_sig_type::ed25519
                        ? tools::view_guts(owner->ed25519)
                        : tools::view_guts(owner->wallet.address);
    }
}

std::string tx_extra_signature(
        std::string_view value,
        ons::generic_owner const* owner,
        ons::generic_owner const* backup_owner,
        crypto::hash const& prev_txid) {
    static_assert(
            sizeof(crypto::hash) == crypto_generichash_BYTES,
            "Using libsodium generichash for signature hash, require we fit into crypto::hash");
    if (value.size() > mapping_value::BUFFER_SIZE) {
        log::error(
                logcat,
                "Unexpected value len={} greater than the expected capacity={}",
                value.size(),
                mapping_value::BUFFER_SIZE);
        return ""s;
    }

    std::string result;
    result.reserve(
            mapping_value::BUFFER_SIZE + sizeof(*owner) + sizeof(*backup_owner) +
            sizeof(prev_txid));
    result += value;
    append_owner(result, owner);
    append_owner(result, backup_owner);
    result += tools::view_guts(prev_txid);

    return result;
}

ons::generic_signature make_ed25519_signature(
        crypto::hash const& hash, crypto::ed25519_secret_key const& skey) {
    ons::generic_signature result = {};
    result.type = ons::generic_owner_sig_type::ed25519;
    crypto_sign_detached(result.ed25519.data(), NULL, hash.data(), hash.size(), skey.data());
    return result;
}

ons::generic_owner make_monero_owner(
        cryptonote::account_public_address const& owner, bool is_subaddress) {
    ons::generic_owner result = {};
    result.type = ons::generic_owner_sig_type::monero;
    result.wallet.address = owner;
    result.wallet.is_subaddress = is_subaddress;
    return result;
}

ons::generic_owner make_ed25519_owner(crypto::ed25519_public_key const& pkey) {
    ons::generic_owner result = {};
    result.type = ons::generic_owner_sig_type::ed25519;
    result.ed25519 = pkey;
    return result;
}

bool parse_owner_to_generic_owner(
        cryptonote::network_type nettype,
        std::string_view owner,
        generic_owner& result,
        std::string* reason) {
    cryptonote::address_parse_info parsed_addr;
    crypto::ed25519_public_key ed_owner;
    if (cryptonote::get_account_address_from_str(parsed_addr, nettype, owner)) {
        result = ons::make_monero_owner(parsed_addr.address, parsed_addr.is_subaddress);
    } else if (owner.size() == 2 * ed_owner.size() && oxenc::is_hex(owner)) {
        oxenc::from_hex(owner.begin(), owner.end(), ed_owner.data());
        result = ons::make_ed25519_owner(ed_owner);
    } else {
        if (reason) {
            char const* type_heuristic = (owner.size() == sizeof(crypto::ed25519_public_key) * 2)
                                               ? "ED25519 Key"
                                               : "Wallet address";
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
static constexpr bool char_is_alphanum_or(char c) {
    bool result = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (... || (c == Extra));
    return result;
}
// Same as above with no extra char values.
static constexpr bool char_is_alphanum(char c) {
    return char_is_alphanum_or<>(c);
}

template <typename... T>
static bool check_condition(
        bool condition, std::string* reason, fmt::format_string<T...> format, T&&... args) {
    if (condition && reason)
        *reason = fmt::format(format, std::forward<T>(args)...);
    return condition;
}

bool validate_ons_name(mapping_type type, std::string name, std::string* reason) {
    bool const is_lokinet = is_lokinet_type(type);
    size_t min_name_len = 1, max_name_len = 0;

    if (is_lokinet) {
        min_name_len = "a.loki"sv.size();
        max_name_len = name.find('-') != std::string::npos ? LOKINET_DOMAIN_NAME_MAX
                                                           : LOKINET_DOMAIN_NAME_MAX_NOHYPHEN;
    } else if (type == mapping_type::session)
        max_name_len = ons::SESSION_DISPLAY_NAME_MAX;
    else if (type == mapping_type::wallet)
        max_name_len = ons::WALLET_NAME_MAX;
    else {
        if (reason)
            *reason = "ONS type '{}' is not supported"_format(type);
        return false;
    }

    // NOTE: Validate name length
    name = tools::lowercase_ascii_string(name);
    if (check_condition(
                name.size() < min_name_len || name.size() > max_name_len,
                reason,
                "ONS {0} name '{1}' (length={2}) is invalid: {0} names must be between {3} and {4} "
                "characters long",
                type,
                name,
                name.size(),
                min_name_len,
                max_name_len))
        return false;

    std::string_view name_view{name};  // Will chop this down as we validate each part

    // NOTE: Validate domain specific requirements
    if (is_lokinet) {
        // LOKINET
        // Domain has to start with an alphanumeric, and can have (alphanumeric or hyphens) in
        // between, the character before the suffix <char>'.loki' must be alphanumeric followed by
        // the suffix '.loki' It's *approximately* this regex, but there are some extra restrictions
        // below
        // ^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.loki$

        // Reserved names:
        // - localhost.loki has special meaning within lokinet (it is always a CNAME to the local
        //   address)
        // - loki.loki and snode.loki are prohibited in case someone added .loki or .snode as search
        //   domains (in which case the user looking up "foo.loki" would try end up trying to
        //   resolve "foo.loki.loki").
        for (auto& reserved : {"localhost.loki"sv, "loki.loki"sv, "snode.loki"sv})
            if (check_condition(
                        name == reserved,
                        reason,
                        "ONS {} name '{}' is a reserved name that cannot be registered",
                        type,
                        name))
                return false;

        // Must end with .loki
        auto constexpr SUFFIX = ".loki"sv;
        if (check_condition(
                    !name_view.ends_with(SUFFIX),
                    reason,
                    "ONS {0} name '{1}' is invalid: {0} names must end with '.loki'",
                    type,
                    name))
            return false;

        assert(name_view.size() > SUFFIX.size());  // Implied by min_name_len check
        name_view.remove_suffix(SUFFIX.size());

        // All domains containing '--' as 3rd/4th letter are reserved except for xn-- punycode
        // domains
        if (check_condition(
                    name_view.size() >= 4 && name_view.substr(2, 2) == "--"sv &&
                            !name_view.starts_with("xn--"sv),
                    reason,
                    // This \? looks stupid, but is to suppress a trigraph warning
                    "ONS {} name '{}' is invalid: names matching '?\?--*' are reserved (other than "
                    "punycode xn--*)",
                    type,
                    name))
            return false;

        // Must start with alphanumeric
        if (check_condition(
                    !char_is_alphanum(name_view.front()),
                    reason,
                    "ONS {} name '{}' is invalid: names must start with a-z or 0-9",
                    type,
                    name))
            return false;

        name_view.remove_prefix(1);

        if (!name_view.empty()) {
            // Character preceding .loki must be alphanumeric
            if (check_condition(
                        !char_is_alphanum(name_view.back()),
                        reason,
                        "ONS {} name '{}' is invalid: the name before '.loki' must end with a-z or "
                        "0-9",
                        type,
                        name))
                return false;
            name_view.remove_suffix(1);
        }

        // Inbetween start and preceding suffix, (alphanumeric or hyphen) characters permitted
        if (check_condition(
                    !std::all_of(name_view.begin(), name_view.end(), char_is_alphanum_or<'-'>),
                    reason,
                    "ONS {} name '{}' is invalid: names may only contain a-z, 0-9, and '-'",
                    type,
                    name))
            return false;
    } else if (type == mapping_type::session || type == mapping_type::wallet) {
        // SESSION & WALLET
        // Name has to start with a (alphanumeric or underscore), and can have (alphanumeric,
        // hyphens or underscores) in between and must end with a (alphanumeric or underscore)
        // ^[a-z0-9_]([a-z0-9-_]*[a-z0-9_])?$

        // Inbetween start and preceding suffix, (alphanumeric, hyphen or underscore) characters
        // permitted
        if (check_condition(
                    !std::all_of(name_view.begin(), name_view.end(), char_is_alphanum_or<'-', '_'>),
                    reason,
                    "Invalid ONS {} name '{}': only a-z, 0-9, _, and - are permitted",
                    type,
                    name))
            return false;

        // Must start with (alphanumeric or underscore)
        if (check_condition(
                    name_view.front() == '-' || name_view.back() == '-',
                    reason,
                    "Invalid ONS {} name '{}': names may not begin or end with a hyphen ('-')",
                    type,
                    name))
            return false;

    } else {
        log::error(logcat, "Type not implemented");
        return false;
    }

    return true;
}

std::optional<cryptonote::address_parse_info> encrypted_wallet_value_to_info(
        std::string name, std::string encrypted_value, std::string nonce) {
    std::string lower_name = tools::lowercase_ascii_string(std::move(name));
    mapping_value record(oxenc::from_hex(encrypted_value), oxenc::from_hex(nonce));
    record.decrypt(lower_name, mapping_type::wallet);
    return record.get_wallet_address_info();
}

static bool check_lengths(
        mapping_type type,
        std::string_view value,
        size_t max,
        bool binary_val,
        std::string* reason) {
    bool result;
    if (type == mapping_type::wallet) {
        result =
                (value.size() == (WALLET_ACCOUNT_BINARY_LENGTH_INC_PAYMENT_ID + max) ||
                 value.size() == (WALLET_ACCOUNT_BINARY_LENGTH_NO_PAYMENT_ID + max));
    } else {
        result = (value.size() == max);
    }
    if (!result) {
        if (reason) {
            *reason =
                    "ONS type={} specifies mapping from name_hash->encrypted_value where the value's length={} does not equal the required length={}, given value={}"_format(
                            type, value.size(), max, binary_val ? oxenc::to_hex(value) : value);
        }
    }

    return result;
}

// This function checks that the value is valid but it also will copy the value into the
// mapping_value buffer ready for mapping_value::encrypt()
bool mapping_value::validate(
        cryptonote::network_type nettype,
        mapping_type type,
        std::string_view value,
        mapping_value* blob,
        std::string* reason) {
    if (blob)
        *blob = {};

    // Check length of the value
    cryptonote::address_parse_info addr_info = {};
    if (type == mapping_type::wallet) {
        if (value.empty() || !get_account_address_from_str(addr_info, nettype, value)) {
            if (reason) {
                if (value.empty())
                    *reason =
                            "The value={}, mapping into the wallet address, specifies a wallet address of 0 length"_format(
                                    value);
                else
                    *reason =
                            "Could not convert the wallet address string, check it is correct, value={}"_format(
                                    value);
            }
            return false;
        }

        // Validate blob contents and generate the binary form if possible
        if (blob) {
            auto iter = blob->buffer.begin();
            uint8_t identifier = 0;
            if (addr_info.is_subaddress) {
                identifier |= ONS_WALLET_TYPE_SUBADDRESS;
            } else if (addr_info.has_payment_id) {
                identifier |= ONS_WALLET_TYPE_INTEGRATED;
            }
            iter = std::copy_n(&identifier, 1, iter);
            iter = std::copy_n(
                    addr_info.address.m_spend_public_key.data(),
                    addr_info.address.m_spend_public_key.size(),
                    iter);
            iter = std::copy_n(
                    addr_info.address.m_view_public_key.data(),
                    addr_info.address.m_view_public_key.size(),
                    iter);

            size_t counter = 65;
            assert(std::distance(blob->buffer.begin(), iter) == static_cast<int>(counter));
            if (addr_info.has_payment_id) {
                std::copy_n(addr_info.payment_id.data(), addr_info.payment_id.size(), iter);
                counter += sizeof(addr_info.payment_id);
            }

            blob->len = counter;
        }
    } else if (is_lokinet_type(type)) {
        // We need a 52 char base32z string that decodes to a 32-byte value, which really means we
        // need 51 base32z chars (=255 bits) followed by a 1-bit value ('y'=0, or 'o'=0b10000);
        // anything else in the last spot isn't a valid lokinet address.
        if (check_condition(
                    value.size() != 57 || !value.ends_with(".loki") ||
                            !oxenc::is_base32z(value.substr(0, 52)) ||
                            !(value[51] == 'y' || value[51] == 'o'),
                    reason,
                    "'{}' is not a valid lokinet address",
                    value))
            return false;

        if (blob) {
            blob->len = sizeof(crypto::ed25519_public_key);
            oxenc::from_base32z(value.begin(), value.begin() + 52, blob->buffer.begin());
        }
    } else {
        assert(type == mapping_type::session);
        // NOTE: Check value is hex of the right size
        if (check_condition(
                    value.size() != 2 * SESSION_PUBLIC_KEY_BINARY_LENGTH,
                    reason,
                    "The value={} is not the required {}-character hex string session public key, "
                    "length={}",
                    value,
                    2 * SESSION_PUBLIC_KEY_BINARY_LENGTH,
                    value.size()))
            return false;

        if (check_condition(
                    !oxenc::is_hex(value),
                    reason,
                    "value={} specifies name -> value mapping where the value is not a hex string",
                    value))
            return false;

        // NOTE: Session public keys are 33 bytes, with the first byte being 0x05 and the remaining
        // 32 being the public key.
        if (check_condition(
                    !value.starts_with("05"),
                    reason,
                    "ONS type=session specifies mapping from name -> ed25519 key where the key is "
                    "not prefixed with 05, given ed25519={}",
                    value))
            return false;

        if (blob)  // NOTE: Given blob, write the binary output
        {
            blob->len = value.size() / 2;
            assert(blob->len <= blob->buffer.size());
            oxenc::from_hex(value.begin(), value.end(), blob->buffer.begin());
        }
    }

    return true;
}

static_assert(
        SODIUM_ENCRYPTION_EXTRA_BYTES ==
        crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(SODIUM_ENCRYPTION_EXTRA_BYTES >= crypto_secretbox_MACBYTES);
bool mapping_value::validate_encrypted(
        mapping_type type, std::string_view value, mapping_value* blob, std::string* reason) {
    if (blob)
        *blob = {};

    int value_len = crypto_aead_xchacha20poly1305_ietf_ABYTES +
                    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    if (is_lokinet_type(type))
        value_len += LOKINET_ADDRESS_BINARY_LENGTH;
    else if (type == mapping_type::wallet) {
        value_len = crypto_aead_xchacha20poly1305_ietf_ABYTES +
                    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // Add the length in check_length
    } else if (type == mapping_type::session) {
        value_len += SESSION_PUBLIC_KEY_BINARY_LENGTH;

        // Allow an HF15 argon2 encrypted value which doesn't contain a nonce:
        if (value.size() == value_len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
            value_len -= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    } else {
        if (reason)
            *reason = "Unhandled type passed into {}"_format(__func__);
        return false;
    }

    if (!check_lengths(type, value, value_len, true /*binary_val*/, reason))
        return false;

    if (blob) {
        blob->len = value.size();
        std::memcpy(blob->buffer.data(), value.data(), value.size());
        blob->encrypted = true;
    }

    return true;
}

mapping_value::mapping_value(std::string encrypted_value, std::string nonce) : buffer{0} {
    auto it = std::copy(encrypted_value.begin(), encrypted_value.end(), buffer.begin());
    std::copy(nonce.begin(), nonce.end(), it);
    len = encrypted_value.size() + nonce.size();
    encrypted = true;
}

mapping_value::mapping_value() : buffer{0}, encrypted(false), len(0) {}

std::string name_hash_bytes_to_base64(std::string_view bytes) {
    if (bytes.size() != NAME_HASH_SIZE)
        throw oxen::traced<std::runtime_error>{"Invalid name hash: expected exactly 32 bytes"};
    return oxenc::to_base64(bytes);
}

std::optional<std::string> name_hash_input_to_base64(std::string_view input) {
    if (input.size() == NAME_HASH_SIZE)
        return name_hash_bytes_to_base64(input);
    if (input.size() == 2 * NAME_HASH_SIZE && oxenc::is_hex(input))
        return name_hash_bytes_to_base64(oxenc::from_hex(input));
    if (input.size() >= NAME_HASH_SIZE_B64_MIN && input.size() <= NAME_HASH_SIZE_B64_MAX &&
        oxenc::is_base64(input)) {
        std::string tmp = oxenc::from_base64(input);
        if (tmp.size() == NAME_HASH_SIZE)  // Could still be off from too much/too little padding
            return name_hash_bytes_to_base64(tmp);
    }
    return std::nullopt;
}

static std::string hash_to_base64(crypto::hash const& hash) {
    return name_hash_bytes_to_base64(tools::view_guts(hash));
}

static bool verify_ons_signature(
        crypto::hash const& hash,
        ons::generic_signature const& signature,
        ons::generic_owner const& owner) {
    if (!owner || !signature)
        return false;
    if (owner.type != signature.type)
        return false;
    if (signature.type == ons::generic_owner_sig_type::monero) {
        return crypto::check_signature(
                hash, owner.wallet.address.m_spend_public_key, signature.monero);
    } else {
        return (crypto_sign_verify_detached(
                        signature.data, hash.data(), hash.size(), owner.ed25519.data()) == 0);
    }
}

static bool validate_against_previous_mapping(
        ons::name_system_db& ons_db,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_oxen_name_system const& ons_extra,
        std::string* reason) {
    crypto::hash expected_prev_txid{};
    std::string name_hash = hash_to_base64(ons_extra.name_hash);
    ons::mapping_record mapping = ons_db.get_mapping(ons_extra.type, name_hash);

    if (ons_extra.is_updating()) {
        // Updating: the mapping must exist and be active, the updated fields must actually change
        // from the current value, and a valid signature over the updated values must be present.

        if (check_condition(
                    !mapping,
                    reason,
                    "{}, {} update requested but mapping does not exist.",
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra)))
            return false;
        if (check_condition(
                    !mapping.active(blockchain_height),
                    reason,
                    "{}, {} TX requested to update mapping that has already expired",
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra)))
            return false;
        expected_prev_txid = mapping.txid;

        constexpr auto SPECIFYING_SAME_VALUE_ERR =
                "{}, {} field to update is specifying the same mapping {}"sv;
        if (check_condition(
                    ons_extra.field_is_set(ons::extra_field::encrypted_value) &&
                            ons_extra.encrypted_value == mapping.encrypted_value.to_view(),
                    reason,
                    SPECIFYING_SAME_VALUE_ERR,
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra),
                    "value"))
            return false;

        if (check_condition(
                    ons_extra.field_is_set(ons::extra_field::owner) &&
                            ons_extra.owner == mapping.owner,
                    reason,
                    SPECIFYING_SAME_VALUE_ERR,
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra),
                    "owner"))
            return false;

        if (check_condition(
                    ons_extra.field_is_set(ons::extra_field::backup_owner) &&
                            ons_extra.backup_owner == mapping.backup_owner,
                    reason,
                    SPECIFYING_SAME_VALUE_ERR,
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra),
                    "backup_owner"))
            return false;

        // Validate signature
        auto data = tx_extra_signature(
                ons_extra.encrypted_value,
                ons_extra.field_is_set(ons::extra_field::owner) ? &ons_extra.owner : nullptr,
                ons_extra.field_is_set(ons::extra_field::backup_owner) ? &ons_extra.backup_owner
                                                                       : nullptr,
                expected_prev_txid);
        if (check_condition(
                    data.empty(),
                    reason,
                    "{}, {} unexpectedly failed to generate signature, please inform the Oxen "
                    "developers",
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra)))
            return false;

        crypto::hash hash;
        crypto_generichash(
                hash.data(),
                hash.size(),
                reinterpret_cast<const unsigned char*>(data.data()),
                data.size(),
                nullptr /*key*/,
                0 /*key_len*/);

        if (check_condition(
                    !verify_ons_signature(hash, ons_extra.signature, mapping.owner) &&
                            !verify_ons_signature(hash, ons_extra.signature, mapping.backup_owner),
                    reason,
                    "{}, {} failed to verify signature for ONS update, current owner={}, backup "
                    "owner={}",
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra),
                    mapping.owner.to_string(ons_db.network_type()),
                    mapping.backup_owner.to_string(ons_db.network_type())))
            return false;
    } else if (ons_extra.is_buying()) {
        // If buying a new name then the existing name must not be active
        if (check_condition(
                    mapping.active(blockchain_height),
                    reason,
                    "Cannot buy an ONS name that is already registered: name_hash={}, type={}; TX: "
                    "{}; {}",
                    mapping.name_hash,
                    mapping.type,
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra)))
            return false;

        // If buying a new wallet name then the existing session name must not be active and vice
        // versa The owner of an existing name but different type is allowed to register but the
        // owner and backup owners of the new mapping must be from the same owners and backup owners
        // of the previous mapping ie no new addresses are allowed to be added as owner or backup
        // owner.
        if (ons_extra.type == mapping_type::wallet || ons_extra.type == mapping_type::session) {
            auto buy_type_name = ons_extra.type == mapping_type::wallet ? "wallet"sv : "session"sv;
            auto alt_type_name = ons_extra.type == mapping_type::wallet ? "session"sv : "wallet"sv;
            auto alt_type = ons_extra.type == mapping_type::wallet ? mapping_type::session
                                                                   : mapping_type::wallet;

            ons::mapping_record alt_mapping = ons_db.get_mapping(alt_type, name_hash);

            auto is_alt_record_owner = [&alt_mapping](const auto& new_owner) {
                return new_owner == alt_mapping.owner || new_owner == alt_mapping.backup_owner;
            };

            if (check_condition(
                        alt_mapping.active(blockchain_height) &&  // alternative mapping exists
                                (!is_alt_record_owner(ons_extra.owner) ||
                                 (ons_extra.field_is_set(ons::extra_field::backup_owner) &&
                                  !is_alt_record_owner(ons_extra.backup_owner))),
                        reason,
                        "Cannot buy an ONS {} name that has an already registered {} name: "
                        "name_hash={}, type={}; TX: {}; {}",
                        buy_type_name,
                        alt_type_name,
                        mapping.name_hash,
                        mapping.type,
                        tx,
                        ons_extra_string(ons_db.network_type(), ons_extra)))
                return false;
        }
    } else if (ons_extra.is_renewing()) {
        // We allow anyone to renew a name, but it has to exist and be currently active
        if (check_condition(
                    !mapping,
                    reason,
                    "{}, {} renewal requested but mapping does not exist.",
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra)))
            return false;
        if (check_condition(
                    !mapping.active(blockchain_height),
                    reason,
                    "{}, {} TX requested to renew mapping that has already expired",
                    tx,
                    ons_extra_string(ons_db.network_type(), ons_extra)))
            return false;
        expected_prev_txid = mapping.txid;
    } else {
        check_condition(
                true,
                reason,
                "{}, {} is not a valid buy, update, or renew ONS tx",
                tx,
                ons_extra_string(ons_db.network_type(), ons_extra));
        return false;
    }

    if (check_condition(
                ons_extra.prev_txid != expected_prev_txid,
                reason,
                "{}, {} specified prior txid {} but expected {}; perhaps a competing ONS TX was "
                "submitted and accepted before this ONS update TX was processed?",
                tx,
                ons_extra_string(ons_db.network_type(), ons_extra),
                ons_extra.prev_txid,
                expected_prev_txid))
        return false;

    return true;
}

// Sanity check value to disallow the empty name hash
static const crypto::hash null_name_hash = name_to_hash("");

bool name_system_db::validate_ons_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_oxen_name_system& ons_extra,
        std::string* reason) {
    // -----------------------------------------------------------------------------------------------
    // Pull out ONS Extra from TX
    // -----------------------------------------------------------------------------------------------
    {
        if (check_condition(
                    tx.type != cryptonote::txtype::oxen_name_system,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::oxen_name_system))
            return false;

        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, ons_extra),
                    reason,
                    "{} didn't have oxen name service in the tx_extra",
                    tx))
            return false;
    }

    // -----------------------------------------------------------------------------------------------
    // Check TX ONS Serialized Fields are NULL if they are not specified
    // -----------------------------------------------------------------------------------------------
    {
        constexpr auto VALUE_SPECIFIED_BUT_NOT_REQUESTED =
                "{}, {} given field {} but field is not requested to be serialised"sv;
        if (check_condition(
                    !ons_extra.field_is_set(ons::extra_field::encrypted_value) &&
                            ons_extra.encrypted_value.size(),
                    reason,
                    VALUE_SPECIFIED_BUT_NOT_REQUESTED,
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    "encrypted_value"))
            return false;

        if (check_condition(
                    !ons_extra.field_is_set(ons::extra_field::owner) && ons_extra.owner,
                    reason,
                    VALUE_SPECIFIED_BUT_NOT_REQUESTED,
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    "owner"))
            return false;

        if (check_condition(
                    !ons_extra.field_is_set(ons::extra_field::backup_owner) &&
                            ons_extra.backup_owner,
                    reason,
                    VALUE_SPECIFIED_BUT_NOT_REQUESTED,
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    "backup_owner"))
            return false;

        if (check_condition(
                    !ons_extra.field_is_set(ons::extra_field::signature) && ons_extra.signature,
                    reason,
                    VALUE_SPECIFIED_BUT_NOT_REQUESTED,
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    "signature"))
            return false;
    }

    // -----------------------------------------------------------------------------------------------
    // Simple ONS Extra Validation
    // -----------------------------------------------------------------------------------------------
    {
        if (check_condition(
                    ons_extra.version != 0,
                    reason,
                    "{}, {} unexpected version={:d}, expected 0",
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    ons_extra.version))
            return false;

        if (check_condition(
                    !ons::mapping_type_allowed(hf_version, ons_extra.type),
                    reason,
                    "{}, {} specifying type={} is disallowed in HF{:d}",
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    ons_extra.type,
                    static_cast<uint8_t>(hf_version)))
            return false;

        // -----------------------------------------------------------------------------------------------
        // Serialized Values Check
        // -----------------------------------------------------------------------------------------------
        if (check_condition(
                    !ons_extra.is_buying() && !ons_extra.is_updating() && !ons_extra.is_renewing(),
                    reason,
                    "{}, {} TX extra does not specify valid combination of bits for serialized "
                    "fields={}",
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    std::bitset<sizeof(ons_extra.fields) * 8>(static_cast<size_t>(ons_extra.fields))
                            .to_string()))
            return false;

        if (check_condition(
                    ons_extra.field_is_set(ons::extra_field::owner) &&
                            ons_extra.field_is_set(ons::extra_field::backup_owner) &&
                            ons_extra.owner == ons_extra.backup_owner,
                    reason,
                    "{}, {} specifying owner the same as the backup owner={}",
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    ons_extra.backup_owner.to_string(nettype))) {
            return false;
        }
    }

    // -----------------------------------------------------------------------------------------------
    // ONS Field(s) Validation
    // -----------------------------------------------------------------------------------------------
    {
        if (check_condition(
                    (ons_extra.name_hash == null_name_hash || !ons_extra.name_hash),
                    reason,
                    "{}, {} specified the null name hash",
                    tx,
                    ons_extra_string(nettype, ons_extra)))
            return false;

        if (ons_extra.field_is_set(ons::extra_field::encrypted_value)) {
            if (!mapping_value::validate_encrypted(
                        ons_extra.type, ons_extra.encrypted_value, nullptr, reason))
                return false;
        }

        if (!validate_against_previous_mapping(*this, blockchain_height, tx, ons_extra, reason))
            return false;
    }

    // -----------------------------------------------------------------------------------------------
    // Burn Validation
    // -----------------------------------------------------------------------------------------------
    {
        uint64_t burn = cryptonote::get_burned_amount_from_tx_extra(tx.extra);
        uint64_t const burn_required = (ons_extra.is_buying() || ons_extra.is_renewing())
                                             ? burn_needed(hf_version, nettype, ons_extra.type)
                                             : 0;
        if (hf_version == hf::hf18 && burn > burn_required && blockchain_height < 524'000) {
            // Testnet sync fix: PR #1433 merged that lowered fees for HF18 while testnet was
            // already on HF18, but broke syncing because earlier HF18 blocks have ONS txes at the
            // higher fees, so this allows them to pass by pretending the tx burned the right
            // amount.
            burn = burn_required;
        }

        if (check_condition(
                    burn != burn_required,
                    reason,
                    "{}, {} burned {} OXEN={}, required={}",
                    tx,
                    ons_extra_string(nettype, ons_extra),
                    burn > burn_required ? "too much" : "insufficient",
                    burn,
                    burn_required))
            return false;
    }

    return true;
}

bool validate_mapping_type(
        std::string_view mapping_type_str,
        hf hf_version,
        ons_tx_type txtype,
        ons::mapping_type* mapping_type,
        std::string* reason) {
    std::string mapping = tools::lowercase_ascii_string(mapping_type_str);
    std::optional<ons::mapping_type> mapping_type_;
    if (txtype != ons_tx_type::renew && tools::string_iequal(mapping, "session"))
        mapping_type_ = ons::mapping_type::session;
    else if (hf_version >= hf::hf16_pulse) {
        if (tools::string_iequal(mapping, "lokinet"))
            mapping_type_ = ons::mapping_type::lokinet;
        else if (txtype == ons_tx_type::buy || txtype == ons_tx_type::renew) {
            if (tools::string_iequal_any(
                        mapping, "lokinet_1y", "lokinet_1years"))  // Can also specify "lokinet"
                mapping_type_ = ons::mapping_type::lokinet;
            else if (tools::string_iequal_any(mapping, "lokinet_2y", "lokinet_2years"))
                mapping_type_ = ons::mapping_type::lokinet_2years;
            else if (tools::string_iequal_any(mapping, "lokinet_5y", "lokinet_5years"))
                mapping_type_ = ons::mapping_type::lokinet_5years;
            else if (tools::string_iequal_any(mapping, "lokinet_10y", "lokinet_10years"))
                mapping_type_ = ons::mapping_type::lokinet_10years;
        }
    }
    if (hf_version >= hf::hf18) {
        if (tools::string_iequal(mapping, "wallet"))
            mapping_type_ = ons::mapping_type::wallet;
    }

    if (!mapping_type_) {
        if (reason)
            *reason = "Unsupported ONS type \"" + std::string{mapping_type_str} + "\"; supported " +
                      (txtype == ons_tx_type::update  ? "update types are: session, lokinet, wallet"
                       : txtype == ons_tx_type::renew ? "renew types are: lokinet_1y, lokinet_2y, "
                                                        "lokinet_5y, lokinet_10y"
                       : txtype == ons_tx_type::buy   ? "buy types are session, lokinet_1y, "
                                                        "lokinet_2y, lokinet_5y, lokinet_10y"
                                                    : "lookup types are session, lokinet, wallet");
        return false;
    }

    if (mapping_type)
        *mapping_type = *mapping_type_;
    return true;
}

crypto::hash name_to_hash(std::string_view name, const std::optional<crypto::hash>& key) {
    assert(std::none_of(name.begin(), name.end(), [](char c) { return std::isupper(c); }));
    crypto::hash result = {};
    static_assert(
            sizeof(result) >= crypto_generichash_BYTES,
            "Sodium can generate arbitrary length hashes, but recommend the minimum size for a "
            "secure hash must be >= crypto_generichash_BYTES");
    crypto_generichash_blake2b(
            result.data(),
            result.size(),
            reinterpret_cast<const unsigned char*>(name.data()),
            static_cast<unsigned long long>(name.size()),
            key ? key->data() : nullptr,
            key ? key->size() : 0);
    return result;
}

std::string name_to_base64_hash(std::string_view name) {
    crypto::hash hash = name_to_hash(name);
    std::string result = hash_to_base64(hash);
    return result;
}

struct alignas(size_t) secretbox_secret_key {
    unsigned char data[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    secretbox_secret_key& operator=(const crypto::hash& h) {
        static_assert(
                sizeof(secretbox_secret_key::data) == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        static_assert(sizeof(secretbox_secret_key::data) == crypto::hash::size());
        std::memcpy(data, h.data(), sizeof(data));
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
static void name_to_encryption_key(
        std::string_view name, const crypto::hash* name_hash, secretbox_secret_key& out) {
    static_assert(
            sizeof(out) == crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
            "Encrypting key needs to have sufficient space for running encryption functions via "
            "libsodium");

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
static bool name_to_encryption_key_argon2(std::string_view name, secretbox_secret_key& out) {
    static_assert(
            sizeof(out) == crypto_secretbox_KEYBYTES,
            "Encrypting key needs to have sufficient space for running encryption functions via "
            "libsodium");
    return 0 == crypto_pwhash(
                        out.data,
                        sizeof(out.data),
                        name.data(),
                        name.size(),
                        OLD_ENC_SALT,
                        crypto_pwhash_OPSLIMIT_MODERATE,
                        crypto_pwhash_MEMLIMIT_MODERATE,
                        crypto_pwhash_ALG_ARGON2ID13);
}

bool mapping_value::encrypt(
        std::string_view name, const crypto::hash* name_hash, bool deprecated_heavy) {
    assert(!encrypted);
    if (encrypted)
        return false;

    assert(std::none_of(name.begin(), name.end(), [](char c) { return std::isupper(c); }));

    size_t const encryption_len =
            len + (deprecated_heavy ? crypto_secretbox_MACBYTES
                                    : crypto_aead_xchacha20poly1305_ietf_ABYTES +
                                              crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (encryption_len > buffer.size()) {
        log::error(
                logcat,
                "Encrypted value pre-allocated buffer too small={}, required={}",
                buffer.size(),
                encryption_len);
        return false;
    }

    decltype(buffer) enc_buffer;
    secretbox_secret_key skey;
    if (deprecated_heavy) {
        if (name_to_encryption_key_argon2(name, skey))
            encrypted =
                    (crypto_secretbox_easy(
                             enc_buffer.data(),
                             buffer.data(),
                             len,
                             OLD_ENCRYPTION_NONCE,
                             skey.data) == 0);
    } else {
        name_to_encryption_key(name, name_hash, skey);
        unsigned long long actual_length;

        // Create a random nonce:
        auto* nonce = &enc_buffer[encryption_len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        encrypted = 0 == crypto_aead_xchacha20poly1305_ietf_encrypt(
                                 &enc_buffer[0],
                                 &actual_length,
                                 &buffer[0],
                                 len,
                                 nullptr,
                                 0,        // additional data
                                 nullptr,  // nsec, always nullptr according to libsodium docs (just
                                           // here for API compat)
                                 nonce,
                                 skey.data);

        if (encrypted)
            assert(actual_length == encryption_len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    }

    if (encrypted) {
        len = encryption_len;
        buffer = enc_buffer;
    }
    return encrypted;
}

bool mapping_value::decrypt(
        std::string_view name, mapping_type type, const crypto::hash* name_hash) {
    assert(encrypted);
    if (!encrypted)
        return false;

    assert(std::none_of(name.begin(), name.end(), [](char c) { return std::isupper(c); }));

    size_t dec_length;
    decltype(buffer) dec_buffer;
    secretbox_secret_key skey;

    // Check for an old-style, argon2-based encryption, used before HF16.  (After HF16 we use a much
    // faster blake2b-hashed key, and a random nonce appended to the end.)
    if (type == mapping_type::session &&
        len == SESSION_PUBLIC_KEY_BINARY_LENGTH + crypto_secretbox_MACBYTES) {
        dec_length = SESSION_PUBLIC_KEY_BINARY_LENGTH;
        encrypted =
                !(name_to_encryption_key_argon2(name, skey) && 0 == crypto_secretbox_open_easy(
                                                                            dec_buffer.data(),
                                                                            buffer.data(),
                                                                            len,
                                                                            OLD_ENCRYPTION_NONCE,
                                                                            skey.data));
    } else {
        switch (type) {
            case mapping_type::session: dec_length = SESSION_PUBLIC_KEY_BINARY_LENGTH; break;
            case mapping_type::lokinet: dec_length = LOKINET_ADDRESS_BINARY_LENGTH; break;
            case mapping_type::wallet:  // Wallet type has variable type, check performed in
                                        // check_length
                if (auto plain_len = len - crypto_aead_xchacha20poly1305_ietf_ABYTES -
                                     crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
                    plain_len == WALLET_ACCOUNT_BINARY_LENGTH_INC_PAYMENT_ID ||
                    plain_len == WALLET_ACCOUNT_BINARY_LENGTH_NO_PAYMENT_ID) {
                    dec_length = plain_len;
                } else {
                    log::error(
                            logcat,
                            "Invalid wallet mapping_type length passed to mapping_value::decrypt");
                    return false;
                }
                break;
            default:
                log::error(logcat, "Invalid mapping_type passed to mapping_value::decrypt");
                return false;
        }

        auto expected_len = dec_length + crypto_aead_xchacha20poly1305_ietf_ABYTES +
                            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (len != expected_len) {
            log::error(
                    logcat, "Encrypted value size is invalid={}, expected={}", len, expected_len);
            return false;
        }
        const auto& [enc, nonce] = value_nonce(type);

        name_to_encryption_key(name, name_hash, skey);
        unsigned long long actual_length;
        encrypted =
                !(0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
                               dec_buffer.data(),
                               &actual_length,
                               nullptr,  // nsec (always null for this algo)
                               enc.data(),
                               enc.size(),
                               nullptr,
                               0,  // additional data
                               nonce.data(),
                               skey.data));

        if (!encrypted)
            assert(actual_length == dec_length);
    }

    if (!encrypted)  // i.e. decryption success
    {
        len = dec_length;
        buffer = dec_buffer;
    }
    return !encrypted;
}

mapping_value mapping_value::make_encrypted(
        std::string_view name, const crypto::hash* name_hash, bool deprecated_heavy) const {
    mapping_value result{*this};
    result.encrypt(name, name_hash, deprecated_heavy);
    assert(result.encrypted);
    return result;
}

mapping_value mapping_value::make_decrypted(
        std::string_view name, const crypto::hash* name_hash) const {
    mapping_value result{*this};
    result.encrypt(name, name_hash);
    assert(!result.encrypted);
    return result;
}

std::optional<cryptonote::address_parse_info> mapping_value::get_wallet_address_info() const {
    assert(!encrypted);
    if (encrypted)
        return std::nullopt;

    cryptonote::address_parse_info addr_info{};
    auto* bufpos = &buffer[1];
    std::memcpy(addr_info.address.m_spend_public_key.data(), bufpos, 32);
    bufpos += 32;
    std::memcpy(addr_info.address.m_view_public_key.data(), bufpos, 32);
    if (buffer[0] == ONS_WALLET_TYPE_INTEGRATED) {
        bufpos += 32;
        std::copy_n(bufpos, 8, addr_info.payment_id.data());
        addr_info.has_payment_id = true;
    } else if (buffer[0] == ONS_WALLET_TYPE_SUBADDRESS) {
        addr_info.is_subaddress = true;
    } else
        assert(buffer[0] == ONS_WALLET_TYPE_PRIMARY);
    return addr_info;
}

namespace {

    void build_default_tables(Connection& conn) {
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

CREATE TABLE IF NOT EXISTS mappings ()" + mappings_columns +
                                            R"();
CREATE INDEX IF NOT EXISTS owner_id_index ON mappings(owner_id);
DROP INDEX IF EXISTS backup_owner_id_index;
CREATE INDEX IF NOT EXISTS backup_owner_index ON mappings(backup_owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS name_type_update ON mappings (name_hash, type, update_height DESC);
CREATE INDEX IF NOT EXISTS mapping_type_name_exp ON mappings (type, name_hash, expiration_height DESC);
)";

        conn.sql.exec(BUILD_TABLE_SQL);

        // In Loki 8 we dropped some columns that are no longer needed, but SQLite can't do this
        // easily: instead we have to manually recreate the table, so check it and see if the
        // prev_txid or register_height columns still exist: if so, we need to recreate.
        bool need_mappings_migration = false;
        for (const auto& col : conn.get_columns("mappings")) {
            if (col.name == "prev_txid" || col.name == "register_height") {
                need_mappings_migration = true;
                break;
            }
        }

        if (need_mappings_migration) {
            // Earlier version migration: we need "update_height" to exist (if this fails it's
            // fine).
            conn.sql.tryExec(
                    "ALTER TABLE mappings ADD COLUMN update_height INTEGER NOT NULL DEFAULT "
                    "register_height");

            log::info(logcat, "Migrating ONS mappings database to new format");
            const std::string migrate = R"(
BEGIN TRANSACTION;
ALTER TABLE mappings RENAME TO mappings_old;
CREATE TABLE mappings ()" + mappings_columns +
                                        R"();
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

            conn.sql.exec(migrate);
        }

        // Updates to add columns; we ignore errors on these since they will fail if the column
        // already exists
        for (const auto& upgrade : {
                     "ALTER TABLE settings ADD COLUMN pruned_height INTEGER NOT NULL DEFAULT 0",
             })
            conn.sql.tryExec(upgrade);
    }

    const std::string sql_select_mappings_and_owners_prefix = R"(
SELECT mappings.*, o1.address, o2.address, MAX(update_height)
FROM mappings
  JOIN owner o1 ON mappings.owner_id = o1.id
  LEFT JOIN owner o2 ON mappings.backup_owner_id = o2.id
)"s;
    const std::string sql_select_mappings_and_owners_suffix = " GROUP BY name_hash, type";

    enum struct db_version { v0, v1_track_updates, v2_full_rows };
    auto constexpr DB_VERSION = db_version::v2_full_rows;

    constexpr auto EXPIRATION = " (expiration_height IS NULL OR expiration_height >= ?) "sv;

    const std::string GET_MAPPINGS_BY_OWNER_STR = sql_select_mappings_and_owners_prefix +
                                                  "WHERE ? IN (o1.address, o2.address)" +
                                                  sql_select_mappings_and_owners_suffix;
    const std::string GET_MAPPING_STR = sql_select_mappings_and_owners_prefix +
                                        "WHERE type = ? AND name_hash = ?" +
                                        sql_select_mappings_and_owners_suffix;

    const std::string GET_MAPPING_COUNTS_STR = R"(
    SELECT type, COUNT(*) FROM (
      SELECT DISTINCT type, name_hash FROM mappings WHERE )" +
                                               std::string{EXPIRATION} + R"(
    )
    GROUP BY type)";

    const std::string RESOLVE_STR = R"(
SELECT encrypted_value, MAX(update_height)
FROM mappings
WHERE type = ? AND name_hash = ? AND)" +
                                    std::string{EXPIRATION};

    const std::string GET_SETTINGS_STR =
            "SELECT top_height, top_hash, version FROM settings WHERE id = 1";
    const std::string GET_OWNER_ID_BY_KEY_STR = "SELECT id FROM owner WHERE address = ?";

    // Prune queries used when we need to rollback to remove records added after the detach point:
    const std::string PRUNE_MAPPINGS_STR = "DELETE FROM mappings WHERE update_height > ?";
    const std::string PRUNE_OWNERS_STR = R"(
DELETE FROM owner
WHERE NOT EXISTS (SELECT * FROM mappings WHERE owner.id = mappings.owner_id)
AND NOT EXISTS   (SELECT * FROM mappings WHERE owner.id = mappings.backup_owner_id))";

    const std::string SAVE_MAPPING_STR =
            "INSERT INTO mappings (type, name_hash, encrypted_value, txid, owner_id, "
            "backup_owner_id, update_height, expiration_height) VALUES (?,?,?,?,?,?,?,?)";
    const std::string SAVE_OWNER_STR = "INSERT INTO owner (address) VALUES (?)";
    const std::string SAVE_SETTINGS_STR =
            "INSERT OR REPLACE INTO settings (id, top_height, top_hash, version) VALUES (1,?,?,?)";

}  // namespace

bool name_system_db::init(
        cryptonote::Blockchain const* blockchain,
        cryptonote::network_type nettype,
        const fs::path& file_path,
        bool read_only) {
    this->nettype = nettype;

    try {
        db = std::make_unique<session::sqlite::Database>(
                file_path,
                session::sqlite::open_readonly{read_only},
                session::sqlite::open_create{!read_only});
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to open ONS db at: {}, reason: {}", file_path, e.what());
        return false;
    }

    try {
        auto conn = db->conn();
        build_default_tables(conn);

        // -----------------------------------------------------------------------------------------
        //
        // Migrate DB
        //
        // -----------------------------------------------------------------------------------------
        if (settings_record settings = get_settings()) {
            if (settings.version != static_cast<decltype(settings.version)>(DB_VERSION)) {
                if (!blockchain) {
                    log::error(logcat, "Migration required, blockchain can not be nullptr");
                    return false;
                }

                if (blockchain->db().is_read_only()) {
                    log::error(logcat, "DB is opened in read-only mode, unable to migrate ONS DB");
                    return false;
                }

                SQLite::Transaction tx{conn.sql};

                if (settings.version <
                    static_cast<decltype(settings.version)>(db_version::v1_track_updates)) {

                    SQLite::Statement all_st{
                            conn.sql,
                            sql_select_mappings_and_owners_prefix +
                                    sql_select_mappings_and_owners_suffix};
                    std::vector<mapping_record> all_mappings = get_mapping_records(all_st);

                    std::vector<crypto::hash> hashes;
                    hashes.reserve(all_mappings.size());
                    for (mapping_record const& record : all_mappings)
                        hashes.push_back(record.txid);

                    std::vector<uint64_t> heights = blockchain->get_transactions_heights(hashes);
                    SQLite::Statement update_height{
                            conn.sql, "UPDATE mappings SET update_height = ? WHERE id = ?"};
                    for (size_t i = 0; i < all_mappings.size(); i++) {
                        session::sqlite::exec_query(
                                update_height, as_i64(heights[i]), all_mappings[i].id);
                        update_height.reset();
                    }
                }

                if (settings.version <
                    static_cast<decltype(settings.version)>(db_version::v2_full_rows))
                    conn.sql.exec(
                            "UPDATE settings SET pruned_height = (SELECT MAX(update_height) FROM "
                            "mappings)");

                save_settings(
                        settings.top_height,
                        settings.top_hash,
                        static_cast<int>(db_version::v2_full_rows));
                tx.commit();
            }
        }

        // -----------------------------------------------------------------------------------------
        //
        // Check settings
        //
        // -----------------------------------------------------------------------------------------
        settings_record settings = get_settings();
        if (!settings)
            return true;

        if (!blockchain) {
            assert(nettype == cryptonote::network_type::FAKECHAIN);
            return nettype == cryptonote::network_type::FAKECHAIN;
        }

        auto [ons_height, ons_hash] = blockchain->get_tail_id();

        // Try support out of date ONS databases by checking if the stored
        // settings->[top_hash|top_height] match what we expect. If they match, we
        // don't drop the DB but will load the missing blocks in a later step.

        cryptonote::block ons_blk = {};
        bool orphan = false;
        if (blockchain->get_block_by_hash(settings.top_hash, ons_blk, nullptr, &orphan)) {
            bool ons_height_matches = settings.top_height == ons_blk.get_height();
            if (ons_height_matches && !orphan) {
                ons_height = settings.top_height;
                ons_hash = settings.top_hash;
            }
        }

        if (settings.top_height == ons_height && settings.top_hash == ons_hash) {
            this->last_processed_height = settings.top_height;
            this->last_processed_hash = settings.top_hash;
            assert(settings.version == static_cast<int>(DB_VERSION));
        } else {
            // Otherwise we've got something unrecoverable: a top_hash + top_height that are
            // different from what we have in the blockchain, which means the ons db and blockchain
            // are out of sync. This likely means something external changed the lmdb and/or the
            // ons.db, and we can't recover from it: so just drop and recreate the tables completely
            // and rescan from scratch.
            //
            // mappings has to go before owner: it references owner, and with foreign keys enforced
            // dropping owner first fails.
            conn.sql.exec(
                    "DROP TABLE IF EXISTS mappings; DROP TABLE IF EXISTS owner; DROP TABLE IF "
                    "EXISTS settings");
            build_default_tables(conn);
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to initialize ONS database: {}", e.what());
        return false;
    }

    return true;
}

name_system_db::~name_system_db() {
    if (db)
        save_settings(last_processed_height, last_processed_hash, static_cast<int>(DB_VERSION));
}

namespace {

    std::optional<int64_t> add_or_get_owner_id(
            ons::name_system_db& ons_db,
            crypto::hash const& tx_hash,
            cryptonote::tx_extra_oxen_name_system const& entry,
            ons::generic_owner const& key) {
        int64_t result = 0;
        if (owner_record owner = ons_db.get_owner_by_key(key))
            result = owner.id;
        if (result == 0) {
            if (!ons_db.save_owner(key, &result)) {
                log::info(
                        logcat,
                        "Failed to save ONS owner to DB tx: {}, type: {}, name_hash: {}, owner: {}",
                        tx_hash,
                        entry.type,
                        entry.name_hash,
                        entry.owner.to_string(ons_db.network_type()));
                return std::nullopt;
            }
        }
        if (result == 0)
            return std::nullopt;
        return result;
    }

    // Build a query and bind values that will create a new row at the given height by copying the
    // current highest-height row values and/or updating the given update fields.
    using update_variant =
            std::variant<uint16_t, int64_t, std::span<const unsigned char>, std::string>;
    std::pair<std::string, std::vector<update_variant>> update_record_query(
            name_system_db& ons_db,
            uint64_t height,
            const cryptonote::tx_extra_oxen_name_system& entry,
            const crypto::hash& tx_hash) {
        assert(entry.is_updating() || entry.is_renewing());

        std::pair<std::string, std::vector<update_variant>> result;
        auto& [sql, bind] = result;

        sql.reserve(500);
        sql += R"(
INSERT INTO mappings (type, name_hash, txid, update_height, expiration_height, owner_id, backup_owner_id, encrypted_value)
SELECT                type, name_hash, ?,    ?)";

        bind.emplace_back(span_guts(tx_hash));
        bind.emplace_back(as_i64(height));

        constexpr auto suffix =
                " FROM mappings WHERE type = ? AND name_hash = ? ORDER BY update_height DESC LIMIT 1"sv;

        if (entry.is_renewing()) {
            sql += ", expiration_height + ?, owner_id, backup_owner_id, encrypted_value";
            bind.emplace_back(as_i64(expiry_blocks(ons_db.network_type(), entry.type).value_or(0)));
        } else {
            // Updating

            sql += ", expiration_height";

            if (entry.field_is_set(ons::extra_field::owner)) {
                auto opt_id = add_or_get_owner_id(ons_db, tx_hash, entry, entry.owner);
                if (!opt_id) {
                    log::error(
                            logcat,
                            "Failed to add or get owner with key={}",
                            entry.owner.to_string(ons_db.network_type()));
                    assert(opt_id);
                    return {};
                }
                sql += ", ?";
                bind.emplace_back(*opt_id);
            } else
                sql += ", owner_id";

            if (entry.field_is_set(ons::extra_field::backup_owner)) {
                auto opt_id = add_or_get_owner_id(ons_db, tx_hash, entry, entry.backup_owner);
                if (!opt_id) {
                    log::error(
                            logcat,
                            "Failed to add or get backup owner with key={}",
                            entry.backup_owner.to_string(ons_db.network_type()));
                    assert(opt_id);
                    return {};
                }

                sql += ", ?";
                bind.emplace_back(*opt_id);
            } else
                sql += ", backup_owner_id";

            if (entry.field_is_set(ons::extra_field::encrypted_value)) {
                sql += ", ?";
                bind.emplace_back(blob(entry.encrypted_value));
            } else
                sql += ", encrypted_value";
        }

        sql += suffix;
        bind.emplace_back(db_mapping_type(entry.type));
        bind.emplace_back(hash_to_base64(entry.name_hash));

        return result;
    }

    bool add_ons_entry(
            ons::name_system_db& ons_db,
            uint64_t height,
            cryptonote::tx_extra_oxen_name_system const& entry,
            crypto::hash const& tx_hash) {
        // -----------------------------------------------------------------------------------------------
        // New Mapping Insert or Completely Replace
        // -----------------------------------------------------------------------------------------------
        if (entry.is_buying()) {
            auto owner_id = add_or_get_owner_id(ons_db, tx_hash, entry, entry.owner);
            if (!owner_id) {
                log::error(
                        logcat,
                        "Failed to add or get owner with key={}",
                        entry.owner.to_string(ons_db.network_type()));
                assert(owner_id);
                return false;
            }

            std::optional<int64_t> backup_owner_id;
            if (entry.backup_owner) {
                backup_owner_id = add_or_get_owner_id(ons_db, tx_hash, entry, entry.backup_owner);
                if (!backup_owner_id) {
                    log::error(
                            logcat,
                            "Failed to add or get backup owner with key={}",
                            entry.backup_owner.to_string(ons_db.network_type()));
                    assert(backup_owner_id);
                    return false;
                }
            }

            auto expiry = expiry_blocks(ons_db.network_type(), entry.type);
            if (expiry)
                *expiry += height;
            if (!ons_db.save_mapping(tx_hash, entry, height, expiry, *owner_id, backup_owner_id)) {
                log::info(
                        logcat,
                        "Failed to save ONS entry to DB tx: {}, type: {}, name_hash: {}, owner: {}",
                        tx_hash,
                        entry.type,
                        entry.name_hash,
                        entry.owner.to_string(ons_db.network_type()));
                return false;
            }
        }
        // -----------------------------------------------------------------------------------------------
        // Update mapping or renewal: create a new row copies and updated from the existing top row
        // -----------------------------------------------------------------------------------------------
        else {
            auto [sql, bind] = update_record_query(ons_db, height, entry, tx_hash);

            if (sql.empty())
                return false;  // already MERROR'd

            auto conn = ons_db.db->conn();
            SQLite::Statement st{conn.sql, sql};
            session::sqlite::exec_query(st, bind_each(bind));
        }

        return true;
    }

}  // namespace

bool name_system_db::add_block(
        const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs) {
    uint64_t height = block.get_height();
    if (last_processed_height >= height)
        return true;

    try {
        // Everything below (including the save_* calls, which get this same connection back from
        // `conn()` on this thread) happens inside this transaction, which only gets committed if
        // the block actually changed something worth saving.
        auto conn = db->conn();
        SQLite::Transaction db_tx{conn.sql};

        bool ons_parsed_from_block = false;
        if (block.major_version >= hf::hf15_ons) {
            for (cryptonote::transaction const& tx : txs) {
                if (tx.type != cryptonote::txtype::oxen_name_system)
                    continue;

                cryptonote::tx_extra_oxen_name_system entry = {};
                std::string fail_reason;
                if (!validate_ons_tx(block.major_version, height, tx, entry, &fail_reason)) {
                    log::error(
                            logcat,
                            "ONS TX: Failed to validate for tx={}. This should have failed "
                            "validation earlier reason={}",
                            get_transaction_hash(tx),
                            fail_reason);
                    assert("Failed to validate acquire name service. Should already have failed "
                           "validation prior" == nullptr);
                    return false;
                }

                crypto::hash const& tx_hash = cryptonote::get_transaction_hash(tx);
                if (!add_ons_entry(*this, height, entry, tx_hash))
                    return false;

                ons_parsed_from_block = true;
            }
        }

        last_processed_height = height;
        last_processed_hash = cryptonote::get_block_hash(block);

        bool do_commit = (height % 16384 == 0) || ons_parsed_from_block;
        if (do_commit) {
            save_settings(last_processed_height, last_processed_hash, static_cast<int>(DB_VERSION));
            db_tx.commit();
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to add block {} to the ONS DB: {}", height, e.what());
        return false;
    }
    return true;
}

struct ons_update_history {
    uint64_t value_last_update_height = static_cast<uint64_t>(-1);
    uint64_t owner_last_update_height = static_cast<uint64_t>(-1);
    uint64_t backup_owner_last_update_height = static_cast<uint64_t>(-1);

    void update(uint64_t height, cryptonote::tx_extra_oxen_name_system const& ons_extra);
    uint64_t newest_update_height() const;
};

void ons_update_history::update(
        uint64_t height, cryptonote::tx_extra_oxen_name_system const& ons_extra) {
    if (ons_extra.field_is_set(ons::extra_field::encrypted_value))
        value_last_update_height = height;

    if (ons_extra.field_is_set(ons::extra_field::owner))
        owner_last_update_height = height;

    if (ons_extra.field_is_set(ons::extra_field::backup_owner))
        backup_owner_last_update_height = height;
}

uint64_t ons_update_history::newest_update_height() const {
    uint64_t result = std::max(
            std::max(value_last_update_height, owner_last_update_height),
            backup_owner_last_update_height);
    return result;
}

struct replay_ons_tx {
    uint64_t height;
    crypto::hash tx_hash;
    cryptonote::tx_extra_oxen_name_system entry;
};

bool name_system_db::save_owner(ons::generic_owner const& owner, int64_t* row_id) {
    try {
        auto conn = db->conn();
        conn.prepared_exec(SAVE_OWNER_STR, span_guts(owner));
        if (row_id)
            *row_id = conn.sql.getLastInsertRowid();
        return true;
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to save ONS owner: {}", e.what());
        return false;
    }
}

bool name_system_db::save_mapping(
        crypto::hash const& tx_hash,
        cryptonote::tx_extra_oxen_name_system const& src,
        uint64_t height,
        std::optional<uint64_t> expiration,
        int64_t owner_id,
        std::optional<int64_t> backup_owner_id) {
    if (!src.is_buying())
        return false;

    std::optional<int64_t> expiration_i64;
    if (expiration)
        expiration_i64 = as_i64(*expiration);

    try {
        db->conn().prepared_exec(
                SAVE_MAPPING_STR,
                db_mapping_type(src.type),
                hash_to_base64(src.name_hash),
                blob(src.encrypted_value),
                span_guts(tx_hash),
                owner_id,
                backup_owner_id,
                as_i64(height),
                expiration_i64);
        return true;
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to save ONS mapping for tx {}: {}", tx_hash, e.what());
        return false;
    }
}

bool name_system_db::save_settings(uint64_t top_height, crypto::hash const& top_hash, int version) {
    try {
        db->conn().prepared_exec(
                SAVE_SETTINGS_STR, as_i64(top_height), span_guts(top_hash), version);
        return true;
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to save ONS settings: {}", e.what());
        return false;
    }
}

bool name_system_db::prune_db(uint64_t top_height, const crypto::hash& top_hash) {
    bool result = false;
    if (db) {
        try {
            auto conn = db->conn();
            conn.prepared_exec(PRUNE_MAPPINGS_STR, as_i64(top_height));
            conn.prepared_exec(PRUNE_OWNERS_STR);
            result = true;
        } catch (const std::exception& e) {
            log::error(logcat, "Failed to prune ONS DB: {}", e.what());
        }

        log::debug(
                logcat,
                "Detach request for ONS (last processed was {}), {} to {} ({})",
                last_processed_height,
                result ? "detached" : "failed to detach",
                top_height,
                top_hash);

        if (result && top_height < last_processed_height) {
            last_processed_height = top_height;
            last_processed_hash = top_hash;
        }
    }
    return result;
}

owner_record name_system_db::get_owner_by_key(ons::generic_owner const& owner) {
    owner_record result = {};
    try {
        if (auto id = db->conn().prepared_maybe_get<int64_t>(
                    GET_OWNER_ID_BY_KEY_STR, span_guts(owner))) {
            result.id = *id;
            result.address = owner;
            result.loaded = true;
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to look up ONS owner: {}", e.what());
    }
    return result;
}

bool name_system_db::get_wallet_mapping(
        std::string str, uint64_t blockchain_height, cryptonote::address_parse_info& addr_info) {
    std::string name = tools::lowercase_ascii_string(std::move(str));
    std::string b64_hashed_name = ons::name_to_base64_hash(name);
    if (auto record =
                name_system_db::resolve(mapping_type::wallet, b64_hashed_name, blockchain_height)) {
        (*record).decrypt(name, mapping_type::wallet);
        std::optional<cryptonote::address_parse_info> addr = (*record).get_wallet_address_info();
        if (addr) {
            addr_info = *addr;
            return true;
        }
    }
    return false;
}

mapping_record name_system_db::get_mapping(
        mapping_type type,
        std::string_view name_base64_hash,
        std::optional<uint64_t> blockchain_height) {
    assert(name_base64_hash.size() == 44 && name_base64_hash.back() == '=' &&
           oxenc::is_base64(name_base64_hash));
    mapping_record result = {};
    try {
        auto conn = db->conn();
        auto st = conn.prepared_bind(GET_MAPPING_STR, db_mapping_type(type), name_base64_hash);
        if (st->executeStep())
            result = mapping_from_row(st);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to get ONS mapping: {}", e.what());
        return {};
    }
    if (blockchain_height && !result.active(*blockchain_height))
        result.loaded = false;
    return result;
}

std::optional<mapping_value> name_system_db::resolve(
        mapping_type type, std::string_view name_hash_b64, uint64_t blockchain_height) {
    assert(name_hash_b64.size() == 44 && name_hash_b64.back() == '=' &&
           oxenc::is_base64(name_hash_b64));
    std::optional<mapping_value> result;
    try {
        auto conn = db->conn();
        auto st = conn.prepared_bind(
                RESOLVE_STR, db_mapping_type(type), name_hash_b64, as_i64(blockchain_height));
        // The MAX() aggregate means we always get a row, but with a NULL value if nothing matched.
        if (st->executeStep()) {
            if (auto value = st->getColumn(0); !value.isNull()) {
                auto& r = result.emplace();
                auto len = static_cast<size_t>(value.getBytes());
                if (len > r.buffer.size())
                    throw std::runtime_error{
                            "encrypted value of {} bytes is too large"_format(len)};
                r.len = len;
                r.encrypted = true;
                std::memcpy(r.buffer.data(), value.getBlob(), len);
            }
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to resolve ONS mapping: {}", e.what());
        return std::nullopt;
    }
    return result;
}

std::vector<mapping_record> name_system_db::get_mappings(
        std::string_view name_base64_hash,
        std::optional<uint64_t> blockchain_height,
        const std::unordered_set<mapping_type>& only_types) {
    assert(name_base64_hash.size() == 44 && name_base64_hash.back() == '=' &&
           oxenc::is_base64(name_base64_hash));
    std::vector<uint16_t> types;
    types.reserve(only_types.size());
    for (auto t : only_types)
        types.push_back(db_mapping_type(t));

    std::optional<int64_t> height;
    if (blockchain_height)
        height = as_i64(*blockchain_height);

    auto sql = "{}WHERE name_hash = ?{}{}{}{}"_format(
            sql_select_mappings_and_owners_prefix,
            types.empty() ? "" : " AND type IN ({})"_format(placeholders(types.size())),
            height ? " AND " : "",
            height ? EXPIRATION : ""sv,
            sql_select_mappings_and_owners_suffix);

    try {
        auto conn = db->conn();
        SQLite::Statement st{conn.sql, sql};
        if (height)
            session::sqlite::bind_oneshot(st, name_base64_hash, bind_each(types), *height);
        else
            session::sqlite::bind_oneshot(st, name_base64_hash, bind_each(types));
        return get_mapping_records(st);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to get ONS mappings: {}", e.what());
        return {};
    }
}

std::vector<mapping_record> name_system_db::get_mappings_by_owners(
        std::vector<generic_owner> const& owners, std::optional<uint64_t> blockchain_height) {
    if (owners.empty())
        return {};

    std::vector<std::span<const uint8_t>> keys;
    keys.reserve(owners.size());
    for (const auto& owner : owners)
        keys.push_back(span_guts(owner));

    std::optional<int64_t> height;
    if (blockchain_height)
        height = as_i64(*blockchain_height);

    auto sql = "{0}WHERE (o1.address IN ({1}) OR o2.address IN ({1})){2}{3}{4}"_format(
            sql_select_mappings_and_owners_prefix,
            placeholders(owners.size()),
            height ? " AND " : "",
            height ? EXPIRATION : ""sv,
            sql_select_mappings_and_owners_suffix);

    try {
        auto conn = db->conn();
        SQLite::Statement st{conn.sql, sql};
        if (height)
            session::sqlite::bind_oneshot(st, bind_each(keys), bind_each(keys), *height);
        else
            session::sqlite::bind_oneshot(st, bind_each(keys), bind_each(keys));
        return get_mapping_records(st);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to get ONS mappings by owners: {}", e.what());
        return {};
    }
}

std::vector<mapping_record> name_system_db::get_mappings_by_owner(
        generic_owner const& owner, std::optional<uint64_t> blockchain_height) {
    std::vector<mapping_record> result;
    try {
        auto conn = db->conn();
        auto st = conn.prepared_bind(GET_MAPPINGS_BY_OWNER_STR, span_guts(owner));
        result = get_mapping_records(st);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to get ONS mappings by owner: {}", e.what());
        return {};
    }
    if (blockchain_height) {
        auto end = std::remove_if(
                result.begin(), result.end(), [height = *blockchain_height](auto& r) {
                    return !r.active(height);
                });
        result.erase(end, result.end());
    }
    return result;
}

std::map<mapping_type, int> name_system_db::get_mapping_counts(uint64_t blockchain_height) {
    std::map<mapping_type, int> result;
    try {
        auto conn = db->conn();
        for (auto [type, count] : conn.prepared_results<mapping_type, int>(
                     GET_MAPPING_COUNTS_STR, as_i64(blockchain_height)))
            result.emplace(type, count);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to get ONS mapping counts: {}", e.what());
        return {};
    }
    return result;
}

settings_record name_system_db::get_settings() {
    settings_record result = {};
    try {
        auto conn = db->conn();
        if (auto row = conn.prepared_maybe_get<int64_t, blob_guts<crypto::hash>, int>(
                    GET_SETTINGS_STR)) {
            auto& [height, hash, version] = *row;
            result.top_height = as_u64(height);
            result.top_hash = hash;
            result.version = version;
            result.loaded = true;
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to read ONS settings: {}", e.what());
    }
    return result;
}

}  // namespace ons

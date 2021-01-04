#include "gtest/gtest.h"

#include "common/oxen.h"
#include "cryptonote_core/oxen_name_system.h"
#include "oxen_economy.h"

TEST(oxen_name_system, name_tests)
{
  struct name_test
  {
    std::string name;
    bool allowed;
  };

  name_test const lokinet_names[] = {
      {"a.loki", true},
      {"domain.loki", true},
      {"xn--tda.loki", true}, // ü
      {"xn--Mnchen-Ost-9db.loki", true}, // München-Ost
      {"xn--fwg93vdaef749it128eiajklmnopqrstu7dwaxyz0a1a2a3a643qhok169a.loki", true}, // ⸘🌻‽💩🤣♠♡♢♣🂡🂢🂣🂤🂥🂦🂧🂨🂩🂪🂫🂬🂭🂮🂱🂲🂳🂴🂵🂶🂷🂸🂹
      {"abcdefghijklmnopqrstuvwxyz123456.loki", true}, // Max length = 32 if no hyphen (so that it can't look like a raw address)
      {"a-cdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789a.loki", true}, // Max length = 63 if there is at least one hyphen

      {"abc.domain.loki", false},
      {"a", false},
      {"a.loko", false},
      {"a domain name.loki", false},
      {"-.loki", false},
      {"a_b.loki", false},
      {" a.loki", false},
      {"a.loki ", false},
      {" a.loki ", false},
      {"localhost.loki", false},
      {"localhost", false},
      {"loki.loki", false},
      {"snode.loki", false},
      {"abcdefghijklmnopqrstuvwxyz1234567.loki", false}, // Too long (no hyphen)
      {"a-cdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789ab.loki", false}, // Too long with hyphen
      {"xn--fwg93vdaef749it128eiajklmnopqrstu7dwaxyz0a1a2a3a643qhok169ab.loki", false}, // invalid (punycode and DNS name parts max at 63)
      {"ab--xyz.loki", false}, // Double-hyphen at chars 3&4 is reserved by DNS (currently only xn-- is used).
  };

  name_test const session_wallet_names[] = {
      {"Hello", true},
      {"1Hello", true},
      {"1Hello1", true},
      {"_Hello1", true},
      {"1Hello_", true},
      {"_Hello_", true},
      {"999", true},
      {"xn--tda", true},
      {"xn--Mnchen-Ost-9db", true},

      {"-", false},
      {"@", false},
      {"'Hello", false},
      {"@Hello", false},
      {"[Hello", false},
      {"]Hello", false},
      {"Hello ", false},
      {" Hello", false},
      {" Hello ", false},

      {"Hello World", false},
      {"Hello\\ World", false},
      {"\"hello\"", false},
      {"hello\"", false},
      {"\"hello", false},
  };

  for (uint16_t type16 = 0; type16 < static_cast<uint16_t>(ons::mapping_type::_count); type16++)
  {
    auto type = static_cast<ons::mapping_type>(type16);
    if (type == ons::mapping_type::wallet) continue; // Not yet supported
    name_test const *names = ons::is_lokinet_type(type) ? lokinet_names : session_wallet_names;
    size_t names_count     = ons::is_lokinet_type(type) ? oxen::char_count(lokinet_names) : oxen::char_count(session_wallet_names);

    for (size_t i = 0; i < names_count; i++)
    {
      name_test const &entry = names[i];
      ASSERT_EQ(ons::validate_ons_name(type, entry.name), entry.allowed) << "Values were {type=" << type << ", name=\"" << entry.name << "\"}";
    }
  }
}

TEST(oxen_name_system, value_encrypt_and_decrypt)
{
  std::string name         = "my ons name";
  ons::mapping_value value = {};
  value.encrypted          = false;
  value.len                = 32;
  memset(&value.buffer[0], 'a', value.len);

  // The type here is not hugely important for decryption except that lokinet (as opposed to
  // session) doesn't fall back to argon2 decryption if decryption fails.
  constexpr auto type = ons::mapping_type::lokinet;

  // Encryption and Decryption success
  {
    auto mval = value;
    ASSERT_TRUE(mval.encrypt(name));
    ASSERT_FALSE(mval == value);
    ASSERT_TRUE(mval.decrypt(name, type));
    ASSERT_TRUE(mval == value);
  }

  // Decryption Fail: Encrypted value was modified
  {
    auto mval = value;
    ASSERT_FALSE(mval.encrypted);
    ASSERT_TRUE(mval.encrypt(name));
    ASSERT_TRUE(mval.encrypted);

    mval.buffer[0] = std::byte{'Z'};
    ASSERT_FALSE(mval.decrypt(name, type));
    ASSERT_TRUE(mval.encrypted);
  }

  // Decryption Fail: Name was modified
  {
    std::string name_copy = name;
    auto mval = value;
    ASSERT_TRUE(mval.encrypt(name_copy));

    name_copy[0] = 'z';
    ASSERT_FALSE(mval.decrypt(name_copy, type));
  }
}

TEST(oxen_name_system, value_encrypt_and_decrypt_heavy)
{
  std::string name         = "abcdefg";
  ons::mapping_value value = {};
  value.encrypted          = false;
  value.len                = 33;
  memset(&value.buffer[0], 'a', value.len);

  // Encryption and Decryption success for the older argon2-based encryption key
  {
    auto mval = value;
    auto mval_new = value;
    ASSERT_TRUE(mval.encrypt(name, nullptr, true));
    ASSERT_TRUE(mval_new.encrypt(name, nullptr, false));
    ASSERT_EQ(mval.len + 24, mval_new.len); // New value appends a 24-byte nonce
    ASSERT_TRUE(mval.decrypt(name, ons::mapping_type::session));
    ASSERT_TRUE(mval_new.decrypt(name, ons::mapping_type::session));
    ASSERT_TRUE(mval == value);
    ASSERT_TRUE(mval_new == value);
  }
}

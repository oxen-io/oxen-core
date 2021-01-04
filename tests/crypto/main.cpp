// Copyright (c) 2014-2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <cstddef>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/hex.h"
#include "common/string_util.h"
#include "epee/warnings.h"
#include "epee/misc_log_ex.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto-tests.h"

using namespace std::literals;
using namespace crypto;
typedef crypto::hash chash;

bool operator !=(const ec_scalar &a, const ec_scalar &b) {
  return 0 != memcmp(&a, &b, sizeof(ec_scalar));
}

bool operator !=(const ec_point &a, const ec_point &b) {
  return 0 != memcmp(&a, &b, sizeof(ec_point));
}

bool operator !=(const key_derivation &a, const key_derivation &b) {
  return 0 != memcmp(&a, &b, sizeof(key_derivation));
}

DISABLE_GCC_WARNING(maybe-uninitialized)

size_t lineno;

template <typename T>
T extract_single(std::string_view val) {
  if constexpr (std::is_same_v<T, bool>) {
    if (val == "true") return true;
    if (val == "false") return false;
    throw std::runtime_error{"Invalid value, expected {true|false}, got " + std::string{val} + " on line " + std::to_string(lineno)};
  } else if constexpr (std::is_integral_v<T>) {
    T v;
    if (!tools::parse_int(val, v))
      throw std::runtime_error{"Invalid value, expected integer, got " + std::string{val} + " on line " + std::to_string(lineno)};
    return v;
  } else if constexpr (std::is_same_v<T, std::string_view>) {
    return val;
  } else {
    T v;
    if (!tools::hex_to_type(val, v))
      throw std::runtime_error("Invalid hex [" + std::string{val} + ", size=" + std::to_string(val.size()/2) + "B], could not extract type (T size=" + std::to_string(sizeof(T)) + ") on line " + std::to_string(lineno));
    return v;
  }
}

template <typename T>
std::string make_single(const T& val) {
  if constexpr (std::is_same_v<T, bool>)
    return val ? "true" : "false";
  else if constexpr (std::is_integral_v<T>)
    return std::to_string(val);
  else if constexpr (std::is_same_v<T, std::string_view>)
    return std::string{val};
  else
    return tools::type_to_hex(val);
}

template <typename... T, typename It, size_t... S>
std::tuple<T...> extract(It it, It end, std::index_sequence<S...>) {
  return {extract_single<T>(it[S])...};
}

template <typename... T>
std::tuple<T...> extract(const std::vector<std::string_view>& line, size_t skip = 0) {
  if (sizeof...(T) + skip + 1 > line.size())
    throw std::runtime_error("Invalid data: too few elements on line " + std::to_string(lineno) + ": expected >= " + std::to_string(sizeof...(T) + skip + 1) + ", have " + std::to_string(line.size()));
  return extract<T...>(line.begin() + skip + 1, line.end(), std::index_sequence_for<T...>{});
}

template <typename... T>
std::string make(const T&... val) {
  return tools::join(" ", std::initializer_list<std::string>{make_single(val)...});
}

static std::mt19937_64 rng{42};
static void test_rng_bytes(void* const buf, const size_t size) {
    // Copy 8 bytes at a time:
    for (size_t i = 0; i < size/8; i++) {
        uint64_t x = rng();
        std::memcpy(reinterpret_cast<unsigned char*>(buf) + 8*i, &x, 8);
    }
    // If requesting something not a multiple of 8 then get one more random value and copy over the
    // first n bytes:
    if (size_t leftover = size % 8; leftover > 0) {
        uint64_t x = rng();
        std::memcpy(reinterpret_cast<unsigned char*>(buf) + size - leftover, &x, leftover);
    }
}
static randombytes_implementation testing_rng_impl{
    [] { return "loki crypto test suite"; }, // name
    [] { return static_cast<uint32_t>(rng()); }, // random
    nullptr, // stir
    nullptr, // uniform
    test_rng_bytes, // buf
    nullptr, // close
};

int main(int argc, char *argv[]) {
  std::fstream input;
  input.exceptions(std::ios::badbit | std::ios::failbit);
  std::string cmd;
  size_t test = 0;
  size_t errors = 0;
  randombytes_set_implementation(&testing_rng_impl);
  if (argc != 2) {
      std::cerr << "Invalid arguments! Usage: " << argv[0] << " /path/to/tests.txt\n";
    return 1;
  }
  input.open(argv[1], std::ios_base::in);

  std::ofstream regen;
  regen.exceptions(std::ios::badbit | std::ios::failbit);
  bool verbose = false;
  if (auto* envverbose = std::getenv("VERBOSE"); envverbose && envverbose == "1"sv)
    verbose = true;
  if (auto* envregen = std::getenv("REGEN"); envregen && envregen == "1"sv) {
    regen.open("tests-regen.txt", std::ios::trunc);
    std::cerr << "Writing calculated test results to ./tests-regen.txt\n";
  }

  input.exceptions(std::ios_base::badbit);

  // If a test fails, this is set to what the line would need to be to pass the test (without the leading command)
  std::string fail_line;
  lineno = 0;
  for (;;) {
    std::vector<char> linebuf(50000); // This test file has some massive lines in it
    input.getline(linebuf.data(), 50000);
    if (input.eof())
      break;
    ++lineno;

    std::string_view line{linebuf.data()};
    fail_line.clear();
    auto test_args = tools::split(line, " ");
    if (test_args.empty()) {
      std::cerr << "Warning: invalid empty test line at " << argv[1] << ":" << test << "\n";
      continue;
    }
    auto& cmd = test_args[0];
    if (cmd == "check_scalar") {
      auto [scalar, expected] = extract<ec_scalar, bool>(test_args);
      bool actual = check_scalar(scalar);
      if (expected != actual)
        fail_line = make(scalar, actual);
    } else if (cmd == "hash_to_scalar") {
      auto [data, expected] = extract<std::string_view, ec_scalar>(test_args);
      ec_scalar actual;
      crypto::hash_to_scalar(data.data(), data.size(), actual);
      if (expected != actual)
        fail_line = make(data, actual);
    } else if (cmd == "generate_keys") {
      auto [expected1, expected2] = extract<public_key, secret_key>(test_args);
      public_key actual1;
      secret_key actual2;
      generate_keys(actual1, actual2);
      if (expected1 != actual1 || expected2 != actual2)
        fail_line = make(actual1, actual2);
    } else if (cmd == "check_key") {
      auto [key, expected] = extract<public_key, bool>(test_args);
      bool actual;
      actual = check_key(key);
      if (expected != actual)
        fail_line = make(key, actual);
    } else if (cmd == "secret_key_to_public_key") {
      auto [sec, expected1] = extract<secret_key, bool>(test_args);
      bool actual1;
      public_key expected2, actual2;
      if (expected1)
        std::tie(expected2) = extract<public_key>(test_args, 2);
      actual1 = secret_key_to_public_key(sec, actual2);
      if (expected1 != actual1 || (expected1 && expected2 != actual2)) {
        fail_line = make(sec, actual1);
        if (actual1) fail_line += " " + make(actual2);
      }
    } else if (cmd == "generate_key_derivation") {
      auto [key1, key2, expected1] = extract<public_key, secret_key, bool>(test_args);
      bool actual1;
      key_derivation expected2, actual2;
      if (expected1)
        std::tie(expected2) = extract<key_derivation>(test_args, 3);
      actual1 = generate_key_derivation(key1, key2, actual2);
      if (expected1 != actual1 || (expected1 && expected2 != actual2)) {
        fail_line = make(key1, key2, actual1);
        if (actual1) fail_line += " " + make(actual2);
      }
    } else if (cmd == "derive_public_key") {
      auto [derivation, output_index, base, expected1] = extract<key_derivation, size_t, public_key, bool>(test_args);
      bool actual1;
      public_key expected2, actual2;
      if (expected1)
        std::tie(expected2) = extract<public_key>(test_args, 4);
      actual1 = derive_public_key(derivation, output_index, base, actual2);
      if (expected1 != actual1 || (expected1 && expected2 != actual2)) {
        fail_line = make(derivation, output_index, base, actual1);
        if (actual1)
          fail_line += " " + make(actual2);
      }
    } else if (cmd == "derive_secret_key") {
      auto [derivation, output_index, base, expected] = extract<key_derivation, size_t, secret_key, secret_key>(test_args);
      secret_key actual;
      derive_secret_key(derivation, output_index, base, actual);
      if (expected != actual)
        fail_line = make(derivation, output_index, base, actual);
    } else if (cmd == "generate_signature") {
      auto [prefix_hash, pub, sec, expected] = extract<chash, public_key, secret_key, signature>(test_args);
      signature actual;
      generate_signature(prefix_hash, pub, sec, actual);
      if (expected != actual)
        fail_line = make(prefix_hash, pub, sec, actual);
    } else if (cmd == "check_signature") {
      auto [prefix_hash, pub, sig, expected] = extract<chash, public_key, signature, bool>(test_args);
      bool actual = check_signature(prefix_hash, pub, sig);
      if (expected != actual)
        fail_line = make(prefix_hash, pub, sig, actual);
    } else if (cmd == "hash_to_point") {
      auto [h, expected] = extract<chash, ec_point>(test_args);
      ec_point actual;
      hash_to_point(h, actual);
      if (expected != actual)
        fail_line = make(h, actual);
    } else if (cmd == "hash_to_ec") {
      auto [key, expected] = extract<public_key, ec_point>(test_args);
      ec_point actual;
      hash_to_ec(key, actual);
      if (expected != actual)
        fail_line = make(key, actual);
    } else if (cmd == "generate_key_image") {
      auto [pub, sec, expected] = extract<public_key, secret_key, key_image>(test_args);
      key_image actual;
      generate_key_image(pub, sec, actual);
      if (expected != actual)
        fail_line = make(pub, sec, actual);
    } else if (cmd == "generate_ring_signature" || cmd == "check_ring_signature") {
      bool generate = cmd == "generate_ring_signature";
      auto [prefix_hash, image, pubs_count] = extract<chash, key_image, size_t>(test_args);

      std::vector<public_key> vpubs;
      std::vector<const public_key *> pubs;
      vpubs.reserve(pubs_count);
      size_t skip = 3;
      for (size_t i = 0; i < pubs_count; i++)
        vpubs.push_back(std::get<0>(extract<public_key>(test_args, skip+i)));
      skip += pubs_count;
      pubs.reserve(vpubs.size());
      for (auto& vpub : vpubs)
        pubs.push_back(&vpub);

      secret_key sec;
      size_t sec_index;
      if (generate) {
        std::tie(sec, sec_index) = extract<secret_key, size_t>(test_args, skip);
        skip += 2;
      }

      std::vector<signature> sigs;
      sigs.reserve(pubs_count);
      for (size_t i = 0; i < pubs_count; i++)
        sigs.push_back(std::get<0>(extract<signature>(test_args, skip+i)));
      skip += pubs_count;

      std::string fail;
      if (generate) {
        std::vector<signature> actual(pubs_count);
        generate_ring_signature(prefix_hash, image, pubs, sec, sec_index, actual.data());
        if (sigs != actual)
          for (auto& a : actual) {
            fail += ' ';
            fail += make(a);
          }
      } else { // check mode
        auto [expected] = extract<bool>(test_args, skip++);
        bool actual = check_ring_signature(prefix_hash, image, pubs, sigs.data());

        if (expected != actual)
          fail = actual ? " true" : " false";
      }

      if (!fail.empty()) {
        fail_line = make(prefix_hash, image, pubs_count);
        for (auto& vpub : vpubs) {
          fail_line += ' ';
          fail_line += make(vpub);
        }
        fail_line += ' ';
        if (generate)
          fail_line += make(sec, sec_index);
        else {
          for (auto& s : sigs) {
            fail_line += ' ';
            fail_line += make(s);
          }
        }
        fail_line += std::move(fail);
      }
    } else {
      throw std::ios_base::failure("Unknown function: " + std::string{cmd});
    }

    if (!fail_line.empty()) {
      if (verbose)
        std::cerr << "Wrong result for " << argv[1] << ":" << lineno << "\nExpected: " << line << "\nActual:   " << fail_line << "\n";
      errors++;
      if (regen.is_open())
        regen << cmd << ' ' << fail_line << '\n';
    }
    else if (regen.is_open())
      regen << line << '\n';
  }
  if (errors > 0) {
    std::cout << errors << " of " << lineno << " tests FAILED\n";
    if (regen.is_open())
      std::cerr << "Test errors occurred. The new results have been written to ./tests-regen.txt\n";
    else
      std::cerr << "Test errors occurred. To create a test file (./tests-regen.txt) based on the new results set environment variable REGEN=1\n";
  }
  else
    std::cout << "All tests (" << lineno << ") passed\n";

  return errors > 0;
}

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
#include <ios>
#include <iostream>
#include <type_traits>
#include <vector>
#include <oxenc/hex.h>

template <typename Char>
inline bool hexdecode(const Char *from, std::size_t length, void *to) {
  const Char* end = from + 2*length;
  if (!oxenc::is_hex(from, end))
    return false;
  oxenc::from_hex(from, end, reinterpret_cast<Char*>(to));
  return true;
}

inline void get(std::istream &input, bool &res) {
  std::string sres;
  input >> sres;
  if (sres == "false") {
    res = false;
  } else if (sres == "true") {
    res = true;
  } else {
    input.setstate(std::ios_base::failbit);
  }
}

template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
void get(std::istream &input, T &res) {
  input >> res;
}

inline void getvar(std::istream &input, std::size_t length, void *res) {
  std::string sres;
  input >> sres;
  if (sres.length() != 2 * length || !hexdecode(sres.data(), length, res)) {
    input.setstate(std::ios_base::failbit);
  }
}

template<typename T, std::enable_if_t<std::is_standard_layout_v<T> && !std::is_scalar_v<T>, int> = 0>
void get(std::istream &input, T &res) {
  getvar(input, sizeof(T), &res);
}

template <typename Char, std::enable_if_t<sizeof(Char) == 1 && std::is_scalar_v<Char>, int> = 0>
inline void get(std::istream &input, std::vector<Char> &res) {
  std::string sres;
  input >> sres;
  if (sres == "x") {
    res.clear();
  } else if (sres.length() % 2 != 0) {
    input.setstate(std::ios_base::failbit);
  } else {
    std::size_t length = sres.length() / 2;
    res.resize(length);
    if (!hexdecode(sres.data(), length, res.data())) {
      input.setstate(std::ios_base::failbit);
    }
  }
}

template<typename... T, std::enable_if_t<(sizeof...(T) >= 2), int> = 0>
void get(std::istream &input, T&&... res) {
  (get(input, res), ...);
}

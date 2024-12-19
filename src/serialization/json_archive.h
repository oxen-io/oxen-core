// Copyright (c) 2018-2020, The Loki Project
// Copyright (c) 2014-2019, The Monero Project
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

/*! \file json_archive.h
 *
 * \brief JSON archiver
 */

#pragma once

#include "serialization.h"
#include "base.h"
#include <cassert>
#include <iostream>
#include <iomanip>
#include <exception>
#include <oxenc/hex.h>

namespace serialization {

using json_variant_tag_type = std::string_view;

/*! \struct json_archiver
 * 
 * \brief a archive using the JSON standard
 *
 * \detailed there is no deserializing counterpart; we only support JSON serializing here.
 */
struct json_archiver : public serializer
{
  using variant_tag_type = std::string_view;

  json_archiver(std::ostream& s, bool indent = false)
    : stream_{s}, indent_{indent}
  {
    exc_restore_ = stream_.exceptions();
    stream_.exceptions(std::istream::badbit | std::istream::failbit | std::istream::eofbit);
  }

  ~json_archiver() { stream_.exceptions(exc_restore_); }

  void tag(std::string_view tag) {
    if (!object_begin)
      stream_ << (indent_ ? ", "sv : ","sv);
    make_indent();
    stream_ << '"' << tag << (indent_ ? "\": "sv : "\":");

    object_begin = false;
  }

  struct nested_object {
    json_archiver& ar;
    ~nested_object() {
      --ar.depth_;
      ar.make_indent();
      ar.stream_ << '}';
    }

    nested_object(const nested_object&) = delete;
    nested_object& operator=(const nested_object&) = delete;
    nested_object(nested_object&&) = delete;
    nested_object& operator=(nested_object&&) = delete;
  };

  [[nodiscard]] nested_object begin_object()
  {
    stream_ << '{';
    ++depth_;
    object_begin = true;
    return nested_object{*this};
  }

  template<typename T>
  static auto promote_to_printable_integer_type(T v)
  {
    // Unary operator '+' performs integral promotion on type T [expr.unary.op].
    // If T is signed or unsigned char, it's promoted to int and printed as number.
    return +v;
  }

  template <class T>
  void serialize_int(T v)
  {
    stream_ << std::dec << promote_to_printable_integer_type(v);
  }

  void serialize_blob(void *buf, size_t len, std::string_view delimiter="\""sv) {
    stream_ << delimiter;
    auto* begin = static_cast<unsigned char*>(buf);
    oxenc::to_hex(begin, begin + len, std::ostreambuf_iterator{stream_});
    stream_ << delimiter;
  }

  template <typename T>
  void serialize_blobs(const std::vector<T>& blobs, std::string_view delimiter="\""sv) {
    serialize_blob(blobs.data(), blobs.size()*sizeof(T), delimiter);
  }

  template <class T>
  void serialize_varint(T &v)
  {
    stream_ << std::dec << promote_to_printable_integer_type(v);
  }

  struct nested_array {
    json_archiver& ar;
    int exc_count = std::uncaught_exceptions();
    bool first = true;

    // Call before writing an element to add a delimiter.  The first element() call adds no
    // delimiter.  Returns the archive itself, allowing you to write:
    // 
    //     auto arr = ar.begin_array();
    //     for (auto& val : whatever)
    //       value(arr.element(), val);
    //
    json_archiver& element() {
      if (first) first = false;
      else ar.delimit_array();
      return ar;
    }

    ~nested_array() noexcept(false) {
      if (std::uncaught_exceptions() == exc_count) { // Normal destruction
        --ar.depth_;
        if (ar.inner_array_contents_)
          ar.make_indent();
        ar.stream_ << ']';
      }
      // else we're destructing during a stack unwind so some other serialization failed, thus don't
      // try terminating the array (since it might *also* throw if an IO error occurs).
    }

    // Non-copyable, non-moveable
    nested_array(const nested_array&) = delete;
    nested_array& operator=(const nested_array&) = delete;
    nested_array(nested_array&&) = delete;
    nested_array& operator=(nested_array&&) = delete;
  };

  // Begins an array and returns an RAII object that is used to delimit array elements and
  // terminates the array on destruction.
  [[nodiscard]] nested_array begin_array(size_t s=0)
  {
    inner_array_contents_ = s > 0;
    ++depth_;
    stream_ << '[';
    return {*this};
  }

  void delimit_array() { stream_ << (indent_ ? ", "sv : ","sv); }

  void write_variant_tag(std::string_view t) { tag(t); }

  // Returns the current position (i.e. stream.tellp()) of the output stream.
  unsigned int streampos() { return static_cast<unsigned int>(stream_.tellp()); }

private:
  static constexpr std::string_view indents{"                                "};
  void make_indent()
  {
    if (indent_)
    {
      stream_ << '\n';
      auto in = 2 * depth_;
      for (; in > indents.size(); in -= indents.size())
        stream_ << indents;
      stream_ << indents.substr(0, in);
    }
  }

  std::ostream& stream_;
  std::ios_base::iostate exc_restore_;
  bool indent_ = false;
  bool object_begin = false;
  bool inner_array_contents_ = false;
  size_t depth_ = 0;
};

} // namespace serialization

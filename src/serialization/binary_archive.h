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

/*! \file binary_archive.h
 *
 * Portable, little-endian binary archive */
#pragma once

#include <common/exception.h>
#include <common/varint.h>
#include <oxenc/endian.h>

#include <cassert>
#include <concepts>
#include <istream>
#include <iterator>
#include <ostream>
#include <string_view>
#include <type_traits>
#include <vector>

#include "base.h"

namespace serialization {

using namespace std::literals;

// Serialization of signed types goes via a reinterpret_cast to the unsigned type, which means we
// need a 2s complement architecture (which is pretty much certain but check just in case).
static_assert(-1 == ~0, "Non 2s-complement architecture not supported!");

using binary_variant_tag_type = uint8_t;

/* \struct binary_unarchiver
 *
 * \brief the deserializer class for a binary archive
 */
class binary_unarchiver : public deserializer {
  public:
    using variant_tag_type = binary_variant_tag_type;

    explicit binary_unarchiver(std::istream& s) : stream_{s} {
        auto pos = stream_.tellg();
        stream_.seekg(0, std::ios_base::end);
        eof_pos_ = stream_.tellg();
        stream_.seekg(pos);
        enable_stream_exceptions();
    }

    /// Serializes a signed integer (by reinterpreting it as unsigned on the wire)
    template <std::signed_integral T>
    void serialize_int(T& v) {
        serialize_int(reinterpret_cast<std::make_unsigned_t<T>&>(v));
    }

    /// Serializes an unsigned integer
    template <std::unsigned_integral T>
    void serialize_int(T& v) {
        stream_.read(reinterpret_cast<char*>(&v), sizeof(T));
        if constexpr (sizeof(T) > 1)
            oxenc::little_to_host_inplace(v);
    }

    /// Serializes binary data of a given size by reading it directly into the given buffer
    void serialize_blob(void* buf, size_t len, [[maybe_unused]] std::string_view delimiter = ""sv) {
        stream_.read(static_cast<char*>(buf), len);
    }

    /// Serializes an integer using varint encoding
    template <class T>
    void serialize_varint(T& v) {
        serialize_uvarint(*reinterpret_cast<std::make_unsigned_t<T>*>(&v));
    }

    template <class T>
    void serialize_uvarint(T& v) {
        using It = std::istreambuf_iterator<char>;
        if (tools::read_varint(It{stream_}, It{}, v) < 0)
            throw oxen::traced<std::runtime_error>{"deserialization of varint failed"};
    }

    // RAII class for `begin_array()`/`begin_object()`.  This particular implementation is a no-op.
    struct nested {
        ~nested(){};  // Avoids unused variable warnings
    };

    // Reads array size into s and returns an RAII object to help delimit and end it.
    [[nodiscard]] nested begin_array(size_t& s) {
        serialize_varint(s);
        return {};
    }

    // Begins a sizeless array (this requires that the size is provided by some other means).
    [[nodiscard]] nested begin_array() { return {}; }

    // Does nothing. (This is used for tag annotations for archivers such as json)
    void tag(std::string_view) {}

    [[nodiscard]] nested begin_object() { return {}; }

    void read_variant_tag(binary_variant_tag_type& t) { serialize_int(t); }

    /// Returns the number of remaining serialization bytes.  If the given `min_required` is
    /// non-zero then we also ensure that at least that many bytes are available (and otherwise set
    /// the stream's failbit to raise an exception).
    size_t remaining_bytes(size_t min_required = 0) {
        assert(stream_.tellg() <= eof_pos_);
        size_t remaining = eof_pos_ - stream_.tellg();
        if (remaining < min_required)
            stream_.setstate(std::istream::eofbit);
        return remaining;
    }

    // Returns the current position (i.e. stream.tellg()) of the input stream.
    unsigned int streampos() { return static_cast<unsigned int>(stream_.tellg()); }

  protected:
    // Protected constructor used by binary_string_unarchiver to avoid the seek (because the istream
    // hasn't been set up yet when this gets called, and because we know the eof position in
    // advance). You must call enable_stream_exceptions() in the derived constructor.
    binary_unarchiver(std::istream& s, std::streamoff eof_pos) : stream_{s}, eof_pos_{eof_pos} {}

    // Set up stream exceptions; called during construction.
    void enable_stream_exceptions() {
        exc_restore_ = stream_.exceptions();
        stream_.exceptions(std::istream::badbit | std::istream::failbit | std::istream::eofbit);
    }

  private:
    std::istream& stream_;
    std::ios_base::iostate exc_restore_;
    std::streamoff eof_pos_;
};

/* \struct binary_archiver
 *
 * \brief the serializer class for a binary archive
 */
class binary_archiver : public serializer {
  public:
    using variant_tag_type = binary_variant_tag_type;

    explicit binary_archiver(std::ostream& s) : stream_{s} { enable_stream_exceptions(); }

    template <std::signed_integral T>
    void serialize_int(T v) {
        serialize_int(static_cast<std::make_unsigned_t<T>>(v));
    }

    template <std::unsigned_integral T>
    void serialize_int(T v) {
        if constexpr (sizeof(T) > 1)
            oxenc::host_to_little_inplace(v);
        stream_.write(reinterpret_cast<const char*>(&v), sizeof(T));
    }

    void serialize_blob(
            const void* buf, size_t len, [[maybe_unused]] std::string_view delimiter = ""sv) {
        stream_.write(static_cast<const char*>(buf), len);
    }

    template <std::signed_integral T>
    void serialize_varint(T v) {
        serialize_varint(static_cast<std::make_unsigned_t<T>>(v));
    }

    template <std::unsigned_integral T>
    void serialize_varint(T v) {
        tools::write_varint(std::ostreambuf_iterator{stream_}, v);
    }

    // RAII class for `begin_array()`/`begin_object()`.  This particular implementation is a no-op.
    struct nested {
        ~nested(){};  // Avoids unused variable warnings
    };

    // Begins an array and returns an RAII object that is used to delimit array elements.  For
    // binary_archiver the size is written when the array begins, and the RAII is a no-op.
    [[nodiscard]] nested begin_array(size_t& s) {
        serialize_varint(s);
        return {};
    }

    // Begins a sizeless array.  (Typically requires that size be stored some other way).
    [[nodiscard]] nested begin_array() { return {}; }

    // Does nothing. (This is used for tag annotations for archivers such as json)
    void tag(std::string_view) {}

    [[nodiscard]] nested begin_object() { return {}; }

    void write_variant_tag(binary_variant_tag_type t) { serialize_int(t); }

    // Returns the current position (i.e. stream.tellp()) of the output stream.
    unsigned int streampos() { return static_cast<unsigned int>(stream_.tellp()); }

  protected:
    // Protected constructor used by binary_string_archiver; this doesn't enable stream exceptions
    // (because they need to be deferred until after the subclass is initialized).  The streamoff
    // argument is ignored (but mirrors the binary_unarchiver protected constructor).  You must call
    // enable_stream_exceptions() in the derived constructor.
    binary_archiver(std::ostream& s, std::streamoff) : stream_{s} {}

    // Set up stream exceptions; called during construction.
    void enable_stream_exceptions() {
        exc_restore_ = stream_.exceptions();
        stream_.exceptions(std::istream::badbit | std::istream::failbit | std::istream::eofbit);
    }

  private:
    std::ostream& stream_;
    std::ios_base::iostate exc_restore_;
};

// True if Archive is a binary archiver or unarchiver
template <typename Archive>
constexpr bool is_binary = std::is_base_of_v<binary_archiver, Archive> ||
                           std::is_base_of_v<binary_unarchiver, Archive>;

}  // namespace serialization

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

#pragma once

#include <sstream>
#include <streambuf>
#include <vector>

#include "binary_archive.h"

namespace serialization {

/// Simple class to read from memory in-place.  Intended use:
///
///     one_shot_read_buffer buf{view};
///     std::istream is{&buf};
///     is >> foo; /* do some istream stuff with is */
///
/// Note that the `view` must be kept valid for the lifetime of the buffer.
///
/// Note that this very limited implementation does not support seeking at all.
///
class one_shot_read_buffer : public std::streambuf {
  public:
    /// Construct from string_view
    explicit one_shot_read_buffer(std::string_view in) {
        // We won't actually modify it, but setg needs non-const
        auto* s = const_cast<char*>(in.data());
        setg(s, s, s + in.size());
    }

    /// Explicitly disallow construction with std::string temporary
    explicit one_shot_read_buffer(const std::string&& s) = delete;

    /// seekoff implementation that can be used *only* to obtain the current input position (i.e.
    /// using off=0, dir=cur, and which=in).  Anything else returns -1.
    pos_type seekoff(
            off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which) override {
        if ((which & (std::ios_base::in | std::ios_base::out)) != std::ios_base::in ||
            dir != std::ios_base::cur || off != 0)
            return pos_type(-1);
        return gptr() - eback();
    }
};

/// Subclass of binary_archiver that writes to a std::ostringstream and returns the string on
/// demand.
class binary_string_archiver : public binary_archiver {
    std::ostringstream oss;

  public:
    /// Constructor; takes no arguments.
    binary_string_archiver() : binary_archiver{oss, std::streamoff{0}} {
        enable_stream_exceptions();
    }

    /// Returns the string from the std::ostringstream
    std::string str() { return oss.str(); }
};

/// Subclass of binary_unarchiver that reads from a string_view.  The caller *must* keep the
/// string_view data available for the lifetime of the unarchiver.
class binary_string_unarchiver : public binary_unarchiver {
    one_shot_read_buffer buf;
    std::istream is{&buf};

  public:
    /// Constructor; takes the string_view to deserialize from.  The caller must keep the referenced
    /// data alive!
    explicit binary_string_unarchiver(std::string_view s) :
            binary_unarchiver{is, static_cast<std::streamoff>(s.size())}, buf{s} {
        enable_stream_exceptions();
    }

    /// Same as above, but taking a vector of uint8_ts
    explicit binary_string_unarchiver(const std::vector<uint8_t>& s) :
            binary_string_unarchiver(
                    std::string_view{reinterpret_cast<const char*>(s.data()), s.size()}) {}

    /// Constructing from a std::string temporary is not allowed.
    binary_string_unarchiver(const std::string&& s) = delete;
};

/*! deserializes a binary_archiver-serialized value into v.  Throws on error.  Not consuming the
 * entire string is considered an error.
 */
template <class T>
void parse_binary(std::string_view blob, T& v) {
    binary_string_unarchiver iar{blob};
    serialize(iar, v);
}

/*! serializes the data in v to a string.  Throws on error.
 */
template <class T>
std::string dump_binary(T& v) {
    binary_string_archiver oar;
    serialize(oar, v);
    return oar.str();
}

}  // namespace serialization

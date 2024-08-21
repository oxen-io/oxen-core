// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#pragma once

#include "portable_storage_base.h"

namespace epee::serialization {
// parameters to all of these:
// - strm - the output stream
// - ... - the value
// - indent - the level of nesting (0, 1, ...)
// - pretty - if true, add newlines, spaces between elements, and indents.  If false make it
// ugly.
void dump_as_json(std::ostream& strm, const array_entry& ae, size_t indent, bool pretty);
void dump_as_json(std::ostream& strm, const storage_entry& se, size_t indent, bool pretty);
void dump_as_json(std::ostream& strm, const std::string& v, size_t indent, bool pretty);
void dump_as_json(std::ostream& strm, const section& sec, size_t indent, bool pretty);

inline void dump_as_json(std::ostream& strm, const int8_t& v, size_t indent, bool pretty) {
    strm << static_cast<int32_t>(v);
}

inline void dump_as_json(std::ostream& strm, const uint8_t& v, size_t indent, bool pretty) {
    strm << static_cast<int32_t>(v);
}

inline void dump_as_json(std::ostream& strm, const bool& v, size_t indent, bool pretty) {
    strm << (v ? "true" : "false");
}

template <typename T>
void dump_as_json(std::ostream& strm, const T& v, size_t indent, bool pretty) {
    strm << v;
}
}  // namespace epee::serialization

#pragma once

#include <cstdint>
#include <session/sqlite.hpp>

namespace db {

// SQLite integers are signed 64-bit, and session::sqlite refuses to bind unsigned 64-bit values,
// but much inherited code uses uint64_t for values (heights, amounts, ...) that never get near the
// top bit.  These convert between the two by value (wrapping, as C++20 defines, past INT64_MAX).
constexpr int64_t as_i64(uint64_t v) {
    return static_cast<int64_t>(v);
}
constexpr uint64_t as_u64(int64_t v) {
    return static_cast<uint64_t>(v);
}

}  // namespace db

#include "writer.h"

#include <oxenc/endian.h>

#include <algorithm>
#include <stdexcept>
#include <utility>

#include "format.h"

namespace levin_kv {

using namespace format;

namespace {

    template <typename T>
    void write_fixed(std::string& out, T v) {
        if constexpr (std::is_same_v<T, bool>)
            out += static_cast<char>(v);
        else {
            oxenc::host_to_little_inplace(v);
            out.append(reinterpret_cast<const char*>(&v), sizeof(v));
        }
    }

    std::string varint(uint64_t v) {
        if (v > VARINT_MAX)
            throw std::invalid_argument{"levin_kv: value too large for a varint"};
        v <<= 2;
        std::string out;
        if (v < (uint64_t{1} << 8))
            write_fixed(out, static_cast<uint8_t>(v));
        else if (v < (uint64_t{1} << 16))
            write_fixed(out, static_cast<uint16_t>(v | 1));
        else if (v < (uint64_t{1} << 32))
            write_fixed(out, static_cast<uint32_t>(v | 2));
        else
            write_fixed(out, v | 3);
        return out;
    }

    void write_string(std::string& out, std::string_view s) {
        out += varint(s.size());
        out += s;
    }

    // The narrowest integer type holding every value from lo to hi: unsigned unless lo is
    // negative.
    template <typename T>
    uint8_t int_type(T lo, T hi) {
        auto fits = [&]<typename To>(std::type_identity<To>) {
            return std::in_range<To>(lo) && std::in_range<To>(hi);
        };
        if (lo >= 0) {
            if (fits(std::type_identity<uint8_t>{}))
                return TYPE_UINT8;
            if (fits(std::type_identity<uint16_t>{}))
                return TYPE_UINT16;
            if (fits(std::type_identity<uint32_t>{}))
                return TYPE_UINT32;
            return TYPE_UINT64;
        }
        if (fits(std::type_identity<int8_t>{}))
            return TYPE_INT8;
        if (fits(std::type_identity<int16_t>{}))
            return TYPE_INT16;
        if (fits(std::type_identity<int32_t>{}))
            return TYPE_INT32;
        return TYPE_INT64;
    }

    // The type a value or array of `T` is written as, given the lowest and highest of its values
    template <typename T>
    uint8_t type_of(const T& lo, const T& hi) {
        if constexpr (std::is_same_v<T, bool>)
            return TYPE_BOOL;
        else if constexpr (std::is_same_v<T, std::string>)
            return TYPE_STRING;
        else
            return int_type(lo, hi);
    }

    // Writes `v` as a value of `type`, which holds it
    template <typename T>
    void write_as(std::string& out, uint8_t type, const T& v) {
        if constexpr (std::is_same_v<T, std::string>)
            write_string(out, v);
        else
            visit_fixed(type, [&]<typename To>(std::type_identity<To>) {
                write_fixed(out, static_cast<To>(v));
            });
    }

}  // namespace

writer::writer() : archive{false} {
    out = HEADER;
    begin_map();
}

std::string writer::finish() && {
    end_map();
    return std::move(out);
}

void writer::begin_map() {
    stack.push_back({out.size()});
    out += '\0';
}

void writer::end_map() {
    auto m = stack.back();
    stack.pop_back();
    out.replace(m.count_pos, 1, varint(m.count));
}

void writer::entry(std::string_view name, uint8_t type) {
    if (name.size() > 255)
        throw std::invalid_argument{"levin_kv: field name longer than 255 bytes"};
    ++stack.back().count;
    out += static_cast<char>(name.size());
    out += name;
    out += static_cast<char>(type);
}

bool writer::scalar_value(std::string_view name, scalar_ref v) {
    std::visit(
            [&]<typename T>(std::reference_wrapper<T> x) {
                auto type = type_of(x.get(), x.get());
                entry(name, type);
                write_as(out, type, x.get());
            },
            v);
    return true;
}

bool writer::array(std::string_view name, array_ref v) {
    return std::visit(
            [&]<typename T>(std::reference_wrapper<std::vector<T>> vec) {
                const auto& xs = vec.get();
                if (xs.empty())
                    return false;
                uint8_t type;
                if constexpr (integer<T>) {
                    auto [lo, hi] = std::ranges::minmax(xs);
                    type = type_of(lo, hi);
                } else
                    type = type_of(xs.front(), xs.front());
                entry(name, type | FLAG_ARRAY);
                out += varint(xs.size());
                for (const T& x : xs)
                    write_as(out, type, x);
                return true;
            },
            v);
}

bool writer::packed_array(std::string_view name, packed_ref v) {
    return std::visit(
            [&]<typename T>(std::reference_wrapper<std::vector<T>> vec) {
                const auto& xs = vec.get();
                if (xs.empty())
                    return false;
                entry(name, TYPE_STRING);
                out += varint(xs.size() * sizeof(T));
                for (T x : xs)
                    write_fixed(out, x);
                return true;
            },
            v);
}

bool writer::bytes(std::string_view name, std::span<std::byte> v) {
    entry(name, TYPE_STRING);
    write_string(out, {reinterpret_cast<const char*>(v.data()), v.size()});
    return true;
}

bool writer::blobs(
        std::string_view name,
        size_t elem_size,
        size_t count,
        const std::function<std::span<std::byte>(size_t)>& storage) {
    if (count == 0)
        return false;
    auto data = storage(count);
    entry(name, TYPE_STRING);
    write_string(out, {reinterpret_cast<const char*>(data.data()), elem_size * count});
    return true;
}

bool writer::map(std::string_view name, const std::function<void(archive&)>& f) {
    entry(name, TYPE_MAP);
    begin_map();
    f(*this);
    end_map();
    return true;
}

bool writer::maps(
        std::string_view name,
        size_t count,
        const std::function<void(size_t)>&,
        const std::function<void(size_t, archive&)>& each) {
    if (count == 0)
        return false;
    entry(name, TYPE_MAP | FLAG_ARRAY);
    out += varint(count);
    for (size_t i = 0; i < count; i++) {
        begin_map();
        each(i, *this);
        end_map();
    }
    return true;
}

}  // namespace levin_kv

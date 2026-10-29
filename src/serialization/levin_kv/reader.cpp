#include "reader.h"

#include <oxenc/endian.h>

#include <cstring>
#include <stdexcept>
#include <utility>

#include "format.h"

namespace levin_kv {

using namespace format;
using detail::parsed;
using detail::parsed_map;

namespace {

    struct parse_error : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    // The fewest bytes a map's field takes: its name's length, its type, and a byte of value
    constexpr size_t MIN_FIELD_SIZE = 3;

    std::string_view take(std::string_view& data, size_t n) {
        if (n > data.size())
            throw parse_error{"truncated"};
        auto s = data.substr(0, n);
        data.remove_prefix(n);
        return s;
    }

    template <typename T>
    T load(const char* p) {
        if constexpr (std::is_same_v<T, bool>)
            return *p != 0;
        else {
            T v;
            std::memcpy(&v, p, sizeof(T));
            return oxenc::little_to_host(v);
        }
    }

    uint64_t take_varint(std::string_view& data) {
        if (data.empty())
            throw parse_error{"truncated"};
        size_t size = size_t{1} << (static_cast<uint8_t>(data[0]) & 0b11);
        auto bytes = take(data, size);
        uint64_t v;
        switch (size) {
            case 1: v = load<uint8_t>(bytes.data()); break;
            case 2: v = load<uint16_t>(bytes.data()); break;
            case 4: v = load<uint32_t>(bytes.data()); break;
            default: v = load<uint64_t>(bytes.data());
        }
        return v >> 2;
    }

    class parser {
      public:
        explicit parser(std::string_view data) : data{data} {}

        std::vector<parsed> fields;
        std::vector<parsed_map> maps;

        parsed_map parse_map() {
            parsed_map m{fields.size(), count(MIN_FIELD_SIZE)};
            fields.resize(m.first + m.count);
            for (size_t i = 0; i < m.count; i++) {
                auto name = take(data, byte());
                auto f = parse_value(byte());
                f.name = name;
                // Not through a reference taken before parse_value, which can grow `fields`
                fields[m.first + i] = f;
            }
            return m;
        }

      private:
        std::string_view data;
        int depth = 0;

        uint8_t byte() { return static_cast<uint8_t>(take(data, 1)[0]); }

        // The number of elements an array or map says it has, each of which takes at least
        // `min_size` bytes, so that no more are allocated for than could be in the data.
        size_t count(size_t min_size) {
            auto n = take_varint(data);
            if (n > data.size() / min_size)
                throw parse_error{"count exceeds the data"};
            return n;
        }

        struct depth_guard {
            int& depth;
            explicit depth_guard(int& depth) : depth{depth} {
                if (++depth > MAX_DEPTH)
                    throw parse_error{"nested too deeply"};
            }
            ~depth_guard() { --depth; }
        };

        parsed parse_value(uint8_t type) {
            depth_guard guard{depth};
            parsed f{.type = type};
            if (type & FLAG_ARRAY) {
                uint8_t elem = type & ~FLAG_ARRAY;
                if (auto width = fixed_width(elem)) {
                    f.count = count(width);
                    f.data = take(data, f.count * width);
                } else if (elem == TYPE_STRING) {
                    f.count = count(1);
                    auto start = data;
                    for (size_t i = 0; i < f.count; i++)
                        take(data, take_varint(data));
                    f.data = start.substr(0, start.size() - data.size());
                } else if (elem == TYPE_MAP) {
                    f.count = count(1);
                    f.first = maps.size();
                    maps.resize(f.first + f.count);
                    for (size_t i = 0; i < f.count; i++) {
                        auto m = parse_map();
                        maps[f.first + i] = m;
                    }
                } else
                    throw parse_error{"unknown array type"};
            } else if (auto width = fixed_width(type))
                f.data = take(data, width);
            else if (type == TYPE_STRING)
                f.data = take(data, take_varint(data));
            else if (type == TYPE_MAP) {
                auto m = parse_map();
                f.first = m.first;
                f.count = m.count;
            } else
                throw parse_error{"unknown type"};
            return f;
        }
    };

    template <typename From, typename To>
    constexpr bool convertible = std::is_same_v<From, To> || (integer<From> && integer<To>);

    template <typename To, typename From>
    bool fits(From v) {
        if constexpr (std::is_same_v<From, To>)
            return true;
        else
            return std::in_range<To>(v);
    }

    // Unsigned integers sent as a string of their little-endian bytes: see archive::packed().
    template <typename To>
    bool read_packed(std::string_view data, std::vector<To>& out) {
        if (data.size() % sizeof(To))
            return false;
        out.resize(data.size() / sizeof(To));
        for (size_t i = 0; i < out.size(); i++)
            out[i] = load<To>(data.data() + i * sizeof(To));
        return true;
    }

}  // namespace

std::optional<reader> reader::parse(std::string_view data) {
    if (!data.starts_with(HEADER))
        return std::nullopt;
    data.remove_prefix(HEADER.size());
    parser p{data};
    try {
        auto root = p.parse_map();
        return reader{std::move(p.fields), std::move(p.maps), root};
    } catch (const parse_error&) {
        return std::nullopt;
    }
}

reader::reader(
        std::vector<parsed> fields, std::vector<parsed_map> maps_in_arrays, parsed_map root) :
        archive{true},
        fields{std::move(fields)},
        maps_in_arrays{std::move(maps_in_arrays)},
        stack{root} {}

const parsed* reader::find(std::string_view name) const {
    auto [first, count] = stack.back();
    for (size_t i = first; i < first + count; i++)
        if (fields[i].name == name)
            return &fields[i];
    return nullptr;
}

bool reader::scalar_value(std::string_view name, scalar_ref v) {
    auto* f = find(name);
    if (!f)
        return false;
    return std::visit(
            [f]<typename To>(std::reference_wrapper<To> to) {
                if constexpr (std::is_same_v<To, std::string>) {
                    if (f->type != TYPE_STRING)
                        return false;
                    to.get().assign(f->data);
                    return true;
                } else {
                    if (!fixed_width(f->type))
                        return false;
                    return visit_fixed(f->type, [&]<typename From>(std::type_identity<From>) {
                        if constexpr (convertible<From, To>) {
                            auto x = load<From>(f->data.data());
                            if (!fits<To>(x))
                                return false;
                            to.get() = static_cast<To>(x);
                            return true;
                        } else
                            return false;
                    });
                }
            },
            v);
}

bool reader::array(std::string_view name, array_ref v) {
    auto* f = find(name);
    if (!f)
        return false;
    return std::visit(
            [f]<typename To>(std::reference_wrapper<std::vector<To>> to) {
                auto& out = to.get();
                if constexpr (std::is_same_v<To, std::string>) {
                    if (f->type != (TYPE_STRING | FLAG_ARRAY))
                        return false;
                    out.resize(f->count);
                    auto data = f->data;
                    for (auto& s : out)
                        s.assign(take(data, take_varint(data)));
                    return true;
                } else {
                    if constexpr (integer<To> && std::is_unsigned_v<To>)
                        if (f->type == TYPE_STRING)
                            return read_packed(f->data, out);
                    if (!(f->type & FLAG_ARRAY))
                        return false;
                    uint8_t elem = f->type & ~FLAG_ARRAY;
                    auto width = fixed_width(elem);
                    if (!width)
                        return false;
                    return visit_fixed(elem, [&]<typename From>(std::type_identity<From>) {
                        if constexpr (convertible<From, To>) {
                            const char* p = f->data.data();
                            // Checked first, so that a vector that one doesn't fit is left as
                            // it was.
                            if constexpr (!std::is_same_v<From, To>)
                                for (size_t i = 0; i < f->count; i++)
                                    if (!fits<To>(load<From>(p + i * width)))
                                        return false;
                            out.resize(f->count);
                            for (size_t i = 0; i < f->count; i++)
                                out[i] = static_cast<To>(load<From>(p + i * width));
                            return true;
                        } else
                            return false;
                    });
                }
            },
            v);
}

bool reader::packed_array(std::string_view name, packed_ref v) {
    return std::visit([&](auto vec) { return array(name, vec); }, v);
}

bool reader::bytes(std::string_view name, std::span<std::byte> v) {
    auto* f = find(name);
    if (!f || f->type != TYPE_STRING || f->data.size() != v.size())
        return false;
    std::memcpy(v.data(), f->data.data(), v.size());
    return true;
}

bool reader::blobs(
        std::string_view name,
        size_t elem_size,
        size_t,
        const std::function<std::span<std::byte>(size_t)>& storage) {
    auto* f = find(name);
    if (!f || f->type != TYPE_STRING || f->data.size() % elem_size)
        return false;
    auto dest = storage(f->data.size() / elem_size);
    if (!dest.empty())
        std::memcpy(dest.data(), f->data.data(), dest.size());
    return true;
}

bool reader::map(std::string_view name, const std::function<void(archive&)>& fn) {
    auto* f = find(name);
    if (!f || f->type != TYPE_MAP)
        return false;
    stack.push_back({f->first, f->count});
    fn(*this);
    stack.pop_back();
    return true;
}

bool reader::maps(
        std::string_view name,
        size_t,
        const std::function<void(size_t)>& resize,
        const std::function<void(size_t, archive&)>& each) {
    auto* f = find(name);
    if (!f || f->type != (TYPE_MAP | FLAG_ARRAY))
        return false;
    resize(f->count);
    for (size_t i = 0; i < f->count; i++) {
        stack.push_back(maps_in_arrays[f->first + i]);
        each(i, *this);
        stack.pop_back();
    }
    return true;
}

}  // namespace levin_kv

#include "kv_json.h"

#include <oxenc/endian.h>

#include <charconv>
#include <cstring>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <utility>

namespace tools::kv_json {

namespace ser = epee::serialization;
using json = nlohmann::json;

namespace {

    template <typename T>
    ser::array_t<T> make_array(const json& arr) {
        ser::array_t<T> result;
        for (const auto& v : arr)
            result.push_back(v.get<T>());
        return result;
    }

    ser::array_entry to_array(const json& arr) {
        const auto& first = arr.front();
        for (const auto& v : arr)
            if (first.is_number() ? !v.is_number() : v.type() != first.type())
                throw std::invalid_argument{"JSON arrays of mixed types are not supported"};

        if (first.is_number()) {
            // Numbers go into the narrowest of uint64/int64/double arrays that can hold them all.
            bool any_float = false, any_negative = false;
            for (const auto& v : arr) {
                if (v.is_number_float())
                    any_float = true;
                else if (!v.is_number_unsigned() && v.get<int64_t>() < 0)
                    any_negative = true;
            }
            if (any_float)
                return make_array<double>(arr);
            if (!any_negative)
                return make_array<uint64_t>(arr);
            for (const auto& v : arr)
                if (v.is_number_unsigned() &&
                    v.get<uint64_t>() > uint64_t{std::numeric_limits<int64_t>::max()})
                    throw std::invalid_argument{"JSON integer array values are out of range"};
            return make_array<int64_t>(arr);
        }
        if (first.is_string())
            return make_array<std::string>(arr);
        if (first.is_boolean())
            return make_array<bool>(arr);
        if (first.is_object()) {
            ser::array_t<ser::section> result;
            for (const auto& v : arr)
                result.push_back(to_section(v));
            return result;
        }
        throw std::invalid_argument{"nested JSON arrays and arrays of nulls are not supported"};
    }

    std::optional<ser::storage_entry> to_entry(const json& v) {
        switch (v.type()) {
            case json::value_t::null: return std::nullopt;
            case json::value_t::boolean: return v.get<bool>();
            case json::value_t::number_unsigned: return v.get<uint64_t>();
            case json::value_t::number_integer: return v.get<int64_t>();
            case json::value_t::number_float: return v.get<double>();
            case json::value_t::string: return v.get<std::string>();
            case json::value_t::object: return to_section(v);
            case json::value_t::array:
                if (v.empty())
                    return std::nullopt;
                return to_array(v);
            default: throw std::invalid_argument{"unsupported JSON value type"};
        }
    }

    template <typename T>
    json value_to_json(const T& v) {
        if constexpr (std::is_same_v<T, ser::section>)
            return to_json(v);
        else if constexpr (std::is_same_v<T, ser::array_entry>)
            return std::visit(
                    [](const auto& arr) {
                        auto result = json::array();
                        for (const auto& x : arr)
                            result.push_back(value_to_json(x));
                        return result;
                    },
                    v);
        else
            return v;
    }

}  // namespace

ser::section to_section(const json& obj) {
    if (!obj.is_object())
        throw std::invalid_argument{"expected a JSON object"};
    ser::section sec;
    for (const auto& [key, val] : obj.items())
        if (auto entry = to_entry(val))
            sec.m_entries.emplace(key, std::move(*entry));
    return sec;
}

json to_json(const ser::section& sec) {
    auto result = json::object();
    for (const auto& [key, val] : sec.m_entries)
        result[key] = std::visit([](const auto& v) { return value_to_json(v); }, val);
    return result;
}

namespace {

    void validate_value(const json& v) {
        if (v.is_object()) {
            for (const auto& [key, val] : v.items())
                validate_value(val);
            return;
        }
        if (v.is_binary() || v.is_discarded())
            throw std::invalid_argument{"unsupported JSON value type"};
        if (!v.is_array() || v.empty())
            return;

        const auto& first = v.front();
        for (const auto& x : v)
            if (first.is_number() ? !x.is_number() : x.type() != first.type())
                throw std::invalid_argument{"JSON arrays of mixed types are not supported"};
        if (first.is_array() || first.is_null())
            throw std::invalid_argument{"nested JSON arrays and arrays of nulls are not supported"};
        if (first.is_object())
            for (const auto& x : v)
                validate_value(x);
        else if (first.is_number()) {
            bool any_float = false, any_negative = false, any_huge = false;
            for (const auto& x : v) {
                if (x.is_number_float())
                    any_float = true;
                else if (x.is_number_unsigned())
                    any_huge |= x.get<uint64_t>() > uint64_t{std::numeric_limits<int64_t>::max()};
                else
                    any_negative |= x.get<int64_t>() < 0;
            }
            if (!any_float && any_negative && any_huge)
                throw std::invalid_argument{"JSON integer array values are out of range"};
        }
    }

    template <typename To>
    bool convert(const json& j, To& to) {
        if constexpr (std::is_same_v<To, std::string>) {
            if (!j.is_string())
                return false;
            to = j.get_ref<const std::string&>();
        } else if constexpr (std::is_same_v<To, bool>) {
            if (!j.is_boolean())
                return false;
            to = j.get<bool>();
        } else if (j.is_number_unsigned()) {
            auto v = j.get<uint64_t>();
            if (!std::in_range<To>(v))
                return false;
            to = static_cast<To>(v);
        } else if (j.is_number_integer()) {
            auto v = j.get<int64_t>();
            if (!std::in_range<To>(v))
                return false;
            to = static_cast<To>(v);
        } else if constexpr (std::is_same_v<To, uint64_t>) {
            // Amounts sent as strings of digits, by clients without 64-bit integers
            if (!j.is_string())
                return false;
            const auto& s = j.get_ref<const std::string&>();
            const auto* end = s.data() + s.size();
            uint64_t v;
            auto [p, ec] = std::from_chars(s.data(), end, v);
            if (ec != std::errc{} || p != end)
                return false;
            to = v;
        } else
            return false;
        return true;
    }

    std::string as_string(std::span<const std::byte> bytes) {
        return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }

}  // namespace

void validate(const json& obj) {
    if (!obj.is_object())
        throw std::invalid_argument{"expected a JSON object"};
    validate_value(obj);
}

bool json_writer::scalar_value(std::string_view name, scalar_ref v) {
    std::visit([&](auto x) { (*current)[std::string{name}] = x.get(); }, v);
    return true;
}

bool json_writer::array(std::string_view name, array_ref v) {
    return std::visit(
            [&](auto vec) {
                if (vec.get().empty())
                    return false;
                auto arr = json::array();
                for (const auto& x : vec.get())
                    arr.push_back(x);
                (*current)[std::string{name}] = std::move(arr);
                return true;
            },
            v);
}

// Written as epee did: a string of the integers' little-endian bytes
bool json_writer::packed_array(std::string_view name, packed_ref v) {
    return std::visit(
            [&]<typename T>(std::reference_wrapper<std::vector<T>> vec) {
                if (vec.get().empty())
                    return false;
                std::string s;
                for (T x : vec.get()) {
                    oxenc::host_to_little_inplace(x);
                    s.append(reinterpret_cast<const char*>(&x), sizeof(x));
                }
                (*current)[std::string{name}] = std::move(s);
                return true;
            },
            v);
}

bool json_writer::bytes(std::string_view name, std::span<std::byte> v) {
    (*current)[std::string{name}] = as_string(v);
    return true;
}

bool json_writer::blobs(
        std::string_view name,
        size_t elem_size,
        size_t count,
        const std::function<std::span<std::byte>(size_t)>& storage) {
    if (count == 0)
        return false;
    (*current)[std::string{name}] = as_string(storage(count).first(elem_size * count));
    return true;
}

bool json_writer::map(std::string_view name, const std::function<void(archive&)>& f) {
    auto* parent = current;
    current = &((*parent)[std::string{name}] = json::object());
    f(*this);
    current = parent;
    return true;
}

bool json_writer::maps(
        std::string_view name,
        size_t count,
        const std::function<void(size_t)>&,
        const std::function<void(size_t, archive&)>& each) {
    if (count == 0)
        return false;
    auto* parent = current;
    auto& arr = (*parent)[std::string{name}] = json::array();
    for (size_t i = 0; i < count; i++) {
        current = &arr.emplace_back(json::object());
        each(i, *this);
    }
    current = parent;
    return true;
}

const json* json_reader::find(std::string_view name) const {
    auto it = current->find(std::string{name});
    if (it == current->end() || it->is_null())
        return nullptr;
    return &*it;
}

bool json_reader::scalar_value(std::string_view name, scalar_ref v) {
    auto* j = find(name);
    return j && std::visit([j](auto to) { return convert(*j, to.get()); }, v);
}

bool json_reader::array(std::string_view name, array_ref v) {
    auto* j = find(name);
    // An empty array is as good as missing, as it was when JSON became an epee section
    if (!j || !j->is_array() || j->empty())
        return false;
    return std::visit(
            [j]<typename T>(std::reference_wrapper<std::vector<T>> to) {
                std::vector<T> result(j->size());
                for (size_t i = 0; i < j->size(); i++) {
                    T x;
                    if (!convert((*j)[i], x))
                        return false;
                    result[i] = std::move(x);
                }
                to.get() = std::move(result);
                return true;
            },
            v);
}

bool json_reader::packed_array(std::string_view name, packed_ref v) {
    return std::visit([&](auto vec) { return array(name, vec); }, v);
}

bool json_reader::bytes(std::string_view name, std::span<std::byte> v) {
    auto* j = find(name);
    if (!j || !j->is_string() || j->get_ref<const std::string&>().size() != v.size())
        return false;
    std::memcpy(v.data(), j->get_ref<const std::string&>().data(), v.size());
    return true;
}

bool json_reader::blobs(
        std::string_view name,
        size_t elem_size,
        size_t,
        const std::function<std::span<std::byte>(size_t)>& storage) {
    auto* j = find(name);
    if (!j || !j->is_string())
        return false;
    const auto& s = j->get_ref<const std::string&>();
    if (s.size() % elem_size)
        return false;
    auto dest = storage(s.size() / elem_size);
    if (!dest.empty())
        std::memcpy(dest.data(), s.data(), dest.size());
    return true;
}

bool json_reader::map(std::string_view name, const std::function<void(archive&)>& f) {
    auto* j = find(name);
    if (!j || !j->is_object())
        return false;
    auto* parent = current;
    current = j;
    f(*this);
    current = parent;
    return true;
}

bool json_reader::maps(
        std::string_view name,
        size_t,
        const std::function<void(size_t)>& resize,
        const std::function<void(size_t, archive&)>& each) {
    auto* j = find(name);
    if (!j || !j->is_array() || j->empty())
        return false;
    for (const auto& x : *j)
        if (!x.is_object())
            return false;
    resize(j->size());
    auto* parent = current;
    for (size_t i = 0; i < j->size(); i++) {
        current = &(*j)[i];
        each(i, *this);
    }
    current = parent;
    return true;
}

}  // namespace tools::kv_json

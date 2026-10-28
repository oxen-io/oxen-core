#include "kv_json.h"

#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>

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

}  // namespace tools::kv_json

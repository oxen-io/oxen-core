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

#include "../span.h"
#include "portable_storage_base.h"
#include "portable_storage_from_bin.h"
#include "portable_storage_from_json.h"
#include "portable_storage_to_bin.h"
#include "portable_storage_to_json.h"
#include "portable_storage_val_converters.h"

namespace epee::serialization {
/************************************************************************/
/*                                                                      */
/************************************************************************/
class portable_storage {
  public:
    portable_storage() = default;
    virtual ~portable_storage() = default;
    section* open_section(
            const std::string& section_name,
            section* parent_section,
            bool create_if_notexist = false);
    template <typename T>
    bool get_value(const std::string& value_name, T& val, section* parent_section);
    bool get_value(const std::string& value_name, storage_entry& val, section* parent_section);
    template <class T>
    bool set_value(const std::string& value_name, const T& target, section* parent_section);

    // Class for iterating through a type with automatic conversion to `T` when dereferencing.
    template <typename T>
    class converting_array_iterator {
        array_entry& array;
        size_t index = 0;

      public:
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using pointer = T*;
        using reference = T;
        using iterator_category = std::input_iterator_tag;

        explicit converting_array_iterator(array_entry& array) : array{array} {}
        converting_array_iterator(array_entry& array, bool end) : array{array} {
            if (end)
                index = var::visit([](auto& a) { return a.size(); }, array);
        }
        // Converting dereference operator.  Returns the converted value.  Note that this can
        // throw if the requested conversion fails.
        T operator*() const {
            return var::visit(
                    [this](auto& a) {
                        T val;
                        convert_t(a[index], val);
                        return val;
                    },
                    array);
        }
        bool operator==(const converting_array_iterator& other) const {
            return &array == &other.array && index == other.index;
        }
        bool operator!=(const converting_array_iterator& other) const { return !(*this == other); }
        converting_array_iterator operator++(int) {
            auto old = *this;
            index++;
            return old;
        }
        converting_array_iterator& operator++() {
            ++index;
            return *this;
        }
    };

    // Returns an input iterator pair for an array with automatic value conversion from the
    // stored type to T.  Throws std::out_of_range if the member doesn't exist or
    // std::bad_variant_access if the member isn't an array.
    template <typename T>
    std::pair<converting_array_iterator<T>, converting_array_iterator<T>> converting_array_range(
            const std::string& value_name, section* parent_section) {
        if (!parent_section)
            parent_section = &m_root;
        storage_entry* pentry = find_storage_entry(value_name, parent_section);
        if (!pentry)
            throw std::out_of_range{value_name + " does not exist"};
        auto& ar_entry = var::get<array_entry>(*pentry);
        return {converting_array_iterator<T>{ar_entry},
                converting_array_iterator<T>{ar_entry, true}};
    }

    // Accesses an existing array value of the given type.  If the given value does not exist or
    // is not an array of the given type then this returns nullptr, otherwise returns a pointer
    // to the array_t<T> (which is a std::vector<T>, or a std::deque<bool>).  Note that, unlike
    // array_range(), this does not convert (so, for example, you can't get uint64_t's if the
    // stored values are uint32_t's).
    template <typename T>
    array_t<T>* get_array(const std::string& value_name, section* parent_section) {
        if (!parent_section)
            parent_section = &m_root;
        if (storage_entry* pentry = find_storage_entry(value_name, parent_section))
            if (auto* ar_entry = std::get_if<array_entry>(pentry))
                if (auto* array = std::get_if<array_t<T>>(ar_entry))
                    return array;
        return nullptr;
    }

    /// Inserts a <T> array with the given name inside parent_section.  If the element already
    /// exists it is replaced (if not an array_t<T>) or cleared.  Returns a pointer to the
    /// stored array_entry (which holds an array_t<T>).  Returns nullptr on error.
    template <typename T>
    array_entry* make_array(const std::string& value_name, section* parent_section);

    /// Same as above, but returns the array_t<T>* rather than the array_entry.
    template <typename T>
    array_t<T>* make_array_t(const std::string& value_name, section* parent_section);

    //------------------------------------------------------------------------
    // delete entry (section, value or array)
    bool delete_entry(const std::string& pentry_name, section* parent_section = nullptr);

    //-------------------------------------------------------------------------------
    bool store_to_binary(std::string& target);
    bool load_from_binary(const epee::span<const uint8_t> target);
    bool load_from_binary(std::string_view target) {
        return load_from_binary(epee::strspan<uint8_t>(target));
    }
    bool dump_as_json(std::string& targetObj, size_t indent = 0, bool insert_newlines = true);
    bool load_from_json(std::string_view source);

    /// Lets you store a pointer to some arbitrary context object; typically used to pass some
    /// context to dependent child objects.
    template <typename T>
    void set_context(const T* obj) {
        context_type = &typeid(T);
        context = obj;
    }
    /// Clears a context pointer stored with set_context
    void clear_context() {
        context_type = nullptr;
        context = nullptr;
    }
    /// Retrieves context set by set_context().  Returns nullptr if the stored type doesn't
    /// match `T`, or if no context pointer is stored at all.
    template <typename T>
    const T* get_context() {
        return (context && context_type && *context_type == typeid(T))
                     ? static_cast<const T*>(context)
                     : nullptr;
    }

  private:
    section m_root;
    section* get_root_section() { return &m_root; }
    storage_entry* find_storage_entry(const std::string& pentry_name, section* psection);
    template <class entry_type>
    storage_entry* insert_new_entry_get_storage_entry(
            const std::string& pentry_name, section* psection, const entry_type& entry);

    section* insert_new_section(const std::string& pentry_name, section* psection);

    const void* context = nullptr;
    const std::type_info* context_type = nullptr;

#pragma pack(push)
#pragma pack(1)
    struct storage_block_header {
        uint32_t m_signature_a;
        uint32_t m_signature_b;
        uint8_t m_ver;
    };
#pragma pack(pop)
};
template <typename T>
bool portable_storage::get_value(const std::string& value_name, T& val, section* parent_section) {
    static_assert(variant_contains<T, storage_entry>);
    // TRY_ENTRY();
    if (!parent_section)
        parent_section = &m_root;
    storage_entry* pentry = find_storage_entry(value_name, parent_section);
    if (!pentry)
        return false;

    var::visit([&val](const auto& v) { convert_t(v, val); }, *pentry);
    return true;
    // CATCH_ENTRY("portable_storage::template<>get_value", false);
}
//---------------------------------------------------------------------------------------------------------------
template <typename T>
bool portable_storage::set_value(
        const std::string& value_name, const T& v, section* parent_section) {
    static_assert(variant_contains<T, storage_entry> || std::is_same_v<T, storage_entry>);
    TRY_ENTRY();
    if (!parent_section)
        parent_section = &m_root;
    storage_entry* pentry = find_storage_entry(value_name, parent_section);
    if (!pentry) {
        pentry = insert_new_entry_get_storage_entry(value_name, parent_section, v);
        if (!pentry)
            return false;
        return true;
    }
    *pentry = std::move(v);
    return true;
    CATCH_ENTRY("portable_storage::template<>set_value", false);
}
//---------------------------------------------------------------------------------------------------------------
template <class entry_type>
storage_entry* portable_storage::insert_new_entry_get_storage_entry(
        const std::string& pentry_name, section* psection, const entry_type& entry) {
    TRY_ENTRY();
    CHECK_AND_ASSERT(psection, nullptr);
    auto ins_res = psection->m_entries.emplace(pentry_name, entry);
    return &ins_res.first->second;
    CATCH_ENTRY("portable_storage::insert_new_entry_get_storage_entry", nullptr);
}
//---------------------------------------------------------------------------------------------------------------
template <typename T>
array_entry* portable_storage::make_array(const std::string& value_name, section* parent_section) {
    TRY_ENTRY();
    if (!parent_section)
        parent_section = &m_root;
    storage_entry* pentry = find_storage_entry(value_name, parent_section);
    if (!pentry) {
        pentry = insert_new_entry_get_storage_entry(
                value_name, parent_section, array_entry(array_t<T>{}));
        if (!pentry)
            return nullptr;
    }
    if (!std::holds_alternative<array_entry>(*pentry))
        *pentry = array_entry(std::in_place_type<array_t<T>>);

    auto& arr = var::get<array_entry>(*pentry);
    if (auto* arr_t = std::get_if<array_t<T>>(&arr))
        arr_t->clear();
    else
        arr = array_t<T>{};

    return &arr;

    CATCH_ENTRY("portable_storage::make_array", nullptr);
}
template <typename T>
array_t<T>* portable_storage::make_array_t(const std::string& value_name, section* parent_section) {
    return std::get_if<array_t<T>>(make_array<T>(value_name, parent_section));
}
}  // namespace epee::serialization

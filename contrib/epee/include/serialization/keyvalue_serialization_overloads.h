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

#include <type_traits>
#include <set>
#include <unordered_set>
#include <list>
#include <vector>
#include <deque>
#include <array>
#include "span.h"
#include "storages/portable_storage_base.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "serialization"

namespace epee
{
  namespace
  {
    template <typename T>
    constexpr bool is_std_vector = false;
    template <typename... T>
    constexpr bool is_std_vector<std::vector<T...>> = true;
    template <typename T>
    constexpr bool is_std_optional = false;
    template <typename T>
    constexpr bool is_std_optional<std::optional<T>> = true;
  }
  namespace serialization
  {

    template <typename T, typename SFINAE = void> constexpr bool is_basic_serializable = false;
    template <typename T> constexpr bool is_basic_serializable<T, std::enable_if_t<std::is_integral<T>::value>> = true;
    template <typename T> constexpr bool is_basic_serializable<const T> = is_basic_serializable<T>;
    template <typename T> constexpr bool is_basic_serializable<std::optional<T>> = is_basic_serializable<T>;
    template <> inline constexpr bool is_basic_serializable<std::string> = true;
    template <> inline constexpr bool is_basic_serializable<double> = true;
    template <> inline constexpr bool is_basic_serializable<storage_entry> = true;

    template <typename T> constexpr bool is_serialize_stl_container = false;
    template <typename T> constexpr bool is_serialize_stl_container<std::vector<T>> = true;
    template <typename T> constexpr bool is_serialize_stl_container<std::deque<T>> = true;
    template <typename T> constexpr bool is_serialize_stl_container<std::list<T>> = true;
    template <typename T> constexpr bool is_serialize_stl_container<std::set<T>> = true;
    template <typename T> constexpr bool is_serialize_stl_container<std::unordered_set<T>> = true;
    template <typename T, size_t S> constexpr bool is_serialize_stl_container<std::array<T, S>> = true;

    // static_asserts that the type is suitable for binary serialization: by default, this means it
    // has no padding and is trivially copyable.  Types that are safe but don't satisfy these
    // requirements can specialize is_byte_spannable.
    template <typename T>
    constexpr void assert_blob_serializable() {
      static_assert(is_byte_spannable<T>, "Type is not acceptable for blob serialization");
    }

    //-------------------------------------------------------------------------------------------------------------------
    template<class t_type, class t_storage>
    static bool serialize_t_val(const t_type& d, t_storage& stg, section* parent_section, const char* pname)
    {
      return stg.set_value(pname, d, parent_section);
    }
    //-------------------------------------------------------------------------------------------------------------------
    template<class t_type, class t_storage>
    static bool unserialize_t_val(t_type& d, t_storage& stg, section* parent_section, const char* pname)
    {
      return stg.get_value(pname, d, parent_section);
    } 
    //-------------------------------------------------------------------------------------------------------------------
    template<class t_type, class t_storage>
    static bool serialize_t_val_as_blob(const t_type& d, t_storage& stg, section* parent_section, const char* pname)
    {
      assert_blob_serializable<t_type>();
      std::string blob((const char *)&d, sizeof(d));
      return stg.set_value(pname, blob, parent_section);
    }
    //-------------------------------------------------------------------------------------------------------------------
    template<class t_type, class t_storage>
    static bool unserialize_t_val_as_blob(t_type& d, t_storage& stg, section* parent_section, const char* pname)
    {
      assert_blob_serializable<t_type>();
      std::string blob;
      if(!stg.get_value(pname, blob, parent_section))
        return false;
      CHECK_AND_ASSERT_MES(blob.size() == sizeof(d), false, "unserialize_t_val_as_blob: size of " << typeid(t_type).name() << " = " << sizeof(t_type) << ", but stored blod size = " << blob.size() << ", value name = " << pname);
      d = *(const t_type*)blob.data();
      return true;
    } 
    //-------------------------------------------------------------------------------------------------------------------
    template<class serializible_type, class t_storage>
    static bool serialize_t_obj(const serializible_type& obj, t_storage& stg, section* parent_section, const char* pname)
    {
      section* child_section = stg.open_section(pname, parent_section, true);
      CHECK_AND_ASSERT_MES(child_section, false, "serialize_t_obj: failed to open/create section " << pname);
      return obj.store(stg, child_section);
    }
    //-------------------------------------------------------------------------------------------------------------------
    template<class serializible_type, class t_storage>
    static bool unserialize_t_obj(serializible_type& obj, t_storage& stg, section* parent_section, const char* pname)
    {
      section* child_section = stg.open_section(pname, parent_section, false);
      if(!child_section) return false;
      return obj._load(stg, child_section);
    }
    //-------------------------------------------------------------------------------------------------------------------
    template<class serializible_type, class t_storage>
    static bool serialize_t_obj(enableable<serializible_type>& obj, t_storage& stg, section* parent_section, const char* pname)
    {
      if(!obj.enabled)
        return true;
      return serialize_t_obj(obj.v, stg, parent_section, pname);
    }
    //-------------------------------------------------------------------------------------------------------------------
    template<class serializible_type, class t_storage>
    static bool unserialize_t_obj(enableable<serializible_type>& obj, t_storage& stg, section* parent_section, const char* pname)
    {
      obj.enabled = false;
      section* child_section = stg.open_section(pname, parent_section, false);
      if(!child_section) return false;
      obj.enabled = true;
      return obj.v._load(stg, child_section);
    }
    //-------------------------------------------------------------------------------------------------------------------
    template<class stl_container, class t_storage>
    static bool serialize_stl_container_t_val(const stl_container& container, t_storage& stg, section* parent_section, const char* pname)
    {
      using T = typename stl_container::value_type;
      if(!container.size()) return true;
      auto *arr = stg.template make_array_t<T>(pname, parent_section);
      CHECK_AND_ASSERT_MES(arr, false, "failed to create array in storage");
      for (auto& elem : container)
        arr->push_back(elem);
      return true;
    }
    //--------------------------------------------------------------------------------------------------------------------
    template<class stl_container, class t_storage>
    static bool unserialize_stl_container_t_val(stl_container& container, t_storage& stg, section* parent_section, const char* pname)
    {
      using T = typename stl_container::value_type;
      container.clear();
      try {
        for (auto [it, end] = stg.template converting_array_range<T>(pname, parent_section); it != end; ++it)
          container.insert(container.end(), *it);
        return true;
      } catch (const std::out_of_range&) { // ignore silently
      } catch (const std::exception& e) {
        LOG_ERROR("Failed to deserialize stl container: " << e.what());
      }
      return false;
    }
    //--------------------------------------------------------------------------------------------------------------------
    template<typename T, size_t Size, class t_storage>
    static bool unserialize_stl_container_t_val(std::array<T, Size>& array, t_storage& stg, section* parent_section, const char* pname)
    {
      static_assert(Size > 0, "cannot deserialize empty std::array");
      size_t next_i = 0;
      for (auto [it, end] = stg.template converting_array_range<T>(pname, parent_section); it != end; ++it) {
        CHECK_AND_ASSERT_MES(next_i < array.size(), false, "too many values to deserialize into fixed size std::array");
        array[next_i++] = *it;
      }
      CHECK_AND_ASSERT_MES(next_i == array.size(), false, "not enough values to deserialize into fixed size std::array");
      return true;
    }
    //--------------------------------------------------------------------------------------------------------------------
    template<class stl_container, class t_storage>
    static bool serialize_stl_container_pod_val_as_blob(const stl_container& container, t_storage& stg, section* parent_section, const char* pname)
    {
      using T = typename stl_container::value_type;
      assert_blob_serializable<T>();

      if(!container.size()) return true;
      std::string mb;
      if constexpr (is_std_vector<stl_container>)
        mb.append(reinterpret_cast<const char*>(container.data()), sizeof(T) * container.size());
      else
      {
        mb.reserve(sizeof(T) * container.size());
        for (const auto &v : container)
          mb.append(reinterpret_cast<const char*>(&v), sizeof(T));
      }
      return stg.set_value(pname, mb, parent_section);
    }
    //--------------------------------------------------------------------------------------------------------------------
    template<class stl_container, class t_storage>
    static bool unserialize_stl_container_pod_val_as_blob(stl_container& container, t_storage& stg, section* parent_section, const char* pname)
    {
      using T = typename stl_container::value_type;
      assert_blob_serializable<T>();

      container.clear();
      std::string buff;
      if (!stg.get_value(pname, buff, parent_section))
        return false;

      CHECK_AND_ASSERT_MES(buff.size() % sizeof(T) == 0,
        false, 
        "size in blob " << buff.size() << " not have not zero modulo for sizeof(value_type) = " << sizeof(T) << ", type " << typeid(T).name());
      if constexpr (is_std_vector<stl_container>)
      {
        container.resize(buff.size() / sizeof(T));
        // The explicit cast to (void*) is to silence a compiler warning about non-trivial types;
        // we've already verified the byte copy is okay with the assert_blob_serializable<T> above.
        std::memcpy((void*) container.data(), buff.data(), buff.size());
      }
      else
      {
        // memcpy one element at a time because we have no alignment guarantee on buff's data
        for (size_t i = 0; i < buff.size(); i += sizeof(T))
          std::memcpy(&container.emplace_back(), buff.data() + i, sizeof(T));
      }
      return true;
    }
    //--------------------------------------------------------------------------------------------------------------------
    template<class stl_container, class t_storage>
    static bool serialize_stl_container_t_obj(const stl_container& container, t_storage& stg, section* parent_section, const char* pname)
    {
      if (container.empty()) return true;
      auto* sec_array = stg.template make_array_t<section>(pname, parent_section);
      CHECK_AND_ASSERT_MES(sec_array, false, "failed to insert first section with section name " << pname);

      for (auto& elem : container)
        if (!elem.store(stg, &sec_array->emplace_back()))
          return false;
      return true;
    }
    //--------------------------------------------------------------------------------------------------------------------
    template<class stl_container, class t_storage>
    static bool unserialize_stl_container_t_obj(stl_container& container, t_storage& stg, section* parent_section, const char* pname)
    {
      container.clear();
      auto* arr = stg.template get_array<section>(pname, parent_section);
      if (!arr) return false;
      for (auto& child_section : *arr)
        if (!container.emplace_back()._load(stg, &child_section))
          return false;
      return true;
    }
    //--------------------------------------------------------------------------------------------------------------------
    template<typename T, size_t Size, class t_storage>
    static bool unserialize_stl_container_t_obj(std::array<T, Size>& out, t_storage& stg, section* parent_section, const char* pname)
    {
      static_assert(Size > 0, "cannot deserialize empty std::array");
      auto* arr = stg.template get_array<section>(pname, parent_section);
      if (!arr) return false;
      CHECK_AND_ASSERT_MES(arr->size() != Size, false, "incorrect number of values to deserialize into fixed size std::array");
      auto it = out.begin();
      for (auto& child_section : *arr)
        if (!(it++)->_load(stg, &child_section))
          return false;
      return true;
    }
    //--------------------------------------------------------------------------------------------------------------------
    template <bool Serializing, typename T, typename Storage>
    bool perform_serialize(T& d, Storage& stg, section* parent_section, const char* pname)
    {
      if constexpr (Serializing)
        return kv_serialize(d, stg, parent_section, pname);
      else
        return kv_unserialize(d, stg, parent_section, pname);
    }

    template <bool Serializing, typename T, typename Storage>
    bool perform_serialize_blob(T& d, Storage& stg, section* parent_section, const char* pname)
    {
      if constexpr (Serializing)
        return serialize_t_val_as_blob(d, stg, parent_section, pname);
      else
        return unserialize_t_val_as_blob(d, stg, parent_section, pname);
    }

    template <bool Serializing, typename T, typename Storage>
    bool perform_serialize_blob_container(T& d, Storage& stg, section* parent_section, const char* pname)
    {
      if constexpr (Serializing)
        return serialize_stl_container_pod_val_as_blob(d, stg, parent_section, pname);
      else
        return unserialize_stl_container_pod_val_as_blob(d, stg, parent_section, pname);
    }

    template<class T, class Storage>
    bool kv_serialize(const T& d, Storage& stg, section* parent_section, const char* pname)
    {
      if constexpr (is_std_optional<T>)
        // Optional: only serialize if non-empty
        return d ? kv_serialize(*d, stg, parent_section, pname) : false;

      else if constexpr (!is_serialize_stl_container<T>)
      { // Non-container
        if constexpr (is_basic_serializable<T>) // basic serializable or using portable storage:
          return stg.set_value(pname, d, parent_section);
        else // non-basic, non-portable serializable:
          return serialize_t_obj(d, stg, parent_section, pname);
      }
      else if constexpr (is_basic_serializable<typename T::value_type>)
        // stl container of basic or portable value type:
        return serialize_stl_container_t_val(d, stg, parent_section, pname);
      else
        // stl containers (non-basic value type and non-portable storage), i.e. containers of custom
        // serializable types.
        return serialize_stl_container_t_obj(d, stg, parent_section, pname);
    }
    template<class T, class Storage>
    bool kv_unserialize(T& d, Storage& stg, section* parent_section, const char* pname)
    {
      if constexpr (is_std_optional<T>) {
        // Emplace a new value and try to deserialize into it
        bool ret = kv_unserialize(d.emplace(), stg, parent_section, pname);
        if (!ret) d.reset(); // Deserialization failed so clear the value
        return ret;
      }
      else if constexpr (!is_serialize_stl_container<T>)
      { // Non-container
        if constexpr (is_basic_serializable<T>) // basic serializable or using portable storage:
          return stg.get_value(pname, d, parent_section);
        else // non-basic, non-portable serializable:
          return unserialize_t_obj(d, stg, parent_section, pname);
      }
      else if constexpr (is_basic_serializable<typename T::value_type>)
        // stl container of basic or portable value type:
        return unserialize_stl_container_t_val(d, stg, parent_section, pname);
      else
        // stl containers (non-basic value type and non-portable storage), i.e. containers of custom
        // serializable types.
        return unserialize_stl_container_t_obj(d, stg, parent_section, pname);
    }
  }
}

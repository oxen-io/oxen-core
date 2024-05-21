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
#include <oxenc/endian.h>
#include <oxenc/variant.h>

namespace epee
{
  namespace serialization
  {
    constexpr size_t RECURSION_LIMIT = 50;

    struct throwable_buffer_reader
    {
      throwable_buffer_reader(const void* ptr, size_t sz);
      void read(void* target, size_t count);
      void read_sec_name(std::string& sce_name);
      template<class type_name>
      storage_entry read_ae();
      storage_entry load_storage_array_entry(uint8_t type);
      uint64_t read_varint();
      template<class t_type>
      storage_entry read_se();
      storage_entry load_storage_entry();
      template <typename T>
      void read(T& pod_val);
      template <typename T>
      T read();
      void read(section& sec);
      void read(std::string& str);
    private:
      struct [[nodiscard]] recursion_limiter
      {
        size_t& m_counter_ref;
        recursion_limiter(size_t& counter):m_counter_ref(counter)
        {
          ++m_counter_ref;
          CHECK_AND_ASSERT_THROW_MES(m_counter_ref < RECURSION_LIMIT, "Wrong blob data in portable storage: recursion limit ({}) exceeded", RECURSION_LIMIT);
        }
        ~recursion_limiter()
        {
          --m_counter_ref;
        }
      };

      const uint8_t* m_ptr;
      size_t m_count;
      size_t m_recursion_count;
    };

    inline throwable_buffer_reader::throwable_buffer_reader(const void* ptr, size_t sz)
    {
      if(!ptr) 
        throw std::runtime_error("throwable_buffer_reader: ptr==nullptr");
      if(!sz)
        throw std::runtime_error("throwable_buffer_reader: sz==0");
      m_ptr = (uint8_t*)ptr;
      m_count = sz;
      m_recursion_count = 0;
    }

    inline 
    void throwable_buffer_reader::read(void* target, size_t count)
    {
      CHECK_AND_ASSERT_THROW_MES(m_count >= count, " attempt to read {} bytes from buffer with {} bytes remained", count, m_count);
      memcpy(target, m_ptr, count);
      m_ptr += count;
      m_count -= count;
    }

    inline 
    void throwable_buffer_reader::read_sec_name(std::string& sce_name)
    {
      uint8_t name_len = 0;
      read(name_len);
      sce_name.resize(name_len);
      read(sce_name.data(), name_len);
    }

    template <class T>
    void throwable_buffer_reader::read(T& v)
    {
      static_assert(std::is_integral_v<T>);
      read(&v, sizeof(T));
      if constexpr (sizeof(T) > 1)
        oxenc::little_to_host(v);
    }

    template <class T>
    T throwable_buffer_reader::read()
    {
      T v;
      read(v);
      return v;
    }

    template <typename T>
    storage_entry throwable_buffer_reader::read_ae()
    {
      size_t size = read_varint();
      CHECK_AND_ASSERT_THROW_MES(size <= m_count, "Size sanity check failed");
      storage_entry se{std::in_place_type<array_entry>, std::in_place_type<array_t<T>>};
      auto& arr = var::get<array_t<T>>(var::get<array_entry>(se));
      if constexpr (!std::is_same_v<T, bool>) // bool uses a std::deque, which isn't reserveable
        arr.reserve(std::min<size_t>(size, 4096));

      while(size--)
        read(arr.emplace_back());

      return se;
    }

    inline 
    storage_entry throwable_buffer_reader::load_storage_array_entry(uint8_t type)
    {
      recursion_limiter lim{m_recursion_count};
      type &= ~SERIALIZE_FLAG_ARRAY;
      switch(type)
      {
        case SERIALIZE_TYPE_TAG<int64_t>:     return read_ae<int64_t>();
        case SERIALIZE_TYPE_TAG<int32_t>:     return read_ae<int32_t>();
        case SERIALIZE_TYPE_TAG<int16_t>:     return read_ae<int16_t>();
        case SERIALIZE_TYPE_TAG<int8_t>:      return read_ae<int8_t>();
        case SERIALIZE_TYPE_TAG<uint64_t>:    return read_ae<uint64_t>();
        case SERIALIZE_TYPE_TAG<uint32_t>:    return read_ae<uint32_t>();
        case SERIALIZE_TYPE_TAG<uint16_t>:    return read_ae<uint16_t>();
        case SERIALIZE_TYPE_TAG<uint8_t>:     return read_ae<uint8_t>();
        //case SERIALIZE_TYPE_TAG<double>:      return read_ae<double>();
        case SERIALIZE_TYPE_TAG<bool>:        return read_ae<bool>();
        case SERIALIZE_TYPE_TAG<std::string>: return read_ae<std::string>();
        case SERIALIZE_TYPE_TAG<section>:     return read_ae<section>();
        //case SERIALIZE_TYPE_ARRAY:  return read_ae<array_entry>(); // nested arrays not supported
        default: { CHECK_AND_ASSERT_THROW_MES(false, "unknown entry_type code = {}", +type); return {}; }
      }
    }

    inline 
    uint64_t throwable_buffer_reader::read_varint()
    {
      CHECK_AND_ASSERT_THROW_MES(m_count >= 1, "empty buff, expected place for varint");
      uint64_t v = 0;
      uint8_t size_mask = *m_ptr & PORTABLE_RAW_SIZE_MARK_MASK;
      switch (size_mask)
      {
        case PORTABLE_RAW_SIZE_MARK_6BIT:  v = read<uint8_t>();  break;
        case PORTABLE_RAW_SIZE_MARK_14BIT: v = read<uint16_t>(); break;
        case PORTABLE_RAW_SIZE_MARK_30BIT: v = read<uint32_t>(); break;
        case PORTABLE_RAW_SIZE_MARK_62BIT: v = read<uint64_t>(); break;
      }
      v >>= 2;
      return v;
    }

    template <typename T>
    storage_entry throwable_buffer_reader::read_se()
    {
      storage_entry e{std::in_place_type<T>};
      read(var::get<T>(e));
      return e;
    }

    inline 
    storage_entry throwable_buffer_reader::load_storage_entry()
    {
      recursion_limiter lim{m_recursion_count};
      uint8_t ent_type = 0;
      read(ent_type);
      if (ent_type & SERIALIZE_FLAG_ARRAY)
        return load_storage_array_entry(ent_type);

      switch(ent_type)
      {
        case SERIALIZE_TYPE_TAG<int64_t>:     return read_se<int64_t>();
        case SERIALIZE_TYPE_TAG<int32_t>:     return read_se<int32_t>();
        case SERIALIZE_TYPE_TAG<int16_t>:     return read_se<int16_t>();
        case SERIALIZE_TYPE_TAG<int8_t>:      return read_se<int8_t>();
        case SERIALIZE_TYPE_TAG<uint64_t>:    return read_se<uint64_t>();
        case SERIALIZE_TYPE_TAG<uint32_t>:    return read_se<uint32_t>();
        case SERIALIZE_TYPE_TAG<uint16_t>:    return read_se<uint16_t>();
        case SERIALIZE_TYPE_TAG<uint8_t>:     return read_se<uint8_t>();
        //case SERIALIZE_TYPE_TAG<double>:      return read_se<double>();
        case SERIALIZE_TYPE_TAG<bool>:        return read_se<bool>();
        case SERIALIZE_TYPE_TAG<std::string>: return read_se<std::string>();
        case SERIALIZE_TYPE_TAG<section>:     return read_se<section>();
        //case SERIALIZE_TYPE_ARRAY:  return read_se<array_entry>(); // nested arrays not supported
        default: { CHECK_AND_ASSERT_THROW_MES(false, "unknown entry_type code = {}", +ent_type); return {}; }
      }
    }
    inline 
    void throwable_buffer_reader::read(section& sec)
    {
      sec.m_entries.clear();
      size_t count = read_varint();
      while(count--)
      {
        //read section name string
        std::string sec_name;
        read_sec_name(sec_name);
        sec.m_entries.insert(std::make_pair(sec_name, load_storage_entry()));
      }
    }
    inline 
    void throwable_buffer_reader::read(std::string& str)
    {
      size_t len = read_varint();
      CHECK_AND_ASSERT_THROW_MES(len < MAX_STRING_LEN_POSSIBLE, "to big string len value in storage: {}", len);
      CHECK_AND_ASSERT_THROW_MES(m_count >= len, "string len count value {} goes out of remain storage len {}", len, m_count);
      //do this manually to avoid double memory write in huge strings (first time at resize, second at read)
      str.assign(reinterpret_cast<const char*>(m_ptr), len);
      m_ptr += len;
      m_count -= len;
    }
  }
}

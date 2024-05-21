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
#include <string_view>
#include <charconv>
#include <oxenc/variant.h>
#include "portable_storage_base.h"
#include "parserse_base_utils.h"

#define EPEE_JSON_RECURSION_LIMIT_INTERNAL 100

namespace epee
{
  using namespace misc_utils::parse;
  namespace serialization
  {
    namespace json
    {
#define CHECK_ISSPACE()  if(!epee::misc_utils::parse::isspace(*it)){ ASSERT_MES_AND_THROW("Wrong JSON character at: {}", std::string(it, buf_end));}

      template <typename T>
      T parse_number(const std::string_view str)
      {
        T num;
        // In theory from_chars should work with double, but neither libc++ nor libstdc++ implement
        // it yet.
        if constexpr (std::is_same_v<T, double>)
        {
          size_t consumed;
          try {
            if (num = std::stod(str.data(), &consumed); consumed == str.size())
              return num;
          }
          catch (...) {}
        }
        else
        {
          auto* end = str.data() + str.size();
          if (auto [p, ec] = std::from_chars(str.data(), end, num); ec == std::errc{} && p == end)
            return num;
        }
        throw std::runtime_error("Invalid number: " + std::string{str});
      }

      template <typename Storage, typename T>
      array_entry* make_array_and_insert(Storage& st, const std::string& value_name, T value, section* parent_section)
      {
        auto* array = st.template make_array<T>(value_name, parent_section);
        CHECK_AND_ASSERT_THROW_MES(array, "failed to insert {} array", typeid(T).name());
        var::get<array_t<T>>(*array).push_back(std::move(value));
        return array;
      }

      /*inline void parse_error()
      {
        ASSERT_MES_AND_THROW("json parse error");
      }*/
      template<typename It, class t_storage>
      void run_handler(section* current_section, It& sec_buf_begin, It buf_end, t_storage& stg, unsigned int recursion)
      {
        CHECK_AND_ASSERT_THROW_MES(recursion < EPEE_JSON_RECURSION_LIMIT_INTERNAL, "Wrong JSON data: recursion limitation ({}) exceeded", EPEE_JSON_RECURSION_LIMIT_INTERNAL);

        std::string::const_iterator sub_element_start;
        std::string name;
        array_entry* array = nullptr;
        enum match_state
        {
          match_state_lookup_for_section_start, 
          match_state_lookup_for_name, 
          match_state_waiting_separator, 
          match_state_wonder_after_separator, 
          match_state_wonder_after_value, 
          match_state_wonder_array, 
          match_state_array_after_value,
          match_state_array_waiting_value, 
          match_state_error
        };

        enum array_mode
        {
          array_mode_undefined = 0,
          array_mode_sections, 
          array_mode_string, 
          array_mode_numbers,
          array_mode_booleans
        };

        match_state state = match_state_lookup_for_section_start;
        array_mode array_md = array_mode_undefined;
        for(auto it = sec_buf_begin; it != buf_end; ++it)
        {
          switch (state)
          {
          case match_state_lookup_for_section_start:
            if(*it == '{')
              state = match_state_lookup_for_name;
            else CHECK_ISSPACE();
            break;
          case match_state_lookup_for_name:
            switch(*it)
            {
            case '"':
              match_string2(it, buf_end, name);
              state = match_state_waiting_separator;
              break;
            case '}':
              //this is it! section ends here.
              //seems that it is empty section
              sec_buf_begin = it;
              return;
            default:
              CHECK_ISSPACE();
            }
            break;
          case match_state_waiting_separator:
            if(*it == ':')
              state = match_state_wonder_after_separator;
            else CHECK_ISSPACE();
            break;
          case match_state_wonder_after_separator:
            if(*it == '"')
            {//just a named string value started
              std::string val;
              match_string2(it, buf_end, val);
              //insert text value 
              stg.set_value(name, std::move(val), current_section);
              state = match_state_wonder_after_value;
            }else if (epee::misc_utils::parse::isdigit(*it) || *it == '-')
            {//just a named number value started
              std::string_view val;
              bool is_v_float = false;bool is_signed = false;
              match_number2(it, buf_end, val, is_v_float, is_signed);
              if(is_v_float)
                stg.set_value(name, parse_number<double>(val), current_section);
              else if(is_signed)
                stg.set_value(name, parse_number<int64_t>(val), current_section);
              else
                stg.set_value(name, parse_number<uint64_t>(val), current_section);
              state = match_state_wonder_after_value;
            }else if(isalpha(*it) )
            {// could be null, true or false
              std::string_view word;
              match_word2(it, buf_end, word);
              if(word == "null")
                //just skip this, 
                state = match_state_wonder_after_value;
              else if(word == "true" || word == "false")
                stg.set_value(name, word == "true", current_section);              
              else ASSERT_MES_AND_THROW("Unknown value keyword {}", word);
              state = match_state_wonder_after_value;
            }else if(*it == '{')
            {
              //sub section here
              section* new_sec = stg.open_section(name, current_section, true);
              CHECK_AND_ASSERT_THROW_MES(new_sec, "Failed to insert new section in json: {}", std::string(it, buf_end));
              run_handler(new_sec, it, buf_end, stg, recursion + 1);
              state = match_state_wonder_after_value;
            }else if(*it == '[')
            {//array of something
              state = match_state_wonder_array;
            }else CHECK_ISSPACE();
            break;
          case match_state_wonder_after_value:
            if(*it == ',')
              state = match_state_lookup_for_name;
            else if(*it == '}')
            {
              //this is it! section ends here.
              sec_buf_begin = it;
              return;
            }else CHECK_ISSPACE();
            break;
          case match_state_wonder_array:
            if(*it == '[')
            {
              ASSERT_MES_AND_THROW("array of array not supported yet :( sorry"); 
              //mean array of array
            }
            if(*it == '{')
            {
              //mean array of sections
              array = make_array_and_insert(stg, name, section{}, current_section);
              run_handler(&var::get<array_t<section>>(*array).back(), it, buf_end, stg, recursion + 1);
              state = match_state_array_after_value;
              array_md = array_mode_sections;
            }else if(*it == '"')
            {
              //mean array of strings
              std::string val;
              match_string2(it, buf_end, val);
              array = make_array_and_insert(stg, name, std::move(val), current_section);
              state = match_state_array_after_value;
              array_md = array_mode_string;
            }else if (epee::misc_utils::parse::isdigit(*it) || *it == '-')
            {//array of numbers value started
              std::string_view val;
              bool is_v_float = false;bool is_signed_val = false;
              match_number2(it, buf_end, val, is_v_float, is_signed_val);
              // This numeric array handling here is gross: the first value determines the array
              // type, but subsequent values have to be guessed as the same type or else you get a
              // parse error because the code requires (and has always required) that the guessed
              // type is the same.  So these are okay:
              //   "foo": [1,2]
              //   "foo": [-1,-2]
              //   "foo": [1.5, 2.0]
              // but these result in parse failures:
              //   "foo": [1,-2]
              //   "foo": [-1,2]
              //   "foo": [1.5, 2]
              // even though 2 is both a valid signed integer and a valid double.  And that means
              // there is *no way* to send a list of signed integer values unless *all* happen to be
              // negative, and no way to send a list of doubles unless *all* happen to not be
              // integers.
              //
              // It is not worth fixing this cursed code, though: better to scrap it and move to a
              // proper library that isn't such a pile of garbage.
              //
              if (is_v_float)
                array = make_array_and_insert(stg, name, parse_number<double>(val), current_section);
              else if (is_signed_val)
                array = make_array_and_insert(stg, name, parse_number<int64_t>(val), current_section);
              else
                array = make_array_and_insert(stg, name, parse_number<uint64_t>(val), current_section);
              state = match_state_array_after_value;
              array_md = array_mode_numbers;
            }else if(*it == ']')//empty array
            {
              array_md = array_mode_undefined;
              state = match_state_wonder_after_value;
            }else if(isalpha(*it) )
            {// array of booleans
              std::string_view word;
              match_word2(it, buf_end, word);
              if(word == "true" || word == "false")
                array = make_array_and_insert(stg, name, word == "true", current_section);              
              else
                ASSERT_MES_AND_THROW("Unknown value keyword {}", word);
              state = match_state_array_after_value;
              array_md = array_mode_booleans;
            }else CHECK_ISSPACE();
            break;
          case match_state_array_after_value:
            if(*it == ',')
              state = match_state_array_waiting_value;
            else if(*it == ']')
            {
              array = nullptr;
              array_md = array_mode_undefined;
              state = match_state_wonder_after_value;
            }else CHECK_ISSPACE();
            break;
          case match_state_array_waiting_value:
            switch(array_md)
            {
            case array_mode_sections:
              if(*it == '{')
              {
                auto* a = std::get_if<array_t<section>>(array);
                CHECK_AND_ASSERT_THROW_MES(a, "failed to insert next section");
                a->emplace_back();
                run_handler(&a->back(), it, buf_end, stg, recursion + 1);
                state = match_state_array_after_value;
              }else CHECK_ISSPACE();
              break;
            case array_mode_string:
              if(*it == '"')
              {
                std::string val;
                match_string2(it, buf_end, val);
                auto* a = std::get_if<array_t<std::string>>(array);
                CHECK_AND_ASSERT_THROW_MES(a, "failed to insert string value");
                a->push_back(std::move(val));
                state = match_state_array_after_value;
              }else CHECK_ISSPACE();
              break;
            case array_mode_numbers:
              if (epee::misc_utils::parse::isdigit(*it) || *it == '-')
              {//array of numbers value started
                std::string_view val;
                bool is_v_float = false;bool is_signed_val = false;
                match_number2(it, buf_end, val, is_v_float, is_signed_val);
                bool insert_res = false;
                // This is broken AF.  See comment above.
                if (is_v_float)
                {
                  if (auto* a = std::get_if<array_t<double>>(array)) {
                    a->push_back(parse_number<double>(val));
                    insert_res = true;
                  }
                }
                else if (is_signed_val)
                {
                  if (auto* a = std::get_if<array_t<int64_t>>(array)) {
                    a->push_back(parse_number<int64_t>(val));
                    insert_res = true;
                  }
                }
                else
                {
                  if (auto* a = std::get_if<array_t<uint64_t>>(array)) {
                    a->push_back(parse_number<uint64_t>(val));
                    insert_res = true;
                  }
                }

                CHECK_AND_ASSERT_THROW_MES(insert_res, "Failed to insert next value");
                state = match_state_array_after_value;
                array_md = array_mode_numbers;
              }else CHECK_ISSPACE();
              break;
            case array_mode_booleans:
              if(isalpha(*it) )
              {// array of booleans
                std::string_view word;
                match_word2(it, buf_end, word);
                bool val;
                if (word == "true" || word == "false")
                  val = true;
                else if (word == "false")
                  val = false;
                else ASSERT_MES_AND_THROW("Unknown value keyword {}", word);

                if (auto* a = std::get_if<array_t<bool>>(array))
                  a->push_back(val);
                else ASSERT_MES_AND_THROW("can't handle a bool value mixed with other types");
              }else CHECK_ISSPACE();
              break;
            case array_mode_undefined:
            default:
              ASSERT_MES_AND_THROW("Bad array state");
            }
            break;
          case match_state_error:
          default:
            ASSERT_MES_AND_THROW("WRONG JSON STATE");
          }
        }
      }
/*
{
    "firstName": "John",
    "lastName": "Smith",
    "age": 25,
    "address": {
        "streetAddress": "21 2nd Street",
        "city": "New York",
        "state": "NY",
        "postalCode": -10021, 
        "have_boobs": true, 
        "have_balls": false 
    },
    "phoneNumber": [
        {
            "type": "home",
            "number": "212 555-1234"
        },
        {
            "type": "fax",
            "number": "646 555-4567"
        }
    ], 
    "phoneNumbers": [
    "812 123-1234",
    "916 123-4567"
    ]
}
*/
      template<class t_storage>
      inline bool load_from_json(std::string_view buff_json, t_storage& stg)
      {
        try
        {
          auto it = buff_json.begin();
          run_handler(nullptr, it, buff_json.end(), stg, 0);
          return true;
        }
        catch(...)
        {
          return false;
        }
      }
    }
  }
}

#include "epee/storages/parserse_base_utils.h"

#include <algorithm>
#include <string>
#include <string_view>
#include <oxenc/hex.h>
#include "epee/misc_log_ex.h"

namespace epee::misc_utils::parse {

/*
  
  \b  Backspace (ascii code 08)
  \f  Form feed (ascii code 0C)
  \n  New line
  \r  Carriage return
  \t  Tab
  \v  Vertical tab
  \'  Apostrophe or single quote
  \"  Double quote
  \\  Backslash character

  */
void match_string2(const char*& star_end_string, const char* buf_end, std::string& val)
{
  bool escape_mode = false;
  auto it = star_end_string;
  ++it;
  auto fi = it;
  while (fi != buf_end && ((detail::lut[(uint8_t)*fi] & 32)) == 0)
    ++fi;
  val.assign(it, fi);
  val.reserve(std::distance(star_end_string, buf_end));
  it = fi;
  for(;it != buf_end;it++)
  {
    if(escape_mode/*prev_ch == '\\'*/)
    {
      switch(*it)
      {
      case 'b':  //Backspace (ascii code 08)
        val.push_back(0x08);break;
      case 'f':  //Form feed (ascii code 0C)
        val.push_back(0x0C);break;
      case 'n':  //New line
        val.push_back('\n');break;
      case 'r':  //Carriage return
        val.push_back('\r');break;
      case 't':  //Tab
        val.push_back('\t');break;
      case 'v':  //Vertical tab
        val.push_back('\v');break;
      case '\'':  //Apostrophe or single quote
        val.push_back('\'');break;
      case '"':  //Double quote
        val.push_back('"');break;
      case '\\':  //Backslash character
        val.push_back('\\');break;
      case '/':  //Slash character
        val.push_back('/');break;
      case 'u':  //Unicode code point
        if (buf_end - it < 4)
        {
          ASSERT_MES_AND_THROW("Invalid Unicode escape sequence");
        }
        else
        {
          uint32_t dst = 0;
          for (int i = 0; i < 4; ++i)
          {
            const auto c = *++it;
            CHECK_AND_ASSERT_THROW_MES(oxenc::is_hex_digit(c), "Bad Unicode encoding: {}", c);
            dst = dst << 4 | oxenc::from_hex_digit(c);
          }
          // encode as UTF-8
          if (dst <= 0x7f)
          {
            val.push_back(dst);
          }
          else if (dst <= 0x7ff)
          {
            val.push_back(0xc0 | (dst >> 6));
            val.push_back(0x80 | (dst & 0x3f));
          }
          else if (dst <= 0xffff)
          {
            val.push_back(0xe0 | (dst >> 12));
            val.push_back(0x80 | ((dst >> 6) & 0x3f));
            val.push_back(0x80 | (dst & 0x3f));
          }
          else
          {
            ASSERT_MES_AND_THROW("Unicode code point is out or range");
          }
        }
        break;
      default:
        val.push_back(*it);
      }
      escape_mode = false;
    }else if(*it == '"')
    {
      star_end_string = it;
      return;
    }else if(*it == '\\')
    {
      escape_mode = true;
    }          
    else
    {
      val.push_back(*it); 
    }
  }
  ASSERT_MES_AND_THROW("Failed to match string in json entry: {}", std::string_view{star_end_string, buf_end});
}
// The only conclusive thing that can be said about this function is that it does indeed
// closely match a "number 2". 💩
void match_number2(const char*& star_end_string, const char* buf_end, std::string_view& val, bool& is_float_val, bool& is_negative_val)
{
  val = {};
  uint8_t float_flag = 0;
  is_negative_val = false;
  is_float_val = false;
  size_t chars = 0;
  auto it = star_end_string;
  if (it != buf_end && *it == '-')
  {
    is_negative_val = true;
    ++chars;
    ++it;
  }
  for(;it != buf_end;it++)
  {
    const uint8_t flags = detail::lut[(uint8_t)*it];
    if (flags & 16)
    {
      float_flag |= flags;
      ++chars;
    }
    else
    {
      val = std::string_view(&*star_end_string, chars);
      if(val.size())
      {
        star_end_string = --it;
        is_float_val = !!(float_flag & 2);
        return;
      }
      else 
        ASSERT_MES_AND_THROW("wrong number in json entry: {}", std::string(star_end_string, buf_end));
    }
  }
  ASSERT_MES_AND_THROW("wrong number in json entry: {}", std::string(star_end_string, buf_end));
}
void match_word2(const char*& star_end_string, const char* buf_end, std::string_view& val)
{
  val = {};

  for(auto it = star_end_string;it != buf_end;it++)
  {
    if (!(detail::lut[(uint8_t)*it] & 4))
    {
      val = std::string_view(&*star_end_string, std::distance(star_end_string, it));
      if(val.size())
      {
        star_end_string = --it;
        return;
      }else 
        ASSERT_MES_AND_THROW("failed to match word number in json entry: {}", std::string(star_end_string, buf_end));
    }
  }
  ASSERT_MES_AND_THROW("failed to match word number in json entry: {}", std::string(star_end_string, buf_end));
}

} // namespace epee::misc_utils::parse

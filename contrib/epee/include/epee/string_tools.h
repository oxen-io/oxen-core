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



#ifndef _STRING_TOOLS_H_
#define _STRING_TOOLS_H_

// Previously pulled in by ASIO, further cleanup still required ...
#ifdef _WIN32
# include <winsock2.h>
# include <windows.h>
#endif

#include <cstring>
#include <cstdlib>
#include <string>
#include <string_view>
#include <type_traits>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include "storages/parserse_base_utils.h"
#include "hex.h"
#include "mlocker.h"
#include "span.h"
#include "warnings.h"


#ifdef WINDOWS_PLATFORM
#pragma comment (lib, "Rpcrt4.lib")
#endif

namespace epee
{

using namespace std::literals;

namespace string_tools
{
  //----------------------------------------------------------------------------
  inline bool parse_hexstr_to_binbuff(const epee::span<const char> s, epee::span<char>& res)
  {
      if (s.size() != res.size() * 2)
        return false;

      unsigned char *dst = (unsigned char *)&res[0];
      const unsigned char *src = (const unsigned char *)s.data();
      for(size_t i = 0; i < s.size(); i += 2)
      {
        int tmp = *src++;
        tmp = epee::misc_utils::parse::isx[tmp];
        if (tmp == 0xff) return false;
        int t2 = *src++;
        t2 = epee::misc_utils::parse::isx[t2];
        if (t2 == 0xff) return false;
        *dst++ = (tmp << 4) | t2;
      }

      return true;
  }
  //----------------------------------------------------------------------------
  inline bool parse_hexstr_to_binbuff(const std::string& s, std::string& res)
  {
    if (s.size() & 1)
      return false;
    res.resize(s.size() / 2);
    epee::span<char> rspan((char*)&res[0], res.size());
    return parse_hexstr_to_binbuff(epee::to_span(s), rspan);
  }
  //----------------------------------------------------------------------------
PUSH_WARNINGS
DISABLE_GCC_WARNING(maybe-uninitialized)
  template<class XType>
  inline bool get_xtype_from_string(XType& val, std::string_view str_id)
  {
    if (std::is_integral_v<XType> && std::is_unsigned_v<XType> && !std::is_same_v<XType, bool>)
    {
      for (char c : str_id)
      {
        if (!epee::misc_utils::parse::isdigit(c))
          return false;
      }
    }

    try
    {
      val = boost::lexical_cast<XType>(std::string{str_id});
      return true;
    }
    catch(const std::exception& /*e*/)
    {
      //const char* pmsg = e.what();
      return false;
    }
    catch(...)
    {
      return false;
    }

    return true;
  }
POP_WARNINGS
	//----------------------------------------------------------------------------
	std::string get_ip_string_from_int32(uint32_t ip);
	//----------------------------------------------------------------------------
	bool get_ip_int32_from_string(uint32_t& ip, const std::string& ip_str);
  //----------------------------------------------------------------------------
  inline bool parse_peer_from_string(uint32_t& ip, uint16_t& port, std::string_view address)
  {
    //parse ip and address
    auto p = address.find(':');
    std::string_view ip_str, port_str;
    if(p == std::string_view::npos)
    {
      port = 0;
      ip_str = address;
    }
    else
    {
      ip_str = address.substr(0, p);
      port_str = address.substr(p+1);
    }

    if(!get_ip_int32_from_string(ip, std::string{ip_str}))
    {
      return false;
    }

    if(p != std::string::npos && !get_xtype_from_string(port, port_str))
    {
      return false;
    }
    return true;
  }

	//----------------------------------------------------------------------------
	template<typename T>
	inline std::string to_string_hex(const T &val)
	{
		static_assert(std::is_arithmetic<T>::value, "only arithmetic types");
		std::stringstream ss;
		ss << std::hex << val;
		std::string s;
		ss >> s;
		return s;
	}
	//----------------------------------------------------------------------------
	
	inline bool compare_no_case(const std::string& str1, const std::string& str2)
	{
		
		return !boost::iequals(str1, str2);
	}
	//----------------------------------------------------------------------------
	inline std::string& get_current_module_name()
	{
		static std::string module_name;
		return module_name;
	}
	//----------------------------------------------------------------------------
	inline std::string& get_current_module_folder()
	{	
		static std::string module_folder;
		return module_folder;
	}
  //----------------------------------------------------------------------------
#ifdef _WIN32
  inline std::string get_current_module_path()
  {
    char pname [5000] = {0};
    GetModuleFileNameA( NULL, pname, sizeof(pname));
    pname[sizeof(pname)-1] = 0; //be happy ;)
    return pname;
  }
#endif
	//----------------------------------------------------------------------------
	inline bool set_module_name_and_folder(const std::string& path_to_process_)
	{
    std::string path_to_process = path_to_process_;
#ifdef _WIN32
    path_to_process = get_current_module_path();
#endif 
		std::string::size_type a = path_to_process.rfind( '\\' );
		if(a == std::string::npos )
		{
			a = path_to_process.rfind( '/' );
		}
		if ( a != std::string::npos )
		{	
			get_current_module_name() = path_to_process.substr(a+1, path_to_process.size());
			get_current_module_folder() = path_to_process.substr(0, a);
			return true;
		}else
			return false;

	}

  //----------------------------------------------------------------------------
  inline std::string& trim_left(std::string& str)
  {
      auto it = str.begin();
      while (it != str.end() && std::isspace(static_cast<unsigned char>(*it)))
          it++;
      if (it != str.begin())
          str.erase(str.begin(), it);
      return str;
  }
  //----------------------------------------------------------------------------
  inline std::string& trim_right(std::string& str)
  {
      while (!str.empty() && std::isspace(static_cast<unsigned char>(str.back())))
          str.pop_back();
      return str;
  }
  //----------------------------------------------------------------------------
  inline std::string& trim(std::string& str)
  {
    return trim_left(trim_right(str));
  }
  //----------------------------------------------------------------------------
  inline std::string trim(const std::string& str_)
  {
    std::string str = str_;
    trim(str);
    return str;
  }
  //----------------------------------------------------------------------------
  inline std::string pad_string(std::string s, size_t n, char c = ' ', bool prepend = false)
  {
    if (s.size() < n)
    {
      if (prepend)
        s = std::string(n - s.size(), c) + s;
      else
        s.append(n - s.size(), c);
    }
    return s;
  }
}
}
#endif //_STRING_TOOLS_H_

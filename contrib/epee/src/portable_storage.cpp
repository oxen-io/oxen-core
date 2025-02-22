#include "epee/storages/portable_storage_to_json.h"
#include "epee/storages/portable_storage.h"
#include <oxenc/variant.h>

namespace epee {
  namespace serialization {

    void dump_as_json(std::ostream& strm, const array_entry& ae, size_t indent, bool pretty)
    {
      var::visit([&](const auto& a) {
          strm << '[';
          for (auto it = a.begin(); it != a.end(); ++it)
          {
            if (it != a.begin()) strm << ',';
            dump_as_json(strm, *it, indent, pretty);
          }
          strm << ']';
        }, ae);
    }

    void dump_as_json(std::ostream& strm, const storage_entry& se, size_t indent, bool pretty)
    {
      var::visit([&](const auto& v) {
          dump_as_json(strm, v, indent, pretty);
        }, se);
    }

    void dump_as_json(std::ostream& s, const std::string& v, size_t, bool)
    {
      s.put('"');
      // JSON strings may only contain 0x20 and above, except for " and \\ which must be escaped.
      // For values below 0x20 we can use \u00XX escapes, except for the really common \n and \t (we
      // could also use \b, \f, \r, but it really isn't worth the bother.
      for (char c : v) {
        switch(c) {
          case '"':
          case '\\':
            s.put('\\'); s.put(c);
            break;
          case '\n': s.write("\\n", 2); break;
          case '\t': s.write("\\t", 2); break;
          case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07:
          case 0x08: /*\t=0x09: \n=0x0a*/  case 0x0b: case 0x0c: case 0x0d: case 0x0e: case 0x0f:
          case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
          case 0x18: case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x1e: case 0x1f:
            s.write("\\u00", 4);
            s.put(c >= 0x10 ? '1' : '0');
            c &= 0xf;
            s.put(c < 0xa ? '0' + c : ('a' - 10) + c);
            break;
          default:
            s.put(c);
        }
      }
      s.put('"');
    }


    void dump_as_json(std::ostream& strm, const section& sec, size_t indent, bool pretty)
    {
      strm << '{';
      if(sec.m_entries.empty())
        strm << '}';
      else
      {
        size_t local_indent = indent + 1;
        std::string line_sep(pretty * (1 + 2*local_indent), ' ');
        if (pretty) line_sep[0] = '\n';

        for (auto it = sec.m_entries.begin(); it != sec.m_entries.end(); ++it)
        {
          if (it != sec.m_entries.begin()) strm << ',';
          strm << line_sep;
          dump_as_json(strm, it->first, local_indent, pretty);
          strm << ':';
          if (pretty) strm << ' ';
          dump_as_json(strm, it->second, local_indent, pretty);
        }
        if (pretty)
          line_sep.resize(line_sep.size() - 2);
        strm << line_sep << '}';
      }
    }

    bool portable_storage::dump_as_json(std::string& buff, size_t indent, bool insert_newlines)
    {
      TRY_ENTRY();
      std::stringstream ss;
      epee::serialization::dump_as_json(ss, m_root, indent, insert_newlines);
      buff = ss.str();
      return true;
      CATCH_ENTRY("portable_storage::dump_as_json", false)
    }

    bool portable_storage::load_from_json(std::string_view source)
    {
      TRY_ENTRY();
      return json::load_from_json(source, *this);
      CATCH_ENTRY("portable_storage::load_from_json", false)
    }

    bool portable_storage::store_to_binary(std::string& target)
    {
      TRY_ENTRY();
      std::stringstream ss;
      storage_block_header sbh{};
      sbh.m_signature_a = PORTABLE_STORAGE_SIGNATUREA;
      sbh.m_signature_b = PORTABLE_STORAGE_SIGNATUREB;
      sbh.m_ver = PORTABLE_STORAGE_FORMAT_VER;
      ss.write(reinterpret_cast<const char*>(&sbh), sizeof(storage_block_header));
      pack_entry_to_buff(ss, m_root);
      target = ss.str();
      return true;
      CATCH_ENTRY("portable_storage::store_to_binary", false)
    }

    bool portable_storage::load_from_binary(const epee::span<const uint8_t> source)
    {
      m_root.m_entries.clear();
      if(source.size() < sizeof(storage_block_header))
      {
        return false;
      }
      storage_block_header* pbuff = (storage_block_header*)source.data();
      if(pbuff->m_signature_a != PORTABLE_STORAGE_SIGNATUREA ||
        pbuff->m_signature_b != PORTABLE_STORAGE_SIGNATUREB
        )
      {
        return false;
      }
      if(pbuff->m_ver != PORTABLE_STORAGE_FORMAT_VER)
      {
        return false;
      }
      TRY_ENTRY();
      throwable_buffer_reader buf_reader(source.data()+sizeof(storage_block_header), source.size()-sizeof(storage_block_header));
      buf_reader.read(m_root);
      return true;//TODO:
      CATCH_ENTRY("portable_storage::load_from_binary", false);
    }

    section* portable_storage::open_section(const std::string& section_name, section* parent_section, bool create_if_notexist)
    {
      TRY_ENTRY();
      if (!parent_section) parent_section = &m_root;

      storage_entry* pentry = find_storage_entry(section_name, parent_section);
      if(!pentry)
      {
        if(!create_if_notexist)
          return nullptr;
        return insert_new_section(section_name, parent_section);
      }
      CHECK_AND_ASSERT(pentry , nullptr);
      //check that section_entry we find is real "CSSection"
      if (!std::holds_alternative<section>(*pentry))
      {
        if(create_if_notexist)
          *pentry = section();//replace
        else
          return nullptr;
      }
      return &var::get<section>(*pentry);
      CATCH_ENTRY("portable_storage::open_section", nullptr);
    }

    bool portable_storage::get_value(const std::string& value_name, storage_entry& val, section* parent_section)
    {
      //TRY_ENTRY();
      if(!parent_section) parent_section = &m_root;
      storage_entry* pentry = find_storage_entry(value_name, parent_section);
      if(!pentry)
        return false;

      val = *pentry;
      return true;
      //CATCH_ENTRY("portable_storage::template<>get_value", false);
    }

    storage_entry* portable_storage::find_storage_entry(const std::string& pentry_name, section* psection)
    {
      TRY_ENTRY();
      CHECK_AND_ASSERT(psection, nullptr);
      auto it = psection->m_entries.find(pentry_name);
      if(it == psection->m_entries.end())
        return nullptr;

      return &it->second;
      CATCH_ENTRY("portable_storage::find_storage_entry", nullptr);
    }

    section* portable_storage::insert_new_section(const std::string& pentry_name, section* psection)
    {
      TRY_ENTRY();
      storage_entry* pse = insert_new_entry_get_storage_entry(pentry_name, psection, section());
      if(!pse) return nullptr;
      return &var::get<section>(*pse);
      CATCH_ENTRY("portable_storage::insert_new_section", nullptr);
    }
  }
}

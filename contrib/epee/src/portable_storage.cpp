#include "epee/storages/portable_storage.h"
#include <sstream>
#include <variant>

namespace epee {
  namespace serialization {

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

    bool portable_storage::load_from_binary(const std::span<const uint8_t> source)
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
      if (!pentry)
        return nullptr;
      //check that section_entry we find is real "CSSection"
      if (!std::holds_alternative<section>(*pentry))
      {
        if(create_if_notexist)
          *pentry = section();//replace
        else
          return nullptr;
      }
      return &std::get<section>(*pentry);
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
      if (!psection)
        return nullptr;
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
      return &std::get<section>(*pse);
      CATCH_ENTRY("portable_storage::insert_new_section", nullptr);
    }
  }
}

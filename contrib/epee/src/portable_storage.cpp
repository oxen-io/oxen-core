#include "epee/storages/portable_storage.h"
#include <sstream>
#include <variant>

namespace epee {
  namespace serialization {

    bool portable_storage::store_to_binary(std::string& target)
    try {
      std::stringstream ss;
      storage_block_header sbh{};
      sbh.m_signature_a = PORTABLE_STORAGE_SIGNATUREA;
      sbh.m_signature_b = PORTABLE_STORAGE_SIGNATUREB;
      sbh.m_ver = PORTABLE_STORAGE_FORMAT_VER;
      ss.write(reinterpret_cast<const char*>(&sbh), sizeof(storage_block_header));
      pack_entry_to_buff(ss, m_root);
      target = ss.str();
      return true;
    } catch (const std::exception& e) {
      log::error(logcat, "Failed to serialize portable storage: {}", e.what());
      return false;
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
      try {
        throwable_buffer_reader buf_reader(source.data()+sizeof(storage_block_header), source.size()-sizeof(storage_block_header));
        buf_reader.read(m_root);
      } catch (const std::exception& e) {
        log::error(logcat, "Failed to deserialize portable storage: {}", e.what());
        return false;
      }
      return true;
    }

    section* portable_storage::open_section(const std::string& section_name, section* parent_section, bool create_if_notexist)
    {
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
    }

    bool portable_storage::get_value(const std::string& value_name, storage_entry& val, section* parent_section)
    {
      if(!parent_section) parent_section = &m_root;
      storage_entry* pentry = find_storage_entry(value_name, parent_section);
      if(!pentry)
        return false;

      val = *pentry;
      return true;
    }

    storage_entry* portable_storage::find_storage_entry(const std::string& pentry_name, section* psection)
    {
      if (!psection)
        return nullptr;
      auto it = psection->m_entries.find(pentry_name);
      if(it == psection->m_entries.end())
        return nullptr;

      return &it->second;
    }

    section* portable_storage::insert_new_section(const std::string& pentry_name, section* psection)
    {
      storage_entry* pse = insert_new_entry_get_storage_entry(pentry_name, psection, section());
      if(!pse) return nullptr;
      return &std::get<section>(*pse);
    }
  }
}

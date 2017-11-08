//
//  StringTableCreator.h
//  gsym
//

#ifndef gsym_StringTableCreator_h
#define gsym_StringTableCreator_h

#include <map>
#include <string>
#include "FileWriter.h"

namespace gsym {
  class StringTableCreator {
    typedef std::map<std::string, uint32_t> StringToOffsetMap;
    StringToOffsetMap m_strings;
    std::vector<const char *> m_ordered_strings; // m_strings contains the backing string
    uint32_t m_next_offset;
  public:
    StringTableCreator() : m_next_offset(0) {
      Insert("");
    }
    uint32_t Insert(std::string s) {
      auto pos = m_strings.find(s);
      if (pos != m_strings.end())
        return pos->second;
      uint32_t offset = m_next_offset;
      m_next_offset += s.size() + 1;
      m_strings[s] = offset;
      m_ordered_strings.push_back(m_strings.find(s)->first.c_str());
      return offset;
    }
    void Write(FileWriter &out) {
      for (auto cstr: m_ordered_strings)
        out.Write(cstr, strlen(cstr) + 1);
    }

  };
}

#endif // #ifndef gsym_StringTableCreator_h

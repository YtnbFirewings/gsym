//
//  FileTableCreator.h
//  gsym
//

#ifndef gsym_FileTableCreator_h
#define gsym_FileTableCreator_h

#include <libgen.h>
#include <map>
#include <string>
#include "gsym.h"
#include "StringTableCreator.h"

namespace gsym {
  class FileWriter;
  
  class FileTableCreator {
    typedef std::map<std::string, uint32_t> FilePathToIndex;
    FilePathToIndex m_path_to_index;
    std::vector<gsym::FileEntry> m_file_entries;
    gsym::StringTableCreator &m_strtab;
    uint32_t m_next_index;
  public:
    FileTableCreator(StringTableCreator &strtab) : m_next_index(0), m_strtab(strtab) {
      m_file_entries.push_back(FileEntry(0,0));
      m_path_to_index[""] = 0;
    }
    uint32_t Insert(std::string s);
    void Write(FileWriter &out);
  };
}

#endif // #ifndef gsym_FileTableCreator_h

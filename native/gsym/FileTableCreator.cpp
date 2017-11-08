//
//  FileTableCreator.cpp
//  gsym
//

#include "FileTableCreator.h"
#include "FileWriter.h"

using namespace gsym;

uint32_t FileTableCreator::Insert(std::string s) {
  auto pos = m_path_to_index.find(s);
  if (pos != m_path_to_index.end())
    return pos->second;
  uint32_t index = ++m_next_index;
  m_path_to_index[s] = index;
  auto last_slash = s.rfind('/');
  if (last_slash == std::string::npos || last_slash == 0) {
    m_file_entries.push_back(FileEntry(0, m_strtab.Insert(s)));
  } else {
    std::string dir = s.substr(0, last_slash);
    std::string base = s.substr(last_slash + 1);
    m_file_entries.push_back(FileEntry(m_strtab.Insert(dir),
                                       m_strtab.Insert(base)));
  }
  return index;
}

void FileTableCreator::Write(FileWriter &out) {
  size_t num_files = m_file_entries.size();
  out.WriteUnsigned(num_files, sizeof(uint32_t));
  out.Write(m_file_entries.data(), num_files * sizeof(FileEntry));
}

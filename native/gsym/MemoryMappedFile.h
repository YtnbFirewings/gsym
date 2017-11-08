//
//  MemoryMappedFile.h
//  gsym
//

#ifndef gsym_MemoryMappedFile_h
#define gsym_MemoryMappedFile_h

#include "DataRef.h"
#include <string>

namespace gsym {
  class MemoryMappedFile {
    DataRef m_data;
  public:
    MemoryMappedFile() = default;
    ~MemoryMappedFile();
    bool Open(const char *path, std::string &error);
    void Clear();
    DataRef GetData() const {
      return m_data;
    }
  };
}

#endif // #ifndef gsym_MemoryMappedFile_h

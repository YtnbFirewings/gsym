//
//  LookupResult.h
//  gsym
//

#ifndef gsym_LookupResult_h
#define gsym_LookupResult_h

#include <stdio.h>

namespace gsym {

  struct LookupResult {
    uint64_t addr;
    uint64_t end_addr;
    const char *name;
    const char *directory;
    const char *basename;
    uint32_t line;
    
    LookupResult() : addr(0), end_addr(0), name(nullptr), directory(nullptr),
      basename(nullptr), line(0) {}
    void Clear() {
      addr = 0;
      end_addr = 0;
      name = nullptr;
      directory = nullptr;
      basename = nullptr;
      line = 0;
    }
    
    void Dump() {
      printf("[0x%llx-0x%llx) in %s @ %s/%s:%u", addr, end_addr, name, directory, basename, line);
    }
  };
}

#endif // #ifndef gsym_LookupResult_h

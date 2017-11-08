//
//  FileEntry.h
//  gsym
//

#ifndef gsym_FileEntry_h
#define gsym_FileEntry_h

#include <stdint.h>

namespace gsym {

  struct FileEntry {
    uint32_t directory; // String table offset in the string table
    uint32_t basename;  // String table offset in the string table

    FileEntry(uint32_t d = 0, uint32_t b = 0) :
      directory(d), basename(b) {
    }
  };

}

#endif // #ifndef gsym_FileEntry_h

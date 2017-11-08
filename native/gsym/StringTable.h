//
//  StringTable.h
//  gsym
//

#ifndef gsym_StringTable_h
#define gsym_StringTable_h

#include <stdint.h>
#include <string>

#include "DataRef.h"

namespace gsym {
  struct StringTable {
    DataRef data;
    StringTable() : data() {}
    StringTable(DataRef d) : data(d) {}
    const char *GetString(uint32_t offset) const {
      return (const char *)data.GetData(offset);
    }
    void Clear() {
      data.Clear();
    }
    void Dump() const {
      printf("String table:\n");
      uint32_t offset = 0;
      while (auto cstr = GetString(offset)) {
        printf("0x%8.8x: \"%s\"\n", offset, cstr);
        offset += strlen(cstr) + 1;
      }
    }
  };
}

#endif // #ifndef gsym_StringTable_h

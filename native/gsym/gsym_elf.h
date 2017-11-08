//
//  gsym_elf.h
//  gsym
//

#ifndef gsym_elf_h
#define gsym_elf_h

#include "DataRef.h"

namespace gsym {
  namespace elf {
    gsym::DataRef GetGSYMSectionData(uint32_t magic, const gsym::DataRef objfile_data);
  }
}

#endif // #ifndef gsym_elf_h

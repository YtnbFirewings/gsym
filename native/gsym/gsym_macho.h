//
//  gsym_macho.h
//  gsym
//
//  Created by Gregory Clayton on 11/3/17.
//  Copyright © 2017 Gregory Clayton. All rights reserved.
//

#ifndef gsym_macho_h
#define gsym_macho_h

#include "DataRef.h"

namespace gsym {
  namespace macho {
    gsym::DataRef GetGSYMSectionData(uint32_t magic,
                                     const gsym::DataRef objfile_data,
                                     uint64_t file_offset = 0);
  }
}

#endif // #ifndef gsym_macho_h

//
//  macho.cpp
//  gsym
//
//  Created by Gregory Clayton on 11/3/17.
//  Copyright © 2017 Gregory Clayton. All rights reserved.
//

#include "gsym_elf.h"
#include "gsym_macho.h"
#include <string.h>

namespace {
  constexpr uint32_t MH_MAGIC = 0xfeedface;
  constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf;
  constexpr uint32_t LC_SEGMENT =	0x1;
  constexpr uint32_t LC_SEGMENT_64 = 0x19;
  static constexpr const char *GSYMSectionName = "__gsym";

  struct mach_header {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
  };

  struct mach_header_64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
  };

  struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
  };

  struct segment_command {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
  };

  struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
  };

  struct section {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
  };

  struct section_64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
  };
  
  template<typename HeaderType, typename SegmentType, typename SectionType,
           uint32_t LC_SEG>
  gsym::DataRef
  ExtractGSYMData(const gsym::DataRef objfile_data, uint64_t file_offset) {
    auto header = objfile_data.GetPointer<HeaderType>(file_offset);
    if (!header)
      return gsym::DataRef();
    uint64_t offset = file_offset + sizeof(HeaderType);
    for (uint32_t i = 0; i < header->ncmds; ++i) {
      auto lc = objfile_data.GetPointer<load_command>(offset);
      if (!lc)
        break;
      if (lc->cmd == LC_SEG) {
        auto segment = objfile_data.GetPointer<SegmentType>(offset);
        if (!segment)
          break;
        uint64_t sect_offset = offset + sizeof(SegmentType);
        for (uint32_t sect_idx = 0; sect_idx < segment->nsects;
             ++sect_idx, sect_offset += sizeof(section)) {
          auto sect = objfile_data.GetPointer<SectionType>(sect_offset);
          if (!sect)
            break;
          if (strcmp(sect->sectname, GSYMSectionName) == 0) {
            gsym::DataRef sect_data;
            if (sect->offset > 0 && sect->size > 0) {
              uint64_t sect_data_offset = file_offset + sect->offset;
              sect_data = objfile_data.GetSlice(sect_data_offset,
                                                sect->size);
            }
            return sect_data;
          }
        }
      }
      offset += lc->cmdsize;
    }
    return gsym::DataRef();
  }
}


gsym::DataRef
gsym::macho::GetGSYMSectionData(uint32_t magic,
                                const gsym::DataRef objfile_data,
                                uint64_t file_offset) {
  if (magic == MH_MAGIC)
    return ExtractGSYMData<mach_header, segment_command, section, LC_SEGMENT>(objfile_data, file_offset);
  if (magic == MH_MAGIC_64)
    return ExtractGSYMData<mach_header_64, segment_command_64, section_64, LC_SEGMENT_64>(objfile_data, file_offset);
  return gsym::DataRef();
}

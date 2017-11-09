//
//  gsym.h
//  gsym
//
//  Created by Gregory Clayton on 10/11/17.
//  Copyright © 2017 Gregory Clayton. All rights reserved.
//

#ifndef gsym_h
#define gsym_h

#include <stdint.h>
#include <string>
#include <vector>

#include "DataRef.h"
#include "FileEntry.h"
#include "FunctionInfo.h"
#include "MemoryMappedFile.h"
#include "StringTable.h"

namespace gsym {
  class DataDecoder;
  class FileTableCreator;
  class LookupResult;
  class StringTableCreator;
  class File {
  public:
    File(const char *path);
    ~File();
    
    void Dump();
    bool Lookup(uint64_t addr, LookupResult &result);

    static bool Save(StringTableCreator &strtab,
                     FileTableCreator &filetab,
                     const std::vector<FunctionInfo> &func_infos,
                     const char *path);
  protected:

    void Unmap();
    uint64_t GetAddressOffset(size_t idx);
    uint64_t GetAddressInfoOffset(size_t idx);
    DataRef GetAddressInfoPayload(size_t idx);
    void DumpLineTable(uint64_t base_addr, DataDecoder &line_data,
                       bool dump_opcodes);

    struct Header {
      uint32_t magic;
      uint16_t version;
      uint8_t  addr_off_size; // Size of addr_off_t
      uint8_t  pad;
      uint64_t base_address;
      uint32_t num_addrs;
      uint32_t strtab_offset;
      uint32_t strtab_size;
      static size_t GetByteSize() {
        return 28;
      }
      std::string GetError() const;
      void Dump() const {
        printf("Header:\n");
        printf("magic         = 0x%8.8x\n", magic);
        printf("version       = 0x%4.4x\n", version);
        printf("addr_off_size = 0x%2.2x\n", addr_off_size);
        printf("pad           = 0x%2.2x\n", pad);
        printf("base_address  = 0x%16.16llx\n", base_address);
        printf("num_addrs     = 0x%8.8x\n", num_addrs);
        printf("strtab_offset = 0x%8.8x\n", strtab_offset);
        printf("strtab_size   = 0x%8.8x\n", strtab_size);
      }
    };

    struct FileTable {
      uint32_t num_files;
      FileEntry files[0];
      size_t GetByteSize() const {
        return sizeof(uint32_t) + num_files * sizeof(FileEntry);
      }
      FileEntry GetFile(uint32_t idx) {
        if (idx == 0 || idx > num_files)
          return FileEntry();
        return files[idx-1];
      }
      void Dump(StringTable &strtab) const {
        printf("Files:\n");
        for (uint32_t i = 0; i < num_files; ++i) {
          printf("files[%u] = 0x%8.8x, 0x%8.8x (\"%s\", \"%s\")\n", i+1,
                 files[i].directory, files[i].basename,
                 strtab.GetString(files[i].directory),
                 strtab.GetString(files[i].basename));
        }
      }
    };
    MemoryMappedFile m_file;
    DataRef m_gsym_data;
    Header *m_header;
    const void *m_addr_offsets;
    uint32_t *m_addr_info_offsets;
    FileTable *m_files;
    StringTable m_strtab;
    std::string m_error;
  };

  
}

#endif // #ifndef gsym_h

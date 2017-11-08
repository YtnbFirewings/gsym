//
//  gsym_elf.cpp
//  gsym
//

#include "gsym_elf.h"
#include "StringTable.h"

// e_ident definitions
#define EI_MAG0       0
#define EI_MAG1       1
#define EI_MAG2       2
#define EI_MAG3       3
#define EI_CLASS      4
#define EI_DATA       5
#define EI_VERSION    6
#define EI_OSABI      7
#define EI_ABIVERSION 8
#define EI_PAD        9
#define EI_NIDENT     16

#define ELFCLASSNONE 0
#define ELFCLASS32   1 // 32-bit object file
#define ELFCLASS64   2 // 64-bit object file

#define ELFDATANONE 0 // Invalid data encoding.
#define ELFDATA2LSB 1 // Little-endian object file
#define ELFDATA2MSB 2 // Big-endian object file

namespace {
  constexpr uint32_t ELF_MAGIC = 0x7f454c46;
  static constexpr const char *GSYMSectionName = ".gsym";
  
  typedef uint32_t Elf32_Addr;
  typedef uint32_t Elf32_Off;
  typedef uint16_t Elf32_Half;
  typedef uint32_t Elf32_Word;
  typedef int32_t Elf32_Sword;
  typedef uint64_t Elf64_Addr;
  typedef uint64_t Elf64_Off;
  typedef uint16_t Elf64_Half;
  typedef uint32_t Elf64_Word;
  typedef int32_t Elf64_Sword;
  typedef uint64_t Elf64_Xword;
  typedef int64_t Elf64_Sxword;
  
  struct Elf32_Ehdr {
    uint8_t e_ident[EI_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
  };

  struct Elf64_Ehdr {
    uint8_t e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
  };

  struct Elf32_Shdr {
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
  };

  struct Elf64_Shdr {
    Elf64_Word sh_name;
    Elf64_Word sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word sh_link;
    Elf64_Word sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
  };
  
  template<typename Ehdr, typename Shdr>
  gsym::DataRef ExtractGSYMData(const gsym::DataRef objfile_data) {
    auto header = objfile_data.GetPointer<Ehdr>(0);
    if (!header)
      return gsym::DataRef();
    // We need the string table that contains the section header names first.
    uint64_t shstr_shoff = header->e_shoff + header->e_shstrndx * sizeof(Shdr);
    auto shstr_sh = objfile_data.GetPointer<Shdr>(shstr_shoff);
    if (shstr_sh && shstr_sh->sh_size > 0) {
      gsym::StringTable shstr(objfile_data.GetSlice(shstr_sh->sh_offset,
                                                    shstr_sh->sh_size));
      for (size_t sh_idx=1; sh_idx<header->e_shnum; ++sh_idx) {
        uint64_t offset = header->e_shoff + sh_idx * sizeof(Shdr);
        auto sh = objfile_data.GetPointer<Shdr>(offset);
        auto sh_name = shstr.GetString(sh->sh_name);
        if (sh_name && strcmp(sh_name, GSYMSectionName) == 0) {
          return objfile_data.GetSlice(sh->sh_offset, sh->sh_size);
        }
      }
    }
    return gsym::DataRef();
  }
}

gsym::DataRef gsym::elf::GetGSYMSectionData(uint32_t magic, const gsym::DataRef objfile_data)
{
  if (magic != ELF_MAGIC)
    return gsym::DataRef();
  auto ei_data = objfile_data.GetValue<uint8_t>(EI_DATA);
  if (ei_data == ELFCLASS32)
    return ExtractGSYMData<Elf32_Ehdr, Elf32_Shdr>(objfile_data);
  if (ei_data == ELFCLASS64)
    return ExtractGSYMData<Elf64_Ehdr, Elf64_Shdr>(objfile_data);
  return gsym::DataRef();
}

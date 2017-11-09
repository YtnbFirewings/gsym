//
//  gsym.cpp
//  gsym
//

#include "gsym.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <functional>
#include <vector>

#include "DataDecoder.h"
#include "FileTableCreator.h"
#include "LookupResult.h"
#include "StringTableCreator.h"
#include "gsym_elf.h"
#include "gsym_macho.h"


using namespace gsym;

#define GSYM_MAGIC 0x4753594d // 'GSYM'
#define GSYM_VERSION 1
namespace {

  enum InfoType {
    EndOfList = 0u,
    LineTableInfo = 1u,
    InlineInfo = 2u
  };

  inline const uint8_t *alignTo(const uint8_t *value, uintptr_t align)
  {
    if (value == nullptr)
      return nullptr;
    // Verify align is power of two and not zero
    assert(align > 0 && (align & (align - 1)) == 0);
    uintptr_t addr  = (uintptr_t)value;
    if (addr % align != 0)
      addr += align - addr % align;
    if (addr >= (uintptr_t)value)
      return (uint8_t *)addr;
    return value;
  }
  
  class LineTable {
    DataDecoder m_data;

    enum Opcode {
      DBG_END_SEQUENCE  = 0x00, // End of the line table
      DBG_SET_FILE      = 0x01, // Set LineTableRow.file_idx, don't push a row
      DBG_ADVANCE_PC    = 0x02, // Increment LineTableRow.address, and push a row
      DBG_ADVANCE_LINE  = 0x03, // Set LineTableRow.file_line, don't push a row
      DBG_FIRST_SPECIAL = 0x04, // All special opcodes push a row
    };
    
    static bool encode_special(int64_t min_line_delta,
                               int64_t max_line_delta,
                               int64_t line_delta,
                               uint64_t addr_delta,
                               uint8_t &special_opcode) {
      if (line_delta < min_line_delta)
        return false;
      if (line_delta > max_line_delta)
        return false;
      int64_t line_range = max_line_delta - min_line_delta + 1;
      int64_t adjusted_opcode = ((line_delta - min_line_delta) +
                                 addr_delta * line_range);
      int64_t opcode = adjusted_opcode + DBG_FIRST_SPECIAL;
      if (opcode < 0)
        return false;
      if (opcode > 255)
        return false;
      special_opcode = (uint8_t)opcode;
      return true;
    }
    
    void Parse(uint64_t base_addr, bool dump,
               std::function<bool(const LineEntry &row)> const &row_callback) {
      m_data.SetPosition(0);
      int64_t min_delta = m_data.GetSLEB128();
      int64_t max_delta = m_data.GetSLEB128();
      int64_t line_range = max_delta - min_delta + 1;
      uint32_t first_line = (uint32_t)m_data.GetULEB128();
      if (dump) {
        printf("base_addr = 0x%8.8llx\n", base_addr);
        printf("min_delta = %lli\n", min_delta);
        printf("max_delta = %lli\n", max_delta);
        printf("first_line = %u\n", first_line);
      }
      LineEntry row(base_addr, 1, first_line);
      bool done = false;
      while (!done) {
        auto opcode_offset = m_data.GetPosition();
        uint8_t opcode = m_data.GetU8();
        switch (opcode) {
          case DBG_END_SEQUENCE:
            if (dump)
              printf ("0x%8.8lx: DBG_END_SEQUENCE\n", opcode_offset);
            done = true;
            break;
          case DBG_SET_FILE:
            row.file = (uint32_t)m_data.GetULEB128();
            if (dump)
              printf ("0x%8.8lx: DBG_SET_FILE(%u)\n", opcode_offset, row.file);
            break;
          case DBG_ADVANCE_PC: {
            auto delta = m_data.GetULEB128();
            if (dump)
              printf ("0x%8.8lx: DBG_ADVANCE_PC(%llu)\n", opcode_offset, delta);
            row.addr += delta;
            // If the function callback returns false, we stop parsing
            if (row_callback(row) == false)
              return;
            if (dump)
              printf ("Pushing row: addr=0x%16.16llx, file=%u, line=%u\n",
                      row.addr, row.file, row.line);
          }
            break;
          case DBG_ADVANCE_LINE: {
            auto delta = m_data.GetSLEB128();
            if (dump)
              printf ("0x%8.8lx: DBG_ADVANCE_LINE(%lli)\n", opcode_offset, delta);
            row.line += delta;
          }
            break;
          default: {
            // A byte that contains both address and line increment
            uint8_t adjusted_opcode = opcode - DBG_FIRST_SPECIAL;
            int64_t line_delta = min_delta + (adjusted_opcode % line_range);
            uint64_t addr_delta = (adjusted_opcode / line_range);
            if (dump)
              printf("0x%8.8lx: DBG_SPECIAL(0x%2.2x) line += %lli, addr += %llu\n",
                     opcode_offset, opcode, line_delta, addr_delta);
            row.line += line_delta;
            row.addr += addr_delta;
            // If the function callback returns false, we stop parsing
            if (row_callback(row) == false)
              return;
            if (dump)
              printf("Pushing row: addr=0x%16.16llx, file=%u, line=%u\n",
                     row.addr, row.file, row.line);
            break;
          }
        }
      }
    }

  public:
    LineTable(DataDecoder data) : m_data(data) {}

    static const char *GetInfoTypeAsString(uint32_t info_type) {
      switch (info_type) {
        case InfoType::EndOfList: return "EndOfList";
        case InfoType::LineTableInfo: return "LineTable";
        case InfoType::InlineInfo: return "InlineInfo";
        default: return "???";
      }
    }
    static bool Write(FileWriter &out, const FunctionInfo &func_info, bool dump) {
      
      if (func_info.lines.empty())
        return false;
      // Write out the unsigned InfoType::LineTableInfo enum
      out.WriteU32(InfoType::LineTableInfo);
      // Write out a zero byte size of this chunk for now, we will fixup later
      const off_t line_table_length_offset = out.Tell();
      out.WriteU32(0);
      const off_t line_table_start = line_table_length_offset + 4;
      int64_t min_line_delta = -4;
      int64_t max_line_delta = 10;
//      int64_t prev_line = 1;
//      bool first = true;
//      for (const auto &line_entry: func_info.lines) {
//        if (first)
//          first = false;
//        else {
//          int64_t line_delta = (int64_t)line_entry.line - prev_line;
//          if (min_line_delta < line_delta)
//            min_line_delta = line_delta;
//          if (max_line_delta > line_delta)
//            max_line_delta = line_delta;
//        }
//        prev_line = line_entry.line;
//      }
//      if (min_line_delta < -4)
//        min_line_delta = -4;
//      if (max_line_delta > 10)
//        max_line_delta = 10;
      
      // Initialize the line entry state as a starting point. All line entries
      // will be deltas from this.
      LineEntry prev(func_info.addr, 1, func_info.lines.front().line);
      
      // Write out the min and max line delta as signed LEB128
      out.WriteSLEB(min_line_delta);
      out.WriteSLEB(max_line_delta);
      
      // Write out the starting line number as a unsigned LEB128
      out.WriteULEB(prev.line);
      
      for (const auto &curr: func_info.lines) {
        assert(curr.addr >= prev.addr);
        uint64_t addr_delta = curr.addr - prev.addr;
        int64_t line_delta = 0;
        if (curr.line > prev.line)
          line_delta = curr.line - prev.line;
        else if (prev.line > curr.line)
          line_delta = -((int32_t)(prev.line - curr.line));
        
        // Set the file if it doesn't match the current one.
        if (curr.file != prev.file) {
          out.WriteU8(DBG_SET_FILE);
          out.WriteULEB(curr.file);
          if (dump)
            printf("%#8.8llx: DBG_SET_FILE(%u)\n", out.Tell(), curr.file);
        }
        
        uint8_t special_op;
        if (encode_special(min_line_delta, max_line_delta, line_delta,
                           addr_delta, special_op)) {
          // Advance the PC and line and push a row
          if (dump)
            printf("%#8.8llx: DBG_SPECIAL(%#2.2x) line += %lli, addr += %lli\n",
                   out.Tell(), special_op, line_delta, addr_delta);
          out.WriteU8(special_op);
        } else {
          // We can't encode the address delta and line delta into
          // a single special opcode, we must do them separately
          
          // Advance the line
          if (line_delta != 0) {
            if (dump)
              printf("%#8.8llx: DBG_ADVANCE_LINE(%lli)\n", out.Tell(), line_delta);
            out.WriteU8(DBG_ADVANCE_LINE);
            out.WriteSLEB(line_delta);
          }
          
          // Advance the PC and push a row
          if (dump)
            printf("%#8.8llx: DBG_ADVANCE_PC(%llu)\n", out.Tell(), addr_delta);
          out.WriteU8(DBG_ADVANCE_PC);
          out.WriteULEB(addr_delta);
        }
        prev = curr;
      }
      if (dump)
        printf("%#8.8llx: DBG_END_SEQUENCE\n", out.Tell());
      out.WriteU8(DBG_END_SEQUENCE);
      
      // Fixup the line table byte size
      const off_t line_table_length = out.Tell() - line_table_start;
      out.Fixup32((uint32_t)line_table_length, line_table_length_offset);
      return true;
    }

    // Parse all line table entries into the "line_table" vector. We can
    // cache the results of this if needed, or we can call LineTable::Lookup()
    // below.
    void ParseAllEntries(std::vector<LineEntry> &line_table,
                         uint64_t base_addr, bool dump) {
      Parse(base_addr, dump, [&line_table](const LineEntry &row) -> bool {
        line_table.push_back(row);
        return true; // Keep parsing by returning true
      });
    }
    // Parse the line table on the fly and find the row we are looking for.
    // We will need to determine if we need to cache the line table by calling
    // LineTable::ParseAllEntries(...) or just call this function each time.
    // There is a CPU vs memory tradeoff we will need to determine.
    LineEntry Lookup(uint64_t base_addr, uint64_t addr) {
      LineEntry result;
      Parse(base_addr, false, [addr, &result](const LineEntry &row) -> bool {
        if (addr < row.addr)
          return false; // Stop parsing, result contains the line table row!
        result = row;
        if (addr == row.addr) {
          // Stop parsing, this is the row we are looking for since the address
          // matches.
          return false;
        }
        return true; // Keep parsing till we find the right row
      });
      return result;
    }    
  };
}

std::string File::Header::GetError() const {
  // TODO: support swapped GSYM files
  if (magic != GSYM_MAGIC)
    return "invalid magic";
  if (version != 1)
    return "invalid version";
  return "";
}

File::File(const char *path) :
  m_file(),
  m_header(nullptr),
  m_addr_offsets(nullptr),
  m_addr_info_offsets(nullptr),
  m_files(nullptr) {
  // Open the input file
  if (!m_file.Open(path, m_error))
    return;
  // We need to keep track of the mmap pointer and size so we can unmap this
  // the mmap data later. We keep this in m_file_data.
  DataRef file_data = m_file.GetData();
  // Now we must see if this is a stand alone gsym file, or of the data is
  // contained in a mach-o or ELF file.
  auto magic = file_data.GetValue<uint32_t>(0, 0);
  if (magic == GSYM_MAGIC) {
    // Stand alone GSYM file.
    m_gsym_data = file_data;
  } else {
    // See if we have gsym data is in a mach-o file.
    m_gsym_data = macho::GetGSYMSectionData(magic, file_data);
  }
    
  if (!m_gsym_data.IsValid())
    return;
  m_header = (Header *)m_gsym_data.GetPointer<Header>(0);

  m_error = m_header->GetError();
  if (!m_error.empty()) {
    m_file.Clear();
    return;
  }
  const uint8_t *p = (uint8_t *)m_gsym_data.data;
  p = alignTo(p + Header::GetByteSize(), m_header->addr_off_size);
  m_addr_offsets = p;
  p = alignTo(p + m_header->num_addrs * m_header->addr_off_size, sizeof(uint32_t));
  m_addr_info_offsets = (uint32_t *)p;
  p = alignTo(p + m_header->num_addrs * sizeof(uint32_t), sizeof(uint32_t));
  m_strtab.data = file_data.GetSlice(m_header->strtab_offset, m_header->strtab_size);
  p = alignTo(p, sizeof(uint32_t));
  m_files = (FileTable *)p;
}


uint64_t File::GetAddressOffset(size_t idx)
{
  if (m_header && m_addr_offsets && idx < m_header->num_addrs) {
    switch (m_header->addr_off_size) {
      case 1: return reinterpret_cast<const  uint8_t *>(m_addr_offsets)[idx];
      case 2: return reinterpret_cast<const uint16_t *>(m_addr_offsets)[idx];
      case 4: return reinterpret_cast<const uint32_t *>(m_addr_offsets)[idx];
      case 8: return reinterpret_cast<const uint64_t *>(m_addr_offsets)[idx];
    }
  }
  return UINT64_MAX;
}

uint64_t File::GetAddressInfoOffset(size_t idx) {
  if (m_header && m_addr_info_offsets && idx < m_header->num_addrs) {
    return m_addr_info_offsets[idx];
  }
  return UINT64_MAX;
}


DataRef File::GetAddressInfoPayload(size_t idx) {
  uint64_t start_offset = GetAddressInfoOffset(idx);
  if (start_offset != UINT64_MAX) {
    start_offset += 8; // Skip uint32_t size and name to get to payload data
    uint64_t end_offset = GetAddressInfoOffset(idx+1);
    if (end_offset == UINT64_MAX)
      return m_gsym_data.GetSlice(start_offset);
    else if (start_offset < end_offset)
      return m_gsym_data.GetSlice(start_offset, end_offset - start_offset);
  }
  return DataRef();
}

void File::Dump() {
  // If m_header is not NULL, then the header has been validated.
  if (!m_header)
    printf("invalid gsym file");
  m_header->Dump();
  const char *addr_off_format = nullptr;
  switch (m_header->addr_off_size) {
    case 1: addr_off_format = "[%3u] 0x%2.2llx (0x%16.16llx)\n"; break;
    case 2: addr_off_format = "[%3u] 0x%4.4llx (0x%16.16llx)\n"; break;
    case 4: addr_off_format = "[%3u] 0x%8.8llx (0x%16.16llx)\n"; break;
    case 8: addr_off_format = "[%3u] 0x%8.8llx (0x%16.16llx)\n"; break;
  }
  printf("Address Offsets:\n");
  for (uint32_t i=0; i<m_header->num_addrs; ++i) {
    auto addr_offset = GetAddressOffset(i);
    printf(addr_off_format, i, addr_offset, addr_offset+m_header->base_address);
  }
  printf("Address Info Offsets:\n");
  for (uint32_t i=0; i<m_header->num_addrs; ++i)
    printf("[%3u] 0x%8.8llx\n", i, GetAddressInfoOffset(i));
  m_files->Dump(m_strtab);
  //m_strtab.Dump();
  
  for (uint32_t i=0; i<m_header->num_addrs; ++i) {
    const auto addr_info_offset = GetAddressInfoOffset(i);
    printf("\n0x%8.8llx: ", addr_info_offset);
    auto addr_info = m_gsym_data.GetPointer<AddressInfo>(addr_info_offset);
    if (addr_info) {
      uint64_t addr = m_header->base_address + GetAddressOffset(i);
      uint64_t end_addr = addr + addr_info->size;
      auto name = m_strtab.GetString(addr_info->name);
      printf("[0x%llx - 0x%llx): %s\n", addr, end_addr, name);
      DataDecoder data = GetAddressInfoPayload(i);
      
      bool done = false;
      while (!done) {
        off_t offset = data.GetPosition() + addr_info_offset + 8;
        uint32_t info_type = data.GetU32();
        uint32_t info_len = data.GetU32();
        printf("0x%8.8llx: %s length=0x%x (%u)\n", offset, LineTable::GetInfoTypeAsString(info_type), info_len, info_len);
        DataDecoder info_data = data.GetData(info_len);
        switch (info_type) {
          case InfoType::EndOfList:
            done = true;
            break;

          case InfoType::LineTableInfo:
            {
              std::vector<LineEntry> line_table;
              LineTable line_parser(info_data);
              DumpLineTable(addr, info_data, false);
            }
            break;

          case InfoType::InlineInfo:
            {
              printf("error: dumping InlineInfo isn't supported yet\n");
            }
            break;
        }
      }
    }
  }
}


void File::DumpLineTable(uint64_t base_addr, DataDecoder &line_data,
                               bool dump_opcodes) {
  LineTable parser(line_data);
  std::vector<LineEntry> line_table;
  parser.ParseAllEntries(line_table, base_addr, dump_opcodes);
  for (const auto &line_entry: line_table) {
    auto file_entry = m_files->GetFile(line_entry.file);
    auto dir = m_strtab.GetString(file_entry.directory);
    auto base = m_strtab.GetString(file_entry.basename);
    printf("0x%16.16llx: %s/%s:%u\n", line_entry.addr, dir, base,
           line_entry.line);
  }
}

bool File::FindAddressInfo(uint64_t addr, LookupInfo &lookup_info) {
  if (addr < m_header->base_address || m_header->num_addrs == 0)
    return nullptr;
  const uint64_t addr_offset = addr - m_header->base_address;
  lookup_info.Clear();
  
  switch (m_header->addr_off_size) {
    case 1: {
      auto first = reinterpret_cast<const uint8_t *>(m_addr_offsets);
      auto last = first + m_header->num_addrs;
      auto pos = std::lower_bound(first, last, addr_offset);
      if (pos == last || addr_offset < *pos)
        --pos;
      lookup_info.addr_info_index = std::distance(first, pos);
      lookup_info.match_addr_offset = *pos;
      break;
    }
    case 2: {
      auto first = reinterpret_cast<const uint16_t *>(m_addr_offsets);
      auto last = first + m_header->num_addrs;
      auto pos = std::lower_bound(first, last, addr_offset);
      if (pos == last || addr_offset < *pos)
        --pos;
      lookup_info.addr_info_index = std::distance(first, pos);
      lookup_info.match_addr_offset = *pos;
      break;
    }
    case 4: {
      auto first = reinterpret_cast<const uint32_t *>(m_addr_offsets);
      auto last = first + m_header->num_addrs;
      auto pos = std::lower_bound(first, last, addr_offset);
      if (pos == last || addr_offset < *pos)
        --pos;
      lookup_info.addr_info_index = std::distance(first, pos);
      lookup_info.match_addr_offset = *pos;
      break;
    }
    case 8: {
      auto first = reinterpret_cast<const uint64_t *>(m_addr_offsets);
      auto last = first + m_header->num_addrs;
      auto pos = std::lower_bound(first, last, addr_offset);
      if (pos == last || addr_offset < *pos)
        --pos;
      lookup_info.addr_info_index = std::distance(first, pos);
      lookup_info.match_addr_offset = *pos;
      break;
    }
    default:
      break;
  }
  
  if (lookup_info.addr_info_index < m_header->num_addrs) {
    auto addr_info_offset = m_addr_info_offsets[lookup_info.addr_info_index];
    auto addr_info = m_gsym_data.GetPointer<AddressInfo>(addr_info_offset);
    if (addr_info) {
      // Make sure the address is within the bounds of the address info's size
      auto func_offset = addr_offset - lookup_info.match_addr_offset;
      // If an entry has zero size, then we will match it regardless of the
      // size. These are typically symbols in the symbol table.
      if (addr_info->size == 0 || func_offset < addr_info->size) {
        lookup_info.addr_info = addr_info;
        return true;
      }
    }
  }
  return false;
}

bool File::Lookup(uint64_t addr, LookupResult &result) {
  result.Clear();
  LookupInfo lookup_info;
  if (!FindAddressInfo(addr, lookup_info))
    return false;
  
  result.addr = m_header->base_address + lookup_info.match_addr_offset;
  result.end_addr = result.addr + lookup_info.addr_info->size;
  result.name = m_strtab.GetString(lookup_info.addr_info->name);
  
  DataDecoder data = GetAddressInfoPayload(lookup_info.addr_info_index);
  uint32_t info_type;
  while ((info_type = data.GetU32())) {
    uint32_t info_len = data.GetU32();
    DataDecoder info_data = data.GetData(info_len);
    switch (info_type) {
    case InfoType::LineTableInfo: {
        std::vector<LineEntry> line_table;
        LineTable line_parser(info_data);
        //DumpLineTable(info_data); // Uncomment to dump the line table
        LineEntry line_entry = line_parser.Lookup(result.addr, addr);
        if (line_entry.IsValid()) {
          auto file_entry = m_files->GetFile(line_entry.file);
          result.directory = m_strtab.GetString(file_entry.directory);
          result.basename = m_strtab.GetString(file_entry.basename);
          result.line = line_entry.line;
        }
      }
      break;
    case InfoType::InlineInfo:
      break;
    }
  }
  return true;
}

bool File::GetFunctionInfo(uint64_t addr, FunctionInfo &func_info) {
  LookupInfo lookup_info;
  if (!FindAddressInfo(addr, lookup_info))
    return false;
  
  func_info.addr = m_header->base_address + lookup_info.match_addr_offset;
  func_info.size = lookup_info.addr_info->size;
  func_info.name = lookup_info.addr_info->name;
  
  DataDecoder data = GetAddressInfoPayload(lookup_info.addr_info_index);
  uint32_t info_type;
  while ((info_type = data.GetU32())) {
    uint32_t info_len = data.GetU32();
    DataDecoder info_data = data.GetData(info_len);
    switch (info_type) {
      case InfoType::LineTableInfo: {
          LineTable parser(info_data);
          parser.ParseAllEntries(func_info.lines, func_info.addr, false);
        }
        break;
      case InfoType::InlineInfo:
        break;
    }
  }
  return true;
}



bool File::Save(StringTableCreator &strtab,
                FileTableCreator &filetab,
                const std::vector<FunctionInfo> &func_infos,
                const char *path) {
  if (func_infos.empty())
    return false;
  const uint64_t min_addr = func_infos.front().addr;
  const uint64_t max_addr = func_infos.back().addr;
  const uint64_t addr_delta = max_addr - min_addr;
  uint8_t addr_info_offset_size = 8;
  if (addr_delta <= UINT8_MAX)
    addr_info_offset_size = 1;
  else if (addr_delta <= UINT16_MAX)
    addr_info_offset_size = 2;
  else if (addr_delta <= UINT32_MAX)
    addr_info_offset_size = 4;
  Header header = {0};
  header.magic = GSYM_MAGIC;
  header.version = GSYM_VERSION;
  header.addr_off_size = addr_info_offset_size;
  header.base_address = min_addr;
  assert(func_infos.size() <= UINT32_MAX);
  header.num_addrs = (uint32_t)func_infos.size();
  header.strtab_offset = 0; // We will need to fix this up later.
  header.strtab_size = 0;// We will need to fix this up later.
  
  FileWriter out;
  int err = out.Open(path);
  if (err)
    return err;
  // Write out the header
  out.Write(&header, Header::GetByteSize());
  out.AlignTo(header.addr_off_size);
  // Write out the address offsets
  for (const auto &func_info: func_infos) {
    uint64_t addr_offset = func_info.addr - header.base_address;
    out.WriteUnsigned(addr_offset, header.addr_off_size);
  }
  // Write out all zeros for the addr_info_offsets;
  const off_t addr_info_offsets_offset = out.Tell();
  out.AlignTo(sizeof(uint32_t));
  for (size_t i=0, n=func_infos.size(); i<n; ++i)
    out.WriteU32(0);

  // Write out the file table
  out.AlignTo(sizeof(uint32_t));
  filetab.Write(out);
  // Write out the sting table
  const off_t strtab_offset = out.Tell();
  strtab.Write(out);
  const off_t strtab_size = out.Tell() - strtab_offset;
  std::vector<uint32_t> addr_info_offsets;
  // Write out the address infos for each address
  for (const auto &func_info: func_infos) {
    out.AlignTo(sizeof(uint32_t));
    addr_info_offsets.push_back((uint32_t)out.Tell());
    // Write the size in bytes of this function as a uint32_t
    out.WriteU32(func_info.size);
    // Write the name of this function as a uint32_t string table offset
    out.WriteU32(func_info.name);
    // Write out the line table if we have one.
    LineTable::Write(out, func_info, true /*dump*/);
    // Terminate the data chunks with and end of list with zero size
    out.WriteU32(InfoType::EndOfList);
    out.WriteU32(0);
  }
  // Fixup the string table offset and size in the header
  out.Seek(offsetof(Header, strtab_offset));
  out.WriteU32((uint32_t)strtab_offset);
  out.WriteU32((uint32_t)strtab_size);

  // Fixup all address info offsets
  out.Seek(addr_info_offsets_offset);
  out.Write(addr_info_offsets.data(), addr_info_offsets.size() * sizeof(uint32_t));
  out.Close();
  return true;
}


void File::Unmap() {
  m_file.Clear();
  m_gsym_data.Clear();
  m_header = nullptr;
  m_addr_offsets = nullptr;
  m_addr_info_offsets = nullptr;
  m_files = nullptr;
  m_strtab.Clear();
}

File::~File() {
  Unmap();
}

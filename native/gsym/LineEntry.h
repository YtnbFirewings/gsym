//
//  LineEntry.h
//  gsym
//

#ifndef gsym_LineEntry_h
#define gsym_LineEntry_h


namespace gsym {
  struct LineEntry {
    uint64_t addr; // Start address of this line entry
    uint32_t file; // 1 based index of file in FileTable
    uint32_t line; // Source line number
    LineEntry(uint64_t a=0, uint32_t f=0, uint32_t l=0) :
        addr(a), file(f), line(l) {
    }
    bool IsValid() {
      return line != 0;
    }
  };
  inline bool operator==(const LineEntry &lhs, const LineEntry &rhs) {
    return lhs.addr == rhs.addr &&
           lhs.file == rhs.file &&
           lhs.line == rhs.line;
  }
  inline bool operator!=(const LineEntry &lhs, const LineEntry &rhs) {
    return !(lhs == rhs);
  }
}

#endif // #ifndef gsym_LineEntry_h

//
//  FunctionInfo
//  gsym
//

#ifndef gsym_FunctionInfo_h
#define gsym_FunctionInfo_h

#include "LineEntry.h"
#include <vector>

namespace gsym {
  struct FunctionInfo {
    uint64_t addr;
    uint32_t size;
    uint32_t name;
    std::vector<gsym::LineEntry> lines;

    FunctionInfo(uint64_t a=0, uint32_t s=0, uint32_t n=0) :
      addr(a), size(s), name(n) {
    }
  
    bool IsValid() const {
      // Address and size can be zero and there can be no line entries for a
      // symbol so the only indication this entry is valid is if the name is
      // not zero.
      return name != 0;
    }

    void Clear() {
      addr = 0;
      size = 0;
      name = 0;
      lines.clear();
    }
  };
  
  inline bool operator==(const FunctionInfo &lhs, const FunctionInfo &rhs) {
    return lhs.addr == rhs.addr &&
           lhs.size == rhs.size &&
           lhs.name == rhs.name &&
           lhs.lines == rhs.lines;
  }
  inline bool operator!=(const FunctionInfo &lhs, const FunctionInfo &rhs) {
    return !(lhs == rhs);
  }
  inline bool operator<(const FunctionInfo &lhs, const FunctionInfo &rhs) {
    return lhs.addr < rhs.addr;
  }

}

#endif // #ifndef gsym_FunctionInfo_h

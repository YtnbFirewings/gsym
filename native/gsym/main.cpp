//
//  main.cpp
//  gsym
//

#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "gsym.h"
#include "LookupResult.h"

int main(int argc, const char * argv[]) {
  if (argc < 2) {
    printf("Usage: gsym PATH [ADDR1 ADDR2]\n");
    return 1;
  }
  gsym::File file(argv[1]);
  if (argc == 2)
    file.Dump();
  else {
    for (int i=2; i<argc; ++i) {
      uint64_t addr = strtoull(argv[i], 0, 0);
      if (addr == ULLONG_MAX) {
        printf("error: invalid address parameter \"%s\"\n", argv[i]);
        return 1;
      } else {
        gsym::LookupResult result;
        if (file.Lookup(addr, result)) {
          printf("matching addr for 0x%16.16llx is ", addr);
          result.Dump();
          puts(""); // Newline
        } else
          printf("no matching entry for 0x%16.16llx\n", addr);
      }
    }
  }
  return 0;
}

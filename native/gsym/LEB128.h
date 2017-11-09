//
//  LEB128.h
//  gsym
//

#ifndef gsym_LEB128_h
#define gsym_LEB128_h

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

namespace gsym {
  
  inline size_t encodeULEB128(uint64_t value, uint8_t *p) {
    uint8_t *start = p;
    do {
      uint8_t byte = value & 0x7f;
      value >>= 7;
      if (value != 0)
        byte |= 0x80;
      *p++ = byte;
    } while (value != 0);
    return p - start; // Return number of bytes encoded
  }

  inline size_t encodeSLEB128(int64_t value, uint8_t *p) {
    uint8_t *start = p;
    bool more;
    do {
      uint8_t byte = value & 0x7f;
      value >>= 7;
      more = !((((value == 0 ) && ((byte & 0x40) == 0)) ||
                ((value == -1) && ((byte & 0x40) != 0))));
      if (more)
        byte |= 0x80;
      *p++ = byte;
    } while (more);
    return p - start;  // Return number of bytes encoded
  }

  inline uint64_t
  decodeULEB128(const uint8_t *p, const uint8_t *end, size_t &n) {
    const uint8_t *start = p;
    uint64_t value = 0;
    unsigned shift = 0;
    do {
      if (end && p == end) {
        n = p - start;
        return 0;
      }
      uint64_t slice = *p & 0x7f;
      if (shift >= 64 || slice << shift >> shift != slice) {
        n = p - start;
        return 0;
      }
      value += uint64_t(*p & 0x7f) << shift;
      shift += 7;
    } while (*p++ >= 128);
    n = p - start;
    return value;
  }

  inline int64_t decodeSLEB128(const uint8_t *p, const uint8_t *end, size_t &n) {
    const uint8_t *start = p;
    int64_t value = 0;
    unsigned shift = 0;
    uint8_t byte;
    do {
      if (end && p == end) {
        n = p - start;
        return 0;
      }
      byte = *p++;
      value |= (int64_t(byte & 0x7f) << shift);
      shift += 7;
    } while (byte >= 128);
    // Sign extend negative numbers only if the sign bit isn't already set.
    if (byte & 0x40 && (value & 0x8000000000000000ll) == 0)
      value |= (-1ULL) << shift;
    n = p - start;
    return value;
  }

}

#endif // #ifndef gsym_LEB128_h

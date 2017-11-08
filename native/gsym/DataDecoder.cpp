//
//  DataDecoder.cpp
//  gsym
//

#include "DataDecoder.h"

using namespace gsym;

uint64_t DataDecoder::GetULEB128(uint64_t fail_value) {
  const uint8_t *start = m_data.GetPointer<uint8_t>(m_pos);
  if (start == nullptr)
    return fail_value;
  const uint8_t *end = m_data.GetEnd();
  if (start >= end)
    return fail_value;
  const uint8_t *p = start;
  uint64_t result = *p++;
  if (result >= 0x80) {
    result &= 0x7f;
    int shift = 7;
    while (p < end) {
      uint8_t byte = *p++;
      result |= (uint64_t)(byte & 0x7f) << shift;
      if ((byte & 0x80) == 0)
        break;
      shift += 7;
    }
  }
  m_pos += p - start;
  return result;
}

int64_t DataDecoder::GetSLEB128(int64_t fail_value) {
  const uint8_t *start = m_data.GetPointer<uint8_t>(m_pos);
  if (start == nullptr)
    return fail_value;
  const uint8_t *end = m_data.GetEnd();
  if (start >= end)
    return fail_value;
  const uint8_t *p = start;
  int64_t result = 0;
  int shift = 0;
  int size = sizeof(int64_t) * 8;
  
  uint8_t byte = 0;
  int bytecount = 0;
  
  while (p < end) {
    bytecount++;
    byte = *p++;
    result |= (int64_t)(byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) == 0)
      break;
  }
  
  // Sign bit of byte is 2nd high order bit (0x40)
  if (shift < size && (byte & 0x40))
    result |= -(1 << shift);

  m_pos += p - start;
  return result;
}

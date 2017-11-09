//
//  DataDecoder.cpp
//  gsym
//

#include "DataDecoder.h"
#include "LEB128.h"

using namespace gsym;

uint64_t DataDecoder::GetULEB128(uint64_t fail_value) {
  const uint8_t *start = m_data.GetPointer<uint8_t>(m_pos);
  if (start == nullptr)
    return fail_value;
  const uint8_t *end = m_data.GetEnd();
  if (start >= end)
    return fail_value;
  size_t n = 0;
  auto result = decodeULEB128(start, end, n);
  m_pos += n;
  return result;
}

int64_t DataDecoder::GetSLEB128(int64_t fail_value) {
  
  const uint8_t *start = m_data.GetPointer<uint8_t>(m_pos);
  if (start == nullptr)
    return fail_value;
  const uint8_t *end = m_data.GetEnd();
  if (start >= end)
    return fail_value;
  size_t n = 0;
  auto result = decodeSLEB128(start, end, n);
  m_pos += n;
  return result;
}

//
//  DataDecoder.h
//  gsym
//

#ifndef gsym_DataDecoder_h
#define gsym_DataDecoder_h

#include "DataRef.h"
#include <assert.h>

namespace gsym {
  class DataDecoder {
    DataRef m_data;
    size_t m_pos;
  public:
    DataDecoder() : m_data(), m_pos(0) {}
    DataDecoder(DataRef data, size_t pos=0) : m_data(data), m_pos(pos) {}

    size_t GetPosition() {
      return m_pos;
    }

    void SetPosition(size_t pos) {
      m_pos = pos;
    }
    void AlignTo(uint32_t align) {
      assert(align != 0);
      m_pos = (m_pos + align - 1) / align * align;
    }

    DataDecoder GetData(uint64_t len) {
      auto bytes = m_data.GetData(m_pos, len);
      if (bytes) {
        m_pos += len;
        return DataDecoder(DataRef(bytes, len), 0);
      }
      return DataDecoder();
    }
    
    int64_t GetSLEB128(int64_t fail_value = 0);
    uint64_t GetULEB128(uint64_t fail_value = 0);
    
    uint8_t GetU8(uint8_t fail_value = 0) {
      auto result = m_data.GetValue<uint8_t>(m_pos, fail_value);
      m_pos += sizeof(fail_value);
      return result;
    }
    uint16_t GetU16(uint16_t fail_value = 0) {
      auto result = m_data.GetValue<uint16_t>(m_pos, fail_value);
      m_pos += sizeof(fail_value);
      return result;
    }
    uint32_t GetU32(uint32_t fail_value = 0) {
      auto result = m_data.GetValue<uint32_t>(m_pos, fail_value);
      m_pos += sizeof(fail_value);
      return result;
    }
    uint64_t GetU64(uint64_t fail_value = 0) {
      auto result = m_data.GetValue<uint64_t>(m_pos, fail_value);
      m_pos += sizeof(fail_value);
      return result;
    }
    int8_t GetS8(int8_t fail_value = 0) {
      auto result = m_data.GetValue<int8_t>(m_pos, fail_value);
      m_pos += sizeof(fail_value);
      return result;
    }
    int16_t GetS16(int16_t fail_value = 0) {
      auto result = m_data.GetValue<int16_t>(m_pos, fail_value);
      m_pos += sizeof(fail_value);
      return result;
    }
    int32_t GetS32(int32_t fail_value = 0) {
      auto result = m_data.GetValue<int32_t>(m_pos, fail_value);
      m_pos += sizeof(fail_value);
      return result;
    }
    int64_t GetS64(int64_t fail_value = 0) {
      auto result = m_data.GetValue<int64_t>(m_pos, fail_value);
      m_pos += sizeof(fail_value);
      return result;
    }
  };
}

#endif // #ifndef gsym_DataDecoder_h

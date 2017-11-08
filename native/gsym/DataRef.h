//
//  gsym.h
//  gsym
//
//  Created by Gregory Clayton on 10/11/17.
//  Copyright © 2017 Gregory Clayton. All rights reserved.
//

#ifndef gsym_DataRef_h
#define gsym_DataRef_h

#include <stdint.h>
#include <string.h>

namespace gsym {
  //----------------------------------------------------------------------
  // The DataRef class is designed to point to memory mapped memory and
  // access structures and data in that memory without needing to parse it
  // in any way. Structures encoded in memory can be easily accessed
  // using:
  //
  //    DataRef data(...);
  //    Foo *foo_ptr = data.GetPointer<Foo>(offset);
  //
  // The "foo_ptr" will be NULL if there isn't enough data in the DataRef
  // to contain a struct whose size is the size of the requested type at
  // the specified byte offset "offset".
  //
  // DataRef has rudimentary functions to extract types with GetValue().
  // It is designed to get around alignment requirements when decoding
  // native types. A uint64_t can only be dereferenced from a buffer of
  // bytes if it is properly aligned on some architectures (ARM/Thumb),
  // so the functionality used memcpy to copy the data into an aligned
  // location before returning it.
  //
  // More complex data extraction should use the gsym::DataDecoder class.
  //----------------------------------------------------------------------
  struct DataRef {
    const uint8_t *data;
    uint64_t length;
    DataRef(const void *d = nullptr, uint64_t l = 0) :
      data(reinterpret_cast<const uint8_t *>(d)), length(l) {
    }

    void SetData(const void *d, uint64_t l) {
      data = reinterpret_cast<const uint8_t *>(d);
      length = l;
    }

    uint64_t ByteLeft(uint64_t offset) const {
      return offset < length ? length - offset : 0;
    }

    void Clear() {
      data = nullptr;
      length = 0;
    }

    bool IsValid() const {
      return data != nullptr && length > 0;
    }
    const uint8_t *GetStart() const {
      return data;
    }
    const uint8_t *GetEnd() const {
      if (IsValid())
        return data + length;
      return nullptr;
    }

    DataRef GetSlice(uint64_t offset, uint64_t len = UINT64_MAX) const {
      if (len == UINT64_MAX)
        len = ByteLeft(offset);
      if (len > 0) {
        auto p = GetData(offset, len);
        if (p)
          return DataRef(p, len);
      }
      return DataRef();
    }

    const void *GetData(uint64_t offset, uint64_t len = 1) const {
      if (ByteLeft(offset) >= len)
        return reinterpret_cast<const uint8_t *>(data) + offset;
      return nullptr;
    }

    template<typename T>
    T GetValue(uint64_t offset, T fail_value = T()) const {
      auto p = GetData(offset, sizeof(T));
      if (p) {
        // Use memcpy to avoid alignment requirements
        T value;
        memcpy(&value, p, sizeof(uint64_t));
        return value;
      }
      return fail_value;
    }
    
    template<typename T>
    const T *GetPointer(uint64_t offset) const {
      return reinterpret_cast<const T *>(GetData(offset, sizeof(T)));
    }
  };
}

#endif // #ifndef gsym_DataRef_h

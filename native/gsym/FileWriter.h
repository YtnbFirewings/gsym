//
//  FileWriter.h
//  gsym
//

#ifndef gsym_FileWriter_h
#define gsym_FileWriter_h

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

namespace gsym {
  
  class FileWriter {
    int m_fd;
  public:
    FileWriter() : m_fd(-1) {}
    ~FileWriter();
    int Open(const char *path);
    void Close();
    bool WriteSLEB(int64_t value);
    bool WriteULEB(uint64_t value);
    bool WriteU8(uint8_t value);
    bool WriteU32(uint32_t value);
    bool Fixup32(uint32_t value, off_t offset);
    bool WriteUnsigned(uint64_t value, size_t n);
    bool Write(const void *src, size_t src_len);
    bool AlignTo(size_t align);
    off_t Seek(off_t pos);
    off_t Tell();
  private:
    FileWriter(const FileWriter &rhs) = delete;
    void operator=(const FileWriter &rhs) = delete;
  };
  
}

#endif // #ifndef gsym_FileWriter_h

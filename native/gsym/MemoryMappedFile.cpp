//
//  MemoryMappedFile.h
//  gsym
//

#include "MemoryMappedFile.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

using namespace gsym;

bool MemoryMappedFile::Open(const char *path, std::string &error) {
  // Open the input file
  int fd = open (path, O_RDONLY);
  if (fd == -1) {
    error.append("open: ");
    error.append(strerror(errno));
    return false;
  }
  
  // We are going mmap this file and we need the file size in bytes for that.
  struct stat stat_info;
  if (fstat (fd, &stat_info) == -1) {
    error.append("fstat: ");
    error.append(strerror(errno));
    return false;
  }
  
  // Make sure we have a file.
  if (!S_ISREG (stat_info.st_mode)) {
    error.append(path);
    error.append(": not a file");
    return false;
  }
  
  if (stat_info.st_size == 0) {
    error.append(path);
    error.append(": empty file");
    return false;
  }
  
  // memory map the file shared and read only.
  const uint8_t *data = (uint8_t *)mmap (0, stat_info.st_size, PROT_READ,
                                         MAP_SHARED, fd, 0);
  if (data == MAP_FAILED) {
    error.append("mmap: ");
    error.append(strerror(errno));
    return false;
  }
  // We need to keep track of the mmap pointer and size so we can unmap this
  // the mmap data later. We keep this in m_file_data.
  m_data = DataRef(data, stat_info.st_size);
  return m_data.IsValid();
}

MemoryMappedFile::~MemoryMappedFile() {
  Clear();
}

void MemoryMappedFile::Clear() {
  if (m_data.IsValid()) {
    munmap ((void *)m_data.data, m_data.length);
    m_data.Clear();
  }
}
